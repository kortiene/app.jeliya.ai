//! THROWAWAY Phase 0 spike (#23) — native iroh echo endpoint.
//!
//! Not a member of the Jeliya workspace. Not built by release.yml. Not shipped.
//!
//! What this does:
//!   1. Generates an iroh [`SecretKey`], then proves possession of it to
//!      relay-auth (signs a challenge) and obtains a short-lived,
//!      endpoint-bound token — exactly the same admission path the browser
//!      takes. The production design treats the native companion as trusted
//!      by package signature rather than by relay-auth, but for the spike the
//!      cleanest proof that relay admission works end-to-end is to run BOTH
//!      peers through it.
//!   2. Builds an iroh [`Endpoint`] whose only transport is the single
//!      dedicated relay, presenting the token as the relay auth credential.
//!      `RelayMode::Custom` with one relay URL matches the production design
//!      (browser sandboxes have no UDP hole-punch path).
//!   3. Registers a single echo ALPN. Every inbound bidi stream is read to
//!      end and echoed back UPPERCASED, so a browser round trip is
//!      unambiguously verifiable in both directions.
//!   4. Prints its own `EndpointId` and the relay URL so the orchestrator
//!      and the browser client can dial it.

use std::time::Duration;

use clap::Parser;
use iroh::{
    Endpoint, RelayMode, RelayUrl, SecretKey,
    endpoint::{Connection, presets},
    protocol::{AcceptError, ProtocolHandler, Router},
};
use n0_error::{Result, StdResultExt};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// The echo ALPN. Distinct from any real Jeliya ALPN so this spike cannot be
/// confused for shipping protocol surface.
pub const ECHO_ALPN: &[u8] = b"jeliya/spike/echo/1";

#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
struct Cli {
    /// The dedicated relay URL the endpoint registers with.
    #[clap(long, env = "SPIKE_RELAY_URL")]
    relay_url: RelayUrl,
    /// The relay-auth HTTP base URL (for proof-of-possession + token mint).
    #[clap(long, env = "SPIKE_RELAY_AUTH_URL")]
    relay_auth_url: String,
    /// How long to stay up before exiting (seconds).
    #[clap(long, env = "SPIKE_UPTIME_SECS", default_value_t = 600)]
    uptime_secs: u64,
}

#[derive(Serialize)]
struct TokenReq<'a> {
    endpoint_id: &'a str,
    challenge: &'a str,
    signature: &'a str,
}

#[derive(Deserialize)]
struct TokenResp {
    token: String,
    #[allow(dead_code)]
    endpoint_id: String,
    #[allow(dead_code)]
    expires_at_ms: u64,
}

#[derive(Deserialize)]
struct ChallengeResp {
    challenge: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("spike_native_endpoint=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();
    info!(relay_url = %cli.relay_url, "spike native endpoint starting");

    // 1. Generate the endpoint identity.
    let secret = SecretKey::generate();
    let endpoint_id = secret.public();
    let endpoint_id_hex = endpoint_id.to_string();

    // 2. Proof of possession: fetch a challenge from relay-auth and sign it.
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .anyerr()?;
    let challenge: ChallengeResp = http
        .get(format!("{}/challenge", cli.relay_auth_url))
        .send()
        .await
        .anyerr()?
        .json()
        .await
        .anyerr()?;
    let challenge_bytes =
        hex::decode(&challenge.challenge).map_err(|_| n0_error::AnyError::from("challenge not hex"))?;
    let sig = secret.sign(&challenge_bytes);
    let sig_hex = hex::encode(sig.to_bytes());
    let req = TokenReq {
        endpoint_id: &endpoint_id_hex,
        challenge: &challenge.challenge,
        signature: &sig_hex,
    };
    let token_resp: TokenResp = http
        .post(format!("{}/token", cli.relay_auth_url))
        .json(&req)
        .send()
        .await
        .anyerr()?
        .json()
        .await
        .anyerr()?;
    info!(token_expires_at_ms = token_resp.expires_at_ms, "got relay-auth token");

    // 3. Build the endpoint with the dedicated relay + token.
    let relay_config = iroh_relay::RelayConfig::new(cli.relay_url.clone(), None)
        .with_auth_token(token_resp.token.clone());
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(secret)
        .relay_mode(RelayMode::Custom(relay_config.into()))
        .bind()
        .await?;
    let router = Router::builder(endpoint.clone())
        .accept(ECHO_ALPN, EchoHandler)
        .spawn();
    let endpoint = router.endpoint();

    endpoint.online().await;
    let relay_url_str = endpoint
        .addr()
        .relay_urls()
        .next()
        .map(|u| u.to_string())
        .unwrap_or_default();
    info!(%endpoint_id, %relay_url_str, "online; browser can dial ALPN {}", std::str::from_utf8(ECHO_ALPN).unwrap_or("<binary>"));

    println!("SPIKE_NATIVE_READY endpoint_id={endpoint_id} relay_url={relay_url_str}");

    let deadline = tokio::time::sleep(Duration::from_secs(cli.uptime_secs));
    tokio::pin!(deadline);
    tokio::select! {
        _ = deadline => warn!("uptime deadline reached, exiting"),
        _ = tokio::signal::ctrl_c() => warn!("ctrl-c, exiting"),
    }
    router.shutdown().await.anyerr()?;
    Ok(())
}

/// Reads a single bidi stream to end, uppercases it, and writes it back.
#[derive(Debug)]
struct EchoHandler;

impl ProtocolHandler for EchoHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let remote = connection.remote_id();
        let (mut send, mut recv) = connection.accept_bi().await?;
        let payload = recv.read_to_end(1024 * 1024).await.anyerr()?;
        let echoed = String::from_utf8_lossy(&payload).to_uppercase();
        send.write_all(echoed.as_bytes()).await.anyerr()?;
        send.finish().anyerr()?;
        connection.closed().await;
        info!(%remote, frame_len = payload.len(), "echoed a frame");
        Ok(())
    }
}
