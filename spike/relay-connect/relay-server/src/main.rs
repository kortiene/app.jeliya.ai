//! THROWAWAY Phase 0 spike (#23) — dedicated iroh-relay with token admission.
//!
//! Not a member of the Jeliya workspace. Not built by release.yml. Not shipped.
//!
//! This is a dedicated relay (not the public n0 managed relay) that admits a
//! connecting peer only if it presents a valid short-lived, endpoint-bound
//! token minted by [`relay-auth`](../relay-auth/). It exercises the production
//! design's abuse-prevention boundary: a browser that has not proved
//! possession of its key to relay-auth gets `Access::Deny` and never reaches
//! the native endpoint.
//!
//! The token format is defined by relay-auth: `base64(payload_json).base64(sig)`
//! where `sig = Ed25519_sign(relay_auth_key, CONTEXT || payload_json)`. The
//! verifying key is passed on the CLI so this binary holds no long-lived
//! secret either.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64ct::{Base64Unpadded, Encoding};
use clap::Parser;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use iroh_relay::server::{
    Access, AccessControl, ClientRequest, RelayConfig, Server, ServerConfig,
};
use n0_error::{Result, StdResultExt};
use serde::Deserialize;
use tracing::{debug, info, warn};

/// Must match relay-auth's TOKEN_CONTEXT exactly.
const TOKEN_CONTEXT: &[u8] = b"jeliya/spike/relay-auth-token/v1";

#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
struct Cli {
    /// Bind address for the relay HTTP server (plain HTTP, dev mode).
    #[clap(long, env = "SPIKE_RELAY_BIND", default_value = "127.0.0.1:3340")]
    bind: SocketAddr,
    /// The relay-auth verifying key (64 hex chars = 32 bytes), as printed by
    /// relay-auth on startup. Without it, every connection is denied.
    #[clap(long, env = "SPIKE_RELAY_AUTH_VERIFYING_KEY")]
    verifying_key: String,
}

#[derive(Debug)]
struct TokenAccess {
    verifying_key: VerifyingKey,
}

impl AccessControl for TokenAccess {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        let Some(token) = request.auth_token() else {
            warn!(endpoint_id = %request.endpoint_id(), "denied: no auth token");
            return Access::Deny { reason: Some("missing token".into()) };
        };
        match validate_token(&token, &self.verifying_key, request.endpoint_id().as_bytes()) {
            Ok(()) => {
                debug!(endpoint_id = %request.endpoint_id(), "admitted");
                Access::Allow
            }
            Err(err) => {
                warn!(endpoint_id = %request.endpoint_id(), %err, "denied: token invalid");
                Access::Deny { reason: Some(format!("token invalid: {err}")) }
            }
        }
    }
}

#[derive(Deserialize)]
struct TokenPayload {
    endpoint_id: String,
    exp: u64,
    #[allow(dead_code)]
    nonce: String,
}

fn validate_token(
    token: &str,
    verifying_key: &VerifyingKey,
    presented_endpoint_bytes: &[u8; 32],
) -> std::result::Result<(), String> {
    let (payload_b64, sig_b64) = token.split_once('.').ok_or("malformed token: no '.'")?;
    let payload_bytes = Base64Unpadded::decode_vec(payload_b64)
        .map_err(|e| format!("payload not base64: {e}"))?;
    let sig_bytes = Base64Unpadded::decode_vec(sig_b64)
        .map_err(|e| format!("signature not base64: {e}"))?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|e| format!("signature malformed: {e}"))?;

    // Verify the detached signature over CONTEXT || payload.
    let sig_body = [TOKEN_CONTEXT, &payload_bytes].concat();
    verifying_key
        .verify(&sig_body, &sig)
        .map_err(|e| format!("signature invalid: {e}"))?;

    // Decode the now-authenticated payload.
    let payload: TokenPayload =
        serde_json::from_slice(&payload_bytes).map_err(|e| format!("payload not json: {e}"))?;

    // Endpoint binding: the token names the id it admits; the relay must see
    // that same id on the connection.
    let token_endpoint_bytes = hex::decode(&payload.endpoint_id)
        .map_err(|e| format!("payload endpoint_id not hex: {e}"))?;
    if token_endpoint_bytes.as_slice() != &presented_endpoint_bytes[..] {
        return Err("endpoint_id mismatch: token bound to a different id".into());
    }

    // Short-lived: exp must be in the future.
    let now_ms = now_ms();
    if payload.exp <= now_ms {
        return Err(format!("token expired (exp={} now={})", payload.exp, now_ms));
    }

    Ok(())
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("spike_relay_server=info".parse().unwrap()),
        )
        .init();
    let cli = Cli::parse();

    let vk_bytes = hex::decode(&cli.verifying_key).anyerr()?;
    let vk_arr: [u8; 32] = vk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| n0_error::AnyError::from("--verifying-key must be 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&vk_arr).anyerr()?;

    let access = Arc::new(TokenAccess { verifying_key });
    let mut relay_config = RelayConfig::new(cli.bind);
    relay_config.access = access;
    let mut server_config = ServerConfig::default();
    server_config.relay = Some(relay_config);

    info!(bind = %cli.bind, "spike relay-server starting");
    println!("SPIKE_RELAY_SERVER_READY bind={}", cli.bind);
    let mut server = Server::spawn(server_config).await.anyerr()?;
    tokio::select! {
        biased;
        _ = tokio::signal::ctrl_c() => warn!("ctrl-c, exiting"),
        res = server.join() => {
            if let Err(err) = res {
                warn!(?err, "relay server task ended");
            }
        }
    }
    let _ = server.shutdown().await.anyerr();
    Ok(())
}
