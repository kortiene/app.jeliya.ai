//! THROWAWAY Phase 0 spike (#23) — relay-auth credential service.
//!
//! Not a member of the Jeliya workspace. Not built by release.yml. Not shipped.
//!
//! This is the spike's proof-of-possession admission service. Its job is to
//! answer ONE question for the relay: "did the endpoint that wants to use the
//! relay recently prove it holds the private key for the endpoint id it claims?"
//!
//! The design contract from docs/production-deployment.md (lines 539-556) is:
//!
//!   - the credential is SHORT-LIVED (TTL is minutes, not hours);
//!   - the credential is ENDPOINT-BOUND (it names the endpoint id it admits,
//!     so it cannot be loaned or stolen and replayed from a different id);
//!   - it is issued AFTER proof of possession — the caller signs a challenge
//!     with the Ed25519 private key whose public half is the endpoint id;
//!   - no PROJECT API SECRET ever appears in a served static asset, bundle,
//!     manifest, or public config. The only secret in this spike is the
//!     relay-auth signing key, which is generated on startup, lives in
//!     process memory, and never leaves this service. The browser only ever
//!     sees its own short-lived token.
//!
//! Protocol:
//!
//!   GET  /challenge  ->  { "challenge": "<hex 32B nonce>" }
//!   POST /token      <-  { "endpoint_id": "<hex 32B>",
//!                           "challenge":   "<hex 32B from /challenge>",
//!                           "signature":   "<hex 64B Ed25519 sig over challenge bytes>" }
//!                       -> { "token": "<base64 payload.signature>",
//!                            "endpoint_id": "<hex 32B>",
//!                            "expires_at_ms": <u64> }
//!
//! The token payload is canonical JSON `{endpoint_id, exp, nonce}`; the
//! signature is a detached Ed25519 sig over the payload bytes. The relay
//! server verifies the signature with this service's public key (printed on
//! startup) and checks exp + endpoint_id binding at admission time.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64ct::{Base64Unpadded, Encoding};
use clap::Parser;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use n0_error::{Result, StdResultExt};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::net::TcpListener;
use tracing::{info, warn};

/// Token lifetime: deliberately short to prove the "short-lived" contract.
/// 60 seconds is long enough for a browser to fetch then connect, short
/// enough that a replay must happen within one minute of issuance.
const TOKEN_TTL: Duration = Duration::from_secs(60);

/// Context string domain-separating relay-auth signatures from any other
/// Ed25519 signature in the system (event signatures, pairing, etc.).
const TOKEN_CONTEXT: &[u8] = b"jeliya/spike/relay-auth-token/v1";

#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
struct Cli {
    /// Bind address for the HTTP service.
    #[clap(long, env = "SPIKE_RELAY_AUTH_BIND", default_value = "127.0.0.1:7780")]
    bind: SocketAddr,
}

#[derive(Serialize)]
struct ChallengeResp {
    challenge: String,
}

#[derive(Deserialize)]
struct TokenReq {
    endpoint_id: String,
    challenge: String,
    signature: String,
}

#[derive(Serialize)]
struct TokenResp {
    token: String,
    endpoint_id: String,
    expires_at_ms: u64,
}

#[derive(Serialize, Deserialize)]
struct TokenPayload {
    endpoint_id: String,
    exp: u64,
    nonce: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("spike_relay_auth=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();

    // The signing key is generated on startup. It is the ONLY secret in the
    // spike. It never leaves the process. The public key is printed so the
    // relay-server can be configured to verify tokens, and so a reviewer can
    // confirm the served static assets contain neither this key nor any
    // project API secret.
    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
    let state = Arc::new(State {
        signing_key,
        verifying_key_hex,
    });

    info!(bind = %cli.bind, verifying_key = %state.verifying_key_hex, "relay-auth spike starting");
    println!(
        "SPIKE_RELAY_AUTH_READY bind={} verifying_key={}",
        cli.bind, state.verifying_key_hex
    );

    let listener = TcpListener::bind(cli.bind).await?;
    loop {
        let (stream, peer) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| {
                let state = state.clone();
                async move { handle(req, state).await }
            });
            if let Err(err) = http1::Builder::new()
                .serve_connection(io, svc)
                .with_upgrades()
                .await
            {
                warn!(%peer, ?err, "connection error");
            }
        });
    }
}

struct State {
    signing_key: SigningKey,
    verifying_key_hex: String,
}

async fn handle(req: Request<hyper::body::Incoming>, state: Arc<State>) -> Result<Response<Full<Bytes>>> {
    let (method, path) = (req.method().clone(), req.uri().path().to_string());
    // CORS preflight: the browser sends OPTIONS before any cross-origin POST
    // with a JSON content type. Answer with permissive CORS headers so the
    // spike's browser page (served from :7788) can reach relay-auth (:7780).
    // The token endpoint accepts only a signed challenge, so CORS openness
    // here is not a secret-exposure risk.
    if method == Method::OPTIONS {
        return Ok(Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header("access-control-allow-origin", "*")
            .header("access-control-allow-methods", "GET, POST, OPTIONS")
            .header("access-control-allow-headers", "content-type")
            .body(Full::new(Bytes::new()))
            .unwrap());
    }
    match (method, path.as_str()) {
        (Method::GET, "/challenge") => Ok(json_response(
            StatusCode::OK,
            &ChallengeResp { challenge: fresh_nonce_hex() },
        )),
        (Method::GET, "/verifying-key") => Ok(json_response(
            StatusCode::OK,
            &json!({ "verifying_key": state.verifying_key_hex }),
        )),
        (Method::POST, "/token") => match issue_token(req, state).await {
            Ok(resp) => Ok(resp),
            Err(err) => {
                warn!(?err, "token issuance rejected");
                Ok(json_response(
                    StatusCode::BAD_REQUEST,
                    &json!({ "error": err.to_string() }),
                ))
            }
        },
        _ => Ok(json_response(
            StatusCode::NOT_FOUND,
            &json!({ "error": "not found" }),
        )),
    }
}

async fn issue_token(req: Request<hyper::body::Incoming>, state: Arc<State>) -> Result<Response<Full<Bytes>>> {
    let body = req.into_body().collect().await.anyerr()?.to_bytes();
    let req: TokenReq = serde_json::from_slice(&body).anyerr()?;

    // 1. Decode the claimed endpoint id (a 32-byte Ed25519 public key).
    let endpoint_pk_bytes = hex::decode(&req.endpoint_id)
        .map_err(|e| format!("endpoint_id is not hex: {e}"))?;
    let endpoint_vk: VerifyingKey = VerifyingKey::from_bytes(
        endpoint_pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "endpoint_id is not 32 bytes".to_string())?,
    )
    .map_err(|e| format!("invalid endpoint_id: {e}"))?;

    // 2. Proof of possession: verify the signature over the challenge under
    //    the claimed endpoint id. A valid signature proves the caller holds
    //    the private half of the endpoint id it is asking to be admitted as.
    let challenge = hex::decode(&req.challenge)
        .map_err(|e| format!("challenge is not hex: {e}"))?;
    let sig_bytes = hex::decode(&req.signature)
        .map_err(|e| format!("signature is not hex: {e}"))?;
    let sig: Signature = Signature::from_slice(&sig_bytes)
        .map_err(|e| format!("signature malformed: {e}"))?;
    endpoint_vk
        .verify(&challenge, &sig)
        .map_err(|e| format!("proof-of-possession signature invalid: {e}"))?;

    // 3. Mint the token. It binds the endpoint id, an expiry, and the
    //    challenge nonce (so two tokens for the same id remain distinct).
    let now_ms = now_ms();
    let exp = now_ms + TOKEN_TTL.as_millis() as u64;
    let payload = TokenPayload {
        endpoint_id: req.endpoint_id.clone(),
        exp,
        nonce: req.challenge.clone(),
    };
    let payload_bytes = serde_json::to_vec(&payload).anyerr()?;
    let sig_body = [TOKEN_CONTEXT, &payload_bytes].concat();
    let sig: Signature = state.signing_key.sign(&sig_body);

    // Compact wire form: base64(payload_bytes) "." base64(sig). Detached
    // signature, no secret material on either side.
    let token = format!(
        "{}.{}",
        Base64Unpadded::encode_string(&payload_bytes),
        Base64Unpadded::encode_string(&sig.to_bytes()[..]),
    );

    Ok(json_response(
        StatusCode::OK,
        &TokenResp {
            token,
            endpoint_id: req.endpoint_id.clone(),
            expires_at_ms: exp,
        },
    ))
}

fn fresh_nonce_hex() -> String {
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn json_response<T: Serialize>(status: StatusCode, body: &T) -> Response<Full<Bytes>> {
    let bytes = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("access-control-allow-origin", "*")
        .body(Full::new(Bytes::from(bytes)))
        .unwrap()
}
