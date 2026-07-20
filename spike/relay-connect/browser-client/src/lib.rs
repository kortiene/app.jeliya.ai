//! THROWAWAY Phase 0 spike (#23) — wasm-bindgen wrapper around iroh for the browser.
//!
//! Not a member of the Jeliya workspace. Not built by release.yml. Not shipped.
//!
//! This is the spike's central bet: that a browser can establish an
//! end-to-end-encrypted iroh connection to a native endpoint through a
//! dedicated relay, using a short-lived endpoint-bound credential obtained
//! after proof of possession, with iroh compiled to wasm32-unknown-unknown
//! via wasm-bindgen (default features off — the browser has no UDP QUIC
//! path, so every connection is relayed).
//!
//! The wrapper exposes ONE function to JS:
//!
//!   runSpikeRoundtrip({
//!     relayAuthUrl,     // e.g. "http://127.0.0.1:7780"
//!     relayUrl,         // e.g. "http://127.0.0.1:3340"
//!     nativeEndpointId, // 64-hex-char iroh EndpointId of the native echo peer
//!     payload,          // string to echo
//!   }) -> Promise<{
//!     endpointId,       // the browser's own iroh EndpointId (the id it proved)
//!     token,            // the short-lived credential minted by relay-auth
//!     tokenExpiresAtMs, // its expiry
//!     echoed,           // the native peer's uppercased reply (round-trip proof)
//!     elapsedMs,        // wall-clock duration of the iroh connect+round-trip
//!   }>
//!
//! Everything — Ed25519 keygen, challenge signing (proof of possession), token
//! fetch, relay connection, the bidirectional round trip — happens inside the
//! wasm module so the spike exercises the full transport stack the production
//! design depends on. The only secret in play is the browser's own ephemeral
//! Ed25519 key; no project API secret enters the bundle, ever.

use iroh::{
    Endpoint, EndpointAddr, RelayMode, RelayUrl, SecretKey,
    endpoint::presets,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

/// The echo ALPN. Must match spike-native-endpoint's ECHO_ALPN.
const ECHO_ALPN: &[u8] = b"jeliya/spike/echo/1";

#[derive(Serialize, Deserialize)]
struct ChallengeResp {
    challenge: String,
}

#[derive(Serialize, Deserialize)]
struct TokenReq {
    endpoint_id: String,
    challenge: String,
    signature: String,
}

#[derive(Serialize, Deserialize)]
struct TokenResp {
    token: String,
    #[allow(dead_code)]
    endpoint_id: String,
    expires_at_ms: u64,
}

/// The full browser→relay-auth→relay→native round trip. See module docs.
#[wasm_bindgen]
pub async fn run_spike_roundtrip(cfg: JsValue) -> Result<JsValue, JsValue> {
    let cfg: SpikeCfg = serde_wasm_bindgen::from_value(cfg)
        .map_err(|e| js_err(&format!("config: {e}")))?;

    // 1. Generate the browser's iroh identity. The public half is the
    //    EndpointId the relay and the native peer will see. iroh's SecretKey
    //    is an Ed25519 key; the bytes come from getrandom's wasm_js backend,
    //    which sources browser CSPRNG randomness.
    let mut key_bytes = [0u8; 32];
    getrandom::fill(&mut key_bytes).map_err(|e| js_err(&format!("getrandom keygen: {e}")))?;
    let secret = SecretKey::from_bytes(&key_bytes);
    let endpoint_id = secret.public();
    let endpoint_id_hex = endpoint_id.to_string();

    // 2. Proof of possession: fetch a challenge from relay-auth and sign it
    //    with the same key whose public half is the endpoint id.
    let challenge = fetch_challenge(&cfg.relay_auth_url).await?;
    let challenge_bytes =
        hex::decode(&challenge).map_err(|e| js_err(&format!("challenge hex: {e}")))?;
    let sig = secret.sign(&challenge_bytes);
    let sig_hex = hex::encode(sig.to_bytes());

    let token_resp = fetch_token(
        &cfg.relay_auth_url,
        &TokenReq {
            endpoint_id: endpoint_id_hex.clone(),
            challenge: challenge.clone(),
            signature: sig_hex,
        },
    )
    .await?;

    // 3. Build the iroh Endpoint pointing at the one dedicated relay, with
    //    the short-lived endpoint-bound token presented as the relay auth
    //    token. Default features are off (no UDP, no portmapper, no tokio):
    //    the wasm build uses wasm-bindgen-futures as its async runtime.
    let relay_url: RelayUrl = cfg
        .relay_url
        .parse()
        .map_err(|e| js_err(&format!("relay_url parse: {e}")))?;
    let relay_config = iroh_relay::RelayConfig::new(relay_url.clone(), None)
        .with_auth_token(token_resp.token.clone());
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(secret)
        .relay_mode(RelayMode::Custom(relay_config.into()))
        .bind()
        .await
        .map_err(|e| js_err(&format!("Endpoint::bind: {e}")))?;

    // Wait until the relay admits us (the token was valid) and we are online.
    endpoint.online().await;

    // 4. Dial the native echo endpoint through the relay, open a bidi stream,
    //    write the payload, read the uppercased echo back. This is the
    //    bidirectional, end-to-end-encrypted round trip the gate asks for.
    let native_id: iroh::EndpointId = cfg
        .native_endpoint_id
        .parse()
        .map_err(|e| js_err(&format!("native_endpoint_id parse: {e}")))?;
    let addr = EndpointAddr::new(native_id).with_relay_url(relay_url.clone());
    let t0 = now_ms();
    let conn = endpoint
        .connect(addr, ECHO_ALPN)
        .await
        .map_err(|e| js_err(&format!("connect to native endpoint: {e}")))?;
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| js_err(&format!("open_bi: {e}")))?;
    send.write_all(cfg.payload.as_bytes())
        .await
        .map_err(|e| js_err(&format!("write_all: {e}")))?;
    send.finish().map_err(|e| js_err(&format!("finish: {e}")))?;
    let echoed = recv
        .read_to_end(1024 * 1024)
        .await
        .map_err(|e| js_err(&format!("read_to_end: {e}")))?;
    let elapsed = now_ms().saturating_sub(t0);

    let echoed_str = String::from_utf8_lossy(&echoed).into_owned();

    Ok(serde_wasm_bindgen::to_value(&RoundtripResult {
        endpoint_id: endpoint_id_hex,
        token: token_resp.token,
        token_expires_at_ms: token_resp.expires_at_ms,
        echoed: echoed_str,
        elapsed_ms: elapsed,
    })
    .map_err(|e| js_err(&format!("serialize result: {e}")))?)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpikeCfg {
    relay_auth_url: String,
    relay_url: String,
    native_endpoint_id: String,
    payload: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RoundtripResult {
    endpoint_id: String,
    token: String,
    token_expires_at_ms: u64,
    echoed: String,
    elapsed_ms: u64,
}

async fn fetch_challenge(relay_auth_url: &str) -> Result<String, JsValue> {
    let body = http_get(&format!("{relay_auth_url}/challenge")).await?;
    let parsed: ChallengeResp = serde_json::from_str(&body)
        .map_err(|e| js_err(&format!("challenge parse: {e}")))?;
    Ok(parsed.challenge)
}

async fn fetch_token(relay_auth_url: &str, req: &TokenReq) -> Result<TokenResp, JsValue> {
    let body =
        serde_json::to_string(req).map_err(|e| js_err(&format!("token req encode: {e}")))?;
    let resp = http_post(&format!("{relay_auth_url}/token"), &body).await?;
    serde_json::from_str(&resp).map_err(|e| js_err(&format!("token resp parse: {e}: {resp}")))
}

async fn http_get(url: &str) -> Result<String, JsValue> {
    http_fetch(url, None).await
}

async fn http_post(url: &str, body: &str) -> Result<String, JsValue> {
    http_fetch(url, Some(body)).await
}

async fn http_fetch(url: &str, body: Option<&str>) -> Result<String, JsValue> {
    use web_sys::{Request, RequestInit, RequestMode};
    let opts = RequestInit::new();
    opts.set_method(if body.is_some() { "POST" } else { "GET" });
    opts.set_mode(RequestMode::Cors);
    if let Some(b) = body {
        opts.set_body(&JsValue::from_str(b));
    }
    let request = Request::new_with_str_and_init(url, &opts)
        .map_err(|e| js_err(&format!("Request::new: {e:?}")))?;
    request
        .headers()
        .set("content-type", "application/json")
        .map_err(|e| js_err(&format!("headers.set: {e:?}")))?;
    let window = web_sys::window().ok_or_else(|| js_err("no window"))?;
    let resp_val = JsFuture::from(window.fetch_with_request(&request)).await?;
    let resp: web_sys::Response = resp_val.into();
    if !resp.ok() {
        let status = resp.status();
        let text = text_of(&resp).await.unwrap_or_default();
        return Err(js_err(&format!("HTTP {status}: {text}")));
    }
    text_of(&resp).await
}

async fn text_of(resp: &web_sys::Response) -> Result<String, JsValue> {
    let text_promise = resp
        .text()
        .map_err(|e| js_err(&format!("resp.text: {e:?}")))?;
    let text = JsFuture::from(text_promise).await?;
    Ok(text.as_string().unwrap_or_default())
}

fn now_ms() -> u64 {
    web_sys::window()
        .and_then(|w| w.performance())
        .map(|p| p.now() as u64)
        .unwrap_or(0)
}

fn js_err(msg: &str) -> JsValue {
    JsValue::from_str(msg)
}
