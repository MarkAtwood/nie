use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use futures::{Sink, SinkExt, Stream, StreamExt};
use rand::Rng;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_socks::tcp::Socks5Stream;
use tokio_tungstenite::{
    client_async_tls_with_config, tungstenite::Error as WsError, tungstenite::Message, Connector,
};
use tracing::{debug, error, info, warn};

use crate::identity::Identity;
use crate::protocol::{
    rpc_methods, AuthenticateParams, ChallengeParams, JsonRpcNotification, JsonRpcRequest,
    JsonRpcResponse,
};

/// Supertrait combining the bounds required by `client_async_tls_with_config`:
/// `AsyncRead + AsyncWrite + Send + Unpin + 'static`.
///
/// Exists solely to unify `TcpStream` (direct connections) and
/// `Socks5Stream<TcpStream>` (proxy connections) so that `ws_upgrade_and_auth`
/// can be generic over both without repeating the full bound list.
trait AsyncRW: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static> AsyncRW for T {}

type WsSink = Box<dyn Sink<Message, Error = WsError> + Send + Unpin>;
type WsStream = Box<dyn Stream<Item = Result<Message, WsError>> + Send + Unpin>;

static REQUEST_ID: AtomicU64 = AtomicU64::new(1);

/// Generate a unique, monotonically increasing request ID.
/// SeqCst ensures strict ordering across threads.
pub fn next_request_id() -> u64 {
    REQUEST_ID.fetch_add(1, Ordering::SeqCst)
}

/// Events delivered on the `rx` channel of both `RelayConn` and `RelayConnRetry`.
#[derive(Debug)]
pub enum ClientEvent {
    /// A JSON-RPC notification from the relay (no id field).
    Message(JsonRpcNotification),
    /// A JSON-RPC response from the relay (has id field), for request-response
    /// flows initiated after the auth handshake (e.g. GetKeyPackage).
    Response(JsonRpcResponse),
    /// Connection lost; will retry after `delay_secs` seconds.
    Reconnecting { delay_secs: u64 },
    /// Successfully reconnected.
    Reconnected,
}

/// A live, authenticated relay connection (single-attempt).
pub struct RelayConn {
    /// Send JSON-RPC requests to the relay.
    pub tx: mpsc::Sender<JsonRpcRequest>,
    /// Receive JSON-RPC notifications and responses from the relay.
    pub rx: mpsc::Receiver<ClientEvent>,
}

/// A relay connection with transparent reconnection.
pub struct RelayConnRetry {
    /// Send JSON-RPC requests to the relay.
    ///
    /// The channel holds up to 64 requests.  Requests sent while disconnected
    /// accumulate in this buffer.  If the buffer fills (>64 requests queued
    /// during a disconnect), excess requests are silently dropped.  Delivery
    /// is at-most-once with a 64-request window, not at-least-once.
    pub tx: mpsc::Sender<JsonRpcRequest>,
    /// Receive notifications, responses, and connection-state events from the relay.
    pub rx: mpsc::Receiver<ClientEvent>,
}

/// Connect to the relay at `url`, perform the auth handshake, and return
/// a bidirectional channel pair (single attempt, no retry).
///
/// `accept_invalid_certs`: skip TLS certificate verification. Only for local
/// dev with self-signed certs. Never set this in production.
pub async fn connect(
    url: &str,
    identity: &Identity,
    accept_invalid_certs: bool,
    proxy: Option<String>,
) -> Result<RelayConn> {
    let (mut sink, mut stream) =
        open_authenticated_ws(url, identity, accept_invalid_certs, proxy).await?;

    let (out_tx, mut out_rx) = mpsc::channel::<JsonRpcRequest>(64);
    let (in_tx, in_rx) = mpsc::channel::<ClientEvent>(64);

    tokio::spawn(async move {
        while let Some(req) = out_rx.recv().await {
            // serde_json::to_string on a derived Serialize cannot fail
            let json = serde_json::to_string(&req).unwrap();
            if let Err(e) = sink.send(Message::Text(json.into())).await {
                error!("ws write error: {e}");
                break;
            }
        }
        // Channel closed (caller dropped RelayConn) — send a clean WS close frame
        // so the relay logs a clean disconnect rather than a connection error.
        let _ = sink.send(Message::Close(None)).await;
        debug!("writer task done");
    });

    tokio::spawn(async move {
        while let Some(frame) = stream.next().await {
            match frame {
                Ok(Message::Text(t)) => {
                    if let Some(event) = parse_incoming(&t) {
                        if in_tx.send(event).await.is_err() {
                            debug!("receiver dropped, reader exiting");
                            break;
                        }
                    }
                }
                Ok(Message::Close(_)) => {
                    info!("relay closed connection");
                    break;
                }
                Err(e) => {
                    error!("ws read error: {e}");
                    break;
                }
                _ => {} // ping/pong/binary: ignore
            }
        }
        debug!("reader task done");
    });

    Ok(RelayConn {
        tx: out_tx,
        rx: in_rx,
    })
}

/// Connect to the relay with exponential-backoff reconnection.
///
/// Returns immediately; the connection is established in a background task.
/// Connection-state changes arrive as `ClientEvent::Reconnecting` and
/// `ClientEvent::Reconnected` on the `rx` channel.
///
/// Dropping `tx` or `rx` terminates the background task cleanly.
pub fn connect_with_retry(
    url: String,
    identity: Identity,
    accept_invalid_certs: bool,
    proxy: Option<String>,
) -> RelayConnRetry {
    let (out_tx, out_rx) = mpsc::channel::<JsonRpcRequest>(64);
    let (in_tx, in_rx) = mpsc::channel::<ClientEvent>(64);

    tokio::spawn(connection_manager(
        url,
        identity,
        accept_invalid_certs,
        proxy,
        out_rx,
        in_tx,
    ));

    RelayConnRetry {
        tx: out_tx,
        rx: in_rx,
    }
}

/// Background task that manages the WebSocket connection with reconnection.
async fn connection_manager(
    url: String,
    identity: Identity,
    accept_invalid_certs: bool,
    proxy: Option<String>,
    mut out_rx: mpsc::Receiver<JsonRpcRequest>,
    in_tx: mpsc::Sender<ClientEvent>,
) {
    let mut delay_secs: u64 = 1;
    let mut ever_connected = false;

    loop {
        match open_authenticated_ws(&url, &identity, accept_invalid_certs, proxy.clone()).await {
            Ok((mut sink, mut stream)) => {
                if ever_connected && in_tx.send(ClientEvent::Reconnected).await.is_err() {
                    return; // chat exited
                }
                ever_connected = true;
                delay_secs = 1; // reset backoff after successful connection

                // Bridge: select between outgoing requests and incoming WS frames.
                // Breaks when WS dies (relay_disconnect = true) or chat exits (= false).
                let relay_disconnect = 'connection: loop {
                    tokio::select! {
                        req = out_rx.recv() => {
                            match req {
                                Some(r) => {
                                    // serde_json::to_string on a derived Serialize cannot fail
                                    let json = serde_json::to_string(&r).unwrap();
                                    if sink.send(Message::Text(json.into())).await.is_err() {
                                        break 'connection true; // WS write failed
                                    }
                                }
                                None => break 'connection false, // chat dropped tx
                            }
                        }
                        frame = stream.next() => {
                            match frame {
                                Some(Ok(Message::Text(t))) => {
                                    if let Some(event) = parse_incoming(&t) {
                                        if in_tx.send(event).await.is_err() {
                                            break 'connection false; // chat dropped rx
                                        }
                                    }
                                }
                                None | Some(Ok(Message::Close(_))) => {
                                    info!("relay closed connection");
                                    break 'connection true;
                                }
                                Some(Err(e)) => {
                                    error!("ws read error: {e}");
                                    break 'connection true;
                                }
                                Some(Ok(_)) => {} // ping/pong/binary: ignore
                            }
                        }
                    }
                };

                if !relay_disconnect {
                    // Chat exited cleanly — send a WebSocket close frame so the relay
                    // logs a clean disconnect rather than a connection error.
                    let _ = sink.send(Message::Close(None)).await;
                    return;
                }
                // fall through to reconnect backoff
            }
            Err(e) => {
                warn!("connection attempt failed: {e}");
                // fall through to reconnect backoff
            }
        }

        // Check if chat already exited before sleeping.
        if in_tx.is_closed() {
            return;
        }

        let jitter = rand::thread_rng().gen_range(0.8_f64..1.2_f64);
        let jittered_secs = ((delay_secs as f64 * jitter) as u64).max(1);

        if in_tx
            .send(ClientEvent::Reconnecting {
                delay_secs: jittered_secs,
            })
            .await
            .is_err()
        {
            return; // chat exited
        }

        tokio::time::sleep(Duration::from_secs(jittered_secs)).await;

        delay_secs = (delay_secs * 2).min(60);
    }
}

/// Open a WebSocket connection and perform the JSON-RPC 2.0 auth handshake.
/// Returns `(sink, stream)` ready for message exchange.
async fn open_authenticated_ws(
    url: &str,
    identity: &Identity,
    accept_invalid_certs: bool,
    proxy: Option<String>,
) -> Result<(WsSink, WsStream)> {
    // build_connector is called before the SOCKS5/TCP connect, but the connector is only
    // applied *after* the stream is established (inside ws_upgrade_and_auth). This ordering
    // is load-bearing: TLS must wrap the fully-tunneled stream, not the raw TCP socket.
    // Changing this order silently breaks proxy + --insecure mode.
    let connector = build_connector(accept_invalid_certs)?;

    if let Some(proxy_url) = proxy {
        // SOCKS5 path: dial the proxy, tunnel to relay, then upgrade to WebSocket.
        let (proxy_host, proxy_port) = parse_proxy_addr(&proxy_url)?;
        let (relay_host, relay_port) = parse_relay_addr(url)?;

        let socks_stream = Socks5Stream::connect(
            (proxy_host.as_str(), proxy_port),
            (relay_host.as_str(), relay_port),
        )
        .await
        .with_context(|| format!("SOCKS5 tunnel to {relay_host}:{relay_port} via proxy failed"))?;

        // Log scheme+host only — never log the full URL (may contain credentials).
        info!("connected via SOCKS5 tunnel to {relay_host}:{relay_port}");
        ws_upgrade_and_auth(socks_stream, url, identity, connector).await
    } else {
        // Direct path: plain TCP → TLS (if wss://) → WebSocket upgrade.
        let relay_addr = relay_socket_addr(url)?;
        let tcp = TcpStream::connect(&relay_addr)
            .await
            .with_context(|| "TCP connect to relay failed")?;

        // Log scheme+host only — never log the full URL (may contain credentials).
        info!("connected to {relay_addr}");
        ws_upgrade_and_auth(tcp, url, identity, connector).await
    }
}

/// Build a `Connector` based on the `accept_invalid_certs` flag.
///
/// When `accept_invalid_certs` is true, returns a native-TLS connector that
/// skips certificate verification (dev/test only).  When false, returns `None`
/// so `client_async_tls_with_config` uses the platform default trust store.
fn build_connector(accept_invalid_certs: bool) -> Result<Option<Connector>> {
    if accept_invalid_certs {
        warn!("TLS certificate verification disabled — dev/test use only");
        let native = native_tls::TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .context("building insecure TLS connector")?;
        Ok(Some(Connector::NativeTls(native)))
    } else {
        Ok(None)
    }
}

/// Upgrade a raw stream `S` to an authenticated WebSocket, performing the
/// JSON-RPC 2.0 challenge-response handshake.  Returns boxed sink/stream.
async fn ws_upgrade_and_auth<S: AsyncRW>(
    stream: S,
    url: &str,
    identity: &Identity,
    connector: Option<Connector>,
) -> Result<(WsSink, WsStream)> {
    let (ws, _) = client_async_tls_with_config(url, stream, None, connector)
        .await
        .with_context(|| format!("WebSocket upgrade to {url} failed"))?;

    let (sink, stream) = ws.split();
    let mut sink: Box<dyn Sink<Message, Error = WsError> + Send + Unpin> = Box::new(sink);
    let mut stream: Box<dyn Stream<Item = Result<Message, WsError>> + Send + Unpin> =
        Box::new(stream);

    // 1. Receive Challenge notification
    let text = recv_text_frame(&mut stream, "challenge").await?;
    let notif: JsonRpcNotification =
        serde_json::from_str(&text).context("failed to parse challenge notification")?;
    if notif.method != rpc_methods::CHALLENGE {
        anyhow::bail!(
            "expected challenge notification, got method: {}",
            notif.method
        );
    }
    let params_value = notif
        .params
        .ok_or_else(|| anyhow::anyhow!("challenge notification missing params"))?;
    let params: ChallengeParams =
        serde_json::from_value(params_value).context("failed to parse challenge params")?;

    debug!("received challenge, signing");

    // 2. Sign nonce and send Authenticate request
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    let pub_key_b64 = identity.pub_key_b64();
    let sig_bytes = identity.sign(params.nonce.as_bytes()).to_bytes();
    let signature_b64 = B64.encode(sig_bytes);

    // Mine PoW token if the relay requires it (difficulty > 0).
    let pow_token: Option<String> = if params.difficulty == 0 {
        None
    } else {
        let salt_bytes = B64
            .decode(&params.server_salt)
            .map_err(|_| anyhow::anyhow!("invalid server_salt base64"))?;
        if salt_bytes.len() != 32 {
            anyhow::bail!("server_salt must be 32 bytes, got {}", salt_bytes.len());
        }
        let mut server_salt = [0u8; 32];
        server_salt.copy_from_slice(&salt_bytes);

        let pub_key_bytes: [u8; 32] = identity.verifying_key().to_bytes();
        let diff = params.difficulty;
        // Reject impossibly high difficulty before spawning the mining task.
        // SHA-256 has 256 bits of output; difficulty > 60 would require more
        // than 2^60 hashes and would never terminate in practice.
        anyhow::ensure!(
            diff <= 60,
            "relay requested impossible PoW difficulty: {diff} (max 60)"
        );
        // Fail explicitly if the system clock is broken.  unwrap_or_default()
        // would silently produce ts_floor=0, which the relay rejects as stale
        // with a cryptic POW_STALE error that gives no hint about the real cause.
        let ts_floor = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock is before the Unix epoch; check your clock")?
            .as_secs()
            / 60) as u32;

        let token = tokio::task::spawn_blocking(move || {
            crate::pow::mine_token(&pub_key_bytes, &server_salt, diff, ts_floor)
        })
        .await
        .context("PoW mining task panicked")?;
        Some(token)
    };

    let auth_id = next_request_id();
    let auth_req = JsonRpcRequest::new(
        auth_id,
        rpc_methods::AUTHENTICATE,
        AuthenticateParams {
            pub_key: pub_key_b64,
            nonce: params.nonce,
            signature: signature_b64,
            pow_token,
        },
    )
    .context("building authenticate request")?;
    // serde_json::to_string on a derived Serialize cannot fail
    let auth_json = serde_json::to_string(&auth_req).unwrap();
    sink.send(Message::Text(auth_json.into()))
        .await
        .with_context(|| "sending authenticate request")?;

    // 3. Wait for auth response
    let text = recv_text_frame(&mut stream, "auth response").await?;
    let resp: JsonRpcResponse =
        serde_json::from_str(&text).context("failed to parse auth response")?;
    if resp.id != auth_id {
        anyhow::bail!(
            "auth response id mismatch: expected {auth_id}, got {}",
            resp.id
        );
    }
    if let Some(err) = resp.error {
        anyhow::bail!("authentication failed: {} (code {})", err.message, err.code);
    }

    // Extract pub_id from result for the info log; missing result is still auth success.
    if let Some(result) = &resp.result {
        if let Some(pub_id) = result.get("pub_id").and_then(|v| v.as_str()) {
            let sub_expires = result.get("subscription_expires").and_then(|v| v.as_str());
            info!("authenticated as {pub_id} (subscription: {sub_expires:?})");
        }
    }

    Ok((sink, stream))
}

// URL parsing for proxy and relay addresses.
//
// These functions use simple string manipulation rather than the `url` crate because:
// - They handle exactly two schemes each (socks5/socks5h and ws/wss)
// - tokio-socks accepts (&str, u16) tuples directly, not url::Url objects
// - Keeping parsing close to the call site makes the data flow explicit
//
// If the relay URL format ever changes (e.g., query parameters for proxy auth),
// switch to `url::Url::parse` at that point — do not patch these functions.

/// Extract the SOCKS5 proxy host and port from a `socks5://` or `socks5h://` URL.
///
/// IPv6 addresses must be bracket-quoted: `socks5h://[::1]:9050`.
/// Credentials in the URL (`user:pass@host`) are not supported — return an error.
fn parse_proxy_addr(proxy_url: &str) -> Result<(String, u16)> {
    let addr = proxy_url
        .strip_prefix("socks5h://")
        .or_else(|| proxy_url.strip_prefix("socks5://"))
        .ok_or_else(|| anyhow::anyhow!("proxy URL must start with socks5:// or socks5h://"))?;
    // Drop any path component after host:port (e.g. trailing slash).
    let addr = addr.split('/').next().unwrap_or(addr);
    // Credentials in the URL cannot be used for SOCKS5 auth — reject with a clear message.
    if addr.contains('@') {
        anyhow::bail!(
            "SOCKS5 proxy credentials in URL are not supported; \
             configure proxy authentication separately"
        );
    }
    let (host, port) = if addr.starts_with('[') {
        // IPv6 literal in brackets, e.g. [::1]:9050.
        let close = addr
            .find(']')
            .ok_or_else(|| anyhow::anyhow!("proxy URL has unclosed IPv6 bracket"))?;
        let host = addr[1..close].to_owned(); // strip brackets
        let port_str = addr[close + 1..]
            .strip_prefix(':')
            .ok_or_else(|| anyhow::anyhow!("proxy URL: IPv6 address requires explicit port"))?;
        let port: u16 = port_str
            .parse()
            .with_context(|| format!("proxy URL port {port_str:?} is not a valid u16"))?;
        (host, port)
    } else {
        let (host, port_str) = addr
            .rsplit_once(':')
            .ok_or_else(|| anyhow::anyhow!("proxy URL missing port"))?;
        let port: u16 = port_str
            .parse()
            .with_context(|| format!("proxy URL port {port_str:?} is not a valid u16"))?;
        (host.to_owned(), port)
    };
    Ok((host, port))
}

/// Extract the relay host and port from a `ws://` or `wss://` URL, suitable
/// for use as the SOCKS5 tunnel target.  The proxy resolves DNS when the
/// caller uses `socks5h://`, so a hostname string is correct here.
///
/// IPv6 addresses must be bracket-quoted in the URL: `ws://[::1]:3210/ws`.
/// Brackets are stripped from the returned host string.
fn parse_relay_addr(relay_url: &str) -> Result<(String, u16)> {
    let (scheme, rest) = relay_url
        .split_once("://")
        .ok_or_else(|| anyhow::anyhow!("relay URL missing scheme separator"))?;
    let default_port: u16 = match scheme {
        "wss" => 443,
        "ws" => 80,
        other => anyhow::bail!("unsupported relay URL scheme: {other}"),
    };
    // Drop any path component after the host:port section.
    let host_port = rest.split('/').next().unwrap_or(rest);
    let (host, port) = if host_port.starts_with('[') {
        // IPv6 literal in brackets, e.g. [::1]:3210 or [::1] (uses default port).
        let close = host_port
            .find(']')
            .ok_or_else(|| anyhow::anyhow!("relay URL has unclosed IPv6 bracket"))?;
        let host = host_port[1..close].to_owned(); // strip brackets
        let after = &host_port[close + 1..];
        let port = if after.is_empty() {
            default_port
        } else {
            let port_str = after.strip_prefix(':').ok_or_else(|| {
                anyhow::anyhow!("relay URL: unexpected characters after IPv6 address")
            })?;
            port_str
                .parse()
                .with_context(|| format!("relay URL port {port_str:?} is not a valid u16"))?
        };
        (host, port)
    } else if let Some((host, port_str)) = host_port.rsplit_once(':') {
        let port: u16 = port_str
            .parse()
            .with_context(|| format!("relay URL port {port_str:?} is not a valid u16"))?;
        (host.to_owned(), port)
    } else {
        (host_port.to_owned(), default_port)
    };
    Ok((host, port))
}

/// Return the relay `host:port` string for a direct TCP connect.
/// DNS resolution happens at connect time, not here.
fn relay_socket_addr(relay_url: &str) -> Result<String> {
    let (host, port) = parse_relay_addr(relay_url)?;
    Ok(format!("{host}:{port}"))
}

/// Read the next text frame from the stream, skipping ping/pong frames.
/// Returns an error if the connection closes before a text frame arrives.
async fn recv_text_frame(stream: &mut WsStream, context: &str) -> Result<String> {
    loop {
        match stream.next().await {
            Some(Ok(Message::Text(t))) => return Ok(t.to_string()),
            Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => {
                // Ignore ping/pong frames and keep waiting.
                continue;
            }
            Some(Ok(other)) => {
                anyhow::bail!("expected text frame for {context}, got: {other:?}");
            }
            Some(Err(e)) => {
                return Err(e).with_context(|| format!("reading {context} frame"));
            }
            None => {
                anyhow::bail!("relay closed connection before {context}");
            }
        }
    }
}

/// Parse an incoming text frame as either a JSON-RPC notification or response.
///
/// Distinguishes by presence of the `id` field:
/// - No `id` + has `method` → notification (`ClientEvent::Message`)
/// - Has `id` → response (`ClientEvent::Response`)
///
/// The auth handshake response is handled synchronously in `open_authenticated_ws`
/// before these tasks start, so any response reaching this path is for a
/// post-auth request (e.g. GetKeyPackage).
fn parse_incoming(text: &str) -> Option<ClientEvent> {
    match serde_json::from_str::<serde_json::Value>(text) {
        Ok(v) if v.get("id").is_none() && v.get("method").is_some() => {
            // Notification: no id, has method.
            match serde_json::from_value::<JsonRpcNotification>(v) {
                Ok(notif) => Some(ClientEvent::Message(notif)),
                Err(e) => {
                    warn!("failed to deserialize notification: {e}");
                    None
                }
            }
        }
        Ok(v) if v.get("id").is_some() => {
            // Response: has id.
            match serde_json::from_value::<JsonRpcResponse>(v) {
                Ok(resp) => Some(ClientEvent::Response(resp)),
                Err(e) => {
                    warn!("failed to deserialize response: {e}");
                    None
                }
            }
        }
        Ok(_) => {
            // Neither notification nor response — discard.
            warn!("unrecognized JSON-RPC frame (no id, no method)");
            None
        }
        Err(e) => {
            warn!("invalid JSON from relay: {e}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    // --- parse_proxy_addr ---

    #[test]
    fn proxy_addr_socks5h_ip() {
        let (host, port) = parse_proxy_addr("socks5h://127.0.0.1:9050").unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 9050);
    }

    #[test]
    fn proxy_addr_socks5_hostname() {
        let (host, port) = parse_proxy_addr("socks5://proxy.example.com:1080").unwrap();
        assert_eq!(host, "proxy.example.com");
        assert_eq!(port, 1080);
    }

    #[test]
    fn proxy_addr_trailing_slash_stripped() {
        let (host, port) = parse_proxy_addr("socks5://127.0.0.1:9050/").unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 9050);
    }

    // --- parse_relay_addr ---

    #[test]
    fn relay_addr_ws_ip_with_port() {
        let (host, port) = parse_relay_addr("ws://127.0.0.1:3210/ws").unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 3210);
    }

    #[test]
    fn relay_addr_wss_hostname_default_port() {
        let (host, port) = parse_relay_addr("wss://relay.example.com/ws").unwrap();
        assert_eq!(host, "relay.example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn relay_addr_wss_hostname_explicit_port() {
        let (host, port) = parse_relay_addr("wss://relay.example.com:8443/ws").unwrap();
        assert_eq!(host, "relay.example.com");
        assert_eq!(port, 8443);
    }

    #[test]
    fn relay_addr_ws_hostname_default_port() {
        let (host, port) = parse_relay_addr("ws://relay.example.com/ws").unwrap();
        assert_eq!(host, "relay.example.com");
        assert_eq!(port, 80);
    }

    #[test]
    fn relay_addr_ipv6_with_port() {
        let (host, port) = parse_relay_addr("ws://[::1]:3210/ws").unwrap();
        assert_eq!(host, "::1", "IPv6 brackets must be stripped from host");
        assert_eq!(port, 3210);
    }

    #[test]
    fn relay_addr_ipv6_default_port() {
        let (host, port) = parse_relay_addr("wss://[::1]/ws").unwrap();
        assert_eq!(host, "::1", "IPv6 brackets must be stripped from host");
        assert_eq!(port, 443, "wss:// default port must be 443");
    }

    // --- proxy_addr_ipv6 ---

    #[test]
    fn proxy_addr_ipv6_brackets_stripped() {
        let (host, port) = parse_proxy_addr("socks5h://[::1]:9050").unwrap();
        assert_eq!(host, "::1", "IPv6 brackets must be stripped from host");
        assert_eq!(port, 9050);
    }

    // --- proxy_addr_credentials_rejected ---

    #[test]
    fn proxy_addr_credentials_rejected() {
        // Credentials in the proxy URL (user:pass@host) cannot be used for
        // SOCKS5 auth; parse_proxy_addr must return a clear error.
        let result = parse_proxy_addr("socks5://user:pass@127.0.0.1:9050");
        assert!(result.is_err(), "credentials in proxy URL must be rejected");
        let msg = format!("{}", result.err().unwrap());
        assert!(
            msg.contains("credentials"),
            "error must mention credentials, got: {msg}"
        );
    }

    // --- proxy_addr_missing_port ---

    #[test]
    fn proxy_addr_missing_port_rejected() {
        let result = parse_proxy_addr("socks5://127.0.0.1");
        assert!(result.is_err(), "proxy URL without port must be rejected");
    }

    // --- proxy_addr_invalid_scheme ---

    #[test]
    fn proxy_addr_invalid_scheme_rejected() {
        let result = parse_proxy_addr("http://127.0.0.1:3128");
        assert!(result.is_err(), "http:// proxy must be rejected");
        let msg = format!("{}", result.err().unwrap());
        assert!(
            msg.contains("socks5"),
            "error must mention socks5, got: {msg}"
        );
    }

    // --- proxy_unreachable_error ---

    #[tokio::test]
    async fn proxy_unreachable_error() {
        let identity = Identity::generate();
        let result = connect(
            "ws://127.0.0.1:3210/ws",
            &identity,
            false,
            Some("socks5h://127.0.0.1:19997".to_string()),
        )
        .await;
        let err = result
            .err()
            .expect("expected error when proxy is unreachable");
        let err_chain = format!("{err:#}");
        assert!(
            err_chain.to_ascii_lowercase().contains("socks5"),
            "error chain should mention SOCKS5, got: {err_chain}"
        );
    }
}
