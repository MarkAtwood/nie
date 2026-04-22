//! lightwalletd gRPC client (nie-ol7, nie-9wo).
//!
//! Fetches compact blocks from a lightwalletd endpoint.  Supports both mainnet
//! and testnet endpoints.  TLS is always enabled; plain-text connections are
//! not supported because all public lightwalletd endpoints require TLS.
//!
//! Use [`connect_with_failover`] to connect using the compiled default endpoints
//! or a user-supplied override list with automatic failover.

/// Default mainnet lightwalletd endpoints, tried in order on failover.
///
/// `mainnet.lightwalletd.com:9067` is the ECC-operated public endpoint.
/// `zec.rocks:443` is operated by the zec.rocks community operator program
/// (emersonian); used as a default endpoint in Zashi (ECC's official wallet).
/// `zuul.free2z.cash:9067` is operated by Free2z; used as a default endpoint
/// in Zingo mobile wallet.
///
/// The testnet endpoint `lightwalletd.testnet.z.cash:443` is not included here;
/// pass it explicitly when `--network testnet` is configured.
pub const DEFAULT_MAINNET_ENDPOINTS: &[&str] = &[
    "https://mainnet.lightwalletd.com:9067", // ECC
    "https://zec.rocks:443",                 // zec.rocks community (emersonian)
    "https://zuul.free2z.cash:9067",         // Free2z
];

/// Default testnet lightwalletd endpoint.
pub const DEFAULT_TESTNET_ENDPOINT: &str = "https://lightwalletd.testnet.z.cash:443";

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use tracing::warn;

static ENDPOINT_COUNTER: AtomicUsize = AtomicUsize::new(0);

// Proto-generated types.  The package name `cash.z.wallet.sdk.rpc` becomes the
// module argument to include_proto!.
mod lwd {
    tonic::include_proto!("cash.z.wallet.sdk.rpc");
}

use lwd::compact_tx_streamer_client::CompactTxStreamerClient;
pub use lwd::{BlockId, BlockRange, ChainSpec, CompactBlock, CompactSaplingOutput, CompactTx};

// ---- broadcast error (nie-5kc) ----

/// Domain error returned by [`LightwalletdClient::broadcast_tx`].
///
/// Callers need to distinguish these cases:
/// - `EmptyTx`: caller bug — must not pass zero-length data.
/// - `Grpc`: transport-layer failure (server unreachable, TLS error, etc.).
///   These are transient; the caller may retry.
/// - `BroadcastFailed`: the node rejected the transaction (insufficient fee,
///   double spend, malformed tx, etc.).  Retry will not help without fixing
///   the transaction itself.
/// - `InvalidTxId`: the server returned a response that did not look like a
///   valid txid.  Likely a server bug or protocol mismatch; log and investigate.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum BroadcastError {
    /// `raw_tx` was empty; the RPC was not called.
    #[error("broadcast_tx called with empty raw_tx")]
    EmptyTx,

    /// gRPC transport error (tonic Status).
    #[error("gRPC error (code {code}): {message}")]
    Grpc { code: i32, message: String },

    /// The lightwalletd node rejected the transaction.
    #[error("broadcast rejected (code {code}): {message}")]
    BroadcastFailed { code: i32, message: String },

    /// The server's success response did not contain a valid 64-hex txid.
    #[error("server returned invalid txid: {0:?}")]
    InvalidTxId(String),
}

/// A connected client to a lightwalletd gRPC endpoint.
///
/// Reconnection is the caller's responsibility: if a streaming RPC returns an
/// error, drop this client and call `connect` again.  The compact-block scanner
/// (nie-bgc) owns the reconnect loop.
pub struct LightwalletdClient {
    /// The endpoint URL (stored for diagnostics and reconnect).
    pub url: String,
    inner: CompactTxStreamerClient<Channel>,
}

impl LightwalletdClient {
    /// Connect to a lightwalletd endpoint.
    ///
    /// `url` must be an `https://` URI.  TLS is mandatory; the server
    /// certificate is validated against the bundled Mozilla root CA set.
    ///
    /// This call performs DNS resolution, TCP handshake, and TLS negotiation.
    /// A 15-second wall-clock timeout covers all three phases.  Returns an
    /// error if the server is unreachable, times out, or presents an invalid
    /// certificate.
    pub async fn connect(url: &str) -> Result<Self> {
        let tls = ClientTlsConfig::new().with_enabled_roots();
        // 15 s covers DNS resolution, TCP handshake, and TLS negotiation.
        // tonic's connect_timeout() only guards the TCP phase; wrapping the
        // full connect() call with tokio::time::timeout bounds all three.
        let endpoint = Endpoint::from_shared(url.to_owned())
            .with_context(|| format!("invalid lightwalletd URL: {url}"))?
            .tls_config(tls)
            .context("TLS configuration failed")?;
        let channel = tokio::time::timeout(Duration::from_secs(15), endpoint.connect())
            .await
            .context("connect to lightwalletd timed out after 15 s (DNS + TCP + TLS)")?
            .with_context(|| format!("could not connect to lightwalletd at {url}"))?;

        Ok(Self {
            url: url.to_owned(),
            inner: CompactTxStreamerClient::new(channel),
        })
    }

    /// Return the height of the chain tip reported by the server.
    pub async fn latest_height(&mut self) -> Result<u64> {
        let response = self
            .inner
            .get_latest_block(ChainSpec {})
            .await
            .context("GetLatestBlock RPC failed")?;
        Ok(response.into_inner().height)
    }

    /// Broadcast a raw Zcash transaction to the network via lightwalletd.
    ///
    /// Returns the txid as a 64-character lowercase hex string on success.
    ///
    /// # Errors
    ///
    /// - [`BroadcastError::EmptyTx`] if `raw_tx` is empty — checked before the
    ///   RPC call so no network round-trip is wasted.
    /// - [`BroadcastError::Grpc`] if the transport layer fails (unreachable,
    ///   TLS, timeout).
    /// - [`BroadcastError::BroadcastFailed`] if the node rejects the transaction
    ///   (insufficient fee, double spend, malformed, etc.).  The `code` and
    ///   `message` fields carry the server's rejection reason.
    /// - [`BroadcastError::InvalidTxId`] if the server's success response does
    ///   not contain a valid 64-hex txid.
    ///
    /// # No retry
    ///
    /// This function does not retry.  Callers are responsible for deciding
    /// whether a failure is transient (`Grpc`) or permanent (`BroadcastFailed`).
    pub async fn broadcast_tx(&mut self, raw_tx: &[u8]) -> Result<String, BroadcastError> {
        // Validate before making any RPC call — an empty tx would be rejected
        // by the node anyway, but we catch it here so callers get a clear error.
        validate_raw_tx(raw_tx)?;

        let response = self
            .inner
            .send_transaction(lwd::RawTransaction {
                data: raw_tx.to_vec(),
                height: 0,
            })
            .await
            .map_err(|status| BroadcastError::Grpc {
                code: status.code() as i32,
                message: status.message().to_owned(),
            })?;

        parse_send_response(response.into_inner())
    }

    /// Stream compact blocks from `start` to `end` inclusive.
    ///
    /// Returns a `tonic::Streaming<CompactBlock>` that yields one item per
    /// block.  The scanner calls `.message().await` in a loop until `None`
    /// (stream closed) or an error.
    pub async fn get_block_range(
        &mut self,
        start: u64,
        end: u64,
    ) -> Result<tonic::Streaming<CompactBlock>> {
        assert!(
            start <= end,
            "get_block_range: start ({start}) must be <= end ({end})"
        );
        let request = BlockRange {
            start: Some(BlockId {
                height: start,
                hash: vec![],
            }),
            end: Some(BlockId {
                height: end,
                hash: vec![],
            }),
        };
        let stream = self
            .inner
            .get_block_range(request)
            .await
            .with_context(|| format!("GetBlockRange({start}..={end}) RPC failed"))?
            .into_inner();
        Ok(stream)
    }
}

// ---- broadcast helpers (pub for unit testing) ----

/// Return `Err(BroadcastError::EmptyTx)` if `raw_tx` is empty.
///
/// This check is extracted as a separate function so it can be unit-tested
/// independently of the gRPC transport.
pub fn validate_raw_tx(raw_tx: &[u8]) -> Result<(), BroadcastError> {
    if raw_tx.is_empty() {
        return Err(BroadcastError::EmptyTx);
    }
    Ok(())
}

/// Parse a `SendResponse` proto into a txid or a [`BroadcastError`].
///
/// Lightwalletd convention (documented in service.proto):
/// - `error_code == 0` and `error_message` is a 64-character lowercase hex txid → success.
/// - `error_code != 0` → `BroadcastFailed` with the server's code and message.
///
/// This function is extracted for unit testing without a real gRPC transport.
pub fn parse_send_response(resp: lwd::SendResponse) -> Result<String, BroadcastError> {
    if resp.error_code != 0 {
        return Err(BroadcastError::BroadcastFailed {
            code: resp.error_code,
            message: resp.error_message,
        });
    }
    let txid = resp.error_message;
    // A valid Zcash txid is 32 bytes = 64 hex characters.
    // Normalize to lowercase: lightwalletd returns lowercase in practice, but
    // normalizing defensively prevents case-sensitivity mismatches when the
    // stored txid is later compared against canonical lowercase strings from
    // block explorers or the user.
    if txid.len() != 64 || !txid.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(BroadcastError::InvalidTxId(txid));
    }
    let txid = txid.to_lowercase();
    tracing::info!(txid, "transaction broadcast successful");
    Ok(txid)
}

/// Connect to the first reachable endpoint from `endpoints`, logging warnings
/// for each failed attempt.
///
/// Tries each URL in order.  Returns the first successful connection, or an
/// error if all endpoints are unreachable.
///
/// Pass [`DEFAULT_MAINNET_ENDPOINTS`] (or [`DEFAULT_TESTNET_ENDPOINT`] wrapped
/// in a slice) as `endpoints`, or a user-configured override list.
pub async fn connect_with_failover(endpoints: &[&str]) -> Result<LightwalletdClient> {
    if endpoints.is_empty() {
        anyhow::bail!("no lightwalletd endpoints configured");
    }
    let start = ENDPOINT_COUNTER.fetch_add(1, Ordering::Relaxed) % endpoints.len();
    let mut last_err = anyhow::anyhow!("no endpoints tried");
    for i in 0..endpoints.len() {
        let url = endpoints[(start + i) % endpoints.len()];
        match LightwalletdClient::connect(url).await {
            Ok(client) => return Ok(client),
            Err(e) => {
                warn!("lightwalletd {url} unreachable: {e}");
                last_err = e;
            }
        }
    }
    Err(last_err.context("all lightwalletd endpoints unreachable"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that the proto-generated CompactBlock type is correctly structured.
    ///
    /// Oracle: the field values are set directly and read back — this checks
    /// that prost generated the expected struct layout, not the network protocol.
    #[test]
    fn compact_block_proto_fields_are_accessible() {
        let block = CompactBlock {
            proto_version: 1,
            height: 2_000_000,
            hash: vec![0xab; 32],
            prev_hash: vec![0xcd; 32],
            time: 1_700_000_000,
            header: vec![],
            vtx: vec![],
            chain_metadata: None,
        };
        assert_eq!(block.height, 2_000_000);
        assert_eq!(block.hash.len(), 32);
        assert_eq!(block.time, 1_700_000_000);
    }

    /// Verify BlockRange proto construction used in get_block_range().
    ///
    /// Oracle: height values round-trip through the struct without change.
    #[test]
    fn block_range_construction() {
        let range = BlockRange {
            start: Some(BlockId {
                height: 100,
                hash: vec![],
            }),
            end: Some(BlockId {
                height: 200,
                hash: vec![],
            }),
        };
        assert_eq!(range.start.as_ref().unwrap().height, 100);
        assert_eq!(range.end.as_ref().unwrap().height, 200);
    }

    /// connect_with_failover with no endpoints returns an error immediately.
    ///
    /// Oracle: the error condition is the empty-list guard in the function
    /// body, independent of network state.
    #[tokio::test]
    async fn connect_with_failover_empty_list_errors() {
        let result = connect_with_failover(&[]).await;
        assert!(result.is_err(), "empty endpoint list must return an error");
    }

    /// connect_with_failover exhausts all endpoints before returning an error.
    ///
    /// Oracle: when every endpoint in the list is unreachable, the function
    /// must return an error whose message contains "all lightwalletd endpoints
    /// unreachable" — the context string appended in the exhaustion path.
    /// This is independent of global state and deterministic under parallelism.
    #[tokio::test]
    async fn connect_with_failover_exhausts_all_endpoints() {
        // Two distinct unreachable addresses ensure the failover loop iterates
        // more than once (start index varies with the global counter, but both
        // addresses are equally unreachable, so the outcome is always an error).
        let result =
            connect_with_failover(&["https://127.0.0.1:1", "https://127.0.0.2:1"]).await;
        match result {
            Ok(_) => panic!("all unreachable endpoints must yield an error"),
            Err(e) => assert!(
                format!("{e:#}").contains("all lightwalletd endpoints unreachable"),
                "error must report exhaustion of all endpoints; got: {e:#}"
            ),
        }
    }

    /// DEFAULT_MAINNET_ENDPOINTS has at least three entries (nie-060.1).
    ///
    /// Oracle: the nie-060.1 spec requires at least three independent mainnet
    /// lightwalletd endpoints for meaningful failover; the array length is an
    /// independent observable from the code under test.
    #[test]
    fn default_mainnet_endpoints_len_at_least_three() {
        assert!(
            DEFAULT_MAINNET_ENDPOINTS.len() >= 3,
            "at least three default mainnet endpoints must be configured"
        );
    }

    /// Default endpoint constants have at least two entries and all use https.
    ///
    /// Oracle: the expected scheme and count are from the nie-9wo issue spec
    /// (2-3 public mainnet endpoints, TLS required).
    #[test]
    fn default_mainnet_endpoints_are_https() {
        assert!(
            DEFAULT_MAINNET_ENDPOINTS.len() >= 2,
            "at least two default mainnet endpoints must be configured"
        );
        for url in DEFAULT_MAINNET_ENDPOINTS {
            assert!(
                url.starts_with("https://"),
                "default endpoint must use https: {url}"
            );
        }
        assert!(
            DEFAULT_TESTNET_ENDPOINT.starts_with("https://"),
            "default testnet endpoint must use https"
        );
    }

    // ---- broadcast_tx unit tests (nie-5kc) ----
    // These test validate_raw_tx() and parse_send_response() directly to avoid
    // requiring a real gRPC server in CI.  The gRPC call in broadcast_tx() is a
    // thin wrapper that has no testable logic beyond what the helpers cover.

    /// Empty raw_tx is rejected before any RPC call.
    ///
    /// Oracle: validate_raw_tx([]) must return EmptyTx, verified by matching the
    /// error variant — no network call is needed to check this condition.
    #[test]
    fn broadcast_validate_empty_tx_returns_err() {
        let err = validate_raw_tx(&[]).unwrap_err();
        assert_eq!(err, BroadcastError::EmptyTx);
    }

    /// Non-empty raw_tx passes validation.
    ///
    /// Oracle: a single byte is sufficient to pass the length check.
    #[test]
    fn broadcast_validate_nonempty_tx_passes() {
        validate_raw_tx(&[0x01]).unwrap();
    }

    /// Successful SendResponse with valid 64-hex txid returns the txid.
    ///
    /// Oracle: txid is a known 64-char lowercase hex string; verified by
    /// comparing the returned value, not by re-running the parse logic.
    #[test]
    fn parse_send_response_success_returns_txid() {
        let txid = "a".repeat(64);
        let resp = lwd::SendResponse {
            error_code: 0,
            error_message: txid.clone(),
        };
        let result = parse_send_response(resp).unwrap();
        assert_eq!(result, txid);
    }

    /// error_code != 0 → BroadcastFailed with the server's code and message.
    ///
    /// Oracle: error_code and error_message are set directly; the returned
    /// error variant and fields are verified independently.
    #[test]
    fn parse_send_response_error_code_returns_broadcast_failed() {
        let resp = lwd::SendResponse {
            error_code: -1,
            error_message: "insufficient fee".to_owned(),
        };
        let err = parse_send_response(resp).unwrap_err();
        assert_eq!(
            err,
            BroadcastError::BroadcastFailed {
                code: -1,
                message: "insufficient fee".to_owned(),
            }
        );
    }

    /// error_code != 0 with a different error message → BroadcastFailed.
    ///
    /// Oracle: tests that the error_message is forwarded verbatim, not truncated.
    #[test]
    fn parse_send_response_double_spend_returns_broadcast_failed() {
        let resp = lwd::SendResponse {
            error_code: 2,
            error_message: "transaction already in mempool".to_owned(),
        };
        let err = parse_send_response(resp).unwrap_err();
        assert_eq!(
            err,
            BroadcastError::BroadcastFailed {
                code: 2,
                message: "transaction already in mempool".to_owned(),
            }
        );
    }

    /// error_code = 0 but txid is not 64 hex chars → InvalidTxId.
    ///
    /// Oracle: a too-short response (e.g. 63 chars) must be rejected.
    #[test]
    fn parse_send_response_short_txid_returns_invalid() {
        let resp = lwd::SendResponse {
            error_code: 0,
            error_message: "a".repeat(63), // one char short
        };
        let err = parse_send_response(resp).unwrap_err();
        assert!(matches!(err, BroadcastError::InvalidTxId(_)));
    }

    /// error_code = 0 but txid contains non-hex chars → InvalidTxId.
    ///
    /// Oracle: 64 chars of 'x' (not valid hex) must be rejected.
    #[test]
    fn parse_send_response_non_hex_txid_returns_invalid() {
        let resp = lwd::SendResponse {
            error_code: 0,
            error_message: "x".repeat(64), // 'x' is not valid hex
        };
        let err = parse_send_response(resp).unwrap_err();
        assert!(matches!(err, BroadcastError::InvalidTxId(_)));
    }

    /// Uppercase hex input is normalized to lowercase.
    ///
    /// Oracle: 64 uppercase hex chars are valid hex; the returned txid must be
    /// the lowercase form so downstream comparisons against canonical txids
    /// (block explorers, DB queries) are case-consistent.
    #[test]
    fn parse_send_response_uppercase_hex_is_normalized_to_lowercase() {
        let resp = lwd::SendResponse {
            error_code: 0,
            error_message: "A".repeat(64),
        };
        let result = parse_send_response(resp).expect("uppercase hex is valid");
        assert_eq!(
            result,
            "a".repeat(64),
            "txid must be normalized to lowercase"
        );
    }
}
