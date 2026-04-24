//! Sapling parameter file download and integrity verification (nie-bqe).
//!
//! The Zcash Sapling proving system requires two large parameter files that
//! must be present on disk before any shielded transaction can be created:
//!
//! - `sapling-spend.params`  (~47.9 MB) — spend circuit parameters
//! - `sapling-output.params` (~3.6 MB)  — output circuit parameters
//!
//! Both files are fetched from ECC's official CDN if not already cached.
//! Integrity is verified using BLAKE2b-512 — the same algorithm and constants
//! used by `zcash_proofs`.
//!
//! # Hash provenance
//!
//! The `SPEND_PARAMS_BLAKE2B` and `OUTPUT_PARAMS_BLAKE2B` constants were
//! extracted from `zcash_proofs/src/lib.rs` in the `zcash/librustzcash`
//! repository at commit **d849151** (the `corez_migration` merge, 2026-04-17).
//! Do not change these constants without re-verifying against the upstream
//! source at that commit.
//!
//! # Architecture: mock-friendly trait
//!
//! The [`ParamsFetcher`] trait separates the download mechanism from the
//! verification logic.  Production code uses [`HttpFetcher`]; tests inject a
//! [`MockFetcher`] that returns canned bytes without making network calls.
//! This satisfies the no-network-in-cargo-test requirement.

use std::path::{Path, PathBuf};

use anyhow::Result;
use blake2b_simd::Params as Blake2bParams;

// ---- CDN URLs (nie-bqe) ----
//
// Each parameter file is split into two parts on ECC's CDN to work around
// Cloudflare's 512 MB cached-file size limit ("denial of wallet" attack
// mitigation).  The two parts are concatenated in order before hashing.
// Part 2 may be absent (0 bytes) for files below the size threshold;
// the fetcher must tolerate a missing or empty part 2.
//
// Extracted from zcash_proofs/src/lib.rs @ d849151.

/// CDN URL for the Sapling spend-circuit parameters, part 1.
pub const SPEND_PARAMS_URL_PART1: &str =
    "https://download.z.cash/downloads/sapling-spend.params.part.1";
/// CDN URL for the Sapling spend-circuit parameters, part 2.
pub const SPEND_PARAMS_URL_PART2: &str =
    "https://download.z.cash/downloads/sapling-spend.params.part.2";
/// CDN URL for the Sapling output-circuit parameters, part 1.
pub const OUTPUT_PARAMS_URL_PART1: &str =
    "https://download.z.cash/downloads/sapling-output.params.part.1";
/// CDN URL for the Sapling output-circuit parameters, part 2.
pub const OUTPUT_PARAMS_URL_PART2: &str =
    "https://download.z.cash/downloads/sapling-output.params.part.2";

// ---- expected BLAKE2b-512 hashes ----
//
// Source: zcash/librustzcash, zcash_proofs/src/lib.rs, commit d849151.
// These are 128-character lowercase hex strings (512 bits = 64 bytes).
// Do NOT change without re-verifying from upstream source.

/// Expected BLAKE2b-512 hex digest of `sapling-spend.params`.
///
/// Source: `zcash_proofs/src/lib.rs` @ librustzcash commit d849151.
pub const SPEND_PARAMS_BLAKE2B: &str =
    "8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca63\
     991ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c";

/// Expected BLAKE2b-512 hex digest of `sapling-output.params`.
///
/// Source: `zcash_proofs/src/lib.rs` @ librustzcash commit d849151.
pub const OUTPUT_PARAMS_BLAKE2B: &str =
    "657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60b\
     f593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028";

// ---- types ----

/// Paths to the two Sapling parameter files on disk.
#[derive(Debug, Clone)]
pub struct SaplingParamPaths {
    /// Absolute path to `sapling-spend.params`.
    pub spend: PathBuf,
    /// Absolute path to `sapling-output.params`.
    pub output: PathBuf,
}

/// Specification for one parameter file: expected hash and CDN URLs.
///
/// Passed to [`ensure_params_with_hashes`] to avoid an excessively long
/// argument list.  Fields wrap the URL and hash constants for one file.
#[derive(Debug, Clone)]
pub struct ParamSpec<'a> {
    /// Expected BLAKE2b-512 digest as 128 lowercase hex characters.
    pub expected_blake2b: &'a str,
    /// CDN URL for the first part of the file (required).
    pub url_part1: &'a str,
    /// CDN URL for the second part of the file (may be absent/empty).
    pub url_part2: &'a str,
}

/// Abstraction over the network download path.
///
/// Implementing this trait lets tests inject a [`MockFetcher`] that returns
/// canned bytes without making real network calls.  Production code uses
/// [`HttpFetcher`].
pub trait ParamsFetcher: Send + Sync {
    /// Fetch a parameter file from a two-part CDN URL.
    ///
    /// `url_part1` is the primary URL; `url_part2` is the continuation.
    /// Implementations must concatenate the bytes from both parts in order.
    /// If `url_part2` returns 404 or is empty, that is acceptable — return
    /// only the bytes from `url_part1`.
    ///
    /// `timeout_secs` is the per-request timeout in seconds.
    ///
    /// Returns `Err` on transport failure (network error, timeout, HTTP error
    /// on part 1).  A non-200 on part 2 is silently ignored.
    fn fetch_combined(
        &self,
        url_part1: &str,
        url_part2: &str,
        timeout_secs: u64,
    ) -> Result<Vec<u8>>;
}

// ---- verification ----

/// Compute BLAKE2b-512 over `data` and compare to `expected_hex`.
///
/// Returns `true` if and only if the digest matches.  `expected_hex` must be
/// 128 lowercase hex characters; any other length returns `false`.
///
/// This function is the core integrity check.  It has no side effects and is
/// fully testable without a file system or network.
pub fn verify_blake2b(data: &[u8], expected_hex: &str) -> bool {
    if expected_hex.len() != 128 {
        return false;
    }
    let digest = Blake2bParams::new().hash_length(64).hash(data);
    // Compare as lowercase hex strings.  Both sides are fixed-length ASCII;
    // constant-time comparison is not required here (these are public checksums).
    let got = digest.to_hex();
    got.as_str() == expected_hex
}

// ---- core logic ----

/// Ensure both Sapling parameter files are present and correct in `cache_dir`.
///
/// This is the testable core of the download/verification flow.  All expected
/// hashes and URLs are passed in; production code calls the convenience wrapper
/// [`ensure_params`] which supplies the canonical constants.
///
/// # Behaviour
///
/// For each parameter file:
/// 1. If the file exists and its BLAKE2b-512 hash matches `expected_blake2b`,
///    it is used as-is (no network call).
/// 2. If the file is missing or its hash does not match, the file is deleted
///    (if present) and re-fetched via `fetcher.fetch_combined()`.
/// 3. After fetching, the hash is re-verified.  If it still does not match,
///    the function returns `Err`.
///
/// # Errors
///
/// Returns `Err` if:
/// - `cache_dir` cannot be created.
/// - `fetcher.fetch_combined()` fails.
/// - The fetched file's hash does not match the expected hash (possibly a
///   CDN tampering or truncation event).
pub fn ensure_params_with_hashes(
    cache_dir: &Path,
    spend: &ParamSpec<'_>,
    output: &ParamSpec<'_>,
    fetcher: &dyn ParamsFetcher,
) -> Result<SaplingParamPaths> {
    std::fs::create_dir_all(cache_dir)?;

    let spend_path = cache_dir.join("sapling-spend.params");
    let output_path = cache_dir.join("sapling-output.params");

    ensure_param_file(
        &spend_path,
        spend.expected_blake2b,
        spend.url_part1,
        spend.url_part2,
        fetcher,
        "sapling-spend.params",
    )?;

    ensure_param_file(
        &output_path,
        output.expected_blake2b,
        output.url_part1,
        output.url_part2,
        fetcher,
        "sapling-output.params",
    )?;

    Ok(SaplingParamPaths {
        spend: spend_path,
        output: output_path,
    })
}

fn ensure_param_file(
    path: &Path,
    expected_blake2b: &str,
    url_part1: &str,
    url_part2: &str,
    fetcher: &dyn ParamsFetcher,
    name: &str,
) -> Result<()> {
    // Check if the cached file is present and valid.
    // Read directly instead of checking exists() first to avoid TOCTOU: a file
    // removed between exists() and read() would produce an unexpected NotFound.
    match std::fs::read(path) {
        Ok(data) => {
            if verify_blake2b(&data, expected_blake2b) {
                tracing::debug!("{name}: cache hit (hash verified)");
                return Ok(());
            }
            tracing::warn!("{name}: cached file hash mismatch — re-downloading");
            // Remove the corrupt/outdated file before re-fetching.
            std::fs::remove_file(path)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!("{name}: not cached — downloading");
        }
        Err(e) => return Err(e.into()),
    }

    // Fetch from CDN (60-second timeout per request).
    let data = fetcher
        .fetch_combined(url_part1, url_part2, 60)
        .map_err(|e| anyhow::anyhow!("Sapling params unavailable — check network: {name}: {e}"))?;

    // Verify the downloaded content before writing to disk.
    if !verify_blake2b(&data, expected_blake2b) {
        anyhow::bail!(
            "{name}: downloaded file hash mismatch — possible CDN tampering or truncation"
        );
    }

    std::fs::write(path, &data)?;
    tracing::info!("{name}: downloaded and verified ({} bytes)", data.len());
    Ok(())
}

/// Ensure both Sapling parameter files are present and correct.
///
/// Uses the canonical CDN URLs and BLAKE2b-512 hashes from ECC's official
/// distribution (librustzcash commit d849151).
///
/// `cache_dir` is typically `~/.zcash-params` on Linux (same convention as
/// other Zcash clients — avoids re-downloading if files are already present).
/// The directory is created if it does not exist.
///
/// In production, pass [`HttpFetcher`].  In tests, pass a [`MockFetcher`].
pub fn ensure_params(cache_dir: &Path, fetcher: &dyn ParamsFetcher) -> Result<SaplingParamPaths> {
    ensure_params_with_hashes(
        cache_dir,
        &ParamSpec {
            expected_blake2b: SPEND_PARAMS_BLAKE2B,
            url_part1: SPEND_PARAMS_URL_PART1,
            url_part2: SPEND_PARAMS_URL_PART2,
        },
        &ParamSpec {
            expected_blake2b: OUTPUT_PARAMS_BLAKE2B,
            url_part1: OUTPUT_PARAMS_URL_PART1,
            url_part2: OUTPUT_PARAMS_URL_PART2,
        },
        fetcher,
    )
}

// ---- production HTTP fetcher ----

/// Production implementation of [`ParamsFetcher`] using `minreq`.
///
/// Uses a synchronous HTTP client with a configurable timeout.  This is
/// intentionally synchronous — params download is a wallet-init-time
/// blocking operation that runs at most once per wallet installation.
pub struct HttpFetcher;

impl ParamsFetcher for HttpFetcher {
    fn fetch_combined(
        &self,
        url_part1: &str,
        url_part2: &str,
        timeout_secs: u64,
    ) -> Result<Vec<u8>> {
        // Fetch part 1 — required.  Non-200 or timeout is a hard error.
        let resp1 = minreq::get(url_part1)
            .with_timeout(timeout_secs)
            .send()
            .map_err(|e| anyhow::anyhow!("fetch {url_part1}: {e}"))?;
        if resp1.status_code != 200 {
            anyhow::bail!("fetch {url_part1}: HTTP {}", resp1.status_code);
        }
        let mut data: Vec<u8> = resp1.into_bytes();

        // Fetch part 2 — optional.  A 404 or network error is silently ignored
        // because many param files fit entirely in part 1.
        match minreq::get(url_part2).with_timeout(timeout_secs).send() {
            Ok(resp2) if resp2.status_code == 200 => {
                data.extend_from_slice(resp2.as_bytes());
            }
            Ok(_) | Err(_) => {
                // Non-200 or error on part 2: file fits in part 1, which is fine.
            }
        }

        Ok(data)
    }
}

// ---- test mock ----

/// A [`ParamsFetcher`] that returns canned byte slices without network access.
///
/// Use in unit tests: construct with per-file byte slices, inject instead of
/// [`HttpFetcher`].  The `fetch_count` field lets tests assert that the
/// downloader was called the expected number of times (0 = cache hit).
#[cfg(test)]
pub struct MockFetcher {
    /// Bytes to return for `sapling-spend.params`.
    pub spend_bytes: Vec<u8>,
    /// Bytes to return for `sapling-output.params`.
    pub output_bytes: Vec<u8>,
    /// Incremented on each successful fetch (spend or output).
    pub fetch_count: std::sync::atomic::AtomicUsize,
}

#[cfg(test)]
impl ParamsFetcher for MockFetcher {
    fn fetch_combined(
        &self,
        url_part1: &str,
        _url_part2: &str,
        _timeout_secs: u64,
    ) -> Result<Vec<u8>> {
        use std::sync::atomic::Ordering;
        self.fetch_count.fetch_add(1, Ordering::SeqCst);
        if url_part1.contains("spend") {
            Ok(self.spend_bytes.clone())
        } else {
            Ok(self.output_bytes.clone())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    // ---- helper: make a MockFetcher with canned data and matching hashes ----

    fn make_mock(spend_data: Vec<u8>, output_data: Vec<u8>) -> MockFetcher {
        MockFetcher {
            spend_bytes: spend_data,
            output_bytes: output_data,
            fetch_count: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn blake2b_hex(data: &[u8]) -> String {
        Blake2bParams::new()
            .hash_length(64)
            .hash(data)
            .to_hex()
            .to_string()
    }

    // ---- verify_blake2b unit tests ----

    /// Correct hash of known data returns true.
    ///
    /// Oracle: independently computed via blake2b_simd::Params.
    #[test]
    fn verify_blake2b_correct_hash() {
        let data = b"hello sapling";
        let expected = blake2b_hex(data);
        assert!(verify_blake2b(data, &expected));
    }

    /// Wrong hash of known data returns false.
    ///
    /// Oracle: a string of 128 zeros is not the hash of any real data.
    #[test]
    fn verify_blake2b_wrong_hash() {
        let data = b"hello sapling";
        let wrong = "0".repeat(128);
        assert!(!verify_blake2b(data, &wrong));
    }

    /// Expected hash of wrong length is rejected without panic.
    ///
    /// Oracle: 64-char string is half the required 128 chars.
    #[test]
    fn verify_blake2b_wrong_length_returns_false() {
        assert!(!verify_blake2b(b"any data", &"a".repeat(64)));
        assert!(!verify_blake2b(b"any data", ""));
    }

    // ---- ensure_params_with_hashes tests ----

    fn run_ensure(
        dir: &Path,
        fetcher: &dyn ParamsFetcher,
        spend_data: &[u8],
        output_data: &[u8],
    ) -> Result<SaplingParamPaths> {
        let sh = blake2b_hex(spend_data);
        let oh = blake2b_hex(output_data);
        ensure_params_with_hashes(
            dir,
            &ParamSpec {
                expected_blake2b: &sh,
                url_part1: "https://example.com/spend.part.1",
                url_part2: "https://example.com/spend.part.2",
            },
            &ParamSpec {
                expected_blake2b: &oh,
                url_part1: "https://example.com/output.part.1",
                url_part2: "https://example.com/output.part.2",
            },
            fetcher,
        )
    }

    /// Cache hit: if valid files are already present, fetcher is NOT called.
    ///
    /// Oracle: fetch_count remains 0 after a successful call with pre-populated cache.
    #[test]
    fn ensure_params_uses_cache_when_valid() {
        let dir = tempfile::tempdir().unwrap();
        let spend = b"fake spend params";
        let output = b"fake output params";

        // Seed the cache with correct files.
        let sh = blake2b_hex(spend);
        let oh = blake2b_hex(output);
        std::fs::write(dir.path().join("sapling-spend.params"), spend).unwrap();
        std::fs::write(dir.path().join("sapling-output.params"), output).unwrap();

        // Fetcher that panics if called — must NOT be invoked on a cache hit.
        struct PanicFetcher;
        impl ParamsFetcher for PanicFetcher {
            fn fetch_combined(&self, _: &str, _: &str, _: u64) -> Result<Vec<u8>> {
                panic!("fetcher must not be called on a cache hit");
            }
        }

        let paths = ensure_params_with_hashes(
            dir.path(),
            &ParamSpec {
                expected_blake2b: &sh,
                url_part1: "https://example.com/spend.part.1",
                url_part2: "https://example.com/spend.part.2",
            },
            &ParamSpec {
                expected_blake2b: &oh,
                url_part1: "https://example.com/output.part.1",
                url_part2: "https://example.com/output.part.2",
            },
            &PanicFetcher,
        )
        .unwrap();

        assert!(paths.spend.exists());
        assert!(paths.output.exists());
    }

    /// Hash mismatch triggers re-download (the main nie-bqe acceptance criterion).
    ///
    /// Oracle: place corrupt file in cache, verify fetcher is called exactly once
    /// for that file (spend), and the result on disk matches the fetched content.
    #[test]
    fn ensure_params_redownloads_on_hash_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let real_spend = b"real spend params content";
        let real_output = b"real output params content";
        let mock = make_mock(real_spend.to_vec(), real_output.to_vec());

        // Plant a corrupt spend file (wrong content → hash mismatch).
        std::fs::write(dir.path().join("sapling-spend.params"), b"corrupt").unwrap();
        // Plant a correct output file (should NOT trigger re-download).
        let oh = blake2b_hex(real_output);
        std::fs::write(dir.path().join("sapling-output.params"), real_output).unwrap();

        let sh = blake2b_hex(real_spend);
        let paths = ensure_params_with_hashes(
            dir.path(),
            &ParamSpec {
                expected_blake2b: &sh,
                url_part1: "https://example.com/spend.part.1",
                url_part2: "https://example.com/spend.part.2",
            },
            &ParamSpec {
                expected_blake2b: &oh,
                url_part1: "https://example.com/output.part.1",
                url_part2: "https://example.com/output.part.2",
            },
            &mock,
        )
        .unwrap();

        // Exactly one download happened (for the corrupt spend file only).
        assert_eq!(
            mock.fetch_count.load(Ordering::SeqCst),
            1,
            "only the corrupt spend file must be re-fetched"
        );

        // The spend file on disk is now the fetched content.
        let on_disk = std::fs::read(&paths.spend).unwrap();
        assert_eq!(on_disk, real_spend);
    }

    /// Missing files are downloaded and verified.
    ///
    /// Oracle: empty cache dir → both files fetched; content and hash verified on disk.
    #[test]
    fn ensure_params_downloads_missing_files() {
        let dir = tempfile::tempdir().unwrap();
        let spend = b"spend params data";
        let output = b"output params data";
        let mock = make_mock(spend.to_vec(), output.to_vec());

        let paths = run_ensure(dir.path(), &mock, spend, output).unwrap();

        assert_eq!(mock.fetch_count.load(Ordering::SeqCst), 2);
        assert_eq!(std::fs::read(&paths.spend).unwrap(), spend);
        assert_eq!(std::fs::read(&paths.output).unwrap(), output);
    }

    /// Fetcher returning wrong-hash content causes ensure_params to return Err.
    ///
    /// Oracle: mock returns "bad_data" but ensure is called with hash of "good_data";
    /// the mismatch must propagate as an error, not silently write the bad file.
    #[test]
    fn ensure_params_err_when_fetched_hash_wrong() {
        let dir = tempfile::tempdir().unwrap();
        let good_spend = b"good spend";
        let bad_spend = b"bad spend - hash will not match";
        let output = b"output";

        // Fetcher returns bad data for spend.
        let mock = make_mock(bad_spend.to_vec(), output.to_vec());

        let sh = blake2b_hex(good_spend); // hash of good, but fetcher gives bad
        let oh = blake2b_hex(output);

        let err = ensure_params_with_hashes(
            dir.path(),
            &ParamSpec {
                expected_blake2b: &sh,
                url_part1: "https://example.com/spend.part.1",
                url_part2: "https://example.com/spend.part.2",
            },
            &ParamSpec {
                expected_blake2b: &oh,
                url_part1: "https://example.com/output.part.1",
                url_part2: "https://example.com/output.part.2",
            },
            &mock,
        )
        .unwrap_err();

        let msg = err.to_string();
        assert!(
            msg.contains("hash mismatch") || msg.contains("tampering"),
            "error must describe hash mismatch: {msg}"
        );
        // The corrupt file must not be left on disk.
        assert!(
            !dir.path().join("sapling-spend.params").exists(),
            "corrupt file must not be written to disk"
        );
    }
}
