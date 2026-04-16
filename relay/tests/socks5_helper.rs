//! Minimal in-process SOCKS5 CONNECT forwarder for integration tests.
//!
//! Implements RFC 1928 §§3–6: no-auth negotiation, CONNECT command,
//! and bidirectional byte-splicing to the real target.  Only one
//! connection is handled; the listener task exits after the first CONNECT.
//!
//! Supported address types: ATYP=1 (IPv4) and ATYP=3 (domain name).
//! ATYP=4 (IPv6) is rejected — the tests do not need it.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Bind a SOCKS5 listener on `127.0.0.1:0`.
///
/// Returns `(port, connect_received_rx)`.
///
/// The spawned task accepts exactly one connection, performs the SOCKS5
/// handshake, connects to `target_addr` (host:port string), then splices
/// bytes bidirectionally until either side closes.  On a successful CONNECT
/// the oneshot sender fires so the test can assert the proxy was used.
pub async fn run_socks5_proxy(target_addr: String) -> (u16, tokio::sync::oneshot::Receiver<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind SOCKS5 listener");
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        let (mut client, _) = listener.accept().await.expect("accept SOCKS5 connection");

        // --- Greeting ---
        // Client: [VER=5, NMETHODS, METHODS...]
        let mut buf = [0u8; 2];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf[0], 5, "SOCKS version must be 5");
        let nmethods = buf[1] as usize;
        let mut methods = vec![0u8; nmethods];
        client.read_exact(&mut methods).await.unwrap();
        // This test proxy only supports NO_AUTH (0x00).  If the client does not
        // offer it, something is misconfigured on the test side.
        assert!(
            methods.contains(&0x00),
            "test client must offer NO_AUTH (0x00); offered methods: {methods:?}"
        );
        // Reply: no-auth required
        client.write_all(&[0x05, 0x00]).await.unwrap();

        // --- CONNECT request ---
        // Client: [VER=5, CMD=1, RSV=0, ATYP, DST.ADDR, DST.PORT]
        let mut hdr = [0u8; 4];
        client.read_exact(&mut hdr).await.unwrap();
        assert_eq!(hdr[0], 5, "request version must be 5");
        assert_eq!(hdr[1], 1, "only CONNECT (CMD=1) is supported");

        // Parse destination address — we forward to target_addr regardless,
        // but we must consume the correct number of bytes from the stream.
        let atyp = hdr[3];
        match atyp {
            0x01 => {
                // IPv4: 4 bytes + 2 port
                let mut addr_port = [0u8; 6];
                client.read_exact(&mut addr_port).await.unwrap();
            }
            0x03 => {
                // Domain: 1-byte length + N bytes + 2 port
                let mut len_buf = [0u8; 1];
                client.read_exact(&mut len_buf).await.unwrap();
                let domain_len = len_buf[0] as usize;
                let mut domain_port = vec![0u8; domain_len + 2];
                client.read_exact(&mut domain_port).await.unwrap();
            }
            0x04 => {
                // ATYP=0x04 is IPv6 (16 bytes address + 2 bytes port).
                // Reply 0x08 = address type not supported, then close cleanly.
                let _ = client
                    .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
                return;
            }
            other => {
                let _ = client
                    .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
                eprintln!("socks5_helper: unsupported ATYP {other:#04x}, closed with error reply");
                return;
            }
        }

        // Connect to the real relay.
        let mut relay = tokio::net::TcpStream::connect(&target_addr)
            .await
            .unwrap_or_else(|e| {
                panic!("SOCKS5 helper: relay connect to {target_addr} failed: {e}")
            });

        // Success reply: VER=5, REP=0, RSV=0, ATYP=1, BND.ADDR=0.0.0.0, BND.PORT=0
        client
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();

        // Signal *after* the success reply is sent so the test assertion fires
        // only once the SOCKS5 handshake is fully complete on the client side.
        let _ = tx.send(());

        // Splice bidirectionally until either side closes.
        tokio::io::copy_bidirectional(&mut client, &mut relay)
            .await
            .ok(); // EOF from either side is normal
    });

    (port, rx)
}
