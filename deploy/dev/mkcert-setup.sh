#!/usr/bin/env bash
# Generate locally-trusted TLS certs for dev wss:// testing.
#
# Requires mkcert: https://github.com/FiloSottile/mkcert
#   Linux:  apt install mkcert  OR  go install filippo.io/mkcert@latest
#   macOS:  brew install mkcert
#
# Run once. After this, `caddy run --config deploy/dev/Caddyfile` serves wss://localhost:8443/ws.
# The cert is trusted system-wide; no --insecure flag needed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v mkcert &>/dev/null; then
    echo "error: mkcert not found. Install it and re-run." >&2
    exit 1
fi

# Install the mkcert root CA into the system trust store (once per machine).
mkcert -install

# Generate cert for localhost / 127.0.0.1 / ::1.
mkcert \
    -key-file "${SCRIPT_DIR}/localhost-key.pem" \
    -cert-file "${SCRIPT_DIR}/localhost.pem" \
    localhost 127.0.0.1 ::1

echo ""
echo "Certs written to deploy/dev/localhost.pem and deploy/dev/localhost-key.pem"
echo "Run: caddy run --config deploy/dev/Caddyfile"
echo "Connect: nie --relay wss://localhost:8443/ws chat <peer>"
