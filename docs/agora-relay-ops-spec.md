# Agora Relay Operations Specification

**Version:** 0.1 (Draft)
**Date:** 2026-04-22
**Status:** Draft
**Companion to:** Agora Protocol Specification v0.2

---

## Abstract

This document is the operational companion to the Agora Protocol Specification. It does not define protocol behavior — that is the protocol spec's job. It defines how an infrastructure engineer deploys, configures, operates, monitors, upgrades, and decommissions an Agora relay in a production environment.

The intended audience is infrastructure engineers, platform teams, and SREs at enterprises or service providers self-hosting an Agora relay. The document assumes familiarity with Linux systems administration, container orchestration (Docker/Kubernetes), and basic distributed systems concepts. No deep knowledge of MLS or DIDs is assumed; protocol concepts are referenced by section number when relevant.

---

## Key Words

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

---

## Table of Contents

1. Overview
2. Deployment Architecture
3. Configuration
4. Deployment Packaging
5. Relay Admin API
6. Observability
7. Alerting
8. Backup and Restore
9. Upgrade Procedure
10. Key Management
11. Network Requirements
12. Capacity Planning
13. Security Hardening
14. Enterprise Integration Deployment
15. Multi-Relay HA Deployment
16. Decommissioning

---

## 1. Overview

### 1.1 Purpose and Scope

This document specifies the operational requirements for running an Agora relay. It covers the full operational lifecycle: initial deployment, day-to-day operations, observability, upgrading, and decommissioning. It introduces the Relay Admin API (§5), which is defined here and not in the protocol spec.

This document does not define the Agora protocol. All protocol behavior references use § notation pointing to the Agora Protocol Specification v0.2 (referred to throughout as "the protocol spec"). Where this document specifies behavior that must be consistent with the protocol spec, the protocol spec takes precedence in case of conflict.

### 1.2 Relationship to the Protocol Specification

The protocol spec defines what a conformant relay MUST do at the protocol level (§11.3): implement WebSocket and WebTransport transports, the KeyPackage Store API, the Peer API, relay-to-relay authentication, gossipsub participation, and the relay manifest. This document defines how to deploy and operate that relay: config file format, packaging, observability, backup procedures, network requirements, and operational runbooks.

Enterprise operators deploying the optional DID sidecar (§2.5) or Purview bridge should consult those companion specifications in addition to this document. Brief deployment guidance for both is included in §14.

### 1.3 Who This Document Is For

- **Infrastructure engineers** provisioning relay infrastructure on cloud or on-premises hardware.
- **Platform teams** integrating the relay into an existing Kubernetes or ECS environment.
- **SREs** responsible for relay availability, monitoring, and incident response.
- **Security engineers** reviewing the relay's security posture.

This document is not aimed at end users, space owners, or Agora client developers.

---

## 2. Deployment Architecture

### 2.1 Component Overview

A production Agora relay deployment consists of the following components:

```
┌──────────────────────────────────────────────────────────────┐
│  Internet-facing                                              │
│                                                               │
│  ┌─────────────────┐   ┌─────────────────┐                   │
│  │  Load Balancer  │   │  Tor Hidden Svc │ (optional)         │
│  │  (QUIC + TCP)   │   │  (WebSocket)    │                    │
│  └────────┬────────┘   └────────┬────────┘                   │
└───────────┼─────────────────────┼──────────────────────────── ┘
            │                     │
┌───────────┼─────────────────────┼──────────────────────────── ┐
│  Relay tier                     │                              │
│           ▼                     ▼                             │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  agora-relay process                                   │  │
│  │                                                        │  │
│  │  • WebTransport (QUIC/HTTP3)  /v1/agora/wt             │  │
│  │  • WebSocket                  /v1/agora/ws             │  │
│  │  • KeyPackage Store API       /v1/agora/kp             │  │
│  │  • Peer API                   /v1/agora/peer           │  │
│  │  • JMAP API                   /jmap                    │  │
│  │  • Push proxy client          (outbound)               │  │
│  │  • Gossipsub peer             (QUIC UDP)               │  │
│  │  • Admin API                  /admin  (internal only)  │  │
│  │  • Prometheus metrics         /metrics (internal only) │  │
│  └───────────┬────────────────────────────────────────────┘  │
│              │                                                 │
│    ┌─────────┼──────────┐                                     │
│    ▼         ▼          ▼                                      │
│  ┌──────┐ ┌──────┐ ┌────────┐                                 │
│  │  DB  │ │ Blob │ │  SFU   │ (optional)                     │
│  │(PG / │ │store │ │        │                                 │
│  │SQLite│ │(CAS) │ │        │                                 │
│  └──────┘ └──────┘ └────────┘                                 │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│  Enterprise sidecar tier (optional, enterprise deployments)   │
│                                                               │
│  ┌──────────────────┐  ┌──────────────────────────────────┐  │
│  │  DID Sidecar     │  │  Purview Bridge                  │  │
│  │  (§2.5 / O365    │  │  (compliance export to Exchange) │  │
│  │   spec)          │  │                                  │  │
│  └──────────────────┘  └──────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

**Required components:**
- `agora-relay` — the relay process. Implements all protocol-level behavior.
- Database — SQLite for development/small deployments; PostgreSQL for production.
- Blob store — content-addressed local storage for space state, message history, and KeyPackage supply. Backed by the local filesystem (`blob_backend = "local"`) or an S3-compatible object store (`blob_backend = "s3"`) for HA deployments. Exposed internally via `GET /v1/agora/blob/{cid}` for relay-to-relay CAS fetches.

**Optional components:**
- SFU (Selective Forwarding Unit) — for voice/video channel routing (§10.6). Can be a separate process or a separate host.
- Push proxy — for mobile push notification wake-ups (§8.7). Can be co-located or externally hosted.
- DID sidecar — for enterprise `did:web` identity provisioning (§2.5). Deployed separately; see §14.
- Purview bridge — for Microsoft Purview compliance export. Deployed separately; see §14.

### 2.2 Single-Node Deployment

Single-node deployment is appropriate for:
- Development and testing environments.
- Small organizations with fewer than ~200 active users.
- Enterprise deployments where the relay serves only internal users on a reliable LAN.

In a single-node deployment, all components run on one host or in one Docker Compose stack. SQLite is acceptable as the database backend. The local filesystem blob store (`blob_backend = "local"`) is sufficient. No load balancer is required; the relay process handles TLS directly.

### 2.3 Multi-Node HA Deployment

Multi-node HA deployment is required when:
- The relay must survive single-node failure.
- Active user count exceeds ~500.
- The relay serves a public community space where downtime causes user-visible disruption.

Multi-node HA is described in detail in §15. The short summary: PostgreSQL with streaming replication replaces SQLite; multiple relay instances share the database and an S3-compatible blob store backend (AWS S3, MinIO, Backblaze B2, or equivalent); a load balancer with QUIC affinity fronts the relay instances.

### 2.4 External Dependencies

| Dependency | Role | Required |
|---|---|---|
| PostgreSQL 15+ or SQLite 3.40+ | Message store, KeyPackage store, peer table, session state | Yes |
| Blob store (local filesystem or S3-compatible) | Content-addressed storage for space state, message history, and KeyPackage supply | Yes |
| Let's Encrypt / ACME CA | TLS certificate provisioning | Yes (or bring your own cert) |
| DNS provider | A/AAAA records, SRV records for DNS-SD discovery | Yes |
| APNs / FCM credentials | Push notification delivery | Only if running push proxy |
| AWS Secrets Manager / Vault | Secrets management | Recommended |
| Prometheus + Grafana | Metrics and dashboards | Recommended |

### 2.5 Network Topology Requirements

The relay requires the following network interfaces:

- **Public interface**: handles WebTransport (QUIC/UDP), WebSocket (TCP), JMAP HTTPS, and the well-known relay manifest endpoint. Must be reachable from the internet.
- **Peer gossip interface**: handles libp2p gossipsub QUIC connections from peer relays. MAY be the same public interface or a separate interface. MUST NOT be firewalled from peer relay IP ranges.
- **Internal/management interface**: handles the Admin API, Prometheus metrics, and database connections. MUST NOT be reachable from the internet.

---

## 3. Configuration

### 3.1 Config File Location and Format

The relay reads configuration from a TOML file. The default path is `/etc/agora-relay/relay.toml`. Override with the `--config` flag or the `AGORA_CONFIG` environment variable.

Secrets (signing keys, database passwords, admin tokens) MUST NOT be placed in the config file. Use environment variable overrides (§3.3) or a secrets manager integration (§3.4).

### 3.2 Full Configuration Reference

```toml
# /etc/agora-relay/relay.toml
# All fields shown. Defaults annotated with "# default: <value>".

# ─────────────────────────────────────────────
# [server] — network and TLS configuration
# ─────────────────────────────────────────────
[server]

# Hostname at which this relay is publicly reachable.
# Used to construct endpoint URLs in the relay manifest.
hostname = "relay.example.com"

# WebTransport (QUIC/HTTP3) listen address.
# default: "0.0.0.0:443"
webtransport_addr = "0.0.0.0:443"

# WebSocket (WSS) listen address.
# If webtransport and websocket share port 443, the relay
# distinguishes them by ALPN ("h3" vs "http/1.1"/"h2").
# default: "0.0.0.0:443"
websocket_addr = "0.0.0.0:443"

# Peer API and gossipsub QUIC listen address.
# This port must be reachable from peer relays.
# default: "0.0.0.0:9001"
peer_addr = "0.0.0.0:9001"

# Admin API listen address. MUST be bound to a non-public interface.
# default: "127.0.0.1:9099"
admin_addr = "127.0.0.1:9099"

# Prometheus metrics listen address.
# default: "127.0.0.1:9100"
metrics_addr = "127.0.0.1:9100"

# TLS certificate and private key paths.
# For Let's Encrypt automation, set tls_acme = true instead.
tls_cert = "/etc/agora-relay/tls/fullchain.pem"
tls_key  = "/etc/agora-relay/tls/privkey.pem"

# Let's Encrypt / ACME automatic certificate management.
# When true, tls_cert and tls_key are managed automatically.
# default: false
tls_acme = false

# ACME email address (required when tls_acme = true).
tls_acme_email = "relay-admin@example.com"

# ACME directory URL. Default is Let's Encrypt production.
# Use "https://acme-staging-v02.api.letsencrypt.org/directory" for testing.
# default: "https://acme-v02.api.letsencrypt.org/directory"
tls_acme_directory = "https://acme-v02.api.letsencrypt.org/directory"

# Maximum number of concurrent client connections.
# default: 10000
max_connections = 10000

# Maximum number of concurrent JMAP requests.
# default: 200
max_jmap_concurrent = 200

# Minimum TLS version. MUST be "1.3" for WebTransport.
# WebSocket may fall back to 1.2 for compatibility with older clients.
# default: "1.3"
tls_min_version = "1.3"

# Enable Tor hidden service (optional).
# Requires a local Tor daemon with control port access.
# default: false
tor_enabled = false

# Tor control port address (required when tor_enabled = true).
tor_control_addr = "127.0.0.1:9051"

# Path to the Tor hidden service key directory.
tor_hidden_service_dir = "/var/lib/tor/agora-relay"

# ─────────────────────────────────────────────
# [identity] — relay DID and signing key
# ─────────────────────────────────────────────
[identity]

# Relay DID. Generated once at initial setup; never changes.
# Example: "did:key:z6MkRelay..."
# This value is public. The signing key is a secret — see §3.3.
relay_did = "did:key:z6MkRelay..."

# Operator DID (the organization or person operating this relay).
operator_did = "did:web:example.com:agora:relay-operator"

# Human-readable operator name, appears in relay manifest.
operator_name = "Example Corp Relay"

# Admin contact email, appears in relay manifest.
admin_contact = "relay-admin@example.com"

# Abuse contact email, appears in relay manifest.
abuse_contact = "abuse@example.com"

# Relay description, appears in relay manifest.
description = "Example Corp internal relay, US-East"

# Geographic region hint, appears in relay manifest.
region = "us-east"

# Path to the relay signing key (Ed25519 private key, PEM format).
# STRONGLY prefer setting via AGORA_SIGNING_KEY_PATH env var or
# a secrets manager. If set here, file permissions MUST be 0600.
# default: "/etc/agora-relay/keys/relay-signing.key"
signing_key_path = "/etc/agora-relay/keys/relay-signing.key"

# PKCS#11 provider library for HSM-backed signing key.
# When set, signing_key_path is the PKCS#11 key label, not a file path.
# default: "" (disabled; use software key)
pkcs11_provider = ""

# Key expiry duration. The relay manifest key entry will have
# expiresAt = now() + key_expiry_days at manifest publication time.
# default: 365
key_expiry_days = 365

# ─────────────────────────────────────────────
# [storage] — database and blob store configuration
# ─────────────────────────────────────────────
[storage]

# Database backend: "sqlite" or "postgres".
# default: "sqlite"
db_backend = "postgres"

# SQLite database file path (used when db_backend = "sqlite").
# default: "/var/lib/agora-relay/relay.db"
sqlite_path = "/var/lib/agora-relay/relay.db"

# PostgreSQL connection string (used when db_backend = "postgres").
# Set via AGORA_DB_URL environment variable; do not put credentials here.
# default: "" (must be set via env var if using postgres)
postgres_url = ""

# PostgreSQL connection pool size.
# default: 20
postgres_pool_size = 20

# Message retention window in days. Cached envelopes older than this
# are eligible for deletion.
# Protocol minimum is the lesser of this value and the envelope expiryHint (§6.4).
# default: 30
retention_days = 30

# Maximum per-channel pin count (enforced per §6.6).
# default: 100
max_pins_per_channel = 100

# Blob store backend: "local" or "s3".
# "local" stores blobs on the local filesystem, indexed by CIDv1.
# "s3" stores blobs in an S3-compatible object store; required for HA deployments.
# default: "local"
blob_backend = "local"

# Local filesystem path for blob store (used when blob_backend = "local").
# default: "/var/lib/agora-relay/blobs"
blob_local_path = "/var/lib/agora-relay/blobs"

# Whether to store space state CIDs in the blob store.
# default: true
blob_store_space_state = true

# Whether to store message history CIDs within the retention window.
# default: true
blob_store_messages = true

# S3-compatible object store configuration (used when blob_backend = "s3").
# Enables shared blob store for HA deployments and off-site archival.
# Compatible with AWS S3, MinIO, Backblaze B2, Cloudflare R2, and any S3-compatible API.
# Set credentials via AGORA_BLOB_S3_ACCESS_KEY and AGORA_BLOB_S3_SECRET_KEY env vars.
# default: "" (disabled)
blob_s3_endpoint   = ""   # e.g. "https://s3.us-east-1.amazonaws.com"
blob_s3_bucket     = ""   # e.g. "agora-relay-blobs-prod"
blob_s3_region     = ""   # e.g. "us-east-1"
blob_s3_access_key = ""   # set via AGORA_BLOB_S3_ACCESS_KEY env var
blob_s3_secret_key = ""   # set via AGORA_BLOB_S3_SECRET_KEY env var

# KeyPackage store GC interval in hours.
# Expired and revoked KeyPackages are purged at this interval.
# default: 24
keypackage_gc_interval_hours = 24

# ─────────────────────────────────────────────
# [peering] — relay-to-relay mesh configuration
# ─────────────────────────────────────────────
[peering]

# Bootstrap peer manifest URLs. The relay contacts these on startup
# to join the gossipsub mesh (§3.5.5, Method 1).
bootstrap_peers = [
  "https://peer1.example.net/.well-known/agora-relay",
  "https://peer2.example.org/.well-known/agora-relay",
]

# Target mesh degree: number of active peer connections to maintain.
# Corresponds to gossipsub D parameter. default: 6
mesh_degree = 6

# Peer manifest cache TTL in seconds. default: 3600
peer_manifest_cache_ttl = 3600

# Peer heartbeat interval in seconds (§3.5.6). default: 60
peer_heartbeat_interval = 60

# Number of missed heartbeats before marking a peer unreachable. default: 3
peer_heartbeat_miss_threshold = 3

# Days to retain an unreachable peer in knownPeers before removal. default: 7
peer_retention_days = 7

# Blocklisted peer DIDs (permanently refused). Array of DID strings.
blocked_peers = []

# Explicitly trusted peer DIDs (trust level 3). Array of DID strings.
# These peers bypass gossip rate limiting entirely (§3.5.4).
trusted_peers = []

# ─────────────────────────────────────────────
# [economics] — relay payment configuration
# ─────────────────────────────────────────────
[economics]

# Whether this relay accepts MOB micropayments (§12.1).
# default: false
mob_enabled = false

# MobileCoin payment address for relay revenue.
mob_address = ""

# Whether this relay accepts Cashu ecash (§12.1).
# default: false
cashu_enabled = false

# Cashu mint URL.
cashu_mint_url = ""

# Whether this relay accepts proof-of-work (§12.4).
# default: true
pow_enabled = true

# Default PoW difficulty for channels that declare scheme=pow
# but do not specify difficulty. default: 18
pow_default_difficulty = 18

# ─────────────────────────────────────────────
# [push_proxy] — push notification proxy (§8.7)
# ─────────────────────────────────────────────
[push_proxy]

# Whether this relay operates a co-located push proxy. default: false
enabled = false

# Push proxy endpoint URL (if operating a push proxy, this is the
# locally-served URL; if using an external proxy, this is its URL).
endpoint = "https://push.relay.example.com/v1/agora/push"

# Push proxy DID (required if enabled = true).
proxy_did = ""

# APNs key ID, team ID, bundle ID (required for APNs support).
apns_key_id   = ""
apns_team_id  = ""
apns_bundle_id = ""
# APNs private key path (PKCS#8 .p8 file). Set via env var AGORA_APNS_KEY.
apns_key_path = ""

# FCM server key. Set via AGORA_FCM_SERVER_KEY env var.
fcm_server_key = ""

# Push registration TTL in days. default: 30
registration_ttl_days = 30

# ─────────────────────────────────────────────
# [jmap] — JMAP Management and Sync API (§8.8)
# ─────────────────────────────────────────────
[jmap]

# Whether to expose the JMAP API. default: true
enabled = true

# JMAP base URL (appears in the relay manifest and session object).
base_url = "https://relay.example.com"

# JMAP bearer token TTL in hours. default: 24
token_ttl_hours = 24

# Maximum message body bytes returned by JMAP. default: 65536
max_message_body_bytes = 65536

# Maximum attachment bytes. default: 104857600 (100 MB)
max_attachment_bytes = 104857600

# EventSource ping interval in seconds. default: 30
eventsource_ping_interval = 30

# ─────────────────────────────────────────────
# [compliance] — compliance logging support (§17)
# ─────────────────────────────────────────────
[compliance]

# Whether this relay admits compliance logger DIDs. default: true
# Setting to false causes the relay to reject spaces with
# complianceLogging.enabled = true.
admit_loggers = true

# Maximum compliance logger queue depth before backpressure.
# default: 100000
logger_queue_depth = 100000

# Compliance log flush interval in seconds. default: 5
flush_interval_seconds = 5

# Whether this relay operates its own compliance logger.
# Operators of regulated organizations may run logger = true;
# public community relays typically run logger = false.
# default: false
operate_logger = false

# Logger DID (required when operate_logger = true).
logger_did = ""

# Logger signing key path. MUST be separate from the relay signing key.
# Set via AGORA_LOGGER_KEY_PATH env var.
logger_key_path = ""

# IPLD log storage path. default: "/var/lib/agora-relay/compliance"
log_store_path = "/var/lib/agora-relay/compliance"

# ─────────────────────────────────────────────
# [enterprise] — SAML/OIDC integration (§2.5)
# ─────────────────────────────────────────────
[enterprise]

# Whether to require DID documents to be provisioned by a configured
# provisioning service (restricts relay to org members). default: false
require_provisioned_dids = false

# Accepted provisioning service DIDs. Only DID documents bearing a
# provisionerSig from one of these DIDs are accepted for authentication.
accepted_provisioner_dids = []

# OIDC issuer URL (for validating IdP tokens on the provisioning endpoint).
oidc_issuer = ""

# SAML IdP metadata URL.
saml_idp_metadata_url = ""

# Maximum number of devices per DID (enforced by provisioning service).
# default: 10
max_devices_per_did = 10

# ─────────────────────────────────────────────
# [rate_limits] — per-channel and per-connection limits
# ─────────────────────────────────────────────
[rate_limits]

# Maximum messages per second per channelToken (§13.5). default: 50
channel_msg_per_second = 50

# Burst allowance per channelToken. default: 200
channel_msg_burst = 200

# Maximum incoming connection rate (new connections per second). default: 100
connection_rate_per_second = 100

# Maximum unauthenticated connections (anonymous). default: 500
max_anonymous_connections = 500

# Maximum KeyPackage upload batch size per PUT request. default: 200
keypackage_upload_batch_max = 200

# ─────────────────────────────────────────────
# [logging] — structured log output
# ─────────────────────────────────────────────
[logging]

# Log level: "error", "warn", "info", "debug", "trace". default: "info"
level = "info"

# Log output: "stdout", "stderr", or a file path. default: "stdout"
output = "stdout"

# Log format: "json" (production) or "text" (development). default: "json"
format = "json"
```

### 3.3 Environment Variable Overrides

All configuration values can be overridden via environment variables using the pattern `AGORA_<SECTION>_<KEY>` in SCREAMING_SNAKE_CASE. Section separators become underscores. The following secrets MUST be set via environment variables and MUST NOT appear in the config file:

| Environment Variable | Config Equivalent | Description |
|---|---|---|
| `AGORA_SIGNING_KEY_PATH` | `identity.signing_key_path` | Path to relay Ed25519 signing key |
| `AGORA_DB_URL` | `storage.postgres_url` | PostgreSQL connection string including password |
| `AGORA_ADMIN_TOKEN` | (no config equivalent) | Admin API bearer token (see §5.1) |
| `AGORA_BLOB_S3_ACCESS_KEY` | `storage.blob_s3_access_key` | S3-compatible blob store access key |
| `AGORA_BLOB_S3_SECRET_KEY` | `storage.blob_s3_secret_key` | S3-compatible blob store secret key |
| `AGORA_APNS_KEY` | `push_proxy.apns_key_path` | APNs private key path |
| `AGORA_FCM_SERVER_KEY` | `push_proxy.fcm_server_key` | FCM server key |
| `AGORA_LOGGER_KEY_PATH` | `compliance.logger_key_path` | Compliance logger signing key path |

### 3.4 Secrets Management

Secrets management approach depends on deployment environment:

**AWS Secrets Manager:** Store each secret as a separate secret. Use the AWS SDK to fetch secrets at startup. The relay process MUST have an IAM role with `secretsmanager:GetSecretValue` permission for the relevant secret ARNs. Inject secret values as environment variables via the ECS task definition `secrets` field or Kubernetes external-secrets operator.

**HashiCorp Vault:** Use the Vault agent sidecar injector for Kubernetes, or the Vault AWS auth method for ECS. The relay process should not contain Vault credentials; authentication should use the platform identity (EC2 instance profile, Kubernetes service account).

**Kubernetes Secrets:** Acceptable for internal/development deployments. For production, use a secrets operator (External Secrets Operator, Sealed Secrets) that syncs from a trusted secrets store rather than committing plaintext secrets to etcd.

The relay signing key requires special treatment — see §10.1.

---

## 4. Deployment Packaging

### 4.1 Docker

The official relay image follows this structure:

```dockerfile
FROM debian:bookworm-slim AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN useradd -r -s /bin/false -u 1000 agora

# Copy relay binary (statically linked or with bundled deps)
COPY --chown=agora:agora agora-relay /usr/local/bin/agora-relay

# Config and key directories
RUN mkdir -p /etc/agora-relay/keys /var/lib/agora-relay \
    && chown -R agora:agora /etc/agora-relay /var/lib/agora-relay

VOLUME ["/etc/agora-relay", "/var/lib/agora-relay"]

USER agora

EXPOSE 443/udp 443/tcp 9001/udp 9001/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:9099/admin/status || exit 1

ENTRYPOINT ["/usr/local/bin/agora-relay"]
CMD ["--config", "/etc/agora-relay/relay.toml"]
```

**Image tags:** Use digest-pinned references in production. The `:latest` tag MUST NOT be used in production deployments. Use immutable tags of the form `agora-relay:0.2.1` and pin to the image digest in your deployment manifests:

```
ghcr.io/agora-protocol/relay:0.2.1@sha256:<digest>
```

**Volume mounts:**
- `/etc/agora-relay` — config file and TLS certificates (read-only at runtime after startup)
- `/var/lib/agora-relay` — database (SQLite), blob store (if using local backend), compliance log store

### 4.2 Docker Compose: Single-Node Stack

```yaml
# docker-compose.yml — single-node Agora relay stack
version: "3.9"

services:
  relay:
    image: ghcr.io/agora-protocol/relay:0.2.1@sha256:<digest>
    restart: unless-stopped
    ports:
      - "443:443/tcp"
      - "443:443/udp"
      - "9001:9001/udp"
      - "9001:9001/tcp"
    volumes:
      - ./config:/etc/agora-relay:ro
      - relay-data:/var/lib/agora-relay
    environment:
      AGORA_SIGNING_KEY_PATH: /etc/agora-relay/keys/relay-signing.key
      AGORA_DB_URL: "postgresql://agora:${DB_PASSWORD}@postgres:5432/agora"
      AGORA_ADMIN_TOKEN: "${ADMIN_TOKEN}"
    depends_on:
      postgres:
        condition: service_healthy
    networks:
      - relay-internal
      - relay-public

  postgres:
    image: postgres:16-alpine@sha256:<digest>
    restart: unless-stopped
    environment:
      POSTGRES_DB: agora
      POSTGRES_USER: agora
      POSTGRES_PASSWORD: "${DB_PASSWORD}"
    volumes:
      - postgres-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U agora"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - relay-internal

volumes:
  relay-data:
  postgres-data:

networks:
  relay-internal:
    internal: true
  relay-public:
```

The `.env` file MUST NOT be committed to version control. It must contain at minimum:

```
DB_PASSWORD=<strong-random-password>
ADMIN_TOKEN=<strong-random-token>
```

### 4.3 Helm Chart: Kubernetes Deployment

Excerpt of `values.yaml` for the Agora relay Helm chart:

```yaml
# values.yaml

image:
  repository: ghcr.io/agora-protocol/relay
  tag: "0.2.1"
  digest: "sha256:<digest>"
  pullPolicy: IfNotPresent

replicaCount: 2  # For HA; see §15

service:
  type: LoadBalancer
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-type: "nlb"
    service.beta.kubernetes.io/aws-load-balancer-nlb-target-type: "ip"
  ports:
    webtransport:
      port: 443
      protocol: UDP
    websocket:
      port: 443
      protocol: TCP
    peer:
      port: 9001
      protocol: UDP

config:
  hostname: "relay.example.com"
  server:
    tls_acme: true
    tls_acme_email: "relay-admin@example.com"
  storage:
    db_backend: "postgres"
    retention_days: 30
  peering:
    mesh_degree: 6
    bootstrap_peers: []
  logging:
    level: "info"
    format: "json"

secrets:
  # Reference to a Kubernetes Secret containing:
  #   AGORA_SIGNING_KEY_PATH, AGORA_DB_URL, AGORA_ADMIN_TOKEN
  existingSecret: "agora-relay-secrets"

persistence:
  enabled: true
  storageClass: "gp3"
  relayData:
    size: "50Gi"

postgresql:
  enabled: true          # Deploy bundled PostgreSQL; set false to use external
  auth:
    database: agora
    username: agora
    existingSecret: "agora-pg-credentials"
  primary:
    persistence:
      size: "100Gi"
      storageClass: "gp3"

blobStore:
  backend: "local"        # "local" or "s3"
  persistence:
    size: "200Gi"
    storageClass: "gp3"
  # For s3 backend, set blob_s3_* values in relay config and
  # provide credentials via AGORA_BLOB_S3_ACCESS_KEY / AGORA_BLOB_S3_SECRET_KEY.

resources:
  relay:
    requests:
      cpu: "1"
      memory: "2Gi"
    limits:
      cpu: "4"
      memory: "8Gi"

serviceMonitor:
  enabled: true           # Create Prometheus ServiceMonitor
  namespace: "monitoring"

adminIngress:
  enabled: false          # Admin API MUST NOT be exposed externally
```

### 4.4 Terraform: AWS Module Sketch

For AWS deployments, the recommended architecture is ECS Fargate (for simplicity) or EKS (for Kubernetes familiarity). The following sketch covers ECS:

```hcl
# modules/agora-relay/main.tf (sketch — not production-complete)

module "relay_ecs" {
  source = "./ecs-service"

  cluster_arn       = aws_ecs_cluster.agora.arn
  task_cpu          = 2048
  task_memory       = 4096
  image             = "ghcr.io/agora-protocol/relay:0.2.1@sha256:<digest>"

  environment = {
    AGORA_SERVER_HOSTNAME = var.relay_hostname
    AGORA_STORAGE_DB_BACKEND = "postgres"
    AGORA_LOGGING_FORMAT = "json"
    AGORA_LOGGING_LEVEL  = "info"
  }

  secrets = {
    AGORA_DB_URL       = aws_secretsmanager_secret.db_url.arn
    AGORA_ADMIN_TOKEN  = aws_secretsmanager_secret.admin_token.arn
    AGORA_SIGNING_KEY_PATH = "/run/secrets/relay-signing.key"
  }
}

resource "aws_rds_cluster" "agora" {
  cluster_identifier = "agora-relay"
  engine             = "aurora-postgresql"
  engine_version     = "16.1"
  database_name      = "agora"
  master_username    = "agora"
  manage_master_user_password = true

  backup_retention_period = 7
  deletion_protection     = true
}

# S3 bucket for relay blob store (content-addressed storage backend)
resource "aws_s3_bucket" "blob_store" {
  bucket = "agora-relay-blobs-${var.environment}"

  versioning { enabled = true }

  lifecycle_rule {
    enabled = true
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
  }
}

# Network Load Balancer for QUIC (UDP) + TCP
resource "aws_lb" "relay" {
  name               = "agora-relay"
  load_balancer_type = "network"
  internal           = false

  enable_cross_zone_load_balancing = true
}

resource "aws_lb_listener" "quic" {
  load_balancer_arn = aws_lb.relay.arn
  port              = 443
  protocol          = "UDP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.relay_udp.arn
  }
}
```

---

## 5. Relay Admin API

The Relay Admin API is an HTTP API served on the admin listen address (default `127.0.0.1:9099`). It MUST NOT be exposed to the public internet. All endpoints require authentication via a static bearer token (see §5.1).

The Admin API is not part of the Agora protocol. It is an operator interface defined here.

### 5.1 Authentication

All Admin API requests MUST include an `Authorization: Bearer <token>` header. The token is configured via the `AGORA_ADMIN_TOKEN` environment variable. The relay MUST reject any request without a valid token with HTTP 401.

The admin token MUST be a cryptographically random value of at least 32 bytes, base64url-encoded. Generate with:

```bash
openssl rand -base64 32
```

The admin token provides full control over the relay. It MUST be treated as a high-value secret: stored in a secrets manager, rotated via `POST /admin/reload` after updating the environment variable, and never logged.

Every Admin API call is recorded in the relay's audit log (retrievable via `GET /admin/audit`).

### 5.2 Endpoint Reference

#### `GET /admin/status`

Returns full relay status. No request body.

**Response 200:**
```json
{
  "version": "0.2.1",
  "relay_did": "did:key:z6MkRelay...",
  "uptime_seconds": 1209600,
  "started_at": "2026-04-08T00:00:00Z",
  "health": "healthy",
  "peer_count": 8,
  "active_connections": 1247,
  "active_anonymous_connections": 83,
  "message_rate_per_second": 342.7,
  "messages_forwarded_total": 187423901,
  "storage": {
    "db_size_bytes": 42949672960,
    "blob_store_size_bytes": 214748364800,
    "keypackage_count_total": 14832,
    "retention_queue_depth": 29183
  },
  "compliance": {
    "loggers_active": 1,
    "queue_depth": 47,
    "last_flush_at": "2026-04-22T13:59:55Z"
  }
}
```

#### `GET /admin/peers`

Lists all known peers with current trust level, reachability, and traffic statistics.

**Response 200:**
```json
{
  "peers": [
    {
      "relay_did": "did:key:z6MkPeer...",
      "manifest_url": "https://peer.example.net/.well-known/agora-relay",
      "trust_level": 2,
      "reachable": true,
      "last_seen_at": "2026-04-22T14:00:01Z",
      "last_heartbeat_at": "2026-04-22T14:00:01Z",
      "peered_since": "2026-04-01T00:00:00Z",
      "gossip_msg_rate_per_second": 12.4,
      "gossip_msg_total": 9827341,
      "region": "eu-west",
      "capabilities": ["gossipsub-v1.1", "gossipsub-quic-v1", "peer-api-v1"]
    }
  ]
}
```

#### `POST /admin/peers/{did}/trust`

Manually set the trust level for a peer. Trust level 3 is the maximum; level 0 effectively blocks the peer from gossiping (manifest fetch only).

**Request body:**
```json
{
  "trust_level": 3,
  "reason": "same-org relay"
}
```

**Response 200:**
```json
{ "relay_did": "did:key:z6MkPeer...", "trust_level": 3, "updated_at": "2026-04-22T14:00:00Z" }
```

**Response 404:** Peer DID not found in the peer table.

#### `DELETE /admin/peers/{did}`

Remove a peer and add it to the permanent blocklist. This action is irreversible via the API; to unblock, restart the relay with the peer removed from `peering.blocked_peers`.

**Request body:**
```json
{
  "reason": "repeated invalid signatures",
  "confirm": "REMOVE_AND_BLOCK"
}
```

The `confirm` field MUST equal the string `"REMOVE_AND_BLOCK"`. Requests without this field return HTTP 400.

**Response 200:**
```json
{ "relay_did": "did:key:z6MkPeer...", "blocked": true }
```

#### `GET /admin/spaces`

Lists all spaces for which this relay holds at least one blob store entry or cached message envelope.

**Response 200:**
```json
{
  "spaces": [
    {
      "space_cid": "bafyrei...",
      "name": "Acme Engineering",
      "channel_count": 24,
      "member_count_approx": 183,
      "message_count": 9284712,
      "storage_bytes": 1073741824,
      "last_message_at": "2026-04-22T13:59:47Z"
    }
  ]
}
```

`member_count_approx` is an approximation derived from observed DID authentication events; the relay has no authoritative membership list (§11.1).

#### `GET /admin/spaces/{cid}`

Returns detail for a specific space.

**Response 200:**
```json
{
  "space_cid": "bafyrei...",
  "name": "Acme Engineering",
  "channels": [
    {
      "channel_cid": "bafyrei...",
      "name": "general",
      "type": "text",
      "message_count": 1284712,
      "storage_bytes": 134217728,
      "last_message_at": "2026-04-22T13:59:47Z",
      "pinned_cid_count": 12
    }
  ],
  "compliance_logging_enabled": true,
  "retention_days": 2555
}
```

#### `DELETE /admin/spaces/{cid}`

Remove all relay-held data for a space: cached message envelopes, blob store entries for that space's CIDs, and the space's entry in the retention queue.

This is a destructive, irreversible operation. It does not affect data held by other relays.

**Request body:**
```json
{
  "confirm_space_cid": "bafyrei...",
  "reason": "space owner requested removal"
}
```

`confirm_space_cid` MUST exactly match the `{cid}` in the URL. Requests where these do not match return HTTP 400.

**Response 200:**
```json
{
  "space_cid": "bafyrei...",
  "messages_deleted": 9284712,
  "blob_store_entries_removed": 847,
  "completed_at": "2026-04-22T14:01:23Z"
}
```

#### `GET /admin/keypackages`

Returns summary statistics for the KeyPackage store.

**Response 200:**
```json
{
  "total_stored": 14832,
  "by_did": [
    {
      "did": "did:key:z6Mk...",
      "count": 18,
      "oldest_uploaded_at": "2026-04-01T00:00:00Z",
      "expires_soonest_at": "2026-07-01T00:00:00Z"
    }
  ],
  "expiry_distribution": {
    "expired": 0,
    "expires_within_7d": 24,
    "expires_within_30d": 183,
    "expires_after_30d": 14625
  },
  "below_alert_threshold": [
    { "did": "did:key:z6MkAlice...", "count": 3, "threshold": 5 }
  ]
}
```

#### `POST /admin/keypackages/gc`

Trigger an immediate KeyPackage garbage collection pass. Removes expired and revoked KeyPackages without waiting for the scheduled interval.

**Response 200:**
```json
{
  "gc_started_at": "2026-04-22T14:00:00Z",
  "expired_removed": 47,
  "revoked_removed": 2,
  "gc_completed_at": "2026-04-22T14:00:01Z"
}
```

#### `GET /admin/compliance`

Returns compliance logging subsystem status.

**Response 200:**
```json
{
  "loggers": [
    {
      "logger_did": "did:key:z6MkLogger...",
      "logger_label": "Acme Corp Compliance Archive",
      "queue_depth": 47,
      "last_flush_at": "2026-04-22T13:59:55Z",
      "last_flush_latency_ms": 12,
      "flush_failures_total": 0,
      "log_store_size_bytes": 10737418240
    }
  ]
}
```

#### `POST /admin/compliance/flush`

Force an immediate flush of the compliance queue to the IPLD log store. Blocks until the flush completes or times out (30 second timeout).

**Response 200:**
```json
{
  "flushed_records": 47,
  "flush_latency_ms": 89,
  "log_chain_head_cid": "bafyrei..."
}
```

**Response 504:** Flush timed out. Queue may be partially flushed; check `GET /admin/compliance` for current state.

#### `GET /admin/metrics`

Returns a redirect to the Prometheus metrics endpoint.

**Response 302:** `Location: http://127.0.0.1:9100/metrics`

#### `POST /admin/reload`

Reload non-breaking configuration changes without restarting the relay process. Reloadable fields: `peering.bootstrap_peers`, `peering.blocked_peers`, `peering.trusted_peers`, `rate_limits.*`, `logging.level`, `economics.*`. Non-reloadable fields (require restart): `server.*`, `identity.*`, `storage.*`.

**Response 200:**
```json
{
  "reloaded_at": "2026-04-22T14:00:00Z",
  "fields_reloaded": ["peering.blocked_peers", "logging.level"],
  "fields_skipped_require_restart": []
}
```

**Response 400:** If the updated config file contains syntax errors or invalid values, the reload is rejected and the running configuration is unchanged.

#### `GET /admin/audit`

Returns the relay operator audit log: all Admin API calls with timestamp, endpoint, caller IP, and HTTP status code.

**Query parameters:**
- `since` — ISO 8601 datetime; return only entries after this time. Default: 24 hours ago.
- `limit` — maximum entries to return. Default: 1000, maximum: 10000.

**Response 200:**
```json
{
  "entries": [
    {
      "ts": "2026-04-22T14:00:00Z",
      "method": "POST",
      "path": "/admin/peers/did:key:z6MkPeer.../trust",
      "remote_addr": "10.0.1.5",
      "http_status": 200,
      "duration_ms": 3
    }
  ]
}
```

---

## 6. Observability

### 6.1 Prometheus Metrics

The relay MUST expose Prometheus metrics at `GET /metrics` on the metrics listen address (default `127.0.0.1:9100`). The metrics endpoint MUST NOT require authentication. It MUST NOT be publicly reachable.

All metric names are prefixed `agora_relay_`.

#### Connection Metrics

| Metric name | Type | Labels | Description |
|---|---|---|---|
| `agora_relay_connections_active` | Gauge | `transport` (`webtransport`, `websocket`) | Currently active client connections |
| `agora_relay_connections_total` | Counter | `transport` | Total connections accepted since start |
| `agora_relay_connections_rejected_total` | Counter | `reason` (`ban`, `rate_limit`, `tls_error`) | Connections rejected |
| `agora_relay_connection_duration_seconds` | Histogram | `transport` | Connection lifetime in seconds |
| `agora_relay_auth_attempts_total` | Counter | `result` (`success`, `failure`, `expired_nonce`, `invalid_sig`, `banned_did`) | Client authentication attempts |
| `agora_relay_anonymous_connections_active` | Gauge | — | Currently active unauthenticated connections |

Example exposition:
```
# HELP agora_relay_connections_active Currently active client connections
# TYPE agora_relay_connections_active gauge
agora_relay_connections_active{transport="webtransport"} 1103
agora_relay_connections_active{transport="websocket"} 144
```

#### Message Metrics

| Metric name | Type | Labels | Description |
|---|---|---|---|
| `agora_relay_messages_received_total` | Counter | `frame_type` (`gossip`, `mls`, `ephemeral`, `control`) | Messages received from clients |
| `agora_relay_messages_forwarded_total` | Counter | `frame_type` | Messages forwarded to subscribers |
| `agora_relay_messages_dropped_total` | Counter | `reason` (`rate_limit`, `malformed`, `unknown_token`, `expired`) | Messages dropped without forwarding |
| `agora_relay_message_bytes_received_total` | Counter | — | Total bytes received in message frames |
| `agora_relay_message_bytes_forwarded_total` | Counter | — | Total bytes forwarded in message frames |
| `agora_relay_channel_token_active` | Gauge | — | Number of distinct channelTokens with active subscribers |
| `agora_relay_message_retention_queue_depth` | Gauge | — | Number of cached envelopes pending retention GC |

#### MLS Metrics

| Metric name | Type | Labels | Description |
|---|---|---|---|
| `agora_relay_mls_keypackages_stored` | Gauge | — | Total KeyPackages currently in store |
| `agora_relay_mls_keypackages_stored_by_did` | Gauge | `did` | KeyPackages stored per DID (label cardinality: cap at top-100 DIDs) |
| `agora_relay_mls_keypackages_consumed_total` | Counter | — | KeyPackages atomically consumed via GET |
| `agora_relay_mls_keypackages_uploaded_total` | Counter | — | KeyPackages uploaded via PUT |
| `agora_relay_mls_keypackages_expired_total` | Counter | — | KeyPackages removed by GC as expired |
| `agora_relay_mls_keypackages_low_alert_total` | Counter | — | KeyPackageLowAlert events emitted |
| `agora_relay_mls_welcome_messages_total` | Counter | — | MLS Welcome messages forwarded |
| `agora_relay_mls_commit_messages_total` | Counter | — | MLS Commit messages forwarded |
| `agora_relay_mls_proposal_messages_total` | Counter | — | MLS Proposal messages forwarded |
| `agora_relay_mls_validation_failures_total` | Counter | `reason` (`outer_format`, `token_format`) | Outer envelope validation failures (relay cannot validate inner MLS) |

#### JMAP Metrics

| Metric name | Type | Labels | Description |
|---|---|---|---|
| `agora_relay_jmap_requests_total` | Counter | `method` | JMAP method calls by method name |
| `agora_relay_jmap_request_duration_seconds` | Histogram | `method` | JMAP request latency; expose p50/p95/p99 |
| `agora_relay_jmap_errors_total` | Counter | `method`, `error_type` | JMAP errors by method and error type |
| `agora_relay_jmap_sessions_active` | Gauge | — | Currently active JMAP bearer tokens |
| `agora_relay_jmap_eventsource_connections_active` | Gauge | — | Active EventSource push connections |

Histogram buckets for `agora_relay_jmap_request_duration_seconds`: `0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0`.

#### Peer Mesh Metrics

| Metric name | Type | Labels | Description |
|---|---|---|---|
| `agora_relay_peer_count` | Gauge | `trust_level` (`0`, `1`, `2`, `3`) | Known peers by trust level |
| `agora_relay_peer_reachable` | Gauge | `trust_level` | Reachable peers by trust level |
| `agora_relay_gossip_messages_received_total` | Counter | — | Gossip messages received from peer relays |
| `agora_relay_gossip_messages_sent_total` | Counter | — | Gossip messages sent to peer relays |
| `agora_relay_peer_heartbeat_failures_total` | Counter | — | Heartbeat check failures across all peers |
| `agora_relay_peer_manifest_refresh_failures_total` | Counter | — | Peer manifest fetch failures |
| `agora_relay_peer_trust_downgrades_total` | Counter | `reason` (`invalid_sig`, `malformed_gossip`, `rate_exceeded`) | Peer trust level downgrades |

#### Storage Metrics

| Metric name | Type | Labels | Description |
|---|---|---|---|
| `agora_relay_db_size_bytes` | Gauge | — | Database file/tablespace size in bytes |
| `agora_relay_blob_store_size_bytes` | Gauge | — | Blob store size in bytes |
| `agora_relay_blob_store_cid_count` | Gauge | — | Number of CIDs held in the blob store |
| `agora_relay_storage_retention_gc_duration_seconds` | Histogram | — | Time taken per retention GC pass |
| `agora_relay_storage_retention_deleted_total` | Counter | — | Message envelopes deleted by retention GC |

#### Compliance Metrics

| Metric name | Type | Labels | Description |
|---|---|---|---|
| `agora_relay_compliance_queue_depth` | Gauge | `logger_did` | Compliance queue depth per logger |
| `agora_relay_compliance_flush_latency_seconds` | Histogram | `logger_did` | Compliance flush latency |
| `agora_relay_compliance_flush_failures_total` | Counter | `logger_did` | Failed compliance flushes |
| `agora_relay_compliance_records_total` | Counter | `logger_did` | Compliance records written |

#### Economic Metrics

| Metric name | Type | Labels | Description |
|---|---|---|---|
| `agora_relay_payment_verifications_total` | Counter | `scheme` (`mob`, `cashu`, `bolt12`), `result` (`accepted`, `rejected`) | Payment verification results |
| `agora_relay_pow_verifications_total` | Counter | `result` (`accepted`, `rejected`) | PoW verification results |
| `agora_relay_rate_limited_requests_total` | Counter | `type` (`channel`, `connection`) | Requests rejected by rate limiter |

### 6.2 Log Format

The relay MUST emit structured JSON logs when `logging.format = "json"`. Each log line is a single JSON object. Fields:

| Field | Type | Always present | Description |
|---|---|---|---|
| `ts` | ISO 8601 string | Yes | Event timestamp with millisecond precision |
| `level` | string | Yes | `error`, `warn`, `info`, `debug`, `trace` |
| `component` | string | Yes | Internal component: `transport`, `peer`, `jmap`, `keypackage`, `compliance`, `admin`, `gossip` |
| `event` | string | Yes | Short machine-readable event name (see below) |
| `msg` | string | Yes | Human-readable description |
| `duration_ms` | number | No | Duration of the operation in milliseconds |
| `peer_did` | string | No | Peer relay DID involved in this event |
| `space_cid` | string | No | Space CID involved in this event |
| `error` | string | No | Error message for `level=error` or `level=warn` events |
| `remote_addr` | string | No | Client IP address (omit for privacy-sensitive paths) |
| `trace_id` | string | No | Request trace ID for correlation |

Example log line:
```json
{"ts":"2026-04-22T14:00:01.234Z","level":"info","component":"transport","event":"client_auth_success","msg":"Client authenticated","duration_ms":3,"trace_id":"abc123"}
```

**Log levels and what goes at each level:**

- `error` — conditions that require operator attention: failed TLS handshake, database write failure, compliance flush failure, blob store write failure.
- `warn` — conditions that are notable but not immediately actionable: peer heartbeat miss (first occurrence), KeyPackage count below alert threshold, rate limit triggered for the first time on a channelToken.
- `info` — normal operational events: relay startup and shutdown, peer connect/disconnect, TLS cert renewal, GC completed, config reload.
- `debug` — per-request events useful for troubleshooting: individual auth handshakes, JMAP method calls, gossip message receipt/forward, KeyPackage operations.
- `trace` — verbose internal state: frame parsing, gossipsub scoring events, blob store write operations. Not for production use.

**Relay blindness in logs:** Logs MUST NOT record sender DIDs for message events (the relay does not have them — §11.1). Logs MUST NOT record channel CIDs or space CIDs in message routing paths. The `space_cid` field is only used in administrative events (space state updates, pin events) where the CID is already part of the public gossip message.

---

## 7. Alerting

The following alert rules MUST be configured for any production relay deployment. Rules are expressed in Prometheus alerting rule format.

```yaml
# agora-relay-alerts.yaml
groups:
  - name: agora_relay
    rules:

    # ── Availability ──────────────────────────────────────────────────────

    - alert: AgoraRelayDown
      expr: up{job="agora-relay"} == 0
      for: 1m
      labels:
        severity: critical
        team: infra
      annotations:
        summary: "Agora relay is down"
        description: >
          Relay {{ $labels.instance }} has been unreachable for over 1 minute.
          Clients cannot connect. Check process health and logs.

    - alert: AgoraRelayHealthDegraded
      expr: >
        agora_relay_connections_active{transport="webtransport"}
        + agora_relay_connections_active{transport="websocket"} == 0
        and up{job="agora-relay"} == 1
      for: 5m
      labels:
        severity: warning
        team: infra
      annotations:
        summary: "Agora relay has no active client connections"
        description: >
          Relay is up but has accepted no client connections for 5 minutes.
          Possible network, TLS, or routing issue.

    # ── Peer Mesh ─────────────────────────────────────────────────────────

    - alert: AgoraPeerMeshDegraded
      expr: sum(agora_relay_peer_reachable) < 3
      for: 10m
      labels:
        severity: warning
        team: infra
      annotations:
        summary: "Agora peer mesh degraded"
        description: >
          Relay has fewer than 3 reachable peers for over 10 minutes.
          Message fanout and space state gossip may be impaired.
          Current reachable peers: {{ $value }}

    - alert: AgoraPeerMeshCritical
      expr: sum(agora_relay_peer_reachable) == 0
      for: 5m
      labels:
        severity: critical
        team: infra
      annotations:
        summary: "Agora relay is isolated from peer mesh"
        description: >
          Relay has zero reachable peers. It is isolated from the gossipsub mesh.
          New space state and cross-relay messages are not being received.

    # ── KeyPackage Store ──────────────────────────────────────────────────

    - alert: AgoraKeyPackageExhaustion
      expr: >
        agora_relay_mls_keypackages_stored_by_did < 5
      for: 15m
      labels:
        severity: warning
        team: infra
      annotations:
        summary: "KeyPackage store critically low for DID {{ $labels.did }}"
        description: >
          DID {{ $labels.did }} has fewer than 5 KeyPackages remaining.
          Senders will not be able to add this user to new MLS groups.
          Alert threshold is 5; current count: {{ $value }}

    # ── Compliance ────────────────────────────────────────────────────────

    - alert: AgoraComplianceFlushFailure
      expr: increase(agora_relay_compliance_flush_failures_total[10m]) > 0
      labels:
        severity: critical
        team: compliance
      annotations:
        summary: "Compliance log flush failure"
        description: >
          Compliance logger {{ $labels.logger_did }} has experienced flush
          failures in the last 10 minutes. Messages may be missing from the
          compliance archive. Immediate investigation required.

    - alert: AgoraComplianceQueueDepthHigh
      expr: agora_relay_compliance_queue_depth > 10000
      for: 5m
      labels:
        severity: warning
        team: compliance
      annotations:
        summary: "Compliance queue depth elevated"
        description: >
          Compliance logger {{ $labels.logger_did }} queue depth is {{ $value }}.
          This may indicate a slow log store or high message volume.

    # ── Storage ───────────────────────────────────────────────────────────

    - alert: AgoraDatabaseStorageHigh
      expr: >
        agora_relay_db_size_bytes / (1024^3)
        > (node_filesystem_size_bytes{mountpoint="/var/lib/agora-relay"}
           / (1024^3)) * 0.80
      for: 30m
      labels:
        severity: warning
        team: infra
      annotations:
        summary: "Agora relay database storage above 80% capacity"
        description: >
          The relay database is using more than 80% of available storage.
          Consider increasing storage allocation or adjusting retention_days.

    - alert: AgoraBlobStoreStorageHigh
      expr: >
        agora_relay_blob_store_size_bytes
        > 200 * (1024^3)
      for: 1h
      labels:
        severity: warning
        team: infra
      annotations:
        summary: "Blob store exceeds 200 GB"
        description: >
          Blob store is {{ $value | humanize1024 }}B. Review retention policy and
          consider switching to an S3-compatible backend for archival.

    # ── Security / Anomaly ────────────────────────────────────────────────

    - alert: AgoraAuthFailureSpike
      expr: >
        rate(agora_relay_auth_attempts_total{result=~"failure|invalid_sig|banned_did"}[5m]) > 10
      for: 2m
      labels:
        severity: warning
        team: security
      annotations:
        summary: "Elevated authentication failure rate"
        description: >
          Authentication failures are occurring at {{ $value | humanizePercentage }} per second.
          This may indicate a credential-stuffing or DDoS attack.
          Threshold: 10/s sustained for 2 minutes.

    - alert: AgoraMlsValidationFailureSpike
      expr: rate(agora_relay_mls_validation_failures_total[5m]) > 5
      for: 2m
      labels:
        severity: warning
        team: security
      annotations:
        summary: "Elevated MLS envelope validation failures"
        description: >
          MLS outer envelope validation failures at {{ $value }}/s for 2 minutes.
          May indicate malformed clients or an active protocol attack.

    - alert: AgoraAdminAPIAccessed
      expr: increase(agora_relay_admin_api_requests_total[1m]) > 0
      labels:
        severity: info
        team: security
      annotations:
        summary: "Admin API accessed"
        description: >
          The relay Admin API was accessed. This alert fires on every access
          as an audit trigger. Review /admin/audit for details.
```

---

## 8. Backup and Restore

### 8.1 What Must Be Backed Up

| Item | Criticality | Notes |
|---|---|---|
| Relay signing key | **CRITICAL** | If lost, the relay DID is permanently lost. All peer relationships must be re-established from scratch with a new DID. |
| Database | High | Message store, KeyPackage store, peer table, session state, compliance queue. |
| Blob store | High | Space state documents and message history for served spaces. Content is content-addressed; deduplication is automatic. Back up the full blob store directory (local backend) or ensure S3 bucket versioning is enabled (S3 backend). |
| Config file | Medium | Reconstructible, but restoring it avoids reconfiguring from scratch. |
| TLS private key | Medium | Loss requires certificate reissuance (fast with ACME, but causes a brief outage). |
| Compliance log store | High (if operating compliance logger) | IPLD chain heads and local log files. |

### 8.2 Relay Signing Key Backup

The relay signing key MUST be backed up before the relay is first deployed. There is no recovery path if it is lost. Key backup procedure:

1. Generate the key using the relay CLI:
   ```bash
   agora-relay keygen --output /etc/agora-relay/keys/relay-signing.key
   ```
   This generates an Ed25519 private key in PEM format.

2. Encrypt the key with a strong passphrase before backup:
   ```bash
   openssl enc -aes-256-cbc -pbkdf2 -in relay-signing.key \
       -out relay-signing.key.enc
   ```

3. Store the encrypted key in at minimum two physically separate locations:
   - Primary: your secrets manager (AWS Secrets Manager, HashiCorp Vault) as a binary secret.
   - Secondary: offline, air-gapped storage (encrypted USB, HSM backup key, printed QR code in a physical safe).

4. Record the relay DID in your CMDB. The DID is derived from the public key and cannot be reconstructed without it.

5. Test the backup by decrypting the backup copy and verifying the DID:
   ```bash
   openssl enc -d -aes-256-cbc -pbkdf2 -in relay-signing.key.enc \
       -out relay-signing.key.restored
   agora-relay did-from-key --key relay-signing.key.restored
   # Output must match the relay DID in your config.
   ```

### 8.3 Database Backup

**PostgreSQL:**

Use `pg_dump` for logical backups or continuous WAL archiving for point-in-time recovery:

```bash
# Daily logical backup (run from a backup host or as a cron job)
pg_dump -h $POSTGRES_HOST -U agora -d agora -Fc \
    -f /backup/agora-relay-$(date +%Y%m%d).dump

# Verify backup integrity
pg_restore --list /backup/agora-relay-$(date +%Y%m%d).dump > /dev/null
echo "Backup exit code: $?"

# Retain 30 days of logical backups
find /backup -name "agora-relay-*.dump" -mtime +30 -delete
```

For production, enable WAL archiving to S3 with `wal_level = replica` and `archive_mode = on`. Use `pgBackRest` or `barman` for managed WAL archiving.

**SQLite** (single-node only):

```bash
# Use SQLite's online backup API — never copy the .db file while the relay is running
sqlite3 /var/lib/agora-relay/relay.db ".backup /backup/relay-$(date +%Y%m%d).db"
```

**RPO/RTO guidance:**
- RPO (Recovery Point Objective): 1 hour maximum. WAL archiving provides near-zero RPO.
- RTO (Recovery Time Objective): 30 minutes for a warm standby (§15), 2 hours for a cold restore from backup.

### 8.4 Blob Store Backup

**Local backend (`blob_backend = "local"`):**

The blob store directory is a flat content-addressed filesystem. Back it up with any standard tool:

```bash
# Incremental rsync to a backup destination
rsync -av --checksum /var/lib/agora-relay/blobs/ \
    backup-host:/backup/agora-blobs/

# Or archive to a tarball
tar -czf /backup/agora-blobs-$(date +%Y%m%d).tar.gz \
    -C /var/lib/agora-relay blobs/
```

Because blobs are content-addressed, incremental backups are efficient — unchanged blobs have unchanged filenames and rsync skips them automatically.

**S3 backend (`blob_backend = "s3"`):**

Enable S3 bucket versioning and cross-region replication in your S3 provider. No additional backup tooling is required; the object store is the durable store. Verify versioning is enabled:

```bash
aws s3api get-bucket-versioning --bucket agora-relay-blobs-prod
# Expected: { "Status": "Enabled" }
```

### 8.5 Database Restore Procedure

1. Stop the relay process:
   ```bash
   systemctl stop agora-relay
   # or: docker compose stop relay
   ```

2. Restore the database:
   ```bash
   # PostgreSQL
   createdb -h $POSTGRES_HOST -U postgres agora_restored
   pg_restore -h $POSTGRES_HOST -U postgres -d agora_restored \
       /backup/agora-relay-20260422.dump

   # Verify row counts
   psql -h $POSTGRES_HOST -U agora -d agora_restored \
       -c "SELECT relname, n_live_tup FROM pg_stat_user_tables ORDER BY n_live_tup DESC;"
   ```

3. Update the config to point at the restored database (if database name changed).

4. Restart the relay:
   ```bash
   systemctl start agora-relay
   ```

5. Verify recovery via the Admin API:
   ```bash
   curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
       http://localhost:9099/admin/status | jq .
   ```

6. Check that peer connections are re-established within 5 minutes. If not, check `GET /admin/peers` for peer reachability.

---

## 9. Upgrade Procedure

### 9.1 Pre-Upgrade Checklist

Before upgrading any relay component:

- [ ] Read the release notes for the new version. Identify breaking vs non-breaking changes (§9.6).
- [ ] Verify the new image digest matches the published digest in the release notes.
- [ ] Back up the database (§8.3).
- [ ] Note the current relay version: `curl -s -H "Authorization: Bearer $ADMIN_TOKEN" localhost:9099/admin/status | jq .version`
- [ ] Verify peer count is at expected baseline: `curl -s -H "Authorization: Bearer $ADMIN_TOKEN" localhost:9099/admin/peers | jq '.peers | length'`
- [ ] Check compliance queue depth is near zero: `curl -s -H "Authorization: Bearer $ADMIN_TOKEN" localhost:9099/admin/compliance | jq '.loggers[].queue_depth'`
- [ ] Flush compliance queue if depth > 0: `curl -s -X POST -H "Authorization: Bearer $ADMIN_TOKEN" localhost:9099/admin/compliance/flush`
- [ ] Confirm a rollback path exists (rollback image tag and database rollback script if schema changes are involved).

### 9.2 Single-Node Upgrade

For a single-node deployment, the upgrade procedure is a rolling restart with minimal downtime (typically under 30 seconds, limited by QUIC connection migration):

```bash
# 1. Pull the new image
docker pull ghcr.io/agora-protocol/relay:0.2.2@sha256:<new-digest>

# 2. Update the image tag in docker-compose.yml or your deployment config

# 3. Run database migrations before starting the new relay version
docker run --rm \
    -e AGORA_DB_URL=$AGORA_DB_URL \
    ghcr.io/agora-protocol/relay:0.2.2@sha256:<new-digest> \
    migrate --up

# 4. Perform a graceful reload (zero-downtime for non-breaking upgrades)
docker compose up -d --no-deps relay

# 5. Verify the new version is running
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" localhost:9099/admin/status | jq .version
# Should return "0.2.2"

# 6. Verify peer connections recovered
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" localhost:9099/admin/peers | jq '[.peers[] | select(.reachable == true)] | length'
```

### 9.3 Multi-Node Rolling Upgrade

For multi-node HA deployments (§15), upgrade one node at a time:

1. Remove one relay node from the load balancer target group (mark as unhealthy or detach).
2. Wait for in-flight WebTransport/WebSocket connections to drain. Clients will reconnect to surviving nodes. Allow 60 seconds for drain.
3. Run database migrations on the removed node (safe: migrations must be backward-compatible, see §9.5).
4. Upgrade the node to the new image.
5. Restart the node and verify it connects to peers and passes health checks.
6. Return the node to the load balancer.
7. Repeat for remaining nodes.

Never upgrade all nodes simultaneously. At minimum, keep one node on the old version until the first upgraded node has been verified healthy.

### 9.4 Database Migration Procedure

Database migrations are managed by the relay binary's built-in migration tool:

```bash
# Check pending migrations
agora-relay migrate --status

# Apply pending migrations (run before starting the new relay version)
agora-relay migrate --up

# Rollback the last migration (only if the upgrade is being aborted)
agora-relay migrate --down --steps 1
```

Migrations are versioned and tracked in the `schema_migrations` table. All migrations must be:
- **Backward-compatible for one version**: a migration that adds a column must have a default value so the old relay binary can continue to read the table. Dropping columns requires a two-version process (deprecate in v0.2, remove in v0.3).
- **Idempotent**: running the same migration twice MUST produce the same result.

### 9.5 Post-Upgrade Verification

After upgrading:

1. Confirm version: `GET /admin/status` returns the expected version string.
2. Confirm peer mesh: `GET /admin/peers` shows expected peer count and all previously reachable peers are still reachable.
3. Confirm auth is working: attempt a client connection (or use a test client CLI).
4. Confirm JMAP: `curl -s https://<relay-hostname>/.well-known/jmap` returns a valid session object.
5. Confirm metrics: check the Prometheus dashboard for any anomalous spikes.
6. If operating compliance logging: confirm `GET /admin/compliance` shows all loggers active and queue depth is not growing unexpectedly.

### 9.6 Breaking vs Non-Breaking Changes

A relay upgrade is **non-breaking** if:
- It adds new optional config fields or Admin API endpoints.
- It adds new optional capabilities to the relay manifest.
- Database migrations only add columns with defaults (backward-compatible).
- The protocol spec version is unchanged.

A relay upgrade is **breaking** if:
- It changes the wire format of any protocol message.
- It removes or renames config fields that were previously set.
- Database migrations drop or rename columns.
- The relay manifest declares a new required capability that peer relays must support.
- The protocol spec version incremented on any transport surface.

Breaking changes MUST be called out explicitly in release notes and MUST NOT be deployed via rolling upgrade without coordination across all relay nodes serving the same spaces.

### 9.7 Rollback Procedure

If a post-upgrade verification fails:

1. Stop the new relay version.
2. If a database migration was applied, roll it back:
   ```bash
   agora-relay migrate --down --steps 1
   ```
3. Start the previous relay version.
4. Verify the relay is healthy via `GET /admin/status`.
5. File an incident report documenting what failed and why.

---

## 10. Key Management

### 10.1 Relay Signing Key

The relay signing key is an Ed25519 private key. It is the cryptographic identity of the relay. The relay DID is derived from this key. Every relay manifest and every relay-to-relay authentication request is signed with it.

**Generation:**
```bash
agora-relay keygen --output /etc/agora-relay/keys/relay-signing.key
# This produces a PEM-encoded Ed25519 private key.
# The corresponding relay DID is printed to stdout.
```

**File permissions:** The key file MUST have permissions `0600` and be owned by the relay process user. Any other permissions MUST be rejected at startup.

**HSM storage (recommended for production):** Store the key in a hardware security module or cloud HSM. Options:

| Option | Notes |
|---|---|
| PKCS#11 + SoftHSM2 | Development/testing only. Software HSM; no hardware protection. |
| PKCS#11 + YubiHSM 2 | Affordable hardware HSM. Supports Ed25519. Network-attached or USB. |
| AWS CloudHSM | FIPS 140-2 Level 3. ~$1.60/hour. Use PKCS#11 or JCE provider. |
| GCP Cloud HSM | FIPS 140-2 Level 3. Use via Cloud KMS API. |
| Azure Dedicated HSM | FIPS 140-2 Level 3. Use PKCS#11 provider. |
| TPM 2.0 | Available on most server hardware. Ed25519 support varies by TPM firmware. |

Configure PKCS#11 in the relay config:
```toml
[identity]
pkcs11_provider = "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"
signing_key_path = "label=agora-relay-signing"
```

**Key rotation (planned):**

Key rotation uses the overlap window mechanism defined in §3.5.6. The relay MUST publish both the old and new keys in its manifest with a minimum 48-hour overlap:

1. Generate a new signing key:
   ```bash
   agora-relay keygen --output /etc/agora-relay/keys/relay-signing-new.key
   ```

2. Update the relay config to reference the new key as `signing_key_path`, and add the old key as `signing_key_deprecated_path`.

3. Reload the config:
   ```bash
   curl -s -X POST -H "Authorization: Bearer $ADMIN_TOKEN" localhost:9099/admin/reload
   ```
   The relay immediately publishes a new manifest with both keys listed: the new key with `"status": "active"` and the old key with `"status": "deprecated"`.

4. Wait the full 48-hour overlap window. During this period, peer relays accept signatures from either key.

5. After 48 hours, remove the deprecated key from the config and reload again. The relay publishes a manifest with only the new active key.

**Emergency key rotation:** If the signing key is believed compromised, rotate immediately without the overlap window. Accept that some peer relays will temporarily reject requests until their manifest caches expire (up to 1 hour). Send a `POST /admin/peers/{did}/trust` to 0 for any peers that need immediate notification.

### 10.2 TLS Certificates

**Let's Encrypt (recommended):** Set `tls_acme = true` in the config. The relay handles ACME certificate negotiation, renewal, and reload automatically. No operator action is required for normal renewals.

**Manual certificate management:**
```bash
# Renew a certificate using certbot
certbot renew --cert-name relay.example.com

# After renewal, reload the relay to pick up the new cert
curl -s -X POST -H "Authorization: Bearer $ADMIN_TOKEN" localhost:9099/admin/reload
```

TLS certificates do not need the relay DID rotation procedure. They are independent of the relay's protocol identity.

### 10.3 Admin API Token

Generate a new token:
```bash
openssl rand -base64 32
```

Rotation procedure:
1. Generate a new token.
2. Update `AGORA_ADMIN_TOKEN` in your secrets manager.
3. Restart the relay (the admin token cannot be reloaded live — it would create a TOCTOU window).

### 10.4 Compliance Logger Signing Key

If the relay operates its own compliance logger (`operate_logger = true`), the logger signing key MUST be a separate Ed25519 key, distinct from the relay signing key. The logger key signs `ComplianceRecord` entries in the IPLD chain (§17.4). It MUST be backed up with the same rigor as the relay signing key — loss of the logger key invalidates the compliance archive's integrity chain.

Generate and manage the logger key the same way as the relay signing key (§10.1), storing it at the path configured in `compliance.logger_key_path` (or `AGORA_LOGGER_KEY_PATH`).

---

## 11. Network Requirements

### 11.1 Required Open Ports

| Port | Protocol | Direction | Purpose | Access |
|---|---|---|---|---|
| 443 | UDP (QUIC) | Inbound | WebTransport (primary client transport) | Public internet |
| 443 | TCP (TLS) | Inbound | WebSocket (fallback client transport), JMAP API, `/.well-known/agora-relay` | Public internet |
| 9001 | UDP (QUIC) | Inbound + Outbound | Gossipsub QUIC (peer relay mesh) | Peer relay IPs |
| 9001 | TCP (TLS) | Inbound + Outbound | Gossipsub TCP fallback, Peer API HTTP/3 fallback | Peer relay IPs |
| 9099 | TCP | Inbound | Admin API | Internal only (loopback or management VLAN) |
| 9100 | TCP | Inbound | Prometheus metrics scrape | Internal only (monitoring system) |

### 11.2 Required DNS Records

```dns
; A/AAAA records for the relay hostname
relay.example.com.      IN  A      203.0.113.1
relay.example.com.      IN  AAAA   2001:db8::1

; SRV records for DNS-SD discovery (§3.5.5, Method 3)
; QUIC (preferred, lower priority number = higher preference)
_agora-relay._udp.example.com.  IN  SRV  10 0 9001  relay.example.com.
; TCP fallback
_agora-relay._tcp.example.com.  IN  SRV  20 0 443   relay.example.com.

; TXT record with relay DID and manifest URL
_agora.relay.example.com.  IN  TXT  "did=did:key:z6MkRelay... manifest=https://relay.example.com/.well-known/agora-relay"

; Optional: separate subdomain for push proxy
push.relay.example.com.  IN  A  203.0.113.1
```

The `_agora-relay._udp` record MUST be published if the relay supports QUIC peer connections. Relays that cannot expose UDP MUST publish only the `_agora-relay._tcp` record and MUST omit `gossipsub-quic-v1` from their manifest capabilities.

### 11.3 Firewall Rules

**Public interface (internet-facing):**
- ALLOW UDP 443 from anywhere (WebTransport)
- ALLOW TCP 443 from anywhere (WebSocket, JMAP, well-known)
- ALLOW UDP 9001 from peer relay CIDR ranges (or from anywhere, if operating a permissionless public relay)
- ALLOW TCP 9001 from peer relay CIDR ranges
- DENY all other inbound

**Management interface (internal):**
- ALLOW TCP 9099 from monitoring/ops CIDR only (Admin API)
- ALLOW TCP 9100 from Prometheus scrape CIDR only (metrics)
- DENY all other inbound on management interface

**Blob store (S3 backend only):**
- ALLOW TCP 443 outbound to S3-compatible endpoint (blob store API)
- No additional inbound ports required; the local blob store serves via the relay process on existing ports

### 11.4 Load Balancer Considerations

WebTransport (QUIC) connections are stateful — a client maintains a QUIC connection to a specific relay instance. Standard round-robin load balancing breaks QUIC connections by routing packets to different backends.

**QUIC load balancing requirements:**
- Use a Network Load Balancer (Layer 4) with UDP support, not an Application Load Balancer (which does not support QUIC for WebTransport).
- Configure the NLB with **connection tracking** so that UDP flows from the same source IP:port are consistently forwarded to the same backend. AWS NLB does this automatically for UDP.
- For Kubernetes, use a Service of type `LoadBalancer` with `externalTrafficPolicy: Local` to prevent SNAT from breaking connection tracking.

**WebSocket sticky sessions:**
WebSocket connections are long-lived TCP connections. Any TLS-terminating load balancer MAY be used, but MUST be configured for **sticky sessions** (source IP or cookie-based affinity). Without sticky sessions, WebSocket upgrade attempts may be routed to a different backend than the original HTTP request.

### 11.5 Tor Hidden Service (Optional)

To expose the relay as a Tor v3 hidden service:

1. Install and configure Tor:
   ```
   # /etc/tor/torrc additions
   HiddenServiceDir /var/lib/tor/agora-relay/
   HiddenServicePort 80 127.0.0.1:443
   HiddenServiceVersion 3
   ```

2. Start Tor. The `.onion` address is in `/var/lib/tor/agora-relay/hostname`.

3. Configure the relay with `tor_enabled = true` and the control port address.

4. The relay will publish the `.onion` address in its manifest under `endpoints.onion` as `ws://examplerelay3xyz.onion/v1/agora/ws`.

The `.onion` key file at `/var/lib/tor/agora-relay/hs_ed25519_secret_key` MUST be backed up with the same rigor as the relay signing key. If lost, the hidden service address changes permanently.

---

## 12. Capacity Planning

### 12.1 Storage

**Message store (database):** Each cached message envelope is approximately 2–10 KB (MLS ciphertext plus routing envelope overhead). For a typical text message:

- Average encrypted message size: ~2 KB (short messages) to ~8 KB (rich text + reactions)
- MLS overhead per message: ~200 bytes (outer envelope fields)
- Effective planning estimate: **4 KB per message**

Storage growth formula:
```
daily_storage_growth_GB = active_users × messages_per_user_per_day × 4KB / (1024^3)
```

For 500 active users sending 50 messages/day each:
```
500 × 50 × 4096 = 102,400,000 bytes ≈ 98 MB/day
```

At 30-day retention: ~2.9 GB. At 90-day retention: ~8.8 GB. At 2555-day (7-year compliance) retention: ~250 GB.

**Blob store:** Space state documents are small (tens of KB). Message history blobs are content-addressed and deduplicated automatically. Plan for:
- Space state + channel history index: ~100 MB per active space
- Message content blobs: same as database storage (no additional overhead beyond the blob store directory structure)

**KeyPackage store:** Each KeyPackage is approximately 1–2 KB. With 20 KeyPackages per user per device, and an average of 2 devices per user:
```
500 users × 2 devices × 20 KPs × 1.5 KB = 30 MB
```
This is negligible.

### 12.2 Memory

| Component | Memory estimate |
|---|---|
| Base relay process | ~100 MB |
| Per active WebTransport connection | ~200 KB (QUIC state, session token, per-connection buffers) |
| Per active WebSocket connection | ~50 KB |
| Per active MLS group in memory (gossipsub routing table) | ~10 KB |
| DID document cache (1-hour TTL) | ~2 KB per cached DID |
| Peer manifest cache | ~10 KB per cached manifest |
| JMAP session cache | ~5 KB per active JMAP session |

For 1,000 active WebTransport connections and 200 WebSocket connections:
```
100 MB base
+ 1000 × 200 KB = 200 MB
+ 200 × 50 KB  = 10 MB
≈ 310 MB minimum
```

Plan for 2× headroom: **2 GB RAM** for up to 1,000 concurrent connections. Scale to 8 GB for up to 5,000 connections.

### 12.3 CPU

| Operation | CPU cost |
|---|---|
| Ed25519 signature verification (per client auth) | ~0.1 ms |
| Outer envelope validation (per message) | ~0.05 ms |
| PoW verification, difficulty 18 | ~0.01 ms (SHA-256 verification) |
| MOB payment proof verification | ~5 ms |
| JMAP history query (50 messages) | ~2–10 ms (database query + serialization) |
| Gossipsub message routing | ~0.1 ms per subscriber |

Message fan-out is the dominant CPU workload. For 500 active users in 50 active channels with average 10 subscribers per channel:
- 50 messages/second total × 10 subscribers × 0.05 ms routing = 25 ms CPU/second (~2.5%)

TLS is offloaded by the kernel or hardware in modern Linux systems and is not a significant CPU consumer.

**Baseline recommendation:** 2 vCPU for up to 1,000 concurrent connections, 4 vCPU for up to 5,000. Gossipsub fanout scales linearly with subscriber count; scale horizontally before vertically when fanout is the bottleneck.

### 12.4 Network Bandwidth

| Direction | Estimate |
|---|---|
| Per active user ingress | ~5–20 KB/s (sending messages) |
| Per active user egress | ~20–100 KB/s (receiving from subscribed channels) |
| Gossipsub peer mesh | ~100–500 KB/s per peer at mesh degree 6 |
| Blob store (S3 backend) | ~1–10 MB/s during active CID fetches from S3 |

For 500 active users:
- Client traffic: 500 × 100 KB/s = 50 MB/s peak egress
- Peer mesh: 6 peers × 500 KB/s = 3 MB/s
- Total estimated peak: ~55 MB/s ≈ 440 Mbps

A 1 Gbps uplink is sufficient for up to ~1,000 concurrent active users. For larger deployments, scale horizontally.

### 12.5 Vertical vs Horizontal Scaling

Scale **vertically** (larger instance) when:
- CPU is the bottleneck (per-message processing, PoW verification at high volume).
- Single-node latency is acceptable and operational complexity matters more than raw capacity.

Scale **horizontally** (add relay nodes, see §15) when:
- Connection count exceeds ~5,000 (QUIC connection table becomes a bottleneck).
- Network bandwidth approaches 1 Gbps.
- Geographic diversity is needed (deploy in multiple regions).
- HA without a maintenance window is required.

---

## 13. Security Hardening

### 13.1 TLS Configuration

The relay MUST be configured with the following TLS parameters:

```toml
[server]
tls_min_version = "1.3"
```

TLS 1.2 is permitted only for WebSocket connections to accommodate legacy clients; WebTransport (QUIC) requires TLS 1.3 by protocol definition.

For TLS 1.3, cipher suites are not configurable (the protocol mandates a fixed set). For TLS 1.2 fallback (WebSocket only), the relay MUST NOT negotiate:
- `TLS_RSA_*` (no forward secrecy)
- `*_RC4_*` (broken cipher)
- `*_3DES_*` (broken cipher)
- `*_CBC_SHA` without `*_SHA256` or stronger HMAC

The acceptable TLS 1.2 cipher list (in priority order):
```
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
```

### 13.2 Network Segmentation

The Admin API (`/admin`) and Prometheus metrics (`/metrics`) MUST be bound to a non-public interface. Default configuration (`admin_addr = "127.0.0.1:9099"`, `metrics_addr = "127.0.0.1:9100"`) is correct for single-node deployments. For multi-node deployments, bind to an internal management VLAN address, not `0.0.0.0`.

The relay's internal blob store API is not a separate network port — it is served by the relay process on the admin interface. The Admin API MUST NOT be exposed to the public internet (§13.2).

The PostgreSQL port MUST NOT be exposed outside the relay's private network.

### 13.3 Rate Limiting

The default rate limits in §3.2 (`[rate_limits]`) are conservative starting points. Tune based on observed traffic:

- If a space has channels with legitimate high-volume bot activity, increase `channel_msg_per_second` for those channels via channel-scoped config.
- If the relay serves Tor clients, do not use per-IP rate limits as the primary mechanism (§8.3). The default config does not.
- If operating a public-facing relay, consider reducing `max_anonymous_connections` from 500 to 100 to limit resource consumption from unauthenticated connections.

### 13.4 PoW Difficulty Tuning

The default PoW difficulty of 18 is appropriate for anti-spam on channels with organic human traffic. Adjust as follows:

| Context | Recommended difficulty | Rationale |
|---|---|---|
| Internal org relay (authenticated users only) | 0 (disabled) | All users are authenticated; PoW adds no value |
| Public channel, light spam pressure | 16–18 | ~65,000–262,000 hash ops; imperceptible to human sender |
| Public channel, heavy spam pressure | 20–22 | ~1M–4M hash ops; still fast for humans, expensive for bots |
| High-security / low-rate channels | 24 | ~16M hash ops; noticeable delay (~1s); appropriate for access-controlled channels |

Difficulty above 24 is NOT RECOMMENDED — it begins to degrade legitimate user experience on low-end hardware.

### 13.5 OS Hardening

Minimal practical checklist for the relay host:

- **Minimal OS install**: Do not install unnecessary packages. Use a minimal container base image (Debian slim or distroless).
- **Non-root process**: The relay MUST run as a non-root user (uid 1000 in the reference Dockerfile). Never run as uid 0.
- **No SSH access in containers**: Use `kubectl exec` or `docker exec` for debugging. Remove SSH daemon from container images.
- **Read-only filesystem where possible**: Mount `/etc/agora-relay/keys` and `/etc/agora-relay/relay.toml` as read-only. Only `/var/lib/agora-relay` needs write access.
- **Seccomp profile**: Apply a restrictive seccomp profile to the relay container. The relay requires a limited syscall set (network I/O, file I/O, time); deny the rest.
- **No capability escalation**: Run containers with `--no-new-privileges` and `CAP_DROP ALL`, adding back only `CAP_NET_BIND_SERVICE` if binding to port 443 directly.
- **Automatic security updates**: Enable unattended upgrades for the OS. Relay binary upgrades follow the procedure in §9.

### 13.6 Dependency Supply Chain

- Pin all Docker images to digests, not just tags (§4.1).
- Verify image signatures before deployment (use `cosign` or Docker Content Trust).
- Pin the relay binary image to a specific version and digest.
- Pin PostgreSQL to a specific minor version.
- Do not pull `:latest` in production.
- Review the relay binary's software bill of materials (SBOM) on each release. The relay publishes SBOM artifacts in SPDX format alongside each release image.

---

## 14. Enterprise Integration Deployment

### 14.1 DID Sidecar (O365/Entra ID)

The DID sidecar implements §2.5 enterprise identity provisioning for organizations using Microsoft Entra ID. It is a separate HTTPS service that serves `did:web` documents and accepts device key registrations.

**Deployment relationship to the relay:**

The DID sidecar does not run inside the relay process or container. It runs as a separate service, typically co-located with the organization's identity infrastructure (Entra ID tenant, corporate domain). It requires:

- A publicly accessible HTTPS endpoint at `https://<org-domain>/users/<upn>/did.json` (to serve DID documents).
- An Entra application registration with access to Graph API (for lifecycle workflow event receipt).
- Write access to the DID document store (Azure Blob or PostgreSQL).
- Outbound connectivity to the Agora gossipsub mesh to publish DID update events.

**Required API connectivity from the relay's perspective:**

The relay resolves DID documents from the sidecar's public endpoint during client authentication (§8.6). No direct API connection from relay to sidecar is required; DID resolution is over public HTTPS.

The relay config should set:
```toml
[enterprise]
require_provisioned_dids = true
accepted_provisioner_dids = ["did:web:acme.com:agora:provisioning"]
```

This restricts relay authentication to DIDs whose documents bear a valid `provisionerSig` from the organization's provisioning service. Non-provisioned `did:key` connections are rejected.

Refer to the companion specification `agora-o365-employer-managed-did-spec-clean.md` for the full sidecar deployment guide including Entra app registration, Logic App bridge configuration, and lifecycle workflow integration.

### 14.2 Purview Bridge

The Purview bridge exports `ComplianceRecord` objects from the Agora compliance logger to Microsoft Exchange Online mailboxes for processing by Microsoft Purview. It is a separate process that runs alongside the compliance logger.

**Deployment model:**

The bridge MUST NOT run on the relay. It runs co-located with or directly connected to the `ComplianceLogger` principal. It requires:

- Service principal credentials for the M365 tenant (`Mail.ReadWrite`, `MailboxItem.ImportExport`, `User.Read.All` application permissions).
- A mapping table from Agora DIDs to Exchange Online UPNs.
- Network access to `https://graph.microsoft.com`.
- Read access to the ComplianceLogger's payload stream (local Unix socket or loopback HTTP).

**Relay configuration for compliance logging:**

```toml
[compliance]
admit_loggers = true
operate_logger = true
logger_did = "did:key:z6MkLogger..."
logger_key_path = "/etc/agora-relay/keys/logger-signing.key"
log_store_path = "/var/lib/agora-relay/compliance"
```

The Purview bridge reads from `log_store_path` and exports to Exchange. The IPLD chain in `log_store_path` remains the authoritative compliance record; the Exchange export is a secondary, Purview-queryable copy.

Refer to `agora-purview-bridge-spec-clean.md` for the full bridge deployment guide including Graph API provisioning, MIME format specification, and idempotency handling.

### 14.3 SAML/OIDC Configuration

For organizations not using the O365 DID sidecar but still wanting to restrict relay access to enterprise-provisioned identities, configure the relay's enterprise section:

```toml
[enterprise]
require_provisioned_dids = true
oidc_issuer = "https://login.microsoftonline.com/<tenant-id>/v2.0"
# or for Okta:
# oidc_issuer = "https://<org>.okta.com/oauth2/default"
accepted_provisioner_dids = ["did:web:acme.com:agora:provisioning"]
```

The relay uses the OIDC issuer only for validating IdP tokens presented by the provisioning service during device key registration (§2.5.4). It does not directly process SAML assertions or OIDC tokens from end users; all client authentication uses the DID challenge-response mechanism (§8.6).

---

## 15. Multi-Relay HA Deployment

### 15.1 Architecture

A multi-relay HA deployment runs two or more relay instances sharing a common database and blob store. The goal is to survive a single relay instance failure without client-visible disruption.

```
                  ┌─────────────────────────────────────┐
                  │   Network Load Balancer              │
                  │   UDP 443 (QUIC) + TCP 443 (WS)      │
                  └───────┬──────────────┬──────────────┘
                          │              │
               ┌──────────▼──┐      ┌───▼──────────┐
               │  relay-1    │      │  relay-2     │
               │  (primary)  │      │  (replica)   │
               └──────┬──────┘      └──────┬───────┘
                      │                    │
               ┌──────▼────────────────────▼──────┐
               │      PostgreSQL Primary           │
               │      + Streaming Replication      │
               └──────────────┬───────────────────┘
                              │
               ┌──────────────▼───────────────────┐
               │     Shared Blob Store             │
               │  (S3-compatible object store)     │
               └──────────────────────────────────┘
```

### 15.2 Active-Active vs Active-Passive

**Active-active** (recommended): Both relay instances accept connections simultaneously. The load balancer distributes connections across instances. The database is the shared state layer; both instances read and write to it. This configuration requires the load balancer to provide QUIC affinity (§11.4) to ensure packets from the same QUIC connection go to the same backend.

**Active-passive**: One relay handles all traffic; the second is a hot standby that becomes active only when the primary fails. Simpler to reason about but wastes the capacity of the standby. Use only when active-active QUIC affinity is not available in the load balancer.

### 15.3 Database: PostgreSQL HA

For multi-relay HA, use PostgreSQL with streaming replication:

- **Primary** handles reads and writes.
- **Replica(s)** receive streaming WAL replication and handle read-only queries.
- Use Patroni or pg_auto_failover for automatic primary election on failure.
- Connection pooling via PgBouncer in front of each relay's database connection.

Alternatively, use **CockroachDB** for a distributed-by-default PostgreSQL-compatible database. CockroachDB handles its own replication and failover with no external HA tooling needed. It is appropriate for multi-region deployments but adds operational complexity for single-region.

### 15.4 Blob Store: Shared Backend

All relay instances MUST share the same blob store so that any instance can serve any CID. Use `blob_backend = "s3"` and configure all instances to point at the same bucket:

- **AWS S3**: Set `blob_s3_endpoint`, `blob_s3_bucket`, and `blob_s3_region` identically across all relay instances. Use an IAM role or access key with `s3:GetObject` and `s3:PutObject` on the bucket.
- **MinIO** (self-hosted): Deploy a MinIO cluster with erasure coding for durability. All relay instances connect to the same MinIO endpoint. Simpler to control than AWS; requires operating the MinIO cluster.
- **Cloudflare R2 / Backblaze B2**: S3-compatible APIs; configure `blob_s3_endpoint` to the provider's S3-compatible URL. Zero egress cost (R2) or very low cost (B2) makes these attractive for read-heavy relay workloads.

Do not use a shared NFS/EFS volume as a blob store backend. NFS introduces a single point of failure and does not provide the atomic put semantics required for correct CID-keyed storage.

### 15.5 Session Affinity

WebTransport (QUIC) connections maintain cryptographic state (QUIC connection ID, TLS session). The load balancer MUST route all packets from a given QUIC connection to the same relay instance for the duration of the connection.

WebSocket connections are long-lived TCP connections. The load balancer MUST NOT terminate and re-route WebSocket connections mid-stream.

**For AWS NLB:** UDP flows are tracked by 5-tuple (source IP, source port, destination IP, destination port, protocol) for the duration of the flow idle timeout. Set the NLB idle timeout to at least 350 seconds (longer than the QUIC idle timeout of 300 seconds).

**For Kubernetes:** Use a Service with `sessionAffinity: ClientIP` and `sessionAffinityConfig.clientIP.timeoutSeconds: 10800` (3 hours).

### 15.6 Peer Mesh: Per-Instance Peering

Each relay instance MUST independently participate in the gossipsub peer mesh. Do not front the peer API behind the load balancer — peer relays SHOULD connect to individual relay instance endpoints for gossip.

Each instance announces itself with the same `relay_did` (the shared identity) but a distinct physical endpoint. The relay manifest should list the load balancer endpoint for client-facing transports and instance-specific endpoints for the peer API and gossipsub:

```json
"endpoints": {
  "webTransport": "https://relay.example.com/v1/agora/wt",
  "webSocket":    "wss://relay.example.com/v1/agora/ws",
  "peerAPI":      "https://relay1.internal.example.com/v1/agora/peer",
  "gossipQuic":   "/ip4/10.0.1.1/udp/9001/quic-v1"
}
```

Relay instances 2, 3, etc. publish their own manifest entries with their instance-specific peer API endpoints.

### 15.7 Health Check and Failover

Configure the load balancer to health-check each relay instance via:
```
GET /v1/agora/peer/health
```

This endpoint is unauthenticated (§3.5.2) and returns `{ "status": "healthy" }` when the relay is operating normally. The load balancer MUST stop routing to an instance that returns `unhealthy` or does not respond within 5 seconds.

Health check interval: 10 seconds. Unhealthy threshold: 2 consecutive failures. Healthy threshold: 3 consecutive successes.

---

## 16. Decommissioning

### 16.1 Overview

Decommissioning a relay is a multi-step process designed to minimize disruption to spaces and clients that depend on it. A relay MUST NOT simply be turned off without following this procedure; abrupt shutdown leaves clients unable to reconnect, space state CIDs potentially inaccessible, and peer relays with stale mesh entries.

### 16.2 Pre-Decommissioning Notification

1. At least 30 days before the planned shutdown date, update the relay manifest to include a retirement notice:
   ```json
   "maintenance": {
     "status": "retiring",
     "retirementDate": "2026-05-22T00:00:00Z",
     "message": "This relay will be decommissioned on 2026-05-22. Please migrate to relay.example-new.com.",
     "migrationRelay": "https://relay-new.example.com/.well-known/agora-relay"
   }
   ```

2. Gossip a `RelayAd` update with the retirement notice. Space admins subscribed to `v1/agora/discovery` will see the notice.

3. Notify space owners via out-of-band channels (email, space announcements) if contact information is available.

### 16.3 Drain

1. Stop accepting new client connections:
   ```toml
   [server]
   accepting_new_connections = false
   ```
   Reload the config via `POST /admin/reload`. Existing connections remain active; new connection attempts receive a TLS `close_notify` alert with a redirect hint.

2. Wait for active client connections to drop. Most clients will reconnect to peer relays automatically (§13.3). Monitor:
   ```bash
   watch -n 5 'curl -s -H "Authorization: Bearer $ADMIN_TOKEN" localhost:9099/admin/status | jq .active_connections'
   ```

3. Allow at least 60 minutes of drain time. After drain, there SHOULD be fewer than 50 active connections (stragglers on slow reconnect schedules).

### 16.4 Export: Ensuring Space State CID Availability

Space state and message history must remain available after the relay shuts down. Because content is addressed by CID, any relay holding a blob can serve it. Before shutdown:

1. Confirm that at least one peer relay holds all CIDs this relay serves. Query the Admin API for the full space list and verify each space CID is reachable from a peer:
   ```bash
   # Get all space CIDs this relay holds
   curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
       localhost:9099/admin/spaces | jq -r '.spaces[].space_cid' \
       > /tmp/space-cids.txt

   # Verify each CID is fetchable from a known peer relay
   while read cid; do
     if ! curl -sf "https://peer-relay.example.com/v1/agora/blob/$cid" \
         -o /dev/null; then
       echo "NOT AVAILABLE ON PEER: $cid" >&2
     fi
   done < /tmp/space-cids.txt
   ```

2. For any CID not available on a peer, push it before proceeding:
   ```bash
   while read cid; do
     # Fetch blob from local store and upload to peer relay CAS
     curl -s "localhost:9099/admin/blob/$cid" | \
       curl -X PUT "https://peer-relay.example.com/v1/agora/blob/$cid" \
           -H "Content-Type: application/octet-stream" --data-binary @-
   done < /tmp/missing-on-peer.txt
   ```

### 16.5 Peer Removal

1. Notify all Level 2+ peers of the planned shutdown. Use the Peer API:
   ```bash
   # For each Level 2+ peer:
   curl -X POST https://peer.example.net/v1/agora/peer/announce \
       -H "Content-Type: application/json" \
       -d '{"@type":"RelayRetirementNotice","relayDID":"did:key:z6MkRelay...","retirementDate":"2026-05-22T00:00:00Z","sig":"..."}'
   ```

2. Update the relay manifest to remove the relay from `knownPeers` entries gossipped by this relay.

3. Stop the peer heartbeat daemon. Peer relays will detect the relay as unreachable after 3 missed heartbeats (180 seconds) and mark it for removal from their peer tables per §3.5.6.

### 16.6 DID Tombstone

After shutdown, publish a signed tombstone to the gossip mesh to formally retire the relay DID:

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "RelayTombstone",
  "relayDID": "did:key:z6MkRelay...",
  "retiredAt": "2026-05-22T00:00:00Z",
  "reason": "decommissioned",
  "successor": "did:key:z6MkNewRelay...",
  "sig": "base64url(signature by relay signing key)"
}
```

Gossip this message on `v1/agora/discovery`. Peer relays that receive this message MUST remove the retired relay from their peer tables and MUST NOT re-establish connections to it.

The tombstone MUST be signed by the relay's current active signing key. Generate and gossip the tombstone before the relay process stops.

### 16.7 Final Shutdown

1. Flush the compliance queue one final time (if operating a compliance logger):
   ```bash
   curl -s -X POST -H "Authorization: Bearer $ADMIN_TOKEN" localhost:9099/admin/compliance/flush
   ```

2. Stop the relay process:
   ```bash
   systemctl stop agora-relay
   # or: docker compose down relay
   ```

3. Take a final database backup (§8.3).

### 16.8 Data Retention After Shutdown

After relay shutdown, retain the following for the applicable legal/regulatory period:

| Data | Retention | Rationale |
|---|---|---|
| Relay signing key (private key) | Until the DID tombstone has propagated and been confirmed by all known peers (minimum 30 days) | Needed to sign any post-shutdown corrections to the tombstone |
| Database backup | Per your jurisdiction's data retention obligations, minimum 90 days | May be needed for dispute resolution or legal requests |
| Compliance log store | Per the `retentionDays` value in the space's compliance config (e.g., 2555 days) | Regulatory obligation; deleting before the retention period is a compliance violation |
| Access logs (connection IP + timestamps) | Per your jurisdiction's data retention obligations, typically 90 days to 1 year | Needed for legal requests; note that access logs do not contain message content |
| Config file and audit log | 1 year | Operational record |

Data not listed above MAY be deleted after shutdown. In particular:
- The local blob store MAY be deleted after confirming all CIDs are available on at least one peer relay or S3 backend (§16.4).
- Session tokens and ephemeral per-connection state SHOULD be deleted immediately on shutdown.

---

*End of Agora Relay Operations Specification v0.1*
