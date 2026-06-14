# Agora Protocol Specification

**Version:** 0.1 (Draft)  
**Date:** 2026-03-12

---

## Version Policy

All versioned protocol surfaces in this specification are at **v1** for the initial release. The version appears as a path prefix on HTTP endpoints (`/v1/agora/...`), as a topic prefix on gossip topics (`v1/agora/...`), in JSON-LD context URLs (`/ns/v1`), and in document `schemaVersion` fields.

A breaking change to any one surface increments only that surface's version; all other surfaces remain at their current version and are unaffected. Clients and relays MUST reject messages or connections whose version they do not support and MUST NOT silently coerce an unknown version to a known one.

Version negotiation is defined per surface:

- **Transport endpoints** — the URL path version is fixed at connection time; a client connects to `/wt/v1` or `/ws/v1` and the relay either accepts or returns HTTP 404/410.
- **Gossip topics** — the version is encoded in the topic string; v1 and v2 topics can coexist on the mesh simultaneously; a relay that supports both subscribes to both topic families.
- **JSON-LD documents** — the `schemaVersion` field carries the document schema version; processors that do not support the declared version MUST reject the document.
- **Client-relay handshake** — version negotiation occurs as part of the `ClientHello`/`RelayChallenge` exchange (§8.6).
- **Relay-to-relay Peer API** — the version is encoded in the URL path; a relay's manifest `capabilities` array declares which versions it supports.

---

## 1. Overview

Agora is a decentralized, end-to-end encrypted, real-time group chat protocol. It is designed to support a user experience comparable to Discord — servers with hierarchical channels, presence indicators, typing notifications, voice/video conferencing — without any central authority owning identity, routing, or message storage. No company holds your keys, your membership lists, or your message history.

### Core Protocol Dependencies

| Dependency | Role |
|---|---|
| **RFC 9420 (MLS)** | Group key agreement and end-to-end encryption |
| **JSON-LD** | Typed, namespace-aware message framing |
| **libp2p gossipsub v1.1** | Peer discovery, room advertisement, live message fanout |
| **IPFS / IPLD** | Content-addressed persistent storage for history, media, and room state |
| **WebTransport (RFC 9000)** | Primary transport for browsers and native clients |
| **WebSocket (RFC 6455)** | Fallback transport, and the only transport available over Tor |
| **MobileCoin (MOB)** | Preferred payment scheme for relay economics and message micropayments (optional) |

Agora does **not** define a central server. It defines a protocol that servers — called **Relays** — implement to form a federated, permissionless mesh. Users are not locked to any particular Relay. Relays gossip with each other. Clients may connect to multiple Relays simultaneously and reconcile state across them.

### Design Principles

**Relay blindness.** A conformant Relay deliberately cannot read message content, identify senders, or map channel tokens to channel identities or member lists. This is not just policy — it is a structural property of the protocol. A Relay operator served a subpoena should be able to honestly say they hold no useful data.

**Federated, not centralized.** Anyone can run a Relay. Any Relay that speaks the protocol can join the mesh. There is no registration, no whitelist, no governing authority over who participates.

**Content addressing.** All persistent state — messages, guild definitions, profiles, channel history — is stored in IPFS/IPLD and addressed by content hash (CID). History is tamper-evident by construction. Two Relays storing the same message store the same CID; deduplication is automatic.

**MLS everywhere.** MLS (RFC 9420) is the sole key agreement mechanism. It provides forward secrecy, post-compromise security, and multi-device membership natively. Every channel is an MLS group. Signaling, moderation records, and compliance logs all flow through MLS-authenticated channels.

---

## 2. Identity

### 2.1 User DID

Every user has a **Decentralized Identifier (DID)** as their persistent identity. DIDs are self-certifying: possession of the private key proves identity without any registry or certificate authority. The recommended methods are:

- **`did:key`** — derives the DID directly from the public key. Entirely self-contained, no DNS dependency, works offline. Preferred for individuals.
- **`did:web`** — anchors identity to a DNS domain. Appropriate for organizations that want verifiable institutional identity tied to their domain name.

A user's DID document contains two key roles:

- **`authentication`** key — Ed25519 key used to sign all protocol messages, guild state mutations, and moderation actions.
- **`keyAgreement`** key — X25519 key used as the source for MLS `KeyPackage` init keys and for encrypting per-device payloads such as social recovery shares.

**Reference implementations:** `did-key` generation and resolution is implemented by:
- TypeScript/JS: [`@digitalbazaar/did-io`](https://github.com/digitalbazaar/did-io), [`@transmute/did-key`](https://github.com/transmute-industries/did-key.js)
- Go: [`github.com/nuts-foundation/go-did`](https://github.com/nuts-foundation/go-did)
- Rust: [`did-key` crate](https://crates.io/crates/did-key), [`ssi` crate (Spruce Systems)](https://github.com/spruceid/ssi)
- Python: [`pyld`](https://github.com/digitalbazaar/pyld) + [`pymultibase`](https://github.com/pinnaculum/py-multibase)

Example DID document:

```json
{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:key:z6Mk...",
  "verificationMethod": [{
    "id": "did:key:z6Mk...#keys-1",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:key:z6Mk...",
    "publicKeyMultibase": "z6Mk..."
  }],
  "authentication": ["did:key:z6Mk...#keys-1"],
  "keyAgreement": [{
    "id": "did:key:z6Mk...#keys-2",
    "type": "X25519KeyAgreementKey2020",
    "controller": "did:key:z6Mk...",
    "publicKeyMultibase": "zABC..."
  }]
}
```

The `keyAgreement` key is the source material for MLS KeyPackage generation. The `authentication` key signs all protocol messages.

### 2.2 Device Keys

A single user identity can span multiple physical devices. MLS handles multi-device membership natively — each device is a separate MLS leaf node in every group the user belongs to. The user's DID document lists all active device verification keys as separate `verificationMethod` entries.

Revoking a device means removing its leaf node from all relevant MLS trees via an `Update` commit, and removing the corresponding `verificationMethod` from the DID document. Both operations must be performed for full revocation; removing only one leaves residual access.

### 2.3 User Display Profile

The user profile is stored separately from the DID document, as an IPLD node addressed by CID. The DID document links to the current profile CID via a `service` endpoint:

```json
{
  "service": [{
    "id": "did:key:z6Mk...#profile",
    "type": "AgoraProfile",
    "serviceEndpoint": "ipfs://bafyrei..."
  }]
}
```

Profile schema (JSON-LD):

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "UserProfile",
  "did": "did:key:z6Mk...",
  "displayName": "alice",
  "avatarCID": "bafyrei...",
  "statusText": "building things",
  "updatedAt": "2026-03-12T00:00:00Z"
}
```

Profile updates are signed by the user's authentication key and gossiped on `v1/agora/discovery`. Because the profile is content-addressed, clients can cache it indefinitely — a stale profile will produce a CID mismatch against the current DID document's `serviceEndpoint`, prompting a refresh.

### 2.4 Account Recovery

`did:key` identities are self-certifying — the private key is the identity. Loss of all device private keys is permanent identity loss with no protocol-level remedy unless recovery mechanisms are established in advance. Agora specifies three complementary recovery mechanisms. Clients SHOULD implement all three; users SHOULD activate at least one before they need it.

#### 2.4.1 Recovery Key

A **recovery key** is a dedicated Ed25519 keypair generated at account creation time and stored entirely separately from all device keys — typically printed as a recovery phrase, stored on an air-gapped device, or written to paper and placed somewhere physically secure. It is registered in the DID document as a verification method with a `recoverableIdentity` relationship:

```json
{
  "verificationMethod": [
    {
      "id": "did:key:z6Mk...#keys-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:key:z6Mk...",
      "publicKeyMultibase": "z6Mk..."
    },
    {
      "id": "did:key:z6Mk...#recovery-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:key:z6Mk...",
      "publicKeyMultibase": "zRECOVERY..."
    }
  ],
  "recoverableIdentity": ["did:key:z6Mk...#recovery-1"]
}
```

The recovery key is **never used for normal protocol operations**. Its only function is to sign a `RecoveryAssertion` that rotates the DID document to a new device key when all other device keys are lost:

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "RecoveryAssertion",
  "did": "did:key:z6Mk...",
  "newDeviceKey": "base64url(new Ed25519 pubkey)",
  "revokeAll": true,
  "ts": "2026-03-12T12:00:00.000Z",
  "recoverySig": "base64url..."
}
```

`recoverySig` is an Ed25519 signature by the recovery key over the canonical serialization of the other fields. `revokeAll: true` instructs relays and peers to immediately treat all previously registered device keys as revoked. The `RecoveryAssertion` is published to `v1/agora/discovery` and appended to the user's profile IPLD chain. Relays that receive a valid `RecoveryAssertion` MUST invalidate all cached sessions for that DID immediately.

**The recovery key is the root of trust for identity recovery.** Its private key MUST be stored offline and MUST NOT be loaded into any networked device during normal operation. Loss of the recovery key means loss of recovery capability via this mechanism.

#### 2.4.2 Social Recovery

Social recovery designates a set of **guardians** — other Agora users trusted to collectively authorize identity recovery. A threshold scheme (e.g., 3-of-5) ensures that no single guardian can unilaterally recover the account, and that losing any one guardian does not prevent recovery.

**Setup:** The client generates a random 256-bit recovery secret `S`, splits it into `N` shares using Shamir's Secret Sharing (SSS), and encrypts each share individually to a guardian's X25519 key agreement key:

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "SocialRecoveryConfig",
  "did": "did:key:z6Mk...",
  "threshold": 3,
  "totalShares": 5,
  "guardians": [
    {
      "guardianDID": "did:key:z6MkGuardian1...",
      "encryptedShare": "base64url..."
    }
  ],
  "recoveryCommitment": "base64url(SHA256(S))",
  "ts": "2026-03-12T12:00:00.000Z",
  "sig": "base64url..."
}
```

The `SocialRecoveryConfig` is stored in the user's profile IPLD chain (publicly readable — guardians need to know they hold a share). `recoveryCommitment` is a SHA-256 hash of `S` used to verify share reconstruction without revealing `S` before recovery begins.

**Recovery:** The user (now on a new device with no existing keys) contacts `threshold` guardians out-of-band and requests their shares. Each guardian decrypts their encrypted share using their X25519 key and transmits it to the recovering user via a direct encrypted message (or any secure out-of-band channel). The user reconstructs `S` from the shares, verifies it against `recoveryCommitment`, then uses `S` to derive a new signing key and publish a `RecoveryAssertion` signed with it.

`S` itself is never stored anywhere — it exists only transiently during setup (to split) and recovery (to reconstruct). Guardians hold encrypted shares; relays hold nothing related to recovery.

**Guardian obligations:** Guardians SHOULD confirm their designation when first asked. A guardian who subsequently loses their own keys loses the ability to decrypt their share. The account owner SHOULD periodically verify that all guardians remain reachable and responsive, and should re-key shares when a guardian becomes unreachable or leaves the system.

**Reference implementations for SSS:** [`hashicorp/vault` SSS](https://github.com/hashicorp/vault/tree/main/shamir) (Go), [`secrets.js`](https://github.com/grempe/secrets.js) (JS), [`sharks` crate](https://crates.io/crates/sharks) (Rust).

#### 2.4.3 Encrypted Backup

A client MAY export an encrypted backup of all device private keys and MLS state to a user-chosen location — a local file, cloud storage, IPFS, or any other storage the user controls. The backup is encrypted with a user-chosen passphrase using Argon2id key derivation:

```
backupKey = Argon2id(passphrase, salt, m=65536, t=3, p=4)
backup    = AEAD_AES_256_GCM(backupKey, backupPayload)
```

`backupPayload` is a CBOR-encoded structure containing:
- All device Ed25519 private keys
- All device X25519 private keys
- Current MLS key material for all group memberships
- The recovery key private key (if one was generated)
- Timestamp and DID

The backup file is self-describing: it includes the Argon2id parameters and the DID, so a client can prompt for the passphrase and restore fully without requiring any additional configuration or external lookup.

Clients SHOULD prompt users to export an encrypted backup at account creation and after any significant key rotation event (new device added, device revoked, recovery key regenerated). Clients MUST NOT store the backup passphrase anywhere on the device.

**Reference implementations for Argon2id:** [`golang.org/x/crypto/argon2`](https://pkg.go.dev/golang.org/x/crypto/argon2) (Go), [`argon2` npm package](https://www.npmjs.com/package/argon2) (JS/Node), [`argon2` crate](https://crates.io/crates/argon2) (Rust), [`argon2-cffi`](https://pypi.org/project/argon2-cffi/) (Python).

#### 2.4.4 Recovery Precedence and Conflict Resolution

If multiple recovery mechanisms are triggered simultaneously and produce conflicting `RecoveryAssertion` messages (for example, if two guardians independently initiate social recovery procedures in parallel), the conflict is resolved by timestamp: the earlier valid `RecoveryAssertion` wins. Relays that observe a second `RecoveryAssertion` for the same DID within 24 hours of the first MUST reject it and flag the conflict in their logs. The account owner SHOULD monitor their DID document's IPLD chain for spurious recovery attempts as a signal of potential compromise.

---

## 3. Topology

### 3.1 Participants

- **Client** — a user agent (web browser, desktop application, mobile app). Connects to one or more Relays. Holds the user's private keys and MLS state. Responsible for all encryption and decryption operations.
- **Relay** — an always-on server that participates in gossipsub, caches recent messages within a configured retention window, serves WebTransport and WebSocket endpoints for clients, and optionally pins IPFS content. Anyone may operate a Relay; no permission is required.
- **Peer** — any participant in the gossipsub mesh, including both Relays and clients with persistent connections.

### 3.2 Guild and Channel Hierarchy

A **Guild** is a named collection of channels, analogous to a Discord server. A **Channel** is a named, typed stream of messages within a Guild.

Guild and Channel identifiers are **namespaced paths**:

```
agora://<guild-id>/<channel-path>
```

Where `<guild-id>` is the CID of the Guild's root state document, and `<channel-path>` is a slash-delimited path supporting arbitrary nesting:

```
agora://bafyrei.../general
agora://bafyrei.../engineering/backend
agora://bafyrei.../engineering/backend/incidents
agora://bafyrei.../voice/lounge
```

Channel nesting is structural only — a parent channel (such as `engineering`) can itself be a message channel, a category header, or both. The namespace is a tree; there is no enforced depth limit.

### 3.3 Guild State Document

The Guild state document is stored as an IPLD DAG node. Its CID changes on every mutation. The Guild's identity is anchored to its genesis CID; subsequent state is represented as a signed chain of mutations, each referencing the prior state CID in its `prevStateCID` field. This makes the Guild history tamper-evident: replacing any intermediate state document breaks the chain.

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "GuildState",
  "schemaVersion": "1",
  "id": "agora://bafyrei...",
  "name": "wolfSSL Dev",
  "iconCID": "bafyrei...",
  "owner": "did:key:z6Mk...",
  "channels": [
    {
      "path": "general",
      "type": "text",
      "name": "general"
    },
    {
      "path": "engineering",
      "type": "category",
      "name": "Engineering",
      "children": [
        { "path": "engineering/backend", "type": "text" },
        { "path": "engineering/fips",    "type": "text" }
      ]
    },
    {
      "path": "voice/lounge",
      "type": "voice"
    }
  ],
  "roles": [...],
  "mlsGroupID": "base64url...",
  "prevStateCID": "bafyrei...",
  "seq": 42,
  "sig": "base64url..."
}
```

`sig` is an Ed25519 signature over the canonical CBOR serialization of the document (per §14.1), signed by the Guild owner's authentication key or a delegated admin's key.

### 3.4 Deployment Topologies

Agora is transport-agnostic at the application layer. The following deployment topologies are explicitly supported:

**Public internet (default)** — Relays are clearnet HTTPS/WSS servers with public IPv4 and/or IPv6 addresses. Clients connect over the public internet. This is the baseline configuration assumed throughout this specification unless otherwise noted.

**Tor hidden service** — A Relay MAY operate as a Tor v3 hidden service, publishing a `.onion` address in its `RelayAd` alongside or instead of a clearnet endpoint. Hidden service Relays provide IP-level anonymity for the Relay operator; the relay's physical location and operator IP are not exposed to the gossipsub mesh or to connecting clients. Clients connecting via Tor MUST use the WebSocket transport (§8.2); WebTransport requires QUIC over UDP and is unavailable over Tor.

**Private overlay (Tailscale / WireGuard / Headscale)** — A Relay MAY operate exclusively on a WireGuard-based overlay network such as Tailscale or a self-hosted Headscale deployment. In this topology the Relay is reachable only by overlay network members, providing network-layer access control without any application-layer authentication overhead. The Relay's `RelayAd` lists overlay-internal hostnames or `100.x.x.x` addresses (Tailscale's CGNAT range); these are only resolvable inside the overlay. This is the recommended topology for private organizational deployments where all members are already on a common overlay. A fully self-contained deployment — Relay + SFU + TURN + Headscale, all on-premise — has zero dependency on any external infrastructure.

**Dual-stack (clearnet + overlay)** — A Relay MAY publish both clearnet and overlay endpoints. Clients on the overlay prefer the overlay path (lower latency, no NAT traversal needed); external clients use the clearnet path. Both sets of clients share the same guild state and message history.

**IPv6** — All Relay endpoints SHOULD support IPv6. Relay URIs MUST use bracket notation for IPv6 address literals (`wss://[2001:db8::1]/v1/agora/ws`). ICE gathers both IPv4 and IPv6 host candidates; dual-stack clients race both address families.

### 3.5 Relay-to-Relay Peering and Authentication

Relays form a gossipsub mesh with each other for fanout. This section specifies how Relays discover each other, authenticate, establish trust levels, and maintain the mesh. The model follows Corundum's operator federation pattern: a well-known manifest endpoint, RFC 9421 HTTP Message Signatures for relay-to-relay authentication, graduated trust levels, and zero-configuration bootstrap from any single known peer.

#### 3.5.1 Relay Manifest

Every Relay MUST publish a **Relay Manifest** at a well-known URL:

```
GET /.well-known/agora-relay
```

The manifest is a signed JSON-LD document that serves as the Relay's authoritative self-declaration. It is the single source of truth for a Relay's identity, capabilities, endpoints, and signing keys. Any Relay that can reach this URL can bootstrap a peering relationship without out-of-band coordination.

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "RelayManifest",
  "version": "1",
  "relayDID": "did:key:z6MkRelay...",
  "operator": "Example Relay Co.",
  "operatorDID": "did:key:z6MkOperator...",
  "adminContact": "relay-admin@example.com",
  "abuseContact": "abuse@example.com",
  "description": "Public community relay, US-West",
  "region": "us-west",
  "endpoints": {
    "webTransport":    "https://relay.example.com/v1/agora/wt",
    "webSocket":       "wss://relay.example.com/v1/agora/ws",
    "onion":           "ws://examplerelay3xyzabc.onion/v1/agora/ws",
    "keyPackageStore": "https://relay.example.com/v1/agora/kp",
    "peerAPI":         "https://relay.example.com/v1/agora/peer"
  },
  "keys": [
    {
      "id": "did:key:z6MkRelay...#key-1",
      "type": "Ed25519VerificationKey2020",
      "publicKeyMultibase": "z6MkRelay...",
      "status": "active",
      "activatedAt": "2026-03-12T00:00:00Z",
      "expiresAt": "2027-03-12T00:00:00Z"
    }
  ],
  "capabilities": [
    "gossipsub-v1.1",
    "keypackage-store-v1",
    "keypackage-forwarding-v1",
    "tor-hidden-service-v1",
    "peer-api-v1"
  ],
  "acceptedSchemes": ["mob", "pow"],
  "knownPeers": [
    {
      "relayDID": "did:key:z6MkPeer...",
      "manifestURL": "https://peer.example.net/.well-known/agora-relay",
      "addedAt": "2026-03-12T00:00:00Z"
    }
  ],
  "publishedAt": "2026-03-12T00:00:00Z",
  "sig": "base64url..."
}
```

`sig` is the Relay operator's Ed25519 signature over the canonical CBOR serialization of the manifest, excluding the `sig` field, signed by the active key listed in `keys`. Peer Relays MUST verify this signature before accepting the manifest.

`knownPeers` is the Relay's current peer list. This serves as a mesh map: a new Relay fetching any existing Relay's manifest obtains a list of further Relays to contact, enabling rapid mesh joining without a central directory server.

`capabilities` is an array of capability strings declaring what features this Relay supports:

| Capability | Meaning |
|---|---|
| `gossipsub-v1.1` | Participates in libp2p gossipsub v1.1 mesh |
| `keypackage-store-v1` | Hosts the KeyPackage Store API (§6.1.1) |
| `keypackage-forwarding-v1` | Supports inter-relay KeyPackage forwarding |
| `tor-hidden-service-v1` | Reachable via a `.onion` endpoint |
| `sfu-v1` | Hosts an SFU for voice channel routing |
| `compliance-logging-v1` | Supports compliance logger DID admission (§17) |
| `peer-api-v1` | Implements the Peer API v1 (§3.5.2) |
| `push-proxy-v1` | Operates a push notification proxy (§8.7) |

#### 3.5.2 Peer API

Relays expose a **Peer API** at the URL declared in `endpoints.peerAPI` for relay-to-relay operations. All Peer API requests (except `manifest` and `health`, which are unauthenticated) are signed using RFC 9421 HTTP Message Signatures (§3.5.3).

```
GET  /v1/agora/peer/manifest
     Returns this relay's current RelayManifest.
     Unauthenticated.

POST /v1/agora/peer/announce
     A peer relay announces itself. Body: the announcing relay's RelayManifest.
     Response: 200 { "status": "accepted"|"known"|"rejected", "trustLevel": N }

GET  /v1/agora/peer/peers
     Returns the relay's known peer list: array of { relayDID, manifestURL }.
     Authenticated. Rate-limited to 1 request/hour per peer.

POST /v1/agora/peer/gossip
     Relay-to-relay gossipsub message submission.
     Body: CBOR-encoded gossipsub message batch.
     Authenticated.

GET  /v1/agora/peer/health
     Returns relay health state.
     Response: { "status": "healthy"|"degraded"|"unhealthy"|"maintenance", "since": ISO8601 }
     Unauthenticated.
```

#### 3.5.3 Relay-to-Relay Authentication

All relay-to-relay requests (except unauthenticated endpoints) use **RFC 9421 HTTP Message Signatures** with Ed25519. The requesting Relay signs each HTTP request using its active signing key from its manifest. The receiving Relay verifies the signature against the requesting Relay's manifest fetched from `/.well-known/agora-relay`.

**Required signature components** (per RFC 9421 §2.5):

```
"@method"
"@target-uri"
"@authority"
"content-digest"      (POST requests with a body)
"x-agora-relay-did"   (requesting relay's DID)
"x-agora-timestamp"   (Unix timestamp, integer seconds)
"x-agora-nonce"       (random 128-bit value, base64url)
```

Example signed request headers:

```http
x-agora-relay-did: did:key:z6MkRelay...
x-agora-timestamp: 1741780800
x-agora-nonce: aGVsbG8gd29ybGQhISEhISE
signature-input: sig1=("@method" "@target-uri" "@authority" \
  "x-agora-relay-did" "x-agora-timestamp" "x-agora-nonce"); \
  keyid="did:key:z6MkRelay...#key-1"; alg="ed25519"
signature: sig1=:base64url...:
```

**Replay prevention:** `x-agora-timestamp` MUST be within 300 seconds of the receiving Relay's clock. `x-agora-nonce` MUST NOT have been seen in the previous 600 seconds (the receiving Relay maintains a nonce cache with a 600-second TTL). Requests violating either condition MUST be rejected with HTTP 401.

**Manifest caching:** Receiving Relays cache peer manifests for 1 hour. On a cache miss or expiry, the Relay fetches a fresh manifest before verifying the request. If the fetch fails, the Relay retries once after 5 seconds before rejecting the request with HTTP 503.

**Reference implementations for RFC 9421:** [`httpbis-message-signatures`](https://github.com/nicowillis/httpbis-message-signatures) (JS), [`httpsig`](https://github.com/bblfish/httpSig) (Scala/JVM reference), [`go-http-signature`](https://github.com/go-fed/httpsig) (Go).

#### 3.5.4 Trust Levels

Relay-to-relay trust is graduated. Trust level determines which Peer API operations a Relay is permitted to invoke and what gossip rate limits apply. Trust level is local state — each Relay maintains its own assessments independently. It is never gossiped or shared. Level 3 is set via local operator configuration and is appropriate for Relays operated by the same organization or well-known partner organizations.

| Level | Name | Criteria | Permissions |
|---|---|---|---|
| 0 | Unknown | No prior contact | Manifest fetch only; `announce` accepted for evaluation |
| 1 | Seen | Valid manifest, valid signature, first contact | `announce`, `health`; gossip rate-limited to 10 msg/s |
| 2 | Known | 7+ days of sustained peering without incident | Full gossip; `peers` accessible; 1000 msg/s |
| 3 | Trusted | Explicitly operator-configured | Full access; relaxed rate limits; no gossip throttling |

**Trust degradation:** A Relay that submits invalid signatures, sends malformed gossip, or repeatedly exceeds rate limits is downgraded to Level 0 and its DID is blocked for 24 hours. Repeated violations (3 or more incidents within 7 days) result in permanent operator-managed blocklisting.

#### 3.5.5 Bootstrap: Joining the Mesh

A new Relay with no existing peers joins the gossipsub mesh using any of the following methods, attempted in parallel:

**Method 1 — Known peer URL.** The operator provides one or more peer Relay URLs in the startup configuration. The new Relay fetches `/.well-known/agora-relay` from each, verifies the manifest signature, sends `POST /peer/v1/announce` with its own manifest, and on acceptance fetches `GET /peer/v1/peers` to discover further Relays.

**Method 2 — Directory document.** The Relay fetches any Agora Relay directory document (§4.4.1) and contacts each listed Relay using Method 1.

**Method 3 — DNS-SD.** The Relay queries `_agora-relay._tcp.<domain>` SRV records:

```
_agora-relay._tcp.example.com. SRV 10 0 443 relay.example.com.
_agora.relay.example.com.      TXT "did=did:key:z6MkRelay... manifest=https://relay.example.com/.well-known/agora-relay"
```

This is primarily useful for organizational deployments where multiple Relays share a DNS domain.

**Method 4 — IPNS fallback.** The Relay resolves `/ipns/agora.protocol/relays/v1` for a community-maintained signed bootstrap list. This is the last resort.

A Relay is considered mesh-joined when it has Level 1 or higher trust with at least 3 peers and is participating in gossipsub fanout. It SHOULD continue discovering peers until it has at least 6 active connections (gossipsub's default mesh degree `D`).

#### 3.5.6 Mesh Maintenance

**Heartbeat.** Relays MUST poll `GET /peer/v1/health` from each peer every 60 seconds. A peer that returns `unhealthy` or fails to respond for 3 consecutive checks (180 seconds total) is marked unreachable. Its gossipsub connection is dropped; it remains in `knownPeers` for 7 days before removal, in case it recovers.

**Manifest refresh.** Relays re-fetch peer manifests every hour to detect key rotation and endpoint changes. A manifest whose `sig` no longer verifies is treated as a trust failure and the peer is downgraded to Level 0 pending re-verification.

**Key rotation overlap.** When rotating its signing key, a Relay MUST publish both the old and new keys in its manifest with a minimum 48-hour overlap, marking the old key with `"status": "deprecated"`. Peer Relays accept signatures from deprecated keys during this overlap window. After the overlap period, the old key is removed and signatures from deprecated keys are rejected.

**Peer gossip.** When a Relay discovers a new valid peer, it SHOULD share that peer's `{ relayDID, manifestURL }` with its Level 2+ peers as a `RelayPeerAnnouncement` gossip message:

```json
{
  "@type": "RelayPeerAnnouncement",
  "relayDID": "did:key:z6MkNewRelay...",
  "manifestURL": "https://newrelay.example.com/.well-known/agora-relay",
  "announcedBy": "did:key:z6MkExistingRelay...",
  "ts": "2026-03-12T00:00:00Z",
  "sig": "base64url..."
}
```

Receiving Relays verify the signature, independently fetch the new Relay's manifest, and decide whether to initiate peering. The announcement is a hint, not an authorization — each Relay makes its own trust determination.

---

## 4. Discovery

### 4.1 Gossip Protocol

Agora uses **libp2p gossipsub v1.1** for peer discovery, guild and channel advertisement, live message delivery, and MLS handshake message delivery (Welcome, Commit, Proposal).

Each gossipsub **topic** maps to a specific scope:

| Topic pattern | Purpose |
|---|---|
| `v1/agora/discovery` | Global guild/user advertisements |
| `v1/agora/guild/<guildCID>` | Guild-scoped events: joins, state updates, moderation records |
| `v1/agora/channel/<channelToken>` | Per-channel messages and ephemeral presence/typing events |
| `v1/agora/mls/<groupID>` | MLS handshake messages: Welcome, Commit, Proposal |

The `v1/` prefix is the gossip protocol version for that topic family. A future breaking change to message framing on a topic introduces a `v2/` prefix (e.g., `v2/agora/channel/<channelToken>`). Relays MUST subscribe to all versions of topics they serve. Clients negotiate which version to publish on via the `negotiated.gossipVersion` field in the `RelayChallenge` (§8.6). During a version transition period, Relays bridge messages between `v1/` and `v2/` topic variants for the same channel.

Clients subscribe to relevant topics via their connected Relays. Relays maintain full mesh connections to each other and fan out incoming messages to all connected clients subscribed to matching topics.

**Reference implementations for libp2p gossipsub:**
- Go: [`go-libp2p-pubsub`](https://github.com/libp2p/go-libp2p-pubsub)
- Rust: [`libp2p` crate, `gossipsub` module](https://docs.rs/libp2p/latest/libp2p/gossipsub/)
- JS: [`@chainsafe/libp2p-gossipsub`](https://github.com/ChainSafe/js-libp2p-gossipsub)

### 4.2 Discovery Advertisements

A **GuildAd** or **UserAd** message is gossiped periodically (default TTL: 60 seconds; re-advertised at 45 seconds to avoid expiry gaps):

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "GuildAd",
  "guildCID": "bafyrei...",
  "name": "wolfSSL Dev",
  "description": "wolfSSL development coordination",
  "memberCount": 12,
  "relayHints": [
    "wss://relay.wolfssl.com",
    "wss://relay.example.net"
  ],
  "isPublic": true,
  "advertisedBy": "did:key:z6Mk...",
  "sig": "base64url...",
  "ts": "2026-03-12T00:00:00Z"
}
```

`relayHints` are connection hints only — clients are not required to use them and SHOULD attempt direct peer connections first. `relayHints` MAY include `.onion` addresses for Tor-connected clients, clearnet HTTPS/WSS URIs, overlay-internal hostnames, and IPv6 address literals. Clients select the hint appropriate for their current transport context.

### 4.3 Relay Discovery Bootstrap

To bootstrap into the gossip network, a client needs at least one known peer. Agora supports the following bootstrap mechanisms, attempted in order:

1. **Directory sources** — user-configured URLs serving `RelayDirectory` or `GuildDirectory` documents (§4.4); the primary bootstrap mechanism in practice.
2. **Previously cached relay list** — Relays successfully contacted in a prior session, stored locally with a staleness TTL of 7 days.
3. **IPFS DHT** — Relays publish a signed record under a well-known IPNS key (`/ipns/agora.protocol/relays/v1`).
4. **DNS-SD** — `_agora._tcp` mDNS for LAN or overlay discovery.

### 4.4 Directory Documents

A **directory document** is a static JSON-LD file served at any reachable URL. It lists Guilds, Relays, or both, and MAY include references to other directory documents by URL. Users configure one or more directory source URLs in their client. Clients fetch and merge all configured sources on startup and refresh on a configurable interval (default: 1 hour).

Directory documents require no special server infrastructure. A file committed to a public GitHub repository and served via `raw.githubusercontent.com` or GitHub Pages is a valid directory source. So is an IPFS CID, a Cloudflare R2 bucket, a `.onion` URL, or any HTTPS endpoint returning valid JSON. The client does not care about the hosting mechanism — only the document format and the signature.

#### 4.4.1 Relay Directory

A `RelayDirectory` lists Relays available for client connection:

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "RelayDirectory",
  "schemaVersion": "1",
  "id": "https://raw.githubusercontent.com/example/agora-relays/main/relays.json",
  "name": "Community Relay List",
  "maintainer": "did:key:z6MkMaintainer...",
  "published": "2026-03-12T00:00:00Z",
  "ttl": 3600,
  "sig": "base64url...",
  "relays": [
    {
      "@type": "RelayEntry",
      "did": "did:key:z6MkRelay...",
      "endpoints": [
        "wss://relay.example.com",
        "wss://relay2.example.com"
      ],
      "onionEndpoints": [
        "ws://examplerelay.onion"
      ],
      "regions": ["us-west", "eu-central"],
      "operator": "Example Relay Operator",
      "operatorDID": "did:key:z6MkOperator...",
      "acceptedSchemes": ["mob", "pow"],
      "tiers": [
        { "label": "free",     "maxBandwidthMbps": 1,  "pricePerMonthPicoMOB": 0      },
        { "label": "standard", "maxBandwidthMbps": 10, "pricePerMonthPicoMOB": 500000 }
      ],
      "note": "Community relay, no logging"
    }
  ],
  "includes": [
    "https://raw.githubusercontent.com/other-org/relays/main/relays.json"
  ]
}
```

`ttl` is the number of seconds before the client should re-fetch the document. `includes` is a list of other directory document URLs whose contents are merged into this one; clients MUST limit include recursion depth to 3 to prevent cycles. `sig` is the maintainer's Ed25519 signature over the canonical CBOR serialization of the document (excluding the `sig` field). Clients SHOULD verify the signature against the `maintainer` DID but MAY accept unsigned directories with a user-visible warning.

#### 4.4.2 Guild Directory

A `GuildDirectory` lists Guilds available for browsing or joining:

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "GuildDirectory",
  "schemaVersion": "1",
  "id": "https://raw.githubusercontent.com/example/agora-guilds/main/guilds.json",
  "name": "Open Source Projects",
  "maintainer": "did:key:z6MkMaintainer...",
  "published": "2026-03-12T00:00:00Z",
  "ttl": 3600,
  "sig": "base64url...",
  "guilds": [
    {
      "@type": "GuildDirectoryEntry",
      "guildCID": "bafyrei...",
      "name": "wolfSSL Community",
      "description": "wolfSSL open source cryptography project",
      "iconCID": "bafyrei...",
      "memberCount": 340,
      "isPublic": true,
      "inviteURL": "https://invite.wolfssl.com/community",
      "relayHints": [
        "wss://relay.wolfssl.com"
      ],
      "tags": ["cryptography", "embedded", "fips", "open-source"],
      "language": "en",
      "addedBy": "did:key:z6MkMaintainer...",
      "addedAt": "2026-03-12T00:00:00Z"
    }
  ],
  "includes": [
    "https://raw.githubusercontent.com/other-org/guilds/main/guilds.json"
  ]
}
```

`inviteURL` is a human-readable join link; the join flow itself is handled by the Guild's invite mechanism (§9.3). `tags` are free-form strings for client-side filtering and discovery. `guildCID` is the authoritative guild identity — clients verify this against the guild's genesis state document when connecting to confirm they reached the right guild.

#### 4.4.3 Combined Directory

A single document MAY contain both `relays` and `guilds` arrays, typed as `AgoraDirectory`:

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "AgoraDirectory",
  "relays": [ ... ],
  "guilds": [ ... ],
  "includes": [ ... ]
}
```

This is convenient for a single maintainer publishing a curated set of both Relays and Guilds in one document.

#### 4.4.4 Client Behavior

On startup, the client fetches all configured directory sources in parallel. Results are merged: Relay lists are deduplicated by `did`; Guild lists are deduplicated by `guildCID`. The client attempts connection to the highest-priority available Relay (ordered by user preference, then by `tiers[0].pricePerMonthPicoMOB` ascending as a proxy for accessibility). Previously cached Relays from prior sessions are used immediately while directory fetches are in flight, preventing a blocking startup delay.

Directory sources are configured as an ordered list in the client's user preferences. A source earlier in the list has no priority over a later one — ordering is only used for display in the client's directory browser UI. All sources are fetched and merged regardless of order.

Failed fetches are retried with exponential backoff (base 30 seconds, maximum 1 hour). A source that consistently fails for 7 days is flagged in the UI as unreachable; it is NOT silently removed from the configured source list. The user decides whether to remove it.

Clients MUST NOT auto-add directory sources from guild state documents, relay advertisements, or any other protocol message without explicit user confirmation. Auto-population of directory sources is a privilege escalation vector — a malicious guild could otherwise silently route users to attacker-controlled Relays.

#### 4.4.5 IPFS-Hosted Directories

A directory document MAY be addressed by IPFS CID instead of (or in addition to) an HTTPS URL:

```
ipfs://bafyrei.../relays.json
ipns://k51qzi5uqu5d.../relays.json
```

Clients with IPFS gateway access fetch these via their configured gateway (default: `https://ipfs.io/ipfs/`). IPNS-addressed directories are mutable — the maintainer can update the content without changing the address — and are the preferred form for long-lived community-maintained lists. CID-addressed directories are immutable snapshots, useful for pinning a known-good state.

#### 4.4.6 Trust Model

Being listed in a directory confers no trust. A Relay in a directory is trusted only to the extent that its DID verifies against its TLS certificate and signed advertisements. A Guild in a directory is trusted only to the extent that its `guildCID` verifies against its genesis state document. A malicious directory entry pointing at a rogue Relay produces a DID mismatch at connection time and is rejected.

Directory maintainers are identified by their `maintainer` DID and signature. Users who trust a maintainer's curation can configure that directory source with confidence. Users who do not verify signatures accept unsigned or unverified entries at their own risk.

There is no global authority over directory content. Multiple competing directories can coexist and are all valid. Clients merge them all.

---

## 5. Message Ordering

### 5.1 Ordering Model

Agora uses **best-effort causal ordering**. Gossipsub does not guarantee total message order and does not need to. The requirement is that messages arrive in approximately the right order on average, with clients able to reconstruct causal order locally.

Each message envelope carries a `seq` (monotonically increasing integer per sender per channel) and an optional `causalRefs` array of message CIDs that the sender had observed before composing the message. This gives clients enough information to:

- Detect gaps (missing `seq` values from a given sender)
- Buffer out-of-order arrivals and flush the buffer when gaps close
- Detect and display causal relationships for reply threading and reaction targets

Clients SHOULD buffer messages for up to 500ms waiting for a gap to close before rendering out-of-order. After 500ms, the client should display what is available and backfill visually when the missing message eventually arrives.

**MLS Commit ordering.** MLS Commits (which advance the group epoch) require stricter ordering than application messages. Clients MUST buffer application messages from a new epoch until the Commit that opened that epoch has been received and processed. Relays MAY provide **sequence attestations** — signed sequence numbers over a channel's message stream — as an optional ordering anchor for clients that require it. Sequence attestations are advisory; clients that do not request them proceed with sender-`seq` ordering only.

**Guild state ordering.** Guild state mutations are ordered by a `seq` field on the `GuildState` document and a Lamport timestamp. Concurrent non-conflicting mutations (e.g., two admins each independently adding a different channel) are merged by taking the union. Conflicting mutations (e.g., two admins simultaneously changing the same user's role) are resolved last-writer-wins using the `seq` value. In a true simultaneous tie, the mutation signed by the higher-authority key wins (owner beats admin).


---

## 6. Messaging

### 6.1 MLS Group Structure

Each **Channel** has its own MLS group. Guild membership does not imply channel membership — each channel manages its own MLS epoch independently. This enables per-channel access control (e.g., private channels within a public guild) without any additional mechanism; it is a direct consequence of the MLS design.

MLS operations follow RFC 9420 exactly:

- **`KeyPackage`** — uploaded to the Relay KeyPackage Store (§6.1.1); rotated on each new device session and after each use.
- **`Welcome`** — sent to new members via `v1/agora/mls/<groupID>` or direct encrypted delivery.
- **`Commit`** — a state-advancing operation (Add, Remove, Update); gossiped to all current group members.
- **`Proposal`** — a pre-commit operation that may be included in a subsequent Commit by any authorized member.

The **Delivery Service** role (as defined in RFC 9420 §4) is performed by the gossipsub mesh in combination with the Relay KeyPackage Store. The **Authentication Service** role is performed by DID verification — MLS leaf node credentials are bound to DID verification keys, so verifying an MLS credential means verifying a DID.

**Reference implementations for MLS (RFC 9420):**
- Rust: [`openmls`](https://github.com/openmls/openmls) — the most complete open-source implementation
- Go: [`golang.org/x/crypto` does not yet include MLS; use openmls via CGo or await the forthcoming `go-mls` work]
- TypeScript: [`@hpke/core`](https://github.com/dajiaji/hpke-js) for HPKE primitives; full MLS client not yet available in JS
- C/C++: [`mlspp`](https://github.com/cisco/mlspp) (Cisco)

### 6.1.1 KeyPackage Store

IPFS alone is insufficient for KeyPackage distribution. IPFS provides no delivery guarantees, no availability SLA, and no mechanism for a sender to atomically fetch-and-consume a KeyPackage to prevent reuse. Relays MUST implement a **KeyPackage Store** — a simple authenticated key-value endpoint for publishing and retrieving MLS KeyPackages.

#### Relay KeyPackage API

All endpoints are authenticated using the client-relay session established in §8.6.

```
PUT  /v1/agora/kp/{did}
     Upload one or more KeyPackages for the authenticated DID.
     Body: CBOR array of RFC 9420 KeyPackage TLS-serialized objects.
     Response: 200 { "stored": N }

GET  /v1/agora/kp/{did}
     Fetch and atomically consume one KeyPackage for the target DID.
     The relay removes the returned KeyPackage from the store in the same operation.
     Response: 200 { "keyPackage": "base64url...", "remaining": N }
              404 if no KeyPackages are available for that DID

GET  /v1/agora/kp/{did}/count
     Return the number of available (unconsumed) KeyPackages without consuming any.
     Response: 200 { "count": N }

DELETE /v1/agora/kp/{did}/{keyPackageRef}
     Revoke a specific KeyPackage by its ref (the SHA-256 hash of the TLS-serialized bytes).
     Only the owning DID may revoke its own KeyPackages.
```

The `GET /count` endpoint allows a client to monitor its own KeyPackage supply and replenish proactively. Clients SHOULD maintain at least 20 pre-uploaded KeyPackages per device at all times. When `count` falls below 5, the client MUST upload a fresh batch immediately.

#### KeyPackage Replication Across Relays

A client connected to multiple Relays SHOULD upload its KeyPackages to all of them. When a sender needs to fetch a KeyPackage to issue a Welcome, it contacts the target user's preferred Relay (declared in their DID document's `service` endpoints). If that Relay has no KeyPackages for the target, it SHOULD attempt to fetch one from other known Relays serving the same guild before returning 404.

Inter-relay KeyPackage forwarding uses a simple pull model:

```
GET /v1/agora/kp/{did}?forward=true
```

The `forward=true` parameter instructs the Relay to attempt peer-relay fetching before returning 404. Relays that support forwarding declare `"keypackage-forwarding-v1"` in their capabilities.

#### KeyPackage Exhaustion

If all KeyPackages for a target DID have been consumed and no fresh ones are available (the user is offline, or the client has not replenished), the sender MUST NOT reuse a previously consumed KeyPackage. Instead:

1. The sender queues the Welcome message locally.
2. The sender publishes a `KeyPackageRequest` to `v1/agora/discovery`:

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "KeyPackageRequest",
  "targetDID": "did:key:z6Mk...",
  "requestedBy": "did:key:z6MkSender...",
  "ts": "2026-03-12T12:00:00Z"
}
```

3. When the target comes online, their client sees the `KeyPackageRequest`, uploads fresh KeyPackages to the store, and the waiting sender completes the Welcome flow.

`KeyPackageRequest` messages are ephemeral (not stored in IPLD history) and MUST NOT identify which channel or guild triggered the request — only that the target's KeyPackages are needed.

#### KeyPackage Validation

Recipients of a Welcome MUST validate the KeyPackage used to construct it:

- The signature verifies against the sender's DID authentication key.
- `KeyPackage.leaf_node.credential` contains a valid DID matching the sender.
- The KeyPackage has not expired (`leaf_node.lifetime.not_after`).
- The ciphersuite matches the group's declared ciphersuite.

A Welcome constructed with an invalid or expired KeyPackage MUST be rejected.

### 6.2 Message Format

All messages use a two-layer structure: an outer **routing envelope** visible to Relays, and an inner **sealed envelope** whose sender identity is hidden from Relays. The inner payload is MLS-encrypted.

#### Outer Routing Envelope

The outer envelope contains only what Relays strictly need for delivery routing. It does not contain the sender's DID.

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "RoutingEnvelope",
  "id": "urn:agora:msg:bafyrei...",
  "channelToken": "base64url...",
  "epoch": 17,
  "seq": 1042,
  "ts": "2026-03-12T12:00:00.000Z",
  "expiryHint": "2026-03-19T12:00:00.000Z",
  "sealedEnvelope": "base64url..."
}
```

`channelToken` is a one-way derivation from the channel CID and the current MLS epoch secret: `HKDF(epochSecret, "channel-token" || channelCID)`. It rotates with every epoch. Relays use it for topic routing without learning the actual channel identifier or any member identity. A Relay that does not hold the epoch secret cannot map a `channelToken` back to a channel or to any sender.

`id` is the CID of the canonical outer envelope, used for deduplication and history indexing. `ts` is present for gossipsub ordering and relay-side TTL enforcement only — it is not authenticated at the outer layer and MUST NOT be trusted for application-level ordering (use the inner `seq` for that). `expiryHint` is set by the sender to match the inner payload `expiry` value; Relays use it as a cache TTL hint (§6.4).

#### Sealed Envelope (Sender-Sealed, Relay-Opaque)

`sealedEnvelope` bundles the sender's DID, a per-message ephemeral key, and the MLS ciphertext, all encrypted together to the channel's current MLS group key. No Relay or non-member can open it.

Plaintext of `sealedEnvelope` before encryption:

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "SealedEnvelope",
  "sender": "did:key:z6Mk...",
  "senderEphemeralKey": "base64url...",
  "mlsCiphertext": "base64url...",
  "sig": "base64url..."
}
```

`sig` covers `sender + senderEphemeralKey + mlsCiphertext`, signed by the sender's authentication key. Recipients verify the signature after decrypting the sealed envelope. `senderEphemeralKey` is a fresh X25519 key generated per-message; it binds the sealed envelope to this specific send without exposing long-term key material to the outer layer.

This design is derived from Signal's Sealed Sender construction. A Relay processing this message learns: a `channelToken` (epoch-rotating, non-reversible without the epoch secret), a sequence number, a timestamp, and an opaque encrypted blob. It learns nothing about who sent the message.

#### Inner Payload (After MLS Decryption)

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "ChatMessage",
  "body": {
    "@type": "TextBody",
    "text": "the fips conversion is green",
    "format": "markdown"
  },
  "expiry": "2026-03-19T12:00:00.000Z",
  "attachments": [],
  "replyTo": null,
  "mentions": [],
  "causalRefs": []
}
```

### 6.3 Message Types

All inner payload types are defined in the Agora JSON-LD context namespace (`https://agora.protocol/ns/v1`):

| `@type` | Description |
|---|---|
| `TextBody` | Plain or Markdown-formatted text |
| `MediaBody` | Reference to IPFS-hosted media (CID + MIME type + size) |
| `EmbedBody` | URL unfurl card (title, description, image CID) |
| `ReactionEvent` | Emoji reaction add/remove targeting a message CID |
| `EditEvent` | Replacement body for a prior message CID |
| `DeleteEvent` | Tombstone for a prior message CID |
| `SystemEvent` | Protocol-level event (member join, role change, gateway added, etc.) |
| `VoiceSignal` | WebRTC SDP offer/answer/ICE candidate, targeted to a specific DID |
| `ParticipantState` | Ephemeral VTC room presence (joined/left, muted, video on/off, screen share) |
| `RecordingGrant` | Admin authorization for an SFU DID to decrypt media for recording |
| `RecordingRevoke` | Revocation of a prior `RecordingGrant` |
| `TypingEvent` | Ephemeral typing indicator; not stored |
| `PresenceEvent` | Ephemeral online/idle/dnd status; not stored |

Ephemeral events (`TypingEvent`, `PresenceEvent`, `ParticipantState`) use the MLS `PublicMessage` application data subtype and are excluded from history storage.

### 6.4 Message Expiry

Message lifetime is a **sender-side cryptographic commitment**, not a server-side promise or a UI affordance. The sender encodes an `expiry` timestamp in the inner payload, inside the MLS ciphertext and therefore invisible to Relays. Recipients' clients are bound by protocol to honor it — not because a Relay requested deletion, but because the expiry is part of the authenticated message content signed by the sender.

Expiry semantics:

- `expiry` is an ISO 8601 timestamp in the inner payload. Absence means no expiry (persistent by default).
- On receipt, the client schedules local deletion of the decrypted message at the expiry time.
- On expiry, clients SHOULD also submit a signed `DeleteEvent` to the channel, so that the IPLD history DAG records a tombstone and Relays drop the cached envelope.
- Relays that cache message envelopes MUST respect the `expiryHint` field in the outer `RoutingEnvelope` as a cache TTL. This field is unauthenticated at the outer layer — Relays use it as a hint only, not as authoritative content.
- The authoritative expiry is always the inner payload value, verified by recipients after MLS decryption.

The threat model this addresses: a Relay under legal compulsion cannot produce message content it has already purged. A client under legal compulsion cannot produce message content past its expiry without detectable falsification (the signed inner payload proves the sender intended deletion). Neither deletion mechanism is perfect against a sophisticated adversary who captures and retains encrypted blobs before expiry, but it substantially raises the bar against bulk retention and routine legal demands.

### 6.5 Message History

Message history is stored as an IPLD linked list. Each message envelope CID is appended to the channel's history DAG, and the channel state document tracks the latest history CID.

Clients fetch history by walking the IPLD DAG backwards from the latest CID. Relays SHOULD pin recent history within their configured retention window (default 30 days). Long-term archival beyond the retention window is the responsibility of guild operators or interested members.

IPFS provides content-addressed deduplication automatically — the same message (same CID) stored at multiple Relays is inherently deduplicated.

**Reference implementations for IPFS/IPLD:**
- Go: [`go-ipfs`](https://github.com/ipfs/go-ipfs), [`go-ipld-prime`](https://github.com/ipld/go-ipld-prime)
- JS: [`helia`](https://github.com/ipfs/helia) (successor to js-ipfs), [`@ipld/dag-cbor`](https://github.com/ipld/js-dag-cbor)
- Rust: [`rust-ipfs`](https://github.com/rs-ipfs/rust-ipfs), [`libipld`](https://github.com/ipld/libipld)

---

## 7. Presence and Ephemeral State

### 7.1 Presence

Presence is gossiped on `v1/agora/channel/<channelToken>` as a `PresenceEvent`:

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "PresenceEvent",
  "sender": "did:key:z6Mk...",
  "channel": "agora://bafyrei.../general",
  "status": "online",
  "ts": "2026-03-12T12:00:00.000Z",
  "ttl": 30
}
```

`status` values: `online`, `idle`, `dnd`, `invisible`. `ttl` is the number of seconds this presence state is valid without a refresh. Clients treat absence of a refresh within the TTL window as offline. Clients MUST publish a fresh `PresenceEvent` before TTL expiry if they remain in the stated status.

### 7.2 Typing Indicators

`TypingEvent` is gossiped to the channel topic and is never written to persistent storage:

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "TypingEvent",
  "sender": "did:key:z6Mk...",
  "channel": "agora://bafyrei.../general",
  "ts": "2026-03-12T12:00:00.000Z"
}
```

A client that receives no `TypingEvent` from a sender for 5 seconds SHOULD clear their typing indicator for that sender.

---

## 8. Transport

### 8.1 Primary Transport: WebTransport

Clients connect to Relays via **WebTransport** (IETF RFC 9000 / HTTP/3 over QUIC). WebTransport provides:

- Multiplexed bidirectional streams over a single QUIC connection
- Reliable ordered streams for MLS handshake messages and persistent message delivery
- Unreliable datagrams for presence and typing events (low-latency, loss-tolerant)

Endpoint: `https://<relay-host>/v1/agora/wt`

WebTransport requires QUIC, which runs over UDP. It is unavailable in any environment that proxies only TCP — including Tor (see §8.3).

**Reference implementations for WebTransport:** The browser has native support in Chromium-based browsers and Firefox 114+. Server-side: [`webtransport-go`](https://github.com/marten-seemann/webtransport-go), [`wtransport`](https://github.com/BiagioFesta/wtransport) (Rust).

### 8.2 Fallback Transport: WebSocket

For environments where QUIC or HTTP/3 is blocked or unavailable:

Endpoint: `wss://<relay-host>/v1/agora/ws`

WebSocket carries the same message framing over a single multiplexed binary stream. Multiplexing is handled by a lightweight channel ID prefix on each frame. WebSocket is the mandatory transport for Tor-connected clients.

### 8.3 Tor Transport Constraints

Tor proxies TCP only. This has the following protocol-level consequences:

**WebTransport unavailable.** Clients connecting via Tor MUST use WebSocket. Clients MUST NOT attempt WebTransport when operating through a SOCKS5 proxy identifiable as Tor (`.onion` exit, `torsocks`, or explicit SOCKS5 configuration). Clients SHOULD detect transport failure and fall back to WebSocket without requiring user intervention.

**VTC severely degraded.** WebRTC ICE relies on UDP for STUN hole-punching and optimal media transport. Over Tor, UDP is unavailable. The only viable VTC path over Tor is TURN-over-TCP through a TURN server reachable via a `.onion` address or a Tor-friendly clearnet endpoint. Even in this configuration, media latency over Tor circuits (typically 200–600ms round-trip) renders real-time audio/video unusable for most participants. Clients SHOULD display a warning when VTC is attempted over Tor, and MAY disable VTC participation entirely in Tor-only mode. Text channels and presence are unaffected by Tor transport constraints.

**Gossipsub fingerprinting.** Connecting to gossipsub via Tor provides IP-level anonymity but gossipsub peer scoring observes message timing and topic subscription patterns. A sufficiently persistent observer correlating topic subscription events across Tor circuits may be able to fingerprint clients by behavior. No clean mitigation exists at the protocol level; clients requiring strong anonymity SHOULD rotate Tor circuits periodically and SHOULD subscribe to decoy topics (§13.4).

**Rate limiting.** A Relay receiving connections from Tor exit nodes sees the exit node's IP address, not the client's IP. IP-based rate limiting will incorrectly aggregate all clients sharing an exit node. Relays MUST use per-`channelToken` rate limits and PoW/payment requirements as the primary spam control mechanism. Per-IP limits MAY be applied as a secondary coarse filter but MUST NOT be the sole mechanism.

**Hidden service Relays.** A Relay operating as a Tor v3 hidden service publishes its `.onion` address in its `RelayAd.relayHints`. Clients with Tor available SHOULD prefer `.onion` endpoints when available — they provide end-to-end Tor routing without depending on an exit node, protecting both the client's and the Relay operator's IP.

### 8.4 Frame Format

All frames are CBOR-encoded (compact binary), with a JSON-LD-compatible schema. Clients MAY use JSON encoding for debugging purposes; Relays MUST accept both JSON and CBOR.

Frame structure:

```
[version: u8, type: u8, topic: string, payload: bytes]
```

`version` values: `0x01` = frame format v1 (this specification). A Relay that receives a frame with an unknown `version` byte MUST discard it and MAY close the connection. Future frame format versions increment this byte.

`type` values: `0x01` Gossip, `0x02` MLS, `0x03` Ephemeral, `0x04` Control.

**Reference implementations for CBOR:** [`cbor2`](https://pypi.org/project/cbor2/) (Python), [`cbor` crate](https://crates.io/crates/cbor) (Rust), [`cbor-js`](https://github.com/paroga/cbor-js) (JS), [`fxamacker/cbor`](https://github.com/fxamacker/cbor) (Go).

### 8.5 Direct Peer Connections

Clients MAY establish direct WebRTC data channels to each other, bypassing Relays entirely. The `VoiceSignal` mechanism (§10.4) is used for ICE negotiation. Direct peer connections are mandatory for voice and video (media MUST NOT transit Relays) and optional for text messaging (latency optimization).

On WireGuard-based overlays (Tailscale, Headscale), direct peer connections benefit from overlay-managed NAT traversal. Overlay-internal `100.x.x.x` addresses appear as ICE host candidates and are preferred over STUN-discovered public addresses when both peers are on the same overlay network.

### 8.6 Client-Relay Authentication

A Relay needs to know which DID it is talking to for three purposes: ban enforcement (reject connections from banned DIDs), per-DID rate limiting (independent of per-channelToken limits), and KeyPackage Store ownership (§6.1.1). Authentication is performed once per connection via a signed challenge-response handshake that establishes a session token for the lifetime of the connection.

Authentication is **optional for read-only operations** (fetching guild state, reading history, subscribing to gossip topics). It is **required for write operations** (publishing messages, uploading KeyPackages, submitting MLS Commits) and for accessing the KeyPackage Store write API.

#### Handshake Protocol

Authentication is initiated by the client immediately after transport connection (WebTransport session establishment or WebSocket upgrade). It uses a `0x04` Control frame.

**Step 1 — Client Hello**

The client sends a `ClientHello` control frame declaring its DID and requesting a challenge:

```json
{
  "@type": "ClientHello",
  "did": "did:key:z6Mk...",
  "deviceKey": "base64url(Ed25519 pubkey)",
  "clientVersion": "agora/0.1",
  "supportedTransportVersions": ["v1"],
  "supportedGossipVersions": ["v1"],
  "supportedFrameVersions": [1],
  "ts": "2026-03-12T12:00:00.000Z"
}
```

`deviceKey` is the device's Ed25519 public key, which MUST match a verification method listed in the DID document for the declared DID. The Relay verifies this correspondence before issuing a challenge.

**Step 2 — Relay Challenge**

The Relay responds with a `RelayChallenge`:

```json
{
  "@type": "RelayChallenge",
  "nonce": "base64url(32 random bytes)",
  "relayDID": "did:key:z6MkRelay...",
  "relaySig": "base64url...",
  "ts": "2026-03-12T12:00:00.000Z",
  "expiresIn": 30,
  "negotiated": {
    "transportVersion": "v1",
    "gossipVersion": "v1",
    "frameVersion": 1
  }
}
```

`relaySig` is the Relay's Ed25519 signature over `nonce || relayDID || ts`. This simultaneously authenticates the Relay to the client — the client verifies `relaySig` against the Relay's DID before proceeding. `expiresIn` is in seconds; the client must respond within this window.

**Step 3 — Client Response**

```json
{
  "@type": "ClientAuth",
  "did": "did:key:z6Mk...",
  "nonce": "base64url...",
  "sig": "base64url..."
}
```

`sig` is the client's Ed25519 signature over `nonce || clientDID || relayDID || ts` using the `deviceKey` declared in `ClientHello`. The Relay verifies:

1. `sig` is a valid signature by the declared `deviceKey`
2. `deviceKey` is listed as an active verification method in the DID document for `did`
3. `nonce` matches the issued challenge and has not expired
4. The DID is not in the Relay's ban list for any guild the Relay serves

**Step 4 — Session Token**

On successful verification, the Relay issues a `SessionToken`:

```json
{
  "@type": "SessionToken",
  "token": "base64url(32 random bytes)",
  "did": "did:key:z6Mk...",
  "expiresAt": "2026-03-12T20:00:00.000Z",
  "relaySig": "base64url..."
}
```

The token is included as a frame header field in all subsequent write operations on this connection. It expires after 8 hours or on disconnection, whichever comes first. Clients reconnecting after expiry repeat the full handshake.

#### Anonymous Connections

A client that does not perform the authentication handshake is treated as anonymous. Anonymous connections MAY:
- Subscribe to public gossip topics
- Fetch public guild state and history
- Receive messages on subscribed topics

Anonymous connections MUST NOT:
- Publish messages to any topic
- Upload KeyPackages
- Submit MLS operations
- Access KeyPackage Store write endpoints

This allows read-only clients (bots, archivers, directory crawlers) to operate without identity, while ensuring all write operations are attributable to a DID for rate limiting and ban enforcement.

#### DID Document Freshness

The Relay caches DID documents to avoid resolving them on every connection. Cached DID documents have a TTL of 1 hour. If a client presents a `deviceKey` that was valid 2 hours ago but has since been revoked, the Relay may temporarily accept it until the cache expires. This is an accepted tradeoff between resolution latency and revocation propagation speed. Clients revoking a device key SHOULD notify their connected Relays via a signed `DeviceRevocation` control frame to accelerate cache invalidation:

```json
{
  "@type": "DeviceRevocation",
  "did": "did:key:z6Mk...",
  "revokedKey": "base64url(Ed25519 pubkey)",
  "sig": "base64url..."
}
```

`sig` is signed by any remaining valid device key for the same DID. Relays MUST process `DeviceRevocation` frames immediately and invalidate any active sessions using the revoked key.

### 8.7 Push Notification Proxy (Optional)

Mobile clients backgrounded by the OS cannot maintain a persistent WebTransport or WebSocket connection. Without a notification mechanism, a backgrounded Agora client receives no messages until the user opens the app. Agora supports an optional **Push Notification Proxy** that enables mobile wake-up notifications without exposing message content, channel identity, or sender identity to the notification infrastructure.

Push proxies are entirely optional. Relays MAY designate one; clients MAY register with one. Clients that maintain persistent connections (desktop clients, server-side bots, always-on mobile processes) do not need them.

#### 8.7.1 Privacy Model

The fundamental constraint: APNs (Apple) and FCM (Google) are centralized services that require a server-side component that knows which device token to wake up. This server-side component is the push proxy. The goal is to limit what the proxy learns to the minimum necessary for its function.

**What the push proxy learns:**
- A client's opaque `pushHandle` (a random token, not linked to any DID or channel)
- The client's APNs or FCM device token (required to send the push)
- The client's platform (`apns` or `fcm`)
- That *some* Relay sent a wake-up for that `pushHandle` at *some* time

**What the push proxy does NOT learn:**
- The client's DID
- Which Relay the client uses
- Which channels the client subscribes to
- Any message content
- The identity of any message sender

**What the Relay learns:**
- The client's DID (from the auth handshake, §8.6)
- The client's `pushHandle` (registered by the client)

**What the Relay does NOT learn:**
- The client's APNs or FCM device token (never transmitted to the Relay)
- The push proxy's internal handle-to-token mapping

The `pushHandle` is the separation layer. It is generated fresh by the client on each app install. The Relay knows DID → pushHandle. The proxy knows pushHandle → device token. Neither party has both mappings. A Relay cannot identify which physical device a DID maps to; a proxy cannot identify which DID a device token belongs to.

#### 8.7.2 Relay Manifest Extension

A Relay that supports push proxy wake-up declares its associated push proxy in the Relay Manifest:

```json
"pushProxy": {
  "endpoint": "https://push.example.com/v1/agora/push",
  "proxyDID": "did:key:z6MkProxy...",
  "platforms": ["apns", "fcm"],
  "registrationEndpoint": "https://push.example.com/v1/agora/push/register"
}
```

A Relay MAY run its own push proxy or point to a third-party proxy. Multiple Relays MAY share a single push proxy. The `proxyDID` identifies the proxy as a DID-bearing principal — the Relay authenticates to it using the same RFC 9421 signed request mechanism as relay-to-relay authentication (§3.5.3).

#### 8.7.3 Client Registration

On first launch on a mobile device, a client wishing to receive push notifications:

1. Generates a random 256-bit `pushHandle` and stores it locally.
2. Obtains a platform device token from APNs or FCM via the OS push notification API.
3. Registers `{ pushHandle, deviceToken, platform }` with the push proxy:

```
POST /v1/agora/push/register
{
  "pushHandle":  "base64url(32 random bytes)",
  "deviceToken": "hex or base64 APNs/FCM token",
  "platform":    "apns" | "fcm",
  "appBundleID": "com.example.agora"
}
Response: 200 { "registered": true, "ttl": 2592000 }
```

The proxy stores `pushHandle → { deviceToken, platform, appBundleID }`. It does not store the client's DID or any channel information. The `pushHandle` itself is the registration credential — any bearer of the handle can update or delete the registration.

4. Registers `{ pushHandle, proxyEndpoint }` with their Relay, authenticated via the session token from §8.6:

```
POST /v1/agora/push/register
{
  "pushHandle":    "base64url...",
  "proxyEndpoint": "https://push.example.com/v1/agora/push"
}
```

The Relay stores `sessionDID → { pushHandle, proxyEndpoint }` and uses this mapping to send wake-up requests when the client is offline.

**Registration renewal:** Push registrations have a TTL (default 30 days). Clients MUST renew before expiry. APNs/FCM device tokens may also change (OS reinstall, token rotation); clients MUST re-register with the proxy when they receive a new device token.

#### 8.7.4 Wake-Up Flow

When a Relay receives a message for a channel and the intended recipient client is not currently connected (no active session for that DID), the Relay:

1. Looks up the client's `{ pushHandle, proxyEndpoint }` from its registration store.
2. Sends a signed wake-up request to the proxy:

```
POST https://push.example.com/v1/agora/push/wake
x-agora-relay-did: did:key:z6MkRelay...
x-agora-timestamp: 1741780800
x-agora-nonce: base64url...
signature: sig1=:base64url...:

{
  "pushHandle": "base64url...",
  "urgency":    "normal" | "high"
}
```

The request body contains only the `pushHandle` and urgency hint — no channel, no sender, no content.

3. The proxy maps `pushHandle → deviceToken` and sends a zero-content push notification to APNs or FCM:

**APNs payload:**
```json
{
  "aps": {
    "content-available": 1,
    "alert": {}
  }
}
```

**FCM payload:**
```json
{
  "data": { "type": "agora-wakeup" },
  "android": { "priority": "high" },
  "apns": { "payload": { "aps": { "content-available": 1 } } }
}
```

Both payloads are content-free silent pushes. APNs `content-available: 1` triggers a background app refresh on iOS; FCM data-only messages do the same on Android. The OS wakes the app; the app reconnects to its Relay and receives queued messages over the authenticated session.

4. The app reconnects, completes the auth handshake (§8.6), and receives all queued messages normally.

`urgency: "high"` is used for direct messages or @mentions; it results in a high-priority push that may produce an audible notification on the device. `urgency: "normal"` is used for general channel traffic and uses silent background push only. Since the Relay cannot inspect sealed content to determine urgency, the sending client attaches an advisory urgency hint to the outer `RoutingEnvelope`:

```json
"pushUrgency": "high" | "normal"
```

This field is unauthenticated and advisory — Relays use it as-is. A malicious sender setting all messages to `high` urgency wastes push quota; per-channel rate limits (§13.5) bound the potential damage.

#### 8.7.5 Proxy Authentication and Rate Limiting

The push proxy MUST verify the RFC 9421 signature on all wake-up requests against the sending Relay's manifest. Wake-up requests from unknown or untrusted Relay DIDs MUST be rejected.

Proxies SHOULD rate-limit wake-up requests per `pushHandle` to prevent a rogue Relay from spamming a client device (for example: 1 push per 5 seconds per handle, with a burst allowance of 3). Excess wake-up requests within the window are silently dropped.

#### 8.7.6 Handle Rotation

A client MAY rotate its `pushHandle` at any time — for example, periodically for privacy, or after suspected handle compromise. Rotation procedure:

1. Generate a new `pushHandle`.
2. Register `{ new pushHandle, deviceToken }` with the proxy.
3. Register `{ new pushHandle, proxyEndpoint }` with the Relay (relay atomically replaces old handle).
4. Delete the old `pushHandle` from the proxy: `DELETE /v1/agora/push/register/{pushHandle}`.

There is a brief window between steps 2 and 3 where wake-ups to the old handle still work; this is acceptable. After step 4, the old handle is invalid and the proxy discards any wake-up requests for it.


---

## 9. Access Control and Moderation

### 9.1 Keyholders

Agora uses a three-tier authority model. Each tier's permissions are enforced cryptographically — an operation not signed by a key with the required authority MUST be rejected by conformant Relays and clients.

**Guild Owner** — holds the signing key for the Guild state document. The Guild Owner has sole authority to transfer or delete the guild, grant or revoke the Admin role, and sign Guild state mutations affecting top-level structure. There is exactly one Guild Owner at any time. Ownership transfer is executed via a signed `GuildState` mutation that replaces the `owner` DID, signed by the current owner.

**Channel/Guild Admin** — a role granted by the owner and recorded in the Guild state document. Admins can sign Guild state mutations within their granted scope, issue invites, execute moderation operations within channels they administer, and add or remove members from channel MLS groups within their scope.

**MLS Group Committer** — by default, any current MLS group member may issue Commit messages (RFC 9420 default). Guild operators MAY restrict Commit authority to a designated keyholder set via a `commitPolicy` field in the channel state. Restricting commits to a smaller set is recommended for large public channels to prevent epoch racing and Commit conflicts.

### 9.2 Guild Roles

Roles beyond Owner and Admin are defined freely in the Guild state document and enforced through MLS group membership. A user's assigned role determines which channel MLS groups they are added to when they join. Role assignment is a Guild state mutation signed by an Admin or Owner.

```json
"roles": [
  {
    "id": "member",
    "label": "Member",
    "color": "#5865F2",
    "channelAccess": ["general", "engineering/*"],
    "canInvite": false
  },
  {
    "id": "engineer",
    "label": "Engineer",
    "color": "#57F287",
    "channelAccess": ["general", "engineering/*", "voice/*"],
    "canInvite": true
  }
]
```

`channelAccess` is a list of channel path globs. When a user is assigned a role, they are added to the MLS groups for all matching channels via a Commit signed by the Admin performing the assignment. Channel access changes (role modification, role reassignment) trigger corresponding MLS Add or Remove commits.

### 9.3 Invite Flow

Invites are signed tokens linking a specific DID (or an open link) to a Guild and an optional role:

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "GuildInvite",
  "guild": "agora://bafyrei...",
  "issuedTo": "did:key:z6MkInvitee...",
  "role": "member",
  "issuedBy": "did:key:z6MkAdmin...",
  "expiresAt": "2026-04-12T00:00:00Z",
  "maxUses": 1,
  "sig": "base64url..."
}
```

Link-based invites (no `issuedTo` field) are supported for public guilds. These use a short random token that resolves to a signed invite document via the issuing Relay. Link-based invites support a `maxUses` limit; setting `maxUses: 0` means unlimited uses until the expiry date.

### 9.4 Private Channels

A channel is private if its MLS group membership is a strict subset of the Guild's member list. The channel's existence MAY be hidden from non-members — the channel path is omitted from the Guild state document served to non-members, and the access-controlled view is signed by the guild owner or a delegated admin. Non-members have no way to enumerate private channels they are not members of.

### 9.5 Moderation Operations

All moderation operations are cryptographically signed and gossip-propagated on `v1/agora/guild/<guildCID>`. Relays that serve the affected guild MUST enforce them on receipt of a valid signed record.

**Kick** — removes a member from one or more channel MLS groups without a guild-level ban. The Admin issues MLS Remove commits for the target DID across the relevant channel groups. The member retains guild membership and may be re-added to channels by an Admin.

**Ban** — removes a member from all guild channel MLS groups and records a signed `BanRecord` in the guild's moderation log:

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "BanRecord",
  "guild": "agora://bafyrei...",
  "target": "did:key:z6MkBanned...",
  "reason": "spam",
  "bannedBy": "did:key:z6MkAdmin...",
  "ts": "2026-03-12T12:00:00Z",
  "sig": "base64url..."
}
```

Relays serving the guild MUST reject message envelopes and MLS KeyPackage submissions from a banned DID. The MLS Remove commit is the authoritative enforcement mechanism — a banned user cannot re-enter channel groups because no current member will issue them a Welcome.

**Timeout** — a time-bounded moderation action with an `expiresAt` field. Relays reject message publication from the target DID for that guild until expiry. MLS group membership is not affected; the user remains a group member and can receive messages but cannot publish for the duration.

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "TimeoutRecord",
  "guild": "agora://bafyrei...",
  "target": "did:key:z6MkMuted...",
  "expiresAt": "2026-03-12T13:00:00Z",
  "issuedBy": "did:key:z6MkAdmin...",
  "sig": "base64url..."
}
```

**Message Delete** — a signed `DeleteEvent` inner payload from a keyholder with Admin authority over the channel. Relays drop the original envelope from cache on receipt. The message CID remains in the IPLD history DAG as a tombstone entry — the `DeleteEvent` becomes the history record at that position, preserving causal chain integrity while removing the content.

**Moderation Log** — all moderation actions are appended to a signed IPLD linked list. The tail CID is referenced in the Guild state document. This log is readable by guild members and provides an auditable record of who moderated whom and when, with no ability to retroactively delete entries.

---

## 10. Voice and Video (VTC)

Agora supports real-time group voice and video conferencing as a first-class channel type. The design uses WebRTC for media transport, MLS-encrypted signaling for all control messages, and an optional SFU (Selective Forwarding Unit) for scalable multi-party sessions. Media never transits Relays.

### 10.1 Voice Channel Type

A channel with `"type": "voice"` is a VTC room. It has all the properties of a text channel (MLS group, channel CID, history) plus a persistent **call state** — a real-time record of who is currently in the call and their media states.

A voice channel is always "open" — there is no concept of starting or ending a call. Participants join and leave; the room exists as long as the channel exists. This matches the Discord voice channel model and avoids the scheduling friction of call initiation.

**Transport constraints.** VTC requires UDP for ICE and media. The following constraints apply by transport context:

- **Clearnet or overlay (Tailscale, WireGuard):** Full VTC supported. Overlay networks provide ICE host candidates directly; NAT traversal is handled by the overlay.
- **Tor:** VTC is severely degraded. UDP is unavailable over Tor; only TURN-over-TCP paths are possible, adding 200–600ms latency. Clients operating in Tor-only mode SHOULD warn users before joining a voice channel and MAY disable VTC participation entirely.

### 10.2 Call State

Call state is ephemeral, gossip-propagated, and not stored in IPLD history. It is maintained as a set of `ParticipantState` records, one per active participant, gossiped on `v1/agora/channel/<channelToken>` alongside presence events:

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "ParticipantState",
  "sender": "did:key:z6Mk...",
  "channel": "agora://bafyrei.../voice/lounge",
  "status": "joined",
  "audioMuted": false,
  "videoEnabled": true,
  "screenSharing": false,
  "handRaised": false,
  "ts": "2026-03-12T12:00:00.000Z",
  "ttl": 15
}
```

`status` values: `joined`, `left`. A client whose `ParticipantState` has not been refreshed within `ttl` seconds is considered to have left. Clients MUST re-publish their state at least every `ttl / 2` seconds while in a call.

`audioMuted`, `videoEnabled`, `screenSharing`, and `handRaised` are advisory UI hints gossiped to other participants. They are not enforced at the media layer. A malicious client can misrepresent its mute state; enforcement at the media level is the SFU's responsibility when one is present.

Call state events are delivered as MLS `PublicMessage` application data — authenticated by the sender's MLS credentials but not encrypted, since call state is visible to all channel members.

### 10.3 Join and Leave

**Join** — a client sends a `ParticipantState` with `status: "joined"` to the channel gossip topic, then initiates WebRTC negotiation with existing participants or the SFU.

**Leave** — a client sends `ParticipantState` with `status: "left"` and closes its WebRTC connections. Clients that disconnect without sending a leave message (crash, network drop) are timed out by other participants after `ttl` seconds.

Join and leave operations do NOT change MLS group membership. A user can be a member of a voice channel's MLS group (and therefore able to receive call state and signaling) without being actively in the call. Being in the call means having an active `ParticipantState` with `status: "joined"` and live WebRTC connections.

### 10.4 Signaling

All WebRTC signaling (SDP offer/answer, ICE candidates) is delivered as `VoiceSignal` inner payloads, MLS-encrypted to the voice channel's group:

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "VoiceSignal",
  "signalType": "offer",
  "targetDID": "did:key:z6MkTarget...",
  "sdp": "v=0\r\no=- ...",
  "candidates": [],
  "ts": "2026-03-12T12:00:00.000Z"
}
```

`signalType` values: `offer`, `answer`, `candidate`, `candidate-end`. `targetDID` is the intended recipient — either another participant (in mesh mode) or the SFU DID (in SFU mode). All signals are broadcast to the channel MLS group; non-target recipients MUST ignore signals not addressed to them.

The consequences of MLS-encrypted signaling:
- **E2EE signaling** — Relays cannot read SDP or ICE candidates.
- **Authenticated signaling** — the MLS sender credential binds each signal to a verified DID.
- **Authenticated DTLS fingerprint** — the DTLS-SRTP fingerprint in the SDP is authenticated by the MLS signature, closing the identity binding loop: a participant's media stream is cryptographically bound to their DID (see §10.10).

For ICE trickling, `candidate` signals are sent as individual messages as candidates are discovered. `candidate-end` signals that ICE gathering is complete.

### 10.5 Topology: Mesh vs SFU

**Mesh (≤4 participants, recommended)** — each participant establishes a direct WebRTC PeerConnection to every other participant. No SFU is required. Signaling is peer-to-peer via the MLS channel. Latency is minimized; bandwidth scales as O(n²).

**SFU (>4 participants, recommended)** — participants connect to a Selective Forwarding Unit which receives each participant's streams and forwards them selectively. Bandwidth scales as O(n). The SFU does not decode or re-encode media — it forwards RTP packets based on subscriber requests (simulcast layer selection, spatial/temporal scalability).

The threshold of 4 is a recommendation. Clients MAY negotiate mesh topology for larger groups if all participants have sufficient bandwidth and consent.

### 10.6 SFU Integration

#### SFU Identity and Trust

An SFU has a DID, just like a user. Before an SFU can participate in a voice channel, its DID MUST be added to the channel's MLS group via a normal MLS Add commit, signed by a channel Admin. This is the trust establishment step — an SFU that has not been admitted to the MLS group cannot receive signaling or be legitimately used for that channel. A participant's client MUST verify the SFU's DID against the channel's MLS group membership before connecting to it; an SFU not in the group MUST be rejected.

#### SFU Discovery

Guild operators publish their SFU's DID and WebRTC endpoint in the Guild state document:

```json
"sfus": [
  {
    "@type": "SFUDescriptor",
    "did": "did:key:z6MkSFU...",
    "endpoint": "wss://sfu.example.com/v1/agora/sfu",
    "regions": ["us-west", "eu-central"],
    "maxParticipants": 500
  }
]
```

Clients select the SFU with the lowest-latency region. Multiple SFUs MAY be listed for redundancy and regional load distribution.

**Reference SFU implementations:** [`mediasoup`](https://mediasoup.org/) (Node.js/Rust), [`Pion SFU`](https://github.com/pion/ion-sfu) (Go), [`LiveKit`](https://github.com/livekit/livekit) (Go, open-source). Any SFU that supports WebRTC simulcast and standard RTP/RTCP can be adapted.

#### SFU Signaling Flow

1. Client sends `VoiceSignal { signalType: "offer", targetDID: <sfuDID> }` to the channel.
2. SFU receives the offer (it is an MLS group member), responds with `VoiceSignal { signalType: "answer", targetDID: <clientDID> }`.
3. ICE candidates are exchanged via `candidate` signals.
4. DTLS handshake completes over the established ICE path — fingerprint from SDP is verified against the SFU's DID document.
5. SRTP media flows.

The SFU subscribes to the channel gossip topic to receive `ParticipantState` events and know which streams to forward to which subscribers.

#### SFU Media Opacity

The SFU forwards SRTP packets without decrypting them. It cannot read audio or video content. It CAN observe:
- Which participants are sending media (RTP SSRC → participant mapping)
- Packet timing and sizes (traffic analysis)
- Whether a stream is active or silent (via RTP activity detection)

This is an accepted tradeoff. An SFU that forwards without decrypting is a routing device, not a surveillance device. The alternative — full E2EE media with per-participant keys — requires Insertable Streams (WebRTC IS) and is specified as an optional extension in §10.9.

#### SFU Recording

An SFU MAY be granted explicit decryption rights for recording. This is a deliberate, auditable, and reversible action:

1. A channel Admin sends a signed `RecordingGrant` inner payload to the channel:

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "RecordingGrant",
  "sfuDID": "did:key:z6MkSFU...",
  "grantedBy": "did:key:z6MkAdmin...",
  "scope": "audio-only",
  "expiresAt": "2026-03-12T14:00:00Z",
  "sig": "base64url..."
}
```

2. On receiving a valid `RecordingGrant`, each participant's client derives a shared recording key from the current MLS epoch secret and delivers it to the SFU via an encrypted direct message.
3. The `RecordingGrant` is stored in the channel's IPLD history — it is a permanent, auditable record that recording was enabled, by whom, and for how long.
4. On `expiresAt` or on receipt of a signed `RecordingRevoke`, clients stop delivering recording keys. The SFU cannot decrypt subsequent media.

### 10.7 Simulcast and Bandwidth Adaptation

Clients SHOULD publish video in multiple simulcast layers (e.g., 1080p / 360p / 180p) to allow the SFU to forward the appropriate quality tier to each subscriber based on their available bandwidth. Layer selection is signaled via RTCP feedback from subscribers to the SFU; the SFU selects the highest layer that fits each subscriber's declared bandwidth budget.

For Scalable Video Coding (SVC) codecs (VP9, AV1), temporal and spatial scalability layers are used instead of discrete simulcast tracks. SFU implementations SHOULD support both simulcast (VP8, H.264) and SVC (VP9, AV1).

Audio is always single-layer. The SFU performs comfort noise injection and silence suppression detection (via Voice Activity Detection on the RTP stream) to forward only active speakers, with a configurable active-speaker window (default: 3 simultaneous speakers).

### 10.8 Screen Sharing

Screen sharing is a video track with a declared purpose. The sharing participant sets `"screenSharing": true` in their `ParticipantState` and adds a second video transceiver to their PeerConnection with a `content` attribute of `"screen"` in the SDP:

```
a=content:screen
```

Clients receiving a screen share track SHOULD display it distinctly from camera video (larger tile, dedicated layout region). Multiple participants MAY share simultaneously; the SFU forwards all active screen share tracks.

Screen share tracks use a separate simulcast configuration from camera video: typically high resolution (up to 1080p or 1440p), low frame rate (5–15 fps), with a high-quality spatial layer prioritized over temporal smoothness.

### 10.9 End-to-End Encrypted Media (Optional Extension)

The default SFU topology trusts the SFU not to analyze RTP packet content. For higher-threat deployments, **WebRTC Insertable Streams** (W3C) enable per-hop media encryption with participant-held keys, such that the SFU forwards ciphertext it cannot decrypt even at the packet level.

In this mode:
- Each participant holds a media encryption key derived from the MLS epoch secret: `HKDF(epochSecret, "media-key" || participantDID)`
- Outgoing media is encrypted by the sender's Insertable Streams transform before entering the RTP stack
- The SFU forwards encrypted RTP packets opaquely
- Each receiving participant's Insertable Streams transform decrypts using the sender's derived media key

Media keys rotate with MLS epochs. A participant whose MLS leaf is removed loses their media key derivation capability for subsequent epochs — they cannot decrypt new media even if they retain a stale RTP stream.

This extension requires browser/runtime support for Insertable Streams (available in Chromium-based browsers; partial in Firefox). It is declared in the channel state as `"e2eeMedia": true`. Clients that do not support Insertable Streams MUST NOT join a channel with `e2eeMedia: true`.

### 10.10 DTLS-SRTP Identity Binding

WebRTC media is encrypted with DTLS-SRTP. The DTLS handshake uses a self-signed certificate; the certificate fingerprint is included in the SDP offer and answer. In standard WebRTC, this fingerprint is unauthenticated — a man-in-the-middle could substitute their own certificate.

In Agora, the SDP carrying the fingerprint is delivered as a `VoiceSignal` inner payload, MLS-encrypted and signed by the sender's DID authentication key. Recipients verify the MLS signature before processing the SDP. This means:

- The DTLS fingerprint is authenticated by the sender's DID.
- A Relay or network attacker cannot substitute a different certificate without breaking the MLS signature.
- The media stream is cryptographically bound to the sending DID.

This closes the identity binding loop without requiring any PKI or certificate authority. The MLS group membership proof IS the identity assertion for media.

### 10.11 TURN Server Integration

WebRTC ICE succeeds with direct peer connectivity in most cases but fails for participants behind **symmetric NAT** — a common configuration in corporate networks, mobile carriers, and some ISPs. In symmetric NAT, the external IP:port mapping changes per destination, so ICE hole-punching fails and a TURN relay is required as a fallback.

TURN servers relay media packets between participants who cannot establish a direct path. Unlike the SFU (which makes forwarding decisions), a TURN server is a dumb packet relay — it forwards whatever it receives without any knowledge of stream identity or content. In SRTP deployments the TURN server cannot read media.

#### TURN Server Identity

TURN servers in Agora have DIDs, published in the Guild state document alongside SFU entries:

```json
"turnServers": [
  {
    "@type": "TURNDescriptor",
    "did": "did:key:z6MkTURN...",
    "uri": "turns:turn.example.com:5349",
    "transport": "tcp",
    "regions": ["us-west", "eu-central"],
    "credentialScheme": "agora-hmac-did"
  }
]
```

`uri` follows the standard TURN URI format (RFC 7065). `turns:` (TLS) is required; `turn:` (plaintext) MUST NOT be used. `transport` is `tcp` or `udp`; TCP is preferred for firewall traversal. Multiple TURN servers MAY be listed for regional redundancy.

**Reference implementations:** [`coturn`](https://github.com/coturn/coturn) is the standard open-source TURN/STUN server. Any RFC 5766 / RFC 7065 compliant TURN implementation can be adapted.

#### TURN Credentials

Standard TURN uses username/password credentials. Agora replaces this with **DID-based HMAC credentials** (`credentialScheme: "agora-hmac-did"`) to avoid any credential that could identify a user to the TURN operator:

1. The TURN server publishes a time-scoped HMAC key in its `TURNDescriptor`, rotated every 24 hours: `hmacKey = HKDF(turnMasterSecret, "turn-key" || floor(unixtime / 86400))`
2. A client wishing to use the TURN server computes: `username = floor(unixtime / 86400) || ":" || randomNonce` and `credential = HMAC-SHA256(hmacKey, username)`
3. The client presents these credentials in the ICE `candidate` for the TURN allocation.
4. The TURN server verifies the HMAC without learning the client's DID or any persistent identity.

The TURN operator sees: a valid HMAC credential, a source IP, and opaque SRTP packets. It cannot link the session to a DID, channel, or guild. The 24-hour HMAC key rotation means captured credentials are useless after they expire.

The TURN server's published HMAC key material is signed by its DID and gossiped on `v1/agora/guild/<guildCID>`. Clients verify the signature against the TURN server's DID document before using its credentials.

#### ICE Candidate Priority

Clients MUST follow standard ICE candidate priority ordering, which naturally prefers direct connectivity over relayed paths:

1. Host candidates (direct LAN or overlay)
2. Server-reflexive candidates (STUN, public IP via NAT)
3. Peer-reflexive candidates (discovered during connectivity checks)
4. Relay candidates (TURN)

TURN candidates are only used if all higher-priority paths fail. Clients SHOULD include at least one TURN candidate in all offers to ensure connectivity for symmetric NAT participants.

#### TURN Credential Distribution

TURN credentials are short-lived and not sensitive (they authorize TURN allocation, not channel membership or identity). They MAY be distributed as plaintext in the outer `RoutingEnvelope` as a `TURNCredentialHint` alongside the `VoiceSignal`, or fetched directly from the TURN server's HTTP endpoint using the DID-HMAC scheme before signaling begins.

For `e2eeMedia: true` channels, TURN credential computation uses the MLS epoch secret as an additional HMAC input: `credential = HMAC-SHA256(hmacKey, username || epochSecret[:16])`. This binds TURN access to current MLS group membership — a participant removed from the MLS group loses the ability to compute valid TURN credentials for subsequent epochs.


---

## 11. Relay Behavior

### 11.1 Relay Knowledge Constraints

A conformant Relay is explicitly designed to know as little as possible about the traffic it routes. The following is both a design target and a compliance requirement: a Relay operator responding to a legal demand or subpoena MUST be able to honestly testify to all of the following:

- I do not know who my users are (no identity registration, no account system, no persistent user records).
- I do not know who is in any group (channel membership is not visible at the relay layer; `channelToken` is epoch-rotating and non-reversible without the epoch secret).
- I do not know who sent any message (sealed sender design; sender DID is inside the MLS ciphertext).
- I store nothing after delivery beyond the configured retention window, and nothing with a message expiry past that expiry.
- The encrypted blobs I forward and cache are opaque to me.

Any protocol extension or Relay implementation that makes any of these statements false introduces a legal liability surface for operators and a surveillance surface for adversaries. Such extensions MUST be explicitly opt-in and clearly documented as degrading the Relay's metadata-blindness guarantees.

### 11.2 Relay-Blind Fan-out

Relays route messages by `channelToken`, not by channel CID or member identity. The routing table maps `channelToken` → set of subscriber connections. Relays MUST NOT:

- Maintain a mapping from `channelToken` to channel CID.
- Maintain a mapping from `channelToken` to member DIDs.
- Log sender/recipient pairs for any message.
- Retain message envelopes beyond the configured retention window or message expiry, whichever is sooner.

The `channelToken` rotates with every MLS epoch. A Relay that captures routing tables across epochs cannot correlate them without also capturing the epoch secrets, which it has no access to.

### 11.3 Conformance Requirements

A conformant Relay MUST:

- Implement WebSocket transport (§8.2); WebTransport is RECOMMENDED.
- Implement the client-relay authentication handshake (§8.6).
- Implement the KeyPackage Store API (§6.1.1).
- Implement the Peer API and relay-to-relay authentication (§3.5).
- Enforce ban records received via guild gossip (§9.5).
- Enforce timeout records for their specified duration (§9.5).
- Respect `expiryHint` on cached message envelopes (§6.4).
- Apply per-`channelToken` rate limits (§13.5).
- Publish a Relay Manifest at `/.well-known/agora-relay` (§3.5.1).
- Maintain heartbeat polling of peer relays (§3.5.6).
- Route messages by `channelToken` only; never attempt to resolve tokens to identities.
- Cache message envelopes up to the lesser of: configured retention window (default 30 days) or the envelope's `expiryHint`.
- Delete cached envelopes on receipt of a valid signed `DeleteEvent` for their CID.
- Pin IPFS content for channels it serves within the retention window.
- Validate outer envelope structure and `channelToken` format before forwarding; drop malformed envelopes silently.
- Support IPv6 on all endpoints; use bracket notation for IPv6 literals in advertised URIs.
- Enforce per-`channelToken` rate limits as the primary spam control mechanism; per-IP limits MUST NOT be the sole mechanism.

A conformant Relay MUST NOT:

- Attempt to decrypt MLS ciphertext.
- Log or retain sender DIDs (sealed sender design means the Relay never has them).
- Use per-IP rate limiting as the sole spam control mechanism.
- Reuse a consumed KeyPackage.
- Modify gossipsub messages in transit.

A conformant Relay SHOULD:

- Announce itself on `v1/agora/discovery` with a signed `RelayAd` including all available endpoint URIs.
- Operate a Tor hidden service endpoint to protect operator IP and support Tor-connected clients.
- Maintain peering connections to at least 3 other known Relays.
- Offer an HTTP API for history fetch: `GET /v1/agora/history/<channelToken>?before=<cid>&limit=50`.
- Implement gossipsub peer scoring to limit amplification attacks.

Relay federation is permissionless. Any Relay that speaks the protocol may join the mesh.

---

## 12. Relay Economics

Agora Relays incur real costs: bandwidth, compute, storage, legal exposure, and abuse handling. Without a sustainable incentive model, the public Relay ecosystem collapses to hobbyists and ideologically motivated operators — adequate for a niche deployment, inadequate at internet scale. Agora specifies two complementary funding mechanisms: service agreements for organized communities, and micropayments for public or anonymous traffic. A third option — proof-of-work — provides spam deterrence without any payment infrastructure.

All three mechanisms are **optional extensions** to the core protocol. A Relay that serves only private, trusted traffic requires no payment infrastructure whatsoever.

### 12.1 Payment Schemes

#### PaymentPointer

All payment destinations in Agora are expressed as a `PaymentPointer` — an abstract type carrying a scheme identifier and a scheme-specific address. The protocol is not coupled to any single payment network; new schemes can be registered via the Agora extension namespace.

```json
{
  "@type": "PaymentPointer",
  "scheme": "mob",
  "address": "3CN5..."
}
```

**Defined schemes:**

| Scheme | Network | Best for | Notes |
|---|---|---|---|
| `mob` | MobileCoin | Micropayments, service agreements | **Preferred for v0.1.** Private by default (CryptoNote one-time addresses, RingCT — no public tx graph), ~5s finality, no routing complexity |
| `cashu` | Cashu ecash over Lightning | High-frequency micropayments | Chaumian blind tokens — mint cannot link issuance to redemption; Relay holds a spent-token DB per trusted mint; bearer instrument, works offline |
| `bolt12` | Lightning Network | Service agreements, larger settlements | Reusable offers; routing reliability degrades for sub-sat amounts; no native browser support without custodial LSP |
| `bolt11` | Lightning Network | Single-use invoice fallback | Use only when the counterparty cannot receive BOLT 12 |
| `xmr` | Monero | Large periodic settlements | Gold standard on-chain privacy; ~2min block time; not suitable for per-message fees |
| `onchain-btc` | Bitcoin | Large periodic settlements | High latency and fees; last resort for settlement only |
| `pow` | Hashcash-style PoW | Spam deterrence, no payment | No money changes hands; see §12.4 |

Implementations MUST support at least one of `mob` or `cashu` for micropayment-capable channels. `bolt12` SHOULD be supported for service agreements. `pow` requires no payment infrastructure and any implementation MAY support it.

**Why MobileCoin is preferred for v0.1:** MOB is private by default — every transaction uses CryptoNote one-time addresses and RingCT, so the payment graph is not public. This aligns with Agora's threat model: a Relay accepting MOB payments cannot be shown, via payment graph analysis, to be receiving funds from a specific user. Lightning payments, even over Tor, leak payment graph information to routing nodes. Cashu is comparably private but introduces mint trust. MOB has no routing problem, no channel liquidity to manage, and finality in seconds.

#### GuildTreasury

A Guild MAY declare a treasury — a payment destination that receives a fraction of message fees and relay fee-sharing. The treasury is a `PaymentPointer` in the Guild state document, not a custodian:

```json
"treasury": {
  "@type": "GuildTreasury",
  "paymentPointers": [
    { "@type": "PaymentPointer", "scheme": "mob",    "address": "3CN5..." },
    { "@type": "PaymentPointer", "scheme": "cashu",  "address": "https://mint.example.com" },
    { "@type": "PaymentPointer", "scheme": "bolt12", "address": "lno1pg..." }
  ],
  "description": "wolfSSL Dev infrastructure fund",
  "feeShareBps": 1000
}
```

`feeShareBps` is the basis points (0–10000) of relay service agreement revenue the Relay is expected to route to the treasury. Enforcement is by Relay selection — Guild owners choose Relays that honor their declared fee-share terms. Clients and Relays select the first scheme they support from the `paymentPointers` list.

### 12.2 Relay Service Agreements

A `RelayServiceAgreement` is a bilaterally signed document between a Guild owner DID and a Relay DID specifying channels served, SLA terms, price, and fee-share obligation. It is the primary funding mechanism for organized communities.

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "RelayServiceAgreement",
  "id": "urn:agora:rsa:bafyrei...",
  "relay": "did:key:z6MkRelay...",
  "guild": "agora://bafyrei...",
  "channels": ["*"],
  "retentionDays": 90,
  "bandwidthTierGbPerMonth": 100,
  "price": {
    "@type": "PaymentPointer",
    "scheme": "mob",
    "address": "3CN5..."
  },
  "billingCycleDays": 30,
  "feeShareBps": 1000,
  "guildTreasuryPointer": {
    "@type": "PaymentPointer",
    "scheme": "mob",
    "address": "3CN5..."
  },
  "validFrom": "2026-03-12T00:00:00Z",
  "validUntil": "2027-03-12T00:00:00Z",
  "relaySig": "base64url...",
  "guildOwnerSig": "base64url..."
}
```

`channels` is a list of channel path globs. `"*"` means all current and future channels in the guild. The agreement is gossiped on `v1/agora/guild/<guildCID>` and stored in the guild's IPLD state. Multiple concurrent agreements (multiple Relays serving the same guild) are valid and encouraged for redundancy.

Relays publish their service tiers and accepted payment schemes in their `RelayAd`. Prices are denominated in picoMOB (10⁻¹² MOB) for precision:

```json
{
  "@type": "RelayAd",
  "did": "did:key:z6MkRelay...",
  "endpoint": "https://relay.example.com",
  "acceptedSchemes": ["mob", "cashu", "bolt12"],
  "serviceTiers": [
    {
      "id": "hobbyist",
      "retentionDays": 7,
      "bandwidthTierGbPerMonth": 10,
      "pricePerMonthPicoMOB": 0,
      "feeShareBpsMax": 0
    },
    {
      "id": "standard",
      "retentionDays": 30,
      "bandwidthTierGbPerMonth": 100,
      "pricePerMonthPicoMOB": 1000000000,
      "feeShareBpsMax": 2000
    },
    {
      "id": "enterprise",
      "retentionDays": 365,
      "bandwidthTierGbPerMonth": 1000,
      "pricePerMonthPicoMOB": 10000000000,
      "feeShareBpsMax": 5000
    }
  ],
  "sig": "base64url...",
  "ts": "2026-03-12T00:00:00Z"
}
```

### 12.3 Message Micropayments

Micropayments attach a small fee to individual message delivery. Purposes: Relay revenue for public traffic, and spam deterrence.

Micropayments are **optional and channel-scoped** via `messageFeePolicy` in the channel state document:

```json
"messageFeePolicy": [
  {
    "@type": "MessageFeePolicy",
    "scheme": "mob",
    "feeAmount": "1000",
    "feeDenomination": "picoMOB",
    "relayShareBps": 7000,
    "guildShareBps": 2000,
    "freeMessageQuota": 100,
    "senderRefundOnReply": true
  },
  {
    "@type": "MessageFeePolicy",
    "scheme": "cashu",
    "feeAmount": "1",
    "feeDenomination": "sat"
  },
  {
    "@type": "MessageFeePolicy",
    "scheme": "pow",
    "difficulty": 18
  }
]
```

`relayShareBps` + `guildShareBps` MUST sum to ≤ 10000. The remainder is burned to a provably unspendable address. `senderRefundOnReply`: if a recipient replies to a message, the sender's fee is refunded — a social mechanic incentivizing content worth responding to. `freeMessageQuota` is the number of messages per MLS epoch a member may send without payment; after exhaustion, payment is required. A channel MAY declare multiple fee policies under different schemes; clients satisfy whichever policy they support.

#### Payment Flow

When a channel requires payment, the sending client attaches a `MessagePayment` to the outer `RoutingEnvelope` before submission:

```json
{
  "@type": "MessagePayment",
  "scheme": "mob",
  "relayPaymentProof": "base64url...",
  "guildPaymentProof": "base64url...",
  "ts": "2026-03-12T12:00:00.000Z"
}
```

Both payments are made before submitting the envelope. The Relay verifies only its own payment proof before forwarding; it does not verify or intermediate the guild payment:

```
Sender
  ├── relayShareBps × feeAmount → Relay payment pointer
  └── guildShareBps × feeAmount → Guild treasury pointer
```

For `mob`: `relayPaymentProof` is a MOB transaction receipt (key image + amount commitment). For `cashu`: it is a spent-token proof presented to the Relay's trusted mint list. For `bolt12`/`bolt11`: it is a Lightning payment preimage.

The Relay tracks free quota consumption per `channelToken` per epoch. Guild admins may grant extended free quotas to specific roles via a signed `QuotaGrant` message gossiped to the channel topic.

### 12.4 Proof-of-Work Spam Deterrence

Channels that want spam deterrence without any payment infrastructure MAY use proof-of-work instead of or alongside monetary fees:

```json
{ "@type": "MessageFeePolicy", "scheme": "pow", "difficulty": 18 }
```

`difficulty` is the number of leading zero bits required in the hash of the message envelope. A client sending a message computes a nonce such that `SHA256(envelopeBytes || nonce)` has at least `difficulty` leading zero bits, then includes the nonce in the outer `RoutingEnvelope`:

```json
"powProof": {
  "@type": "PowProof",
  "nonce": "base64url...",
  "difficulty": 18
}
```

The Relay verifies the PoW before forwarding. Difficulty 18 requires ~262,000 SHA-256 hash operations — roughly 10–50ms on a modern CPU, imperceptible to a human sender, but economically prohibitive for bulk message flooding. Difficulty is tunable by channel admins via a signed channel state mutation. PoW provides spam deterrence only, not Relay revenue.

### 12.5 End-to-End Payment Flow Summary

| Direction | Mechanism | Purpose |
|---|---|---|
| Guild owner → Relay | `RelayServiceAgreement` recurring payment | Reliable relay service, history retention, SLA |
| Relay → Guild treasury | Fee-share from service agreement revenue | Community sustainability fund |
| Message sender → Relay | `MessagePayment` proof-of-payment | Relay revenue for public traffic, spam deterrence |
| Message sender → Guild treasury | `MessagePayment` proof-of-payment | Community fund, spam deterrence |
| Message sender → (none) | `PowProof` | Spam deterrence only, no revenue |

All flows are optional. A self-hosted zero-fee deployment uses none of them. A large public guild with anonymous users may use all of them simultaneously across different channels.

---

## 13. Security Considerations

### 13.1 Forward Secrecy

MLS provides forward secrecy by design. Each epoch derives a new application secret via the MLS key schedule. Compromise of a member's current epoch key material does not expose prior messages, which were encrypted under previous epoch secrets.

### 13.2 Post-Compromise Security

MLS `Update` proposals (triggered by devices or by time-based policy) ratchet the ratchet tree forward, healing from key compromise. A member whose keys were compromised but who subsequently performs an `Update` commit regains security — the compromised old key material cannot decrypt new messages. Guild operators SHOULD enforce periodic key rotation (recommended: 7-day maximum epoch lifetime for active channels).

### 13.3 Relay Trust and Legal Exposure

Relays are untrusted for message content and deliberately blind to metadata. The threat model addressed here is: a Relay operator receives a subpoena or legal demand. What can they produce?

**What a Relay can observe:**
- That a connection was made from an IP address at a given time.
- That messages matching a `channelToken` were forwarded (opaque encrypted blob, no content, no identity).
- Cached message envelopes within the retention window (opaque, MLS-encrypted, sender DID sealed inside).
- The existence and approximate size of a gossipsub topic mesh.

**What a Relay cannot observe:**
- Message content (MLS E2EE; the Relay never holds decryption keys).
- Sender identity for any message (sealed sender; sender DID is inside the MLS ciphertext).
- Channel identity from `channelToken` (epoch-rotating HKDF derivation, non-reversible without the epoch secret).
- Group membership (no membership list at the Relay layer).
- Message graphs or conversation structure.

**What a Relay cannot do:**
- Forge messages (sender DID and signature are inside the sealed envelope, verified by recipients).
- Silently modify history (IPLD content addressing detects tampering).
- Map routing tables across epochs without epoch secrets.

Clients SHOULD connect to multiple Relays simultaneously. A single Relay going dark (legal seizure, operator shutdown) does not partition a user from their channels as long as at least one other Relay serving that `channelToken` is reachable.

### 13.4 Metadata Leakage

The sealed sender design eliminates sender identity from the Relay layer. Residual metadata leakage points:

**IP address** — a Relay sees the connecting IP. Clients requiring IP-level anonymity SHOULD connect via Tor (preferring the Relay's `.onion` endpoint where available, to avoid exit node exposure) or a trusted front-end proxy.

**Timing correlation** — a global passive adversary watching both sender and Relay can correlate message timing. This is a known limitation of all low-latency messaging protocols. Mixing/batching (as in Katzenpost) defeats timing analysis but is incompatible with Discord-like UX latency targets. This is an accepted tradeoff.

**Gossipsub topic subscription** — Relays and mesh peers observe which `channelTokens` a peer subscribes to. Since tokens rotate per epoch, long-term correlation requires capturing multiple epochs' tokens. Clients MAY subscribe to decoy `channelTokens` (derived from non-existent channels using valid HKDF derivation) to obscure their actual channel membership count and pattern. Clients requiring strong subscription privacy SHOULD maintain a fixed subscription count (padding with decoys to a constant) and rotate decoy selections each epoch.

**Tor gossipsub fingerprinting** — as noted in §8.3, gossipsub peer scoring observes message timing and subscription behavior independently of IP. A client connecting via Tor is not fully anonymous at the gossipsub layer. Clients requiring strong anonymity against a Relay-level adversary should treat this as a known residual risk.

**Channel token to channel CID correlation** — the `channelToken` derivation uses `HKDF(epochSecret, "channel-token" || channelCID)`. An adversary who obtains the epoch secret (e.g., via member compromise) can compute the token for any channel they know the CID of. This is acceptable: epoch secret compromise already implies full message compromise for that epoch; the token mapping adds no new capability beyond what the compromised epoch secret already provides.

### 13.5 Denial of Service

Gossipsub v1.1 includes peer scoring and flood control built-in. Relays MUST enforce per-`channelToken` rate limits on message publication. Spam control is local policy — there is no global reputation system (by design; global reputation systems become censorship infrastructure).

---

## 14. JSON-LD Context and Canonicalization

The canonical Agora JSON-LD context is published at:

```
https://agora.protocol/ns/v1
```

It maps all Agora message types and properties to globally unique IRIs and declares their relationship to relevant external vocabularies (schema.org, W3C DID Core, ActivityStreams where applicable).

All Agora messages MUST include `"@context": "https://agora.protocol/ns/v1"` or an equivalent inline context. Processors that do not perform full JSON-LD expansion MAY treat the context URL as a version tag, but MUST NOT reject messages that include additional `@context` entries for extension vocabularies.

The context URL is versioned: `/ns/v1` is the v1 schema. A breaking change to the type system produces `/ns/v2`. The context URL is frozen once published — `/ns/v1` will always describe the v1 schema without modification. A document using v2 types in a v1-context document MUST include the v2 context as an additional `@context` entry.

### 14.1 Canonicalization and Signing Pipeline

All signatures over JSON-LD documents in this specification use the following normative pipeline:

1. **Expand** the document using the Agora JSON-LD context, resolving all terms to absolute IRIs. Use a strict JSON-LD 1.1 processor. Unknown terms MUST be dropped during expansion, not passed through.
2. **Serialize** the expanded document to RDF N-Quads (one quad per line, no trailing blank line).
3. **Canonicalize** the N-Quads dataset using **URDNA2015** (W3C RDF Dataset Normalization Algorithm). This deterministically renames blank nodes and sorts quads, producing a stable byte string regardless of input key ordering or whitespace.
4. **Hash** the canonical N-Quads byte string with **SHA-256**, producing a 32-byte digest.
5. **Sign** the digest with **Ed25519** using the signer's authentication key. The signature is 64 bytes (RFC 8032).

The resulting signature is encoded as **base64url** (no padding) and placed in the document's `proof.signatureValue` field (W3C Data Integrity Proofs format), or carried out-of-band in the enclosing envelope depending on context (see §6.2 for message signing, §3.5 for Relay manifest signing).

This pipeline is identical to **W3C Data Integrity Proofs** with the `eddsa-rdna-2022` cryptosuite, which is the signing layer used by the W3C Verifiable Credentials ecosystem. Implementations SHOULD use an existing conformant library rather than implementing the pipeline from scratch.

**Reference implementations:**
- TypeScript/JS: [`jsonld`](https://github.com/digitalbazaar/jsonld.js) + [`rdf-canonize`](https://github.com/digitalbazaar/rdf-canonize) (Digital Bazaar — the W3C reference implementations)
- Go: [`go-jsonld-signatures`](https://github.com/go-jsonld-signatures) or FFI binding to the above for correctness during initial development
- Rust: [`json-ld` crate](https://crates.io/crates/json-ld) + [`rdf-types`](https://crates.io/crates/rdf-types) + [`ssi` crate (Spruce Systems)](https://github.com/spruceid/ssi)

**Test vectors:** The Agora repository MUST include a `test-vectors/canonicalization/` directory containing at minimum: (a) five representative Agora document types in their pre-signing JSON-LD form, (b) the expected N-Quads output after expansion and URDNA2015 normalization, and (c) the expected SHA-256 digest. Implementations MUST pass all test vectors before signing or verification code is considered conformant.

### 14.2 Context Document Caching

Because URDNA2015 requires a JSON-LD expansion step, implementations need access to the context document at `https://agora.protocol/ns/v1`. Fetching this document over the network at signing or verification time is unacceptable for latency and offline operation.

Implementations MUST cache the context document locally. The canonical context document for each published version is pinned by its SHA-256 hash, which is included in this specification and in the Agora repository. Implementations MUST verify the cached document against the pinned hash before use. A context document that does not match the pinned hash MUST be rejected.

The pinned hash for `/ns/v1` will be published alongside the v1 context document at spec finalization. During development, implementations SHOULD use the context document from the Agora repository at a pinned commit.

Implementations MUST NOT fetch the context document from the network during signature verification of an untrusted message — this is a denial-of-service vector (an adversary could stall verification by making the context URL slow or unreachable). The context document MUST be loaded from the local cache only.

---

## 15. Extension Points

The protocol is designed to be extended without breaking existing clients:

- Unknown `@type` values in inner payloads MUST be ignored by clients that do not understand them (forward compatibility).
- Guild state documents MAY include extension fields prefixed with a registered namespace.
- New channel types MAY be introduced by extending the channel `type` enum in the JSON-LD context.
- Transport encodings beyond CBOR/JSON MAY be negotiated via WebTransport stream headers.

**Version surface registry.** The following table lists every versioned protocol surface, its current version, and the mechanism by which it is negotiated or detected:

| Surface | Current Version | Location | Negotiation Mechanism |
|---|---|---|---|
| JSON-LD context | v1 | `@context` URL | Static; reject unknown context URLs |
| Canonicalization pipeline | URDNA2015 + Ed25519 | §14.1; `proof.cryptosuite` field | Static for v1; new cryptosuite = new surface version |
| Document schema | 1 | `schemaVersion` field | Field presence; reject unsupported values |
| WebTransport endpoint | v1 | URL path prefix `/v1/agora/wt` | HTTP 404 on unknown version |
| WebSocket endpoint | v1 | URL path prefix `/v1/agora/ws` | HTTP 404 on unknown version |
| Frame format | 0x01 | Frame `version` byte | Discard unknown; may close connection |
| Gossip topics | v1 | Topic string prefix `v1/` | `negotiated.gossipVersion` in RelayChallenge |
| KeyPackage Store API | v1 | URL path prefix `/v1/agora/kp/` | HTTP 404 on unknown version |
| Peer API | v1 | URL path prefix `/v1/agora/peer/` + `peer-api-v1` capability | HTTP 404; capability string |
| Push Proxy API | v1 | URL path prefix `/v1/agora/push/` + `push-proxy-v1` capability | HTTP 404; capability string |
| Relay Manifest schema | 1 | `version` field | Field value; reject unsupported |
| Client-relay handshake | v1 | `supportedTransportVersions` in ClientHello | Negotiated in RelayChallenge |


---

## 16. Interoperability

### 16.1 MIMI Native Interop

MIMI (More Instant Messaging Interoperability) is an IETF working group producing a standard for cross-system E2EE messaging using MLS as the shared key agreement layer. Agora and MIMI share RFC 9420 as their cryptographic foundation, which means interop between the two is not a gateway problem requiring re-encryption — it is a content format and delivery protocol bridging problem. E2EE is preserved end-to-end across the system boundary.

**Reference specifications:** RFC 9764 (MIMI architecture), `draft-ietf-mimi-content` (content format), `draft-ietf-mimi-protocol` (delivery service protocol).

#### Shared MLS Group

In MIMI interop mode, a single MLS group spans both Agora and the MIMI-compliant peer system. Members from both systems hold leaves in the same MLS tree and share the same epoch secrets. There is no re-encryption at the boundary. A message sent by an Agora client is decryptable by a MIMI client using its own MLS implementation, and vice versa.

This requires that both systems use compatible MLS ciphersuites. Agora MUST support `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (ciphersuite 0x0001, the MIMI-mandated baseline) in addition to any other suites it implements. Channels operating in MIMI interop mode MUST use this ciphersuite.

#### Identity Mapping

Agora users are identified by DID. MIMI users are identified by MIMI URIs (of the form `mimi://provider/user-id`). For a cross-system MLS group, each leaf node's credential carries both identifiers:

```json
{
  "@type": "CrossSystemCredential",
  "agoraDID": "did:key:z6Mk...",
  "mimiURI": "mimi://example.com/alice",
  "sig": "base64url..."
}
```

The credential is signed by the Agora authentication key. MIMI clients verify the MIMI URI portion; Agora clients verify the DID portion. Neither side needs to parse the other's identifier format — it is treated as an opaque string for display purposes.

#### Content Format

Agora inner payloads use JSON-LD (`@type: ChatMessage` etc.). MIMI defines its own content format (`draft-ietf-mimi-content`). A channel in MIMI interop mode MUST negotiate a shared content format. Two modes are supported:

**MIMI content format mode** — the channel uses the MIMI content format as the canonical inner payload. Agora clients serialize outgoing messages to MIMI content format and deserialize incoming MIMI content to their local display model. Agora-specific features not representable in MIMI content format are carried as MIMI content extensions using the MIMI extension mechanism.

**Agora content format mode** — the channel uses Agora JSON-LD as the canonical inner payload. MIMI clients that support Agora content format (via a registered MIMI content type) can participate natively. MIMI clients that do not support Agora content format receive a fallback plain-text rendering negotiated at join time.

The content format in use is declared in the channel state document:

```json
"mimiInterop": {
  "@type": "MIMIInteropConfig",
  "enabled": true,
  "contentFormat": "mimi-v1",
  "mimiProvider": "example.com",
  "mimiRoomURI": "mimi://example.com/rooms/engineering",
  "mimiSpecVersion": "draft-ietf-mimi-content-10"
}
```

#### Delivery Service Bridging

MIMI defines a delivery service protocol (`draft-ietf-mimi-protocol`) for cross-provider message routing. In MIMI interop mode, Agora Relays act as MIMI delivery service endpoints for their served channels. MLS Commits and Welcome messages are exchanged between Agora Relays and MIMI provider infrastructure via the MIMI delivery protocol. Gossipsub fanout handles Agora-side delivery; the MIMI protocol handles the cross-provider leg.

The Agora Relay serving a MIMI-interop channel registers itself as the MIMI delivery service endpoint for that channel's MLS group with the MIMI provider. MLS handshake messages (Proposals, Commits, KeyPackages) flow bidirectionally between the two delivery services.

#### Limitations

MIMI interop is currently limited by the MIMI specification's own draft status. The content format and protocol drafts are not finalized as of this writing. Agora implementations SHOULD track the MIMI drafts and update their interop implementation as the specs stabilize. Channel state documents carrying `mimiInterop` configurations SHOULD include a `mimiSpecVersion` field (as shown above) to allow clients to detect and handle version skew.

MIMI interop does not currently specify voice/video interop. VTC channels cannot operate in MIMI interop mode until MIMI adds a media signaling specification.

---

### 16.2 Matrix Gateway

Matrix interop is a **gateway**, not native interop. A Matrix gateway holds an Agora DID, is admitted to the relevant channel MLS groups as a member, decrypts Agora messages, re-encrypts them using Matrix's Megolm E2EE for delivery to Matrix users, and performs the reverse for Matrix→Agora direction. **E2EE is broken at the gateway — the gateway holds plaintext.** This MUST be made visible to all participants (§16.3).

#### Gateway Identity and Admission

The Matrix gateway runs as an Agora client with its own DID. It is added to channel MLS groups by a channel Admin via a normal MLS Add commit, exactly like any other member. The gateway's DID document includes a `service` entry identifying it as a gateway:

```json
{
  "service": [{
    "id": "did:key:z6MkGateway...#gateway",
    "type": "AgoraMatrixGateway",
    "serviceEndpoint": "https://matrix.example.com",
    "matrixServerName": "example.com"
  }]
}
```

The channel state document records the gateway's presence and type:

```json
"gateways": [
  {
    "@type": "GatewayDescriptor",
    "did": "did:key:z6MkGateway...",
    "protocol": "matrix",
    "matrixRoomID": "!abc123:example.com",
    "addedBy": "did:key:z6MkAdmin...",
    "addedAt": "2026-03-12T00:00:00Z"
  }
]
```

#### Message Flow: Agora → Matrix

1. Gateway receives an MLS-encrypted message from the Agora channel gossip topic.
2. Gateway decrypts it using its MLS leaf key (it is a full group member).
3. Gateway translates Agora inner payload to Matrix event format:
   - `TextBody` → `m.room.message` with `msgtype: m.text`
   - `MediaBody` → `m.room.message` with `msgtype: m.image/m.file` etc.; media fetched from IPFS and re-uploaded to the Matrix media server
   - `EditEvent` → `m.room.message` with `m.new_content` relation
   - `DeleteEvent` → `m.room.redaction`
   - `ReactionEvent` → `m.reaction`
4. Gateway sends the translated event to the bridged Matrix room via the Matrix Client-Server API, attributed to a virtual Matrix user representing the Agora sender (`@agora_z6Mk...:example.com`).
5. If the Matrix room has Megolm E2EE enabled, the gateway re-encrypts the event using Megolm before sending.

#### Message Flow: Matrix → Agora

1. Gateway receives a Matrix event via the Matrix Application Service API.
2. Gateway translates the Matrix event to Agora inner payload format.
3. Gateway encrypts the payload using its MLS group membership (the gateway is a sender from Agora's perspective).
4. Gateway publishes the outer `RoutingEnvelope` to the Agora channel gossip topic.
5. Agora clients see the message as coming from the gateway DID with a `bridgedFrom` field in the inner payload identifying the original Matrix sender:

```json
{
  "@type": "ChatMessage",
  "body": { "@type": "TextBody", "text": "hello from matrix" },
  "bridgedFrom": {
    "protocol": "matrix",
    "senderID": "@alice:example.com",
    "eventID": "$abc123"
  }
}
```

#### Identity and Namespace Mapping

Agora DIDs map to Matrix virtual users with a deterministic MXID derived from the DID: `@agora_<did-fragment>:<gateway-homeserver>`. Matrix MXIDs map to Agora gateway messages with `bridgedFrom.senderID` carrying the MXID.

Agora's nested channel namespace does not map cleanly to Matrix's flat room model. The gateway maps each Agora channel path to a separate Matrix room, organized into a Matrix Space:

```
agora://bafyrei.../general             → !room1:example.com (in Space)
agora://bafyrei.../engineering/backend → !room2:example.com (in Space)
agora://bafyrei.../engineering/fips    → !room3:example.com (in Space)
```

Category channels (`type: category`) with no messages of their own map to Matrix Space sub-spaces rather than rooms.

#### E2EE Mismatch Handling

When the Matrix room has Megolm E2EE enabled, the gateway holds both MLS session state (for Agora) and Megolm session state (for Matrix). The gateway is the trust boundary — it decrypts on one side and re-encrypts on the other. This is unavoidable; it is the structural nature of bridging two incompatible E2EE systems.

The gateway MUST NOT cache decrypted message content beyond the time needed for translation and re-encryption. It SHOULD operate in a memory-only mode with no persistent plaintext storage. Gateway operators SHOULD publish a transparency policy describing their plaintext handling.

When the Matrix room does not have Megolm E2EE enabled, the gateway sends plaintext to the Matrix server. This is a further trust degradation — the Matrix homeserver operator can read bridged messages. This MUST be disclosed to Agora channel members (§16.3).

#### Implementation Approach

The recommended implementation uses the **Matrix Application Service API** rather than the Client-Server API. Application services receive all events in a room without polling, can register virtual users in bulk, and receive better rate limit treatment. The gateway registers as an application service on the Matrix homeserver with a namespace regex matching all virtual Agora users.

**Reference implementations:** [`mautrix-go`](https://github.com/mautrix/go) and [`mautrix-python`](https://github.com/mautrix/python) provide the application service scaffolding. The Agora-specific work is the MLS client integration, the Agora↔Matrix content format translation, and the IPFS↔Matrix media re-hosting.

---

### 16.3 Gateway Transparency

Any gateway admitted to an Agora channel — Matrix, or any future gateway type — MUST be disclosed to all channel members. This is enforced at the protocol level, not by policy.

**Channel state disclosure.** The `gateways` array in the channel state document (§16.2) is visible to all MLS group members. Clients MUST display a visible indicator when a channel has active gateways. The indicator MUST identify the gateway protocol and target system. A channel with an active gateway is not E2EE-private for bridged traffic; members must be able to determine this without reading protocol documentation.

**Gateway transparency message.** When a gateway DID is added to a channel's MLS group, the adding Admin MUST also send a signed `SystemEvent` inner payload to the channel announcing the gateway:

```json
{
  "@type": "SystemEvent",
  "event": "gateway-added",
  "gatewayDID": "did:key:z6MkGateway...",
  "protocol": "matrix",
  "target": "!abc123:example.com",
  "addedBy": "did:key:z6MkAdmin...",
  "e2eeNote": "Messages in this channel are bridged to Matrix. E2EE is not preserved for bridged traffic."
}
```

This event is stored in the channel's IPLD history — it is a permanent record that a gateway was added and when.

**Client rendering.** Clients MUST render a persistent banner or channel badge indicating gateway presence. The banner MUST NOT be dismissible per-session without re-appearing on reconnect. Members who joined after a gateway was added receive the `SystemEvent` from history and see the indicator immediately on first load.

---

## 17. Compliance Logging

### 17.1 Overview

Organizations in regulated industries (financial services, healthcare, legal, government) are subject to message retention and audit requirements that conflict with the default Agora model of E2EE with relay-opaque content. Agora supports compliance logging as an **optional, guild-level feature** that satisfies these requirements without architectural kludges.

Mechanically, compliance logging is implemented as an MLS group member — a `ComplianceLogger` principal — that silently receives and archives all messages in every channel it is admitted to. It is structurally identical to a gateway (§16.2) but is treated differently at the protocol and UI layers:

- It does not appear as a chat participant in client UI.
- It does not generate join/leave events in the message stream.
- Its presence is disclosed in guild metadata and MLS group membership, but not in the message feed.
- It is added to channels automatically when logging is enabled, without requiring per-channel Admin action.

The result is compliant message capture that is cryptographically sound and tamper-evident, without a "Logger Bot joined #engineering" message appearing in every channel.

### 17.2 Enabling Compliance Logging

Compliance logging is enabled in the Guild state document by the guild owner:

```json
"complianceLogging": {
  "@type": "ComplianceLoggingConfig",
  "schemaVersion": "1",
  "enabled": true,
  "loggerDID": "did:key:z6MkLogger...",
  "loggerLabel": "Acme Corp Compliance Archive",
  "logStore": "ipfs://bafyrei...",
  "retentionDays": 2555,
  "scope": "all-channels",
  "enabledBy": "did:key:z6MkOwner...",
  "enabledAt": "2026-03-12T00:00:00Z",
  "sig": "base64url..."
}
```

`loggerDID` is the DID of the compliance logging principal. `logStore` is the IPFS CID root of the compliance log — a content-addressed, append-only IPLD structure. `retentionDays` is the minimum retention period the logger is obligated to maintain. `scope` is `all-channels` or a list of channel path globs.

Once `complianceLogging.enabled` is set to `true` and gossiped to the guild topic, conformant clients MUST add the `loggerDID` to the MLS group of every channel matching `scope` on the next available Commit. This addition IS recorded in the MLS group membership (verifiable by any MLS-aware client) but MUST NOT produce a UI-visible join notification.

Disabling compliance logging requires a signed Guild state mutation by the guild owner. Clients remove the logger DID from channel MLS groups via Remove commits. The `complianceLogging` history in the IPLD guild state chain retains a permanent record of when logging was enabled and disabled.

### 17.3 Logger Principal

The `ComplianceLogger` is a DID-identified principal operated by the guild's compliance infrastructure — typically an on-premise archival system or a regulated third-party compliance service (e.g., a FINRA-registered archiving vendor).

The logger's DID document identifies it as a compliance logger:

```json
{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:key:z6MkLogger...",
  "verificationMethod": [...],
  "service": [{
    "id": "did:key:z6MkLogger...#compliance",
    "type": "AgoraComplianceLogger",
    "serviceEndpoint": "https://archive.acme-corp.internal/v1/agora/compliance",
    "operator": "Acme Corp Legal",
    "regulatoryFramework": ["FINRA 17a-4", "SEC 17a-4"]
  }]
}
```

`regulatoryFramework` is an informational array of the regulatory requirements under which the logger operates. Clients MAY display this to members who inspect the guild's compliance configuration.

The logger operates as a receive-only MLS client. It holds leaf credentials, participates in epoch ratchets, and receives `Welcome` messages when added to new channel groups. It does not send messages, publish presence events, or generate typing indicators.

### 17.4 Log Record Format

Every message received by the logger is written as a signed `ComplianceRecord` to the IPLD log:

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "ComplianceRecord",
  "envelopeID": "urn:agora:msg:bafyrei...",
  "channel": "agora://bafyrei.../engineering/backend",
  "senderDID": "did:key:z6MkSender...",
  "epoch": 17,
  "seq": 1042,
  "ts": "2026-03-12T12:00:00.000Z",
  "plaintextPayload": "base64url...",
  "outerEnvelopeCID": "bafyrei...",
  "loggerSig": "base64url...",
  "prevRecordCID": "bafyrei..."
}
```

`plaintextPayload` is the decrypted inner payload (JSON-LD `ChatMessage` or other type), base64-encoded. `outerEnvelopeCID` links the compliance record to the tamper-evident message history. `loggerSig` is the logger's Ed25519 signature over the canonical record. `prevRecordCID` chains records into a linked list, making the log append-only and tamper-evident — inserting or deleting a record breaks the chain.

The log is organized as a per-channel IPLD DAG, with a guild-level index mapping channel CIDs to their respective log chain heads.

### 17.5 Ephemeral Message and Expiry Handling

Ephemeral messages (`TypingEvent`, `PresenceEvent`) are never logged — they are excluded by type at the logger.

Messages with an `expiry` field present a deliberate tension: the sender expressed an intent for the message to be deleted, but the compliance obligation may override that intent. The resolution is explicit and must be disclosed:

- If `complianceLogging.enabled` is `true`, message expiry is honored for relay caches and client display, but the compliance logger retains the plaintext for `retentionDays` regardless of the sender's `expiry` value.
- The Guild state document MUST include a human-readable `retentionNotice` field when compliance logging is enabled:

```json
"retentionNotice": "This guild is subject to regulatory message retention. Messages are archived for 2555 days regardless of expiry settings."
```

- Clients MUST display this notice to members when they first join a compliance-logging-enabled guild, and MUST make it accessible from the guild's information panel at any time.

This is the correct behavior for a regulated environment. The sender's expiry preference is preserved in the client and relay layers; the compliance layer overrides it with explicit disclosure.

### 17.6 Voice and Video Logging

VTC logging (audio/video recording) is handled separately from message logging and is governed by the `RecordingGrant` mechanism in §10.6. Compliance logging as defined in this section covers text channels, reactions, edits, deletions, and file attachments only.

An organization requiring VTC compliance recording MUST issue a `RecordingGrant` for the compliance logger's DID on relevant voice channels. The same logger DID MAY hold both text compliance membership and VTC recording grants, but these are governed by separate mechanisms and MUST be separately authorized.

### 17.7 Member Disclosure

Compliance logging is not hidden from members. It is disclosed in guild metadata and MLS group membership (which is visible to any technically capable member). Conformant clients MUST:

- Display a compliance logging indicator in the guild information panel when `complianceLogging.enabled` is `true`.
- Display the `retentionNotice` to new members on first join.
- Allow members to inspect the full `ComplianceLoggingConfig` including `loggerDID`, `loggerLabel`, `retentionDays`, and `regulatoryFramework` from the guild settings UI.
- NOT display a join/leave notification in any channel's message feed when the logger DID is added or removed from an MLS group.

The logger's MLS group membership is visible to any client that inspects raw MLS group state. This is intentional — the logger is not cryptographically hidden, only UI-silent. A technically capable member can always verify that a compliance logger is present.

---

## 18. Cross-Guild Channel Sharing

### 18.1 Overview

A channel MAY be shared across Guild boundaries, giving members of multiple Guilds access to the same message stream, history, and MLS group. From any member's perspective in either Guild, the shared channel appears as a normal channel in their sidebar — there is no visible workspace transition or foreign-context indicator.

Agora channel sharing is structurally simpler than analogous features in centralized systems (like Slack Connect) because channels are already identified by content-addressed CID rather than opaque server-internal IDs. A channel shared between Guild A and Guild B is the same MLS group, the same IPLD history DAG, and the same `channelToken` — there is no synchronization problem because there is no duplication.

### 18.2 Home Guild and Guest Guilds

Every shared channel has exactly one **home guild** — the Guild whose namespace contains the channel's canonical path and whose admin is responsible for channel state mutations. There MAY be one or more **guest guilds** whose members access the channel via a local alias path.

The home/guest distinction governs:
- Namespace ownership (home guild owns the path)
- Channel state mutations (home guild admin signs them)
- Compliance logging (home guild's configuration applies to all members, including guests)
- Channel deletion (only the home guild owner can delete)

Guest guild members have full read/write access to the channel's message stream, subject to the roles negotiated in the `ChannelShareAgreement` (§18.3). They are first-class MLS group members — not observers or read-only participants unless the agreement specifies otherwise.

### 18.3 Channel Share Agreement

Sharing a channel requires bilateral authorization: the home guild admin and the guest guild admin both sign a `ChannelShareAgreement`. Neither side can unilaterally impose sharing on the other.

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "ChannelShareAgreement",
  "schemaVersion": "1",
  "id": "urn:agora:csa:bafyrei...",
  "homeGuild": "agora://bafyrei.../",
  "homeChannel": "agora://bafyrei.../engineering/backend",
  "guestGuild": "agora://bafyxyz.../",
  "guestAlias": "shared/wolfssl-backend",
  "guestRoles": ["member", "engineer"],
  "guestPermissions": {
    "canSend": true,
    "canReact": true,
    "canUpload": true,
    "canDeleteOwn": true,
    "canDeleteOthers": false,
    "canInviteToChannel": false
  },
  "validFrom": "2026-03-12T00:00:00Z",
  "validUntil": "2027-03-12T00:00:00Z",
  "homeAdminSig": "base64url...",
  "guestAdminSig": "base64url...",
  "homeAdminDID": "did:key:z6MkHomeAdmin...",
  "guestAdminDID": "did:key:z6MkGuestAdmin..."
}
```

`guestAlias` is the channel path under which the shared channel appears in the guest guild's sidebar. It is a local display alias only — the channel's canonical identity remains `homeChannel`. `guestRoles` is the list of guest guild roles whose members are eligible for admission. `guestPermissions` defines the capability constraints applied to guest guild members in this channel, independently of their role in their own guild.

The agreement is stored as an IPLD node, CID-referenced from both guild state documents, and gossiped on both `v1/agora/guild/<homeGuildCID>` and `v1/agora/guild/<guestGuildCID>`.

### 18.4 Member Admission

When a `ChannelShareAgreement` is established and gossiped, conformant clients from the guest guild whose roles match `guestRoles` are eligible to join the shared channel's MLS group. Admission follows the standard MLS Add flow, initiated either by:

- A home guild admin issuing a Welcome to the guest member directly, or
- A guest guild admin issuing a bulk Welcome on behalf of all eligible members (this requires that the guest admin is themselves already an MLS group member, admitted by the home guild admin as part of agreement setup).

The recommended flow is: home guild admin admits the guest guild admin first; guest guild admin then admits their eligible members. This distributes the Commit workload and avoids requiring the home admin to manage foreign guild membership individually.

Guest members appear in the channel participant list with a visual indicator of their home guild (a guild icon or badge), distinguishable from home guild members. Clients SHOULD display the member's display name from their own guild's profile, with the foreign guild indicator making affiliation clear.

### 18.5 Namespace Resolution

A guest guild member sees the channel at `guestAlias` in their guild sidebar. Internally, the client resolves this alias to the home channel's CID and connects to the home channel's MLS group and gossip topic. The alias is purely a display and navigation convenience — all protocol operations (message send, history fetch, MLS operations) use the home channel's identity.

The guest guild's state document records the alias mapping:

```json
"sharedChannels": [
  {
    "@type": "SharedChannelAlias",
    "aliasPath": "shared/wolfssl-backend",
    "homeChannelCID": "bafyrei...",
    "agreementCID": "bafyrei...",
    "homeGuildCID": "bafyrei..."
  }
]
```

Clients resolve `guestAlias` → `homeChannelCID` before any protocol operation. If the agreement is revoked (§18.7), the alias entry is removed from the guest guild state and clients remove the channel from their sidebar on next state refresh.

### 18.6 Relay Coordination

The home channel's gossip topic (`v1/agora/channel/<channelToken>`) is where all messages flow. Guest guild members subscribe to this topic via their own Relays. For this to work, the guest guild's Relays must be peered with (or able to reach) the home channel's Relays.

No special Relay configuration is required if both guilds' Relays participate in the same gossipsub mesh — this is the common case for public or semi-public guilds. For private guilds whose Relays are isolated (e.g., on a private Tailscale overlay), explicit Relay peering must be established between the home and guest guild operators. The `ChannelShareAgreement` MAY include a `relayHints` array suggesting peering endpoints:

```json
"relayHints": [
  "wss://relay.home-guild.example.com",
  "wss://relay.guest-guild.example.com"
]
```

### 18.7 Revocation

Either party MAY revoke the `ChannelShareAgreement` by publishing a signed `ChannelShareRevocation`:

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "ChannelShareRevocation",
  "agreementCID": "bafyrei...",
  "revokedBy": "did:key:z6MkRevoker...",
  "revokedByGuild": "agora://bafyrei.../",
  "reason": "partnership-ended",
  "ts": "2026-03-12T00:00:00Z",
  "sig": "base64url..."
}
```

On revocation:

1. The revoking admin issues MLS Remove commits for all members of the foreign guild from the channel's MLS group.
2. The alias entry is removed from the guest guild's state document.
3. The `ChannelShareRevocation` is gossiped on both guild topics and stored in both guild IPLD state chains.
4. Clients of the guest guild remove the channel from their sidebar on next state refresh.
5. Guest guild members lose the ability to decrypt new messages immediately (the MLS epoch advances on the Remove commits); they retain locally cached history up to the revocation epoch.

Either admin may revoke unilaterally; the counter-party does not need to co-sign the revocation.

### 18.8 Compliance Logging Across Guild Boundaries

The home guild's compliance logging configuration (§17) applies to all messages in the shared channel regardless of the sender's guild affiliation. A guest guild member sending a message in a compliance-logged shared channel has that message captured by the home guild's compliance logger.

Guest guild members MUST be notified of this at channel join time. The client displays the home guild's `retentionNotice` to guest members on first entry to the shared channel, clearly attributing it to the home guild:

> "This channel is hosted by [Home Guild Name] and is subject to their message retention policy: [retentionNotice text]"

If the guest guild also has compliance logging enabled, its logger MAY also be added to the shared channel's MLS group, subject to home guild admin approval (an additional MLS Add commit is required). Both loggers may simultaneously hold membership. The home guild admin MAY reject a guest guild's compliance logger by declining to issue a Welcome; in that case the guest guild admin is responsible for any resulting regulatory non-compliance on their side.

### 18.9 Voice Channel Sharing

Voice channels MAY be shared using the same `ChannelShareAgreement` mechanism. All VTC semantics (§10) apply unchanged — the shared voice channel has one MLS group, one set of call state gossip, and one SFU if configured. The SFU used is the home guild's SFU (declared in the home guild state document). Guest guild members connect to the home guild's SFU directly.

If the home guild does not have an SFU configured and the shared voice channel exceeds the mesh threshold (§10.5), the home guild admin is responsible for provisioning one. The `ChannelShareAgreement` MAY specify a minimum SFU capacity as a precondition for guest guild participation.

---

## Appendix A: Dependency Summary

| Component | Specification | Reference Implementation |
|---|---|---|
| E2EE group key management | RFC 9420 (MLS) | `openmls` (Rust), `mlspp` (C++) |
| Message framing | JSON-LD (W3C) | `jsonld` + `rdf-canonize` (JS) |
| Identity | W3C DID Core, `did:key`, `did:web` | `ssi` (Rust), `go-did` (Go) |
| Content addressing | IPFS / IPLD (CIDv1, dag-cbor) | `go-ipfs`, `helia` (JS), `rust-ipfs` |
| Peer discovery / fanout | libp2p gossipsub v1.1 | `go-libp2p-pubsub`, `libp2p` (Rust) |
| Primary transport | WebTransport (RFC 9000) | Native browser; `webtransport-go`, `wtransport` (Rust) |
| Fallback transport | WebSocket (RFC 6455) | Native in all environments |
| Voice/video media | WebRTC | Native browser; `pion` (Go) |
| SFU | WebRTC SFU | `mediasoup`, `Pion ion-sfu`, `LiveKit` |
| TURN relay | RFC 5766 / RFC 7065 | `coturn` |
| Wire encoding | CBOR (RFC 8949) | `fxamacker/cbor` (Go), `cbor2` (Python) |
| Relay-to-relay auth | RFC 9421 HTTP Message Signatures | `httpsig` (Go), `httpbis-message-signatures` (JS) |
| Ed25519 / X25519 | RFC 8032 / RFC 7748 | Native in all major crypto libraries |
| Argon2id KDF | RFC 9106 | `golang.org/x/crypto/argon2`, `argon2` crate |
| Shamir Secret Sharing | — | `hashicorp/vault` shamir (Go), `sharks` (Rust) |
| Payments (preferred) | MobileCoin (MOB) | MobileCoin SDK |
| Payments (micropayment alt) | Cashu ecash over Lightning | `cashu-ts` (JS), `nutshell` (Python) |
| Payments (service agreements) | Lightning Network BOLT 12 | Core Lightning, LND |
| Spam deterrence (no payment) | Hashcash-style PoW | SHA-256 (standard library) |
| Native cross-system interop | MIMI (RFC 9764, drafts) | TBD (spec in progress) |
| Matrix gateway | Matrix Application Service API | `mautrix-go`, `mautrix-python` |
| Relay bootstrap DNS | DNS-SD / SRV / TXT records | Standard DNS libraries |
| JSON-LD canonicalization | URDNA2015 | `rdf-canonize` (JS), `ssi` (Rust) |

---

## Appendix B: Open Questions

1. **KeyPackage availability SLA** — RFC 9420 requires a reliable KeyPackage store. Agora uses IPFS-backed relay storage for this but does not specify pinning guarantees or availability SLAs. A Relay-hosted KeyPackage endpoint with explicit uptime obligations may be necessary for reliability in practice, and a formal SLA model for KeyPackage stores may be worth specifying.

2. **SFU trust model for voice recording** — the SFU holds decryption rights for voice streams when a `RecordingGrant` is active. The mechanism by which a guild auditably grants and revokes recording rights to an SFU DID is specified at a high level in §10.6, but the key delivery sub-protocol (how participants securely deliver the recording key to the SFU DID) needs a dedicated sub-specification before implementation can be considered conformant.

3. **Cross-guild identity and reputation** — there is currently no mechanism for carrying moderation history or reputation across Guild boundaries. A user banned from one Guild can freely join another. Whether this is a feature (clean-slate by design, prevents monoculture moderation) or a gap (enables bad actors to evade consequences) depends on use case. A voluntary cross-guild reputation attestation format is worth considering as an optional extension.

4. **Push notification proxy conformance** — §8.7 specifies the push proxy protocol but does not define conformance requirements for proxy operators (logging policy, data retention, handle-to-token mapping security). A push proxy operator specification analogous to the Relay operator conformance requirements may be warranted for deployments where push proxy trust is a concern.

