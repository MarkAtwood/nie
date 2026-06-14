# RLCHAT Protocol Specification

**Version:** 0.1 (Draft)
**Date:** 2026-03-12

---

## 1. Overview

RLCHAT is a decentralized, end-to-end encrypted real-time group chat protocol. It is designed to support a user experience comparable to Discord — servers, channels, presence, typing indicators, voice/video signaling — without any central authority owning identity, routing, or message storage.

Core dependencies:

- **RFC 9420 (MLS)** — group key agreement and E2EE
- **JSON-LD** — typed, namespace-aware message framing
- **libp2p gossipsub** — peer discovery, room advertisement, live message fanout
- **IPFS/IPLD** — content-addressed persistent storage (history, media, room state)
- **WebTransport / WebSocket** — transport layer for browser and native clients
- **MobileCoin (MOB)** — preferred payment scheme for relay economics and micropayments (optional)

RLCHAT does not define a central server. It defines a protocol that servers (called **Relays**) implement to form a federated mesh. Users are not locked to any Relay. Relays gossip with each other. Clients MAY connect to multiple Relays simultaneously and reconcile state.

---

## 2. Identity

### 2.1 User DID

Every user has a **Decentralized Identifier (DID)** as their persistent identity. The recommended method is `did:key` (self-certifying, no registry needed) or `did:web` (for organizations requiring DNS-anchored identity).

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

The `keyAgreement` key is the MLS init key source. The `authentication` key signs all protocol messages.

### 2.2 Device Keys

A single user identity MAY have multiple device credentials. MLS handles multi-device membership natively — each device is a separate MLS leaf node. The user's DID document lists all active device verification keys. Revoking a device means removing its leaf from the MLS tree via an `Update` commit.

### 2.3 User Display Profile

The user display profile is stored as an IPLD node, CID-addressed, and is separate from the DID document. The DID document contains a `service` endpoint linking to the current profile CID:

```json
{
  "service": [{
    "id": "did:key:z6Mk...#profile",
    "type": "RLCHATProfile",
    "serviceEndpoint": "ipfs://bafyrei..."
  }]
}
```

Profile schema (JSON-LD):

```json
{
  "@context": "https://rlchat.protocol/ns/v1",
  "@type": "UserProfile",
  "did": "did:key:z6Mk...",
  "displayName": "alice",
  "avatarCID": "bafyrei...",
  "statusText": "building things",
  "updatedAt": "2026-03-12T00:00:00Z"
}
```

Profile updates are signed by the user's authentication key and gossiped via the discovery layer.

### 2.4 Account Recovery

`did:key` identities are self-certifying — the private key is the identity. Loss of all device private keys is permanent identity loss with no protocol-level remedy unless recovery mechanisms are established in advance. RLCHAT specifies three complementary recovery mechanisms. Clients SHOULD implement all three; users SHOULD activate at least one.

#### 2.4.1 Recovery Key

A **recovery key** is a dedicated Ed25519 keypair generated at account creation and stored separately from all device keys — typically as a printed or air-gapped backup. It is registered in the DID document as a verification method with a `recoverableIdentity` relationship:

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

The recovery key is never used for normal protocol operations. Its sole function is to sign a `RecoveryAssertion` that rotates the DID document to a new device key when all other device keys are lost:

```json
{
  "@context": "https://rlchat.protocol/ns/v1",
  "@type": "RecoveryAssertion",
  "did": "did:key:z6Mk...",
  "newDeviceKey": "base64url(new Ed25519 pubkey)",
  "revokeAll": true,
  "ts": "2026-03-12T12:00:00.000Z",
  "recoverySig": "base64url..."
}
```

`recoverySig` is signed by the recovery key. `revokeAll: true` instructs relays and peers to treat all previously registered device keys as revoked. The `RecoveryAssertion` is published to `rlchat/discovery/v1` and stored in the user's profile IPLD chain. Relays that receive a valid `RecoveryAssertion` MUST immediately invalidate all cached sessions for that DID.

The recovery key is the root of trust for identity recovery. Its private key MUST be stored offline and MUST NOT be loaded into any networked device during normal operation. Loss of the recovery key means loss of recovery capability via this mechanism.

#### 2.4.2 Social Recovery

Social recovery designates a set of **guardians** — other RLCHAT users trusted to collectively authorize identity recovery. A threshold scheme (e.g., 3-of-5) ensures no single guardian can unilaterally recover the account, and loss of any one guardian does not prevent recovery.

**Setup:** The client generates a random 256-bit recovery secret `S`, splits it into `N` shares using Shamir's Secret Sharing, and encrypts each share to a guardian's DID key agreement key (X25519):

```json
{
  "@context": "https://rlchat.protocol/ns/v1",
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

The `SocialRecoveryConfig` is stored in the user's profile IPLD chain (publicly readable, so guardians can locate their shares). `recoveryCommitment` is a hash of `S` used to verify share reconstruction without revealing `S` before recovery.

**Recovery:** The user (on a new device) contacts `threshold` guardians out-of-band and requests their shares. Each guardian decrypts their share using their X25519 key and sends it to the recovering user via a direct encrypted message. The user reconstructs `S`, verifies it against `recoveryCommitment`, then uses `S` to derive a new signing key and publish a `RecoveryAssertion` signed with it.

`S` is never stored — it exists only during setup (to split) and recovery (to reconstruct). Guardians hold encrypted shares; relays hold nothing related to recovery.

Guardians SHOULD be notified when designated and SHOULD confirm acceptance. A guardian who loses their own keys loses the ability to decrypt their share. The account owner SHOULD periodically verify that guardians are still reachable and re-key shares if a guardian leaves the system.

#### 2.4.3 Encrypted Backup

A client MAY export an encrypted backup of all device private keys and MLS state to a user-chosen location (local file, cloud storage, IPFS). The backup is encrypted with a user-chosen passphrase using Argon2id key derivation:

```
backupKey = Argon2id(passphrase, salt, m=65536, t=3, p=4)
backup    = AEAD_AES_256_GCM(backupKey, backupPayload)
```

`backupPayload` is a CBOR-encoded structure containing:

- All device Ed25519 private keys
- All device X25519 private keys
- Current MLS key material for all group memberships
- The recovery key private key (if one has been generated)
- Timestamp and DID

The backup file format is self-describing — it contains the Argon2id parameters and the DID, so a client can prompt the user to enter their passphrase and restore without additional configuration.

Clients SHOULD prompt users to export an encrypted backup at account creation and after any significant key rotation event. Clients MUST NOT store the backup passphrase anywhere on the device.

#### 2.4.4 Recovery Precedence and Conflicts

If multiple recovery mechanisms produce conflicting `RecoveryAssertion` messages simultaneously (e.g., two guardians independently trigger social recovery), the conflict is resolved by timestamp — the earlier valid `RecoveryAssertion` wins. A relay that receives a second `RecoveryAssertion` for the same DID within 24 hours of the first MUST reject it and flag the conflict. The account owner SHOULD monitor for spurious recovery attempts as a signal of account compromise.

---

## 3. Topology

### 3.1 Participants

- **Client** — user agent (browser, desktop, mobile). Connects to one or more Relays.
- **Relay** — always-on server that participates in gossip, caches recent messages, serves WebTransport/WebSocket endpoints, and optionally pins IPFS content. Anyone MAY operate one.
- **Peer** — any participant in the gossipsub mesh, including clients with persistent connections.

### 3.2 Guild and Channel Hierarchy

A **Guild** is a named collection of channels, analogous to a Discord server. A **Channel** is a named, typed stream of messages within a Guild.

Guild and Channel identifiers are **namespaced paths**:

```
rlchat://<guild-id>/<channel-path>
```

`<guild-id>` is the CID of the Guild's root state document; `<channel-path>` is a slash-delimited path supporting arbitrary nesting:

```
rlchat://bafyrei.../general
rlchat://bafyrei.../engineering/backend
rlchat://bafyrei.../engineering/backend/incidents
rlchat://bafyrei.../voice/lounge
```

Channel nesting is structural only — a parent channel may itself be a message channel, a category header, or both. The namespace is a tree with no depth limit.

### 3.3 Guild State Document

Stored as an IPLD DAG node. The CID changes on every mutation. The Guild's identity is pinned to its genesis CID; subsequent state is a chain of signed mutations.

```json
{
  "@context": "https://rlchat.protocol/ns/v1",
  "@type": "GuildState",
  "id": "rlchat://bafyrei...",
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

`sig` is an Ed25519 signature over the canonical JSON-LD serialization, signed by the Guild owner's authentication key (or a designated admin's key).

### 3.4 Deployment Topologies

RLCHAT is transport-agnostic at the application layer. The following deployment topologies are explicitly supported.

**Public internet (standard)** — Relays are clearnet HTTPS/WSS servers with public IPv4 and/or IPv6 addresses. This is the default topology.

**Tor hidden service** — A Relay MAY operate as a Tor hidden service, publishing a `.onion` address in its `RelayAd` alongside or instead of a clearnet endpoint. This provides IP-level anonymity for the relay operator. Clients connecting via Tor MUST use the WebSocket transport (§8.3); WebTransport is unavailable over Tor.

**Private overlay (Tailscale / WireGuard / Headscale)** — A Relay MAY operate exclusively on a WireGuard-based overlay network. In this topology the Relay is reachable only by overlay network members, providing network-layer access control without application-layer authentication overhead. The Relay's `RelayAd` lists overlay-internal hostnames or `100.x.x.x` addresses. This is the recommended topology for private organizational deployments. A fully self-contained deployment (Relay + SFU + TURN + Headscale, all on-premise) has zero dependency on external infrastructure.

**Dual-stack (clearnet + overlay)** — A Relay MAY publish both clearnet and overlay endpoints. Clients on the overlay prefer the overlay path; external clients use the clearnet path. Both sets of clients share the same guild state and message history.

**IPv6** — All relay endpoints SHOULD support IPv6. Relay URIs MUST use bracket notation for IPv6 literals (e.g., `wss://[2001:db8::1]/rlchat/ws/v1`). ICE gathers both IPv4 and IPv6 host candidates; dual-stack clients race both address families.

### 3.5 Relay-to-Relay Peering and Authentication

Relays form a gossipsub mesh with each other for fanout. This section specifies how relays discover each other, authenticate, establish trust, and maintain the mesh.

#### 3.5.1 Relay Manifest

Every relay MUST publish a **Relay Manifest** at:

```
GET /.well-known/rlchat-relay
```

The manifest is a signed JSON-LD document serving as the relay's authoritative self-declaration — the single source of truth for a relay's identity, capabilities, endpoints, and signing keys. Any relay that can reach this URL can bootstrap a peering relationship without out-of-band coordination.

```json
{
  "@context": "https://rlchat.protocol/ns/v1",
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
    "webTransport": "https://relay.example.com/rlchat/wt/v1",
    "webSocket": "wss://relay.example.com/rlchat/ws/v1",
    "onion": "ws://examplerelay3xyzabc.onion/rlchat/ws/v1",
    "keyPackageStore": "https://relay.example.com/rlchat/kp/v1",
    "peerAPI": "https://relay.example.com/rlchat/peer/v1"
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
    "tor-hidden-service-v1"
  ],
  "acceptedSchemes": ["mob", "pow"],
  "knownPeers": [
    {
      "relayDID": "did:key:z6MkPeer...",
      "manifestURL": "https://peer.example.net/.well-known/rlchat-relay",
      "addedAt": "2026-03-12T00:00:00Z"
    }
  ],
  "publishedAt": "2026-03-12T00:00:00Z",
  "sig": "base64url..."
}
```

`sig` is the relay operator's Ed25519 signature over the canonical CBOR serialization of the manifest (excluding the `sig` field), signed by the key in `keys[0]`. Peer relays MUST verify this signature before accepting the manifest.

`knownPeers` is the relay's current peer list. A new relay fetching any existing relay's manifest obtains a list of further relays to contact, enabling rapid mesh joining without a central directory.

`capabilities` is an array of capability strings:

| Capability                 | Meaning                                              |
|:---------------------------|:-----------------------------------------------------|
| `gossipsub-v1.1`           | Participates in libp2p gossipsub v1.1 mesh           |
| `keypackage-store-v1`      | Hosts KeyPackage Store API (§6.1.1)                  |
| `keypackage-forwarding-v1` | Supports inter-relay KeyPackage forwarding           |
| `tor-hidden-service-v1`    | Reachable via `.onion` endpoint                      |
| `sfu-v1`                   | Hosts an SFU for voice channels                      |
| `compliance-logging-v1`    | Supports compliance logger DID admission             |

#### 3.5.2 Peer API

Relays expose a **Peer API** at the `endpoints.peerAPI` URL for relay-to-relay operations. All Peer API requests are authenticated using RFC 9421 HTTP Message Signatures (§3.5.3).

```
GET  /rlchat/peer/v1/manifest
     Returns this relay's current RelayManifest. Unauthenticated.

POST /rlchat/peer/v1/announce
     A peer relay announces itself. Body: RelayManifest of the announcing relay.
     Response: 200 { "status": "accepted"|"known"|"rejected", "trustLevel": N }

GET  /rlchat/peer/v1/peers
     Returns the relay's known peer list (array of { relayDID, manifestURL }).
     Authenticated. Rate-limited to 1 request/hour per peer.

POST /rlchat/peer/v1/gossip
     Relay-to-relay gossipsub message submission.
     Body: CBOR-encoded gossipsub message batch.
     Authenticated.

GET  /rlchat/peer/v1/health
     Returns relay health state.
     Response: { "status": "healthy"|"degraded"|"unhealthy"|"maintenance", "since": ISO8601 }
     Unauthenticated.
```

#### 3.5.3 Relay-to-Relay Authentication

Relay-to-relay requests use **RFC 9421 HTTP Message Signatures** with Ed25519. The requesting relay signs each HTTP request using its active signing key from its manifest. The receiving relay verifies the signature against the requesting relay's manifest fetched from `/.well-known/rlchat-relay`.

Required signature components (per RFC 9421 §2.5):

```
"@method"
"@target-uri"
"@authority"
"content-digest"        (POST requests with body)
"x-rlchat-relay-did"    (requesting relay's DID)
"x-rlchat-timestamp"    (Unix timestamp, integer seconds)
"x-rlchat-nonce"        (random 128-bit value, base64url)
```

Example signed request headers:

```http
x-rlchat-relay-did: did:key:z6MkRelay...
x-rlchat-timestamp: 1741780800
x-rlchat-nonce: aGVsbG8gd29ybGQhISEhISE
signature-input: sig1=("@method" "@target-uri" "@authority" "x-rlchat-relay-did" "x-rlchat-timestamp" "x-rlchat-nonce"); keyid="did:key:z6MkRelay...#key-1"; alg="ed25519"
signature: sig1=:base64url...:
```

`x-rlchat-timestamp` MUST be within 300 seconds of the receiving relay's clock. `x-rlchat-nonce` MUST NOT have been seen in the last 600 seconds (the receiving relay maintains a nonce cache with 600s TTL). Requests violating either condition MUST be rejected with HTTP 401.

Receiving relays cache peer manifests for 1 hour. On cache miss or expiry, the relay fetches a fresh manifest before verifying. If the fetch fails, the relay retries once after 5 seconds before rejecting the request with HTTP 503.

#### 3.5.4 Trust Levels

Relay-to-relay trust is graduated. Trust level determines which Peer API operations are permitted and what gossip rate limits apply.

| Level | Name    | Criteria                                             | Permissions                                              |
|:-----:|:--------|:-----------------------------------------------------|:---------------------------------------------------------|
| 0     | Unknown | No prior contact                                     | Manifest fetch only; `announce` accepted for evaluation  |
| 1     | Seen    | Valid manifest, valid signature, first contact       | `announce`, `health`; gossip rate-limited to 10 msg/s   |
| 2     | Known   | 7+ days sustained peering without incident           | Full gossip; `peers` accessible; 1000 msg/s             |
| 3     | Trusted | Explicitly operator-configured                       | Full access; relaxed rate limits; no gossip throttling  |

Trust level is local state — each relay maintains its own assessments independently and never gossips them. Level 3 is set via local operator configuration and is appropriate for relays run by the same organization or known partners.

A relay that submits invalid signatures, sends malformed gossip, or repeatedly exceeds rate limits is downgraded to Level 0 and its DID is blocked for 24 hours. Three or more incidents within 7 days result in permanent operator-managed blocklisting.

#### 3.5.5 Bootstrap: Joining the Mesh

A new relay with no existing peers joins the gossipsub mesh using any of the following methods, attempted in parallel:

**Method 1 — Known peer URL.** The operator provides one or more peer relay URLs in startup configuration. The new relay fetches `/.well-known/rlchat-relay`, verifies the manifest signature, sends `POST /peer/v1/announce` with its own manifest, and on acceptance fetches `GET /peer/v1/peers` to discover further relays.

**Method 2 — Directory document.** The relay fetches any RLCHAT relay directory document (§4.4.1) and contacts listed relays via Method 1.

**Method 3 — DNS-SD.** The relay queries `_rlchat-relay._tcp.<domain>` SRV records:

```
_rlchat-relay._tcp.example.com. SRV 10 0 443 relay.example.com.
_rlchat.relay.example.com.      TXT "did=did:key:z6MkRelay... manifest=https://relay.example.com/.well-known/rlchat-relay"
```

This is primarily useful for organizational deployments where multiple relays share a DNS domain.

**Method 4 — IPNS fallback.** The relay resolves `/ipns/rlchat.protocol/relays/v1` for a community-maintained signed bootstrap list. This is a last resort.

A relay is considered mesh-joined when it has Level 1 or higher trust with at least 3 peers and is participating in gossipsub fanout. It SHOULD continue discovering peers until it has at least 6 active connections (gossipsub default mesh degree `D`).

#### 3.5.6 Mesh Maintenance

**Heartbeat.** Relays MUST poll `GET /peer/v1/health` from each peer every 60 seconds. A peer that returns `unhealthy` or fails to respond for 3 consecutive checks (180 seconds) is marked unreachable. Its gossipsub connection is dropped; it remains in `knownPeers` for 7 days before removal in case it recovers.

**Manifest refresh.** Relays re-fetch peer manifests every hour to detect key rotation and endpoint changes. A manifest whose `sig` no longer verifies is treated as a trust failure and the peer is downgraded to Level 0 pending re-verification.

**Key rotation overlap.** When rotating its signing key, a relay MUST publish both old and new keys in its manifest with a minimum 48-hour overlap, marking the old key `"status": "deprecated"`. Peer relays accept signatures from deprecated keys during this window. After the overlap, the old key is removed and deprecated-key signatures are rejected.

**Peer gossip.** When a relay discovers a new valid peer it SHOULD share that peer's `{ relayDID, manifestURL }` with its Level 2+ peers as a `RelayPeerAnnouncement` gossip message:

```json
{
  "@type": "RelayPeerAnnouncement",
  "relayDID": "did:key:z6MkNewRelay...",
  "manifestURL": "https://newrelay.example.com/.well-known/rlchat-relay",
  "announcedBy": "did:key:z6MkExistingRelay...",
  "ts": "2026-03-12T00:00:00Z",
  "sig": "base64url..."
}
```

Receiving relays verify the signature, fetch the new relay's manifest independently, and decide whether to initiate peering. The announcement is a hint, not an authorization.

---

## 4. Discovery

### 4.1 Gossip Protocol

RLCHAT uses **libp2p gossipsub v1.1** for:

- User presence advertisements
- Guild/channel discovery
- Live message delivery
- MLS Welcome and Commit delivery

Each gossipsub **topic** maps to a scope:

| Topic pattern                        | Purpose                                                |
|:-------------------------------------|:-------------------------------------------------------|
| `rlchat/discovery/v1`                | Global guild/user advertisements                       |
| `rlchat/guild/<guildCID>/v1`         | Guild-scoped events (joins, state updates)             |
| `rlchat/channel/<channelCID>/v1`     | Per-channel messages and presence                      |
| `rlchat/mls/<groupID>/v1`            | MLS handshake messages (Welcome, Commit, Proposal)     |

Clients subscribe to relevant topics via their connected Relays. Relays maintain full mesh connections to each other and fan out to connected clients.

### 4.2 Discovery Advertisement

A **GuildAd** or **UserAd** message is gossiped periodically (default: 60s TTL, re-advertised at 45s):

```json
{
  "@context": "https://rlchat.protocol/ns/v1",
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

`relayHints` are connection hints only — clients are not required to use them and SHOULD attempt direct peer connections first. `relayHints` MAY include `.onion` addresses, clearnet HTTPS/WSS URIs, overlay-internal hostnames, and IPv6 URIs. Clients select the hint appropriate for their transport context.

### 4.3 Relay Discovery Bootstrap

To bootstrap into the gossip network, a client needs at least one known peer. RLCHAT supports the following bootstrap mechanisms, attempted in order:

1. **Directory sources** — user-configured URLs serving `RelayDirectory` or `GuildDirectory` documents (§4.4); the primary bootstrap mechanism in practice
2. **Previously cached relay list** — relays successfully contacted in a prior session, stored locally with a staleness TTL of 7 days
3. **IPFS DHT** — Relays publish a signed record under a well-known IPNS key (`/ipns/rlchat.protocol/relays/v1`)
4. **DNS-SD** — `_rlchat._tcp` mDNS for LAN/overlay discovery

### 4.4 Directory Documents

A **directory document** is a static JSON-LD file served at any reachable URL. It lists guilds, relays, or both, and MAY include other directory documents by reference. Users configure one or more directory source URLs in their client. Clients fetch and merge all configured sources on startup and refresh them on a configurable interval (default: 1 hour).

Directory documents require no special server infrastructure. A file committed to a public GitHub repository, an IPFS CID, a Cloudflare R2 bucket, a `.onion` URL, or any HTTPS endpoint returning the correct JSON format is a valid directory source. The client cares only about the document format and the signature.

#### 4.4.1 Relay Directory

A `RelayDirectory` lists relays available for client connection:

```json
{
  "@context": "https://rlchat.protocol/ns/v1",
  "@type": "RelayDirectory",
  "id": "https://raw.githubusercontent.com/example/rlchat-relays/main/relays.json",
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

`ttl` is the number of seconds before the client SHOULD re-fetch the document. `includes` is a list of other directory document URLs whose contents are merged; clients MUST limit include depth to 3 to prevent cycles. `sig` is the maintainer's Ed25519 signature over the canonical CBOR serialization of the document (excluding the `sig` field). Clients SHOULD verify the signature against the `maintainer` DID but MAY accept unsigned directories with a user-visible warning.

#### 4.4.2 Guild Directory

A `GuildDirectory` lists guilds available for browsing or joining:

```json
{
  "@context": "https://rlchat.protocol/ns/v1",
  "@type": "GuildDirectory",
  "id": "https://raw.githubusercontent.com/example/rlchat-guilds/main/guilds.json",
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

`inviteURL` is a human-readable join link; the join flow is out of scope for this document. `tags` are free-form strings for client-side filtering. `iconCID` is an IPFS CID pointing to the guild's icon image. `guildCID` is the authoritative guild identity — clients verify this against the guild's genesis state document when connecting.

#### 4.4.3 Combined Directory

A single document MAY contain both `relays` and `guilds` arrays, typed as `RLCHATDirectory`:

```json
{
  "@context": "https://rlchat.protocol/ns/v1",
  "@type": "RLCHATDirectory",
  "relays": [ ... ],
  "guilds": [ ... ],
  "includes": [ ... ]
}
```

#### 4.4.4 Client Behavior

On startup, the client fetches all configured directory sources in parallel. Results are merged: relay lists are deduplicated by `did`, guild lists are deduplicated by `guildCID`. The client attempts connection to the highest-priority available relay (ordered by user preference, then by `tiers[0].pricePerMonthPicoMOB` ascending). Previously cached relays from prior sessions are used immediately while directory fetches are in flight, avoiding a blocking startup delay.

Directory source ordering in user preferences is used only for display in the client's directory browser UI; it does not affect priority. All sources are fetched and merged regardless of order.

Failed fetches are retried with exponential backoff (base 30s, max 1 hour). A source that consistently fails for 7 days is flagged in the UI as unreachable but MUST NOT be silently removed from the configured list.

Clients MUST NOT auto-add directory sources from guild state documents, relay advertisements, or any other protocol message without explicit user confirmation. Auto-population of directory sources is a privilege escalation vector.

#### 4.4.5 IPFS-Hosted Directories

A directory document MAY be addressed by IPFS CID:

```
ipfs://bafyrei.../relays.json
ipns://k51qzi5uqu5d.../relays.json
```

Clients with IPFS gateway access fetch these via their configured gateway (default: `https://ipfs.io/ipfs/`). IPNS-addressed directories are mutable and are the preferred form for long-lived community-maintained lists. CID-addressed directories are immutable snapshots, useful for pinning a known-good state.

#### 4.4.6 Trust Model

Being listed in a directory conveys no trust. A relay in a directory is trusted only to the extent that its DID verifies against its TLS certificate and signed advertisements. A guild in a directory is trusted only to the extent that its `guildCID` verifies against its genesis state document. A malicious directory entry pointing at a rogue relay produces a DID mismatch at connection time and MUST be rejected.

Directory maintainers are identified by their `maintainer` DID and signature. There is no global authority over directory content; multiple competing directories can coexist and clients merge them all.

---

## 5. Message Ordering

RLCHAT uses **best-effort causal ordering**. Gossipsub does not guarantee total order. The requirement is that messages arrive in approximately the right order on average, with clients able to reconstruct causal order locally.

Each message envelope carries a `seq` (monotonically increasing integer per sender per channel) and an optional `causalRefs` array of message CIDs that the sender had observed before sending. This gives clients sufficient information to:

- Detect gaps (missing `seq` values from a given sender)
- Buffer out-of-order arrivals and flush when gaps close
- Detect and display causal relationships (reply threading, reaction targets)

Clients SHOULD buffer messages for up to 500ms waiting for a gap to close before displaying out-of-order. After 500ms, the client displays what is available and backfills visually when the missing message arrives.

MLS Commits require stricter ordering than application messages. Clients MUST buffer application messages from a new epoch until the Commit that opened that epoch has been received and applied. Relays MAY provide **sequence attestations** — signed sequence numbers over a channel's message stream — as an optional ordering anchor. Sequence attestations are advisory; clients that do not request them proceed with sender-`seq` ordering only.

Guild state mutations (role changes, channel additions) are ordered by a `seq` field on the `GuildState` document and a Lamport timestamp. Concurrent non-conflicting mutations (e.g., two admins each adding a different channel) are merged by taking the union. Conflicting mutations (e.g., two admins simultaneously changing the same user's role) are resolved last-writer-wins using `seq`; in a true tie, the mutation signed by the higher-authority key (owner beats admin) wins.

---

## 6. Messaging

### 6.1 MLS Group Structure

Each **Channel** has its own MLS group. Guild membership does not imply channel membership — each channel manages its own MLS epoch independently, enabling per-channel access control (e.g., private channels within a public guild).

MLS operations follow RFC 9420 exactly:

- `KeyPackage` — uploaded to the Relay KeyPackage Store (§6.1.1); rotated on each new device session and after each use
- `Welcome` — sent to new members via `rlchat/mls/<groupID>/v1` or direct encrypted delivery
- `Commit` — state-advancing operation (add, remove, update); gossiped to all group members
- `Proposal` — pre-commit operation; may be included in a subsequent Commit by any member

The **Delivery Service** role (per RFC 9420 §4) is performed by the gossipsub mesh plus the Relay KeyPackage Store. The **Authentication Service** role is performed by DID verification — MLS leaf credentials bind to DID verification keys.

### 6.1.1 KeyPackage Store

IPFS alone is insufficient for KeyPackage distribution. IPFS provides no delivery guarantees, no availability SLA, and no mechanism for a sender to atomically fetch-and-consume a KeyPackage (preventing reuse). Relays MUST implement a **KeyPackage Store** — an authenticated key-value endpoint for publishing and retrieving MLS KeyPackages.

#### Relay KeyPackage API

All endpoints are authenticated using the client-relay session established in §8.6.

```
PUT  /rlchat/kp/v1/{did}
     Upload one or more KeyPackages for the authenticated DID.
     Body: CBOR array of RFC 9420 KeyPackage TLS-serialized objects.
     Response: 200 { "stored": N }

GET  /rlchat/kp/v1/{did}
     Fetch and consume one KeyPackage for the target DID.
     The relay atomically removes the returned KeyPackage from the store.
     Response: 200 { "keyPackage": "base64url...", "remaining": N }
              404 if no KeyPackages available for that DID

GET  /rlchat/kp/v1/{did}/count
     Return the number of available (unconsumed) KeyPackages without consuming any.
     Response: 200 { "count": N }

DELETE /rlchat/kp/v1/{did}/{keyPackageRef}
     Revoke a specific KeyPackage by its ref (hash of the TLS-serialized bytes).
     Only the owning DID may revoke its own KeyPackages.
```

Clients SHOULD maintain at least 20 pre-uploaded KeyPackages per device at all times. When `count` falls below 5, the client MUST upload a fresh batch immediately.

#### KeyPackage Replication Across Relays

A client connected to multiple Relays SHOULD upload its KeyPackages to all of them. When a sender fetches a KeyPackage to issue a Welcome, it contacts the target user's preferred Relay (from their DID document's `service` endpoints). If that Relay has no KeyPackages for the target, it SHOULD attempt to fetch one from other known Relays serving the same guild before returning 404.

Inter-relay KeyPackage forwarding uses a simple pull model:

```
GET /rlchat/kp/v1/{did}?forward=true
```

The `forward=true` parameter instructs the relay to attempt peer relay fetching before returning 404. Relays that support forwarding include `"keyPackageForwarding": true` in their `RelayAd`.

#### KeyPackage Exhaustion

If all KeyPackages for a target DID are consumed and no fresh ones are available, the sender MUST NOT reuse a previously consumed KeyPackage. Instead:

1. The sender queues the Welcome message locally.
2. The sender publishes a `KeyPackageRequest` to `rlchat/discovery/v1`:

```json
{
  "@context": "https://rlchat.protocol/ns/v1",
  "@type": "KeyPackageRequest",
  "targetDID": "did:key:z6Mk...",
  "requestedBy": "did:key:z6MkSender...",
  "ts": "2026-03-12T12:00:00Z"
}
```

3. When the target comes online, their client sees the `KeyPackageRequest`, uploads fresh KeyPackages, and the waiting sender completes the Welcome flow.

`KeyPackageRequest` messages are ephemeral (not stored in IPLD history) and MUST NOT identify which channel or guild triggered the request — only that the target's KeyPackages are needed.

#### KeyPackage Validation

Recipients of a Welcome MUST validate the KeyPackage used to construct it:

- Signature verifies against the sender's DID authentication key
- `KeyPackage.leaf_node.credential` contains a valid DID matching the sender
- KeyPackage has not expired (`leaf_node.lifetime.not_after`)
- Ciphersuite matches the group's declared ciphersuite

A Welcome constructed with an invalid or expired KeyPackage MUST be rejected.

### 6.2 Message Format

All messages use a two-layer structure: an outer **routing envelope** visible to relays, and an inner **sealed envelope** whose sender identity is hidden from relays. The inner payload is MLS-encrypted.

#### Outer Routing Envelope

The outer envelope contains only what relays strictly need for delivery. It does not contain the sender's DID.

```json
{
  "@context": "https://rlchat.protocol/ns/v1",
  "@type": "RoutingEnvelope",
  "id": "urn:rlchat:msg:bafyrei...",
  "channelToken": "base64url...",
  "epoch": 17,
  "seq": 1042,
  "ts": "2026-03-12T12:00:00.000Z",
  "sealedEnvelope": "base64url..."
}
```

`channelToken` is a one-way derivation from the channel CID and the current MLS epoch secret: `HKDF(epochSecret, "channel-token" || channelCID)`. It changes every epoch. Relays use it for topic routing without learning the actual channel identifier or any member identity. A relay that does not hold the epoch secret cannot map a `channelToken` back to a channel or a sender.

`id` is a CID of the canonical outer envelope for deduplication and history indexing. `ts` is present for gossipsub ordering and relay-side TTL enforcement only — it is not authenticated at the outer layer and MUST NOT be trusted for application-level ordering. Use the inner `seq` for ordering.

#### Sealed Envelope (Sender-Sealed, Relay-Opaque)

`sealedEnvelope` is the sender's DID, a per-message ephemeral key, and the MLS ciphertext, encrypted as a unit to the channel's current MLS group key. No relay or non-member can open it.

Plaintext of `sealedEnvelope` before encryption:

```json
{
  "@context": "https://rlchat.protocol/ns/v1",
  "@type": "SealedEnvelope",
  "sender": "did:key:z6Mk...",
  "senderEphemeralKey": "base64url...",
  "mlsCiphertext": "base64url...",
  "sig": "base64url..."
}
```

`sig` covers `sender + senderEphemeralKey + mlsCiphertext`, signed by the sender's authentication key. Recipients verify the signature after decrypting the sealed envelope. The `senderEphemeralKey` is a fresh X25519 key generated per message.

This design is derived from Signal's sealed sender. A relay processing this message learns: a `channelToken` (epoch-rotating, non-reversible), a sequence number, a timestamp, and an opaque blob. It learns nothing about who sent the message.

#### Inner Payload (After MLS Decryption)

```json
{
  "@context": "https://rlchat.protocol/ns/v1",
  "@type": "ChatMessage",
  "body": {
    "@type": "TextBody",
    "text": "the fips conversion is green",
    "format": "markdown"
  },
  "expiry": "2026-03-19T12:00:00.000Z",
  "attachments": [],
  "replyTo": null,
  "mentions": []
}
```

### 6.3 Message Types

All inner payload types are defined in the RLCHAT JSON-LD context namespace (`https://rlchat.protocol/ns/v1`):

| `@type`            | Description                                                                 |
|:-------------------|:----------------------------------------------------------------------------|
| `TextBody`         | Plain or markdown text                                                      |
| `MediaBody`        | Reference to IPFS-hosted media (CID + mime type + size)                    |
| `EmbedBody`        | URL unfurl card (title, description, image CID)                            |
| `ReactionEvent`    | Emoji reaction add/remove targeting a message CID                          |
| `EditEvent`        | Replacement body for a prior message CID                                   |
| `DeleteEvent`      | Tombstone for a prior message CID                                          |
| `SystemEvent`      | Protocol-level event (member join, role change, etc.)                      |
| `VoiceSignal`      | WebRTC SDP offer/answer/ICE candidate, targeted to a DID                  |
| `ParticipantState` | Ephemeral VTC room presence (joined/left, muted, video, screen share)      |
| `RecordingGrant`   | Admin authorization for SFU to decrypt media for recording                 |
| `RecordingRevoke`  | Revocation of a prior `RecordingGrant`                                     |
| `TypingEvent`      | Ephemeral; not stored                                                       |
| `PresenceEvent`    | Ephemeral; not stored                                                       |

Ephemeral events (`TypingEvent`, `PresenceEvent`) use a separate MLS `PublicMessage` application data subtype and are excluded from history storage.

### 6.4 Message Expiry

Message lifetime is a **sender-side cryptographic commitment**, not a server-side promise or a UI affordance. The sender encodes an `expiry` timestamp in the inner payload (inside the MLS ciphertext, therefore invisible to relays). Recipients' clients are bound to honor it by protocol.

Expiry semantics:

- `expiry` is an ISO 8601 timestamp in the inner payload. Absence means no expiry (persistent by default).
- On receipt, clients schedule local deletion of the decrypted message at the expiry time.
- On expiry, clients SHOULD submit a `DeleteEvent` to the channel so that the IPLD history DAG records a tombstone and Relays drop the cached envelope.
- Relays that cache message envelopes MUST respect `expiry` hints carried in the outer `RoutingEnvelope` field `"expiryHint"`. This field is set by the sender to match the inner `expiry` and is unauthenticated at the outer layer — relays use it as a cache TTL hint only.
- The authoritative expiry is always the inner payload value, verified by recipients after MLS decryption.

The threat model addressed: a relay under legal compulsion cannot produce message content it has already purged. A client under legal compulsion cannot produce message content past its expiry without detectable falsification. Neither deletion mechanism is perfect against an adversary who captures and retains encrypted blobs before expiry, but it substantially raises the bar against bulk retention and routine legal demands.

### 6.5 Message History

Message history is stored as an IPLD linked list. Each message envelope CID is appended to the channel's history DAG. The channel state document tracks the latest history CID.

Clients fetch history by walking the IPLD DAG backwards from the latest CID. Relays SHOULD pin recent history (configurable retention window, default 30 days). Long-term archival is the responsibility of guild operators or interested members.

IPFS provides content-addressed deduplication — the same message CID stored at multiple Relays is automatically deduplicated.

---

## 7. Presence and Ephemeral State

### 7.1 Presence

Presence is gossiped on `rlchat/channel/<channelCID>/v1` as a `PresenceEvent`:

```json
{
  "@context": "https://rlchat.protocol/ns/v1",
  "@type": "PresenceEvent",
  "sender": "did:key:z6Mk...",
  "channel": "rlchat://bafyrei.../general",
  "status": "online",
  "ts": "2026-03-12T12:00:00.000Z",
  "ttl": 30
}
```

`status` values: `online`, `idle`, `dnd`, `invisible`. `ttl` is seconds; clients treat absence of a refresh within `ttl` as offline.

### 7.2 Typing Indicators

`TypingEvent` is gossiped to the channel topic and not stored:

```json
{
  "@context": "https://rlchat.protocol/ns/v1",
  "@type": "TypingEvent",
  "sender": "did:key:z6Mk...",
  "channel": "rlchat://bafyrei.../general",
  "ts": "2026-03-12T12:00:00.000Z"
}
```

A client that has not received a `TypingEvent` from a sender within 5 seconds SHOULD clear that sender's typing indicator.

---

## 8. Transport

### 8.1 Primary: WebTransport

Clients connect to Relays via **WebTransport** (RFC 9000 / HTTP/3). WebTransport provides:

- Multiplexed bidirectional streams over QUIC
- Reliable streams for MLS handshake and message delivery
- Unreliable datagrams for presence/typing (low-latency, loss-tolerant)

Endpoint: `https://<relay-host>/rlchat/wt/v1`

WebTransport requires QUIC, which runs over UDP. It is unavailable in any environment that proxies only TCP, including Tor (§8.3).

### 8.2 Fallback: WebSocket

For environments where QUIC/HTTP/3 is blocked or unavailable:

Endpoint: `wss://<relay-host>/rlchat/ws/v1`

WebSocket carries the same message framing over a single multiplexed binary stream. Multiplexing is handled by a lightweight channel ID prefix on each frame. WebSocket is the mandatory transport for Tor-connected clients.

### 8.3 Tor Transport Constraints

Tor proxies TCP only. This has the following protocol-level consequences.

**WebTransport unavailable.** Clients connecting via Tor MUST use WebSocket. Clients MUST NOT attempt WebTransport when operating through a SOCKS5 proxy identifiable as Tor (`.onion` exit, `torsocks`, or explicit SOCKS5 configuration). Clients SHOULD detect transport failure and fall back to WebSocket without user intervention.

**VTC severely degraded.** WebRTC ICE relies on UDP for STUN hole-punching and optimal media paths. UDP is unavailable over Tor. The only viable VTC path over Tor is TURN-over-TCP through a TURN server reachable via a `.onion` address or a Tor-friendly clearnet endpoint. Even in this configuration, media latency over Tor circuits (typically 200–600ms round-trip) renders real-time audio/video unusable for most participants. Clients SHOULD display a warning when VTC is attempted over Tor, and MAY disable VTC participation entirely in Tor-only mode. Text channels and presence are unaffected.

**Gossipsub fingerprinting.** Connecting to gossipsub via Tor provides IP-level anonymity, but gossipsub peer scoring observes message timing and subscription patterns. A sufficiently persistent observer correlating topic subscription events across Tor circuits may be able to fingerprint clients by behavior. No clean mitigation exists at the protocol level; clients requiring strong anonymity SHOULD rotate Tor circuits periodically and SHOULD subscribe to decoy topics (§13.4).

**Rate limiting.** A relay receiving connections from Tor exit nodes sees the exit node IP, not the client IP. IP-based rate limiting will incorrectly aggregate all clients sharing an exit node. Relays MUST use per-`channelToken` rate limits and PoW/payment requirements as the primary spam control mechanism; per-IP limits MUST NOT be the sole mechanism.

**Hidden service relays.** A Relay operating as a Tor hidden service publishes its `.onion` address in `RelayAd.relayHints`. Clients with Tor available SHOULD prefer `.onion` endpoints — they provide end-to-end Tor routing without depending on an exit node and protect the relay operator's IP from exposure.

### 8.4 Frame Format

All frames are CBOR-encoded (compact binary) with a JSON-LD compatible schema. Clients MAY use JSON encoding for debugging; Relays MUST accept both.

Frame structure:

```
[version: u8, type: u8, topic: string, payload: bytes]
```

`type` values: `0x01` Gossip, `0x02` MLS, `0x03` Ephemeral, `0x04` Control.

### 8.5 Direct Peer Connections

Clients MAY establish direct WebRTC data channels to each other, bypassing Relays entirely, using the `VoiceSignal` mechanism for ICE negotiation. This is mandatory for voice/video (media never transits Relays) and optional for text (latency optimization).

On WireGuard-based overlays (Tailscale, Headscale), direct peer connections benefit from overlay-managed NAT traversal. Overlay-internal `100.x.x.x` addresses appear as ICE host candidates and are preferred over STUN-discovered public addresses when both peers are on the same overlay network.

### 8.6 Client-Relay Authentication

A relay identifies the client DID for three purposes: ban enforcement, per-DID rate limiting, and KeyPackage Store ownership (§6.1.1). Authentication is performed once per connection via a signed challenge-response handshake, establishing a session token for the connection lifetime.

Authentication is **optional for read-only operations** (fetching guild state, reading history, subscribing to gossip topics). It is **required for write operations** (publishing messages, uploading KeyPackages, submitting MLS Commits) and for accessing the KeyPackage Store write endpoints.

#### Handshake Protocol

Authentication is initiated by the client immediately after transport connection. It uses a `0x04` Control frame.

**Step 1 — Client Hello**

The client sends a `ClientHello` control frame declaring its DID and requesting a challenge:

```json
{
  "@type": "ClientHello",
  "did": "did:key:z6Mk...",
  "deviceKey": "base64url(Ed25519 pubkey)",
  "clientVersion": "rlchat/0.1",
  "ts": "2026-03-12T12:00:00.000Z"
}
```

`deviceKey` is the device's Ed25519 public key, which MUST match a verification method listed in the DID document for the declared DID. The relay verifies this correspondence before issuing a challenge.

**Step 2 — Relay Challenge**

```json
{
  "@type": "RelayChallenge",
  "nonce": "base64url(32 random bytes)",
  "relayDID": "did:key:z6MkRelay...",
  "relaySig": "base64url...",
  "ts": "2026-03-12T12:00:00.000Z",
  "expiresIn": 30
}
```

`relaySig` is the relay's Ed25519 signature over `nonce || relayDID || ts`. This simultaneously authenticates the relay to the client; the client MUST verify `relaySig` against the relay's DID before proceeding. `expiresIn` is seconds; the client MUST respond within this window.

**Step 3 — Client Response**

```json
{
  "@type": "ClientAuth",
  "did": "did:key:z6Mk...",
  "nonce": "base64url...",
  "sig": "base64url..."
}
```

`sig` is the client's Ed25519 signature over `nonce || clientDID || relayDID || ts` using the `deviceKey` declared in `ClientHello`. The relay verifies:

1. `sig` is valid for the declared `deviceKey`
2. `deviceKey` is listed as a verification method in the DID document for `did`
3. `nonce` matches the issued challenge and has not expired
4. The DID is not in the relay's ban list for any guild the relay serves

**Step 4 — Session Token**

On successful verification the relay issues a `SessionToken`:

```json
{
  "@type": "SessionToken",
  "token": "base64url(32 random bytes)",
  "did": "did:key:z6Mk...",
  "expiresAt": "2026-03-12T20:00:00.000Z",
  "relaySig": "base64url..."
}
```

The token is included as a frame header field in all subsequent write operations on this connection. It expires after 8 hours or on disconnection, whichever comes first. Clients reconnecting after expiry MUST repeat the full handshake.

#### Anonymous Connections

A client that does not perform the auth handshake is treated as anonymous. Anonymous connections MAY:

- Subscribe to public gossip topics
- Fetch public guild state and history
- Receive messages on subscribed topics

Anonymous connections MUST NOT:

- Publish messages to any topic
- Upload KeyPackages
- Submit MLS operations
- Access KeyPackage Store write endpoints

#### DID Document Freshness

The relay caches DID documents to avoid resolving them on every connection, with a TTL of 1 hour. If a client presents a `deviceKey` that was valid in the cached document but has since been revoked, the relay may temporarily accept it until cache expiry. This is an accepted tradeoff between DID document resolution latency and revocation propagation speed. Clients revoking a device key SHOULD notify their connected relays via a signed `DeviceRevocation` control frame to accelerate cache invalidation:

```json
{
  "@type": "DeviceRevocation",
  "did": "did:key:z6Mk...",
  "revokedKey": "base64url(Ed25519 pubkey)",
  "sig": "base64url..."
}
```

`sig` is signed by any remaining valid device key for the same DID. Relays MUST process `DeviceRevocation` frames immediately and invalidate any active sessions using the revoked key.

---

## 9. Access Control and Moderation

### 9.1 Authority Model

RLCHAT uses a three-tier authority model. Each tier's permissions are enforced cryptographically — an operation not signed by a key with the required authority MUST be rejected by conformant Relays and clients.

**Guild Owner** — holds the signing key for the Guild state document. Sole authority to transfer or delete the guild, grant or revoke the Admin role, and sign Guild state mutations affecting top-level structure. There is exactly one guild owner at any time. Ownership transfer is a signed `GuildState` mutation replacing the `owner` DID, signed by the current owner.

**Channel/Guild Admin** — a role granted by the owner and recorded in the Guild state document. Admins can sign Guild state mutations within their granted scope, issue invites, execute moderation operations within channels they administer, and add/remove members from channel MLS groups within their scope.

**MLS Group Committer** — by default any current MLS group member may issue Commit messages (RFC 9420 default). Guild operators MAY restrict Commit authority to a designated keyholder set via a `commitPolicy` field in the channel state. Restricting commits is recommended for large public channels to prevent epoch racing.

### 9.2 Guild Roles

Roles beyond Owner and Admin are defined freely in the Guild state document and enforced by MLS group membership. A user's role determines which channel MLS groups they are added to. Role assignment is a Guild state mutation signed by an Admin or Owner.

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

`channelAccess` is a list of channel path globs. When a user is assigned a role, they are added to the MLS groups for all matching channels via a Commit signed by the Admin performing the assignment.

### 9.3 Invite Flow

Invites are signed tokens linking a DID to a Guild and optional role:

```json
{
  "@context": "https://rlchat.protocol/ns/v1",
  "@type": "GuildInvite",
  "guild": "rlchat://bafyrei...",
  "issuedTo": "did:key:z6MkInvitee...",
  "role": "member",
  "issuedBy": "did:key:z6MkAdmin...",
  "expiresAt": "2026-04-12T00:00:00Z",
  "maxUses": 1,
  "sig": "base64url..."
}
```

Link-based invites (no `issuedTo`) are supported for public guilds; these use a short random token that resolves to a signed invite via the issuing Relay.

### 9.4 Private Channels

A channel is private if its MLS group membership is a strict subset of the Guild's member list. The channel's existence MAY be hidden from non-members — the channel path does not appear in the Guild state document served to non-members; the access-controlled view is signed by the guild owner or a delegated admin.

### 9.5 Moderation Operations

All moderation operations are cryptographically signed and gossip-propagated on `rlchat/guild/<guildCID>/v1`. Relays that serve the affected guild MUST enforce them on receipt of a valid signed record.

**Kick** — removes a member from one or more channel MLS groups without a guild-level ban. The Admin issues MLS Remove commits for the target DID across the relevant channel groups. The member retains guild membership and may be re-added to channels by an Admin.

**Ban** — removes a member from all guild channel MLS groups and records a signed `BanRecord` in the guild's moderation log:

```json
{
  "@context": "https://rlchat.protocol/ns/v1",
  "@type": "BanRecord",
  "guild": "rlchat://bafyrei...",
  "target": "did:key:z6MkBanned...",
  "reason": "spam",
  "bannedBy": "did:key:z6MkAdmin...",
  "ts": "2026-03-12T12:00:00Z",
  "sig": "base64url..."
}
```

Relays serving the guild MUST reject message envelopes and MLS KeyPackage submissions from a banned DID. The MLS Remove commit is the authoritative enforcement — a banned user cannot re-enter channel groups because no current member will issue them a Welcome.

**Timeout** — a time-bounded variant with an `expiresAt` field. Relays reject message publication from the target DID for that guild until expiry. MLS group membership is not affected; the user remains a group member and can receive messages but cannot publish.

```json
{
  "@context": "https://rlchat.protocol/ns/v1",
  "@type": "TimeoutRecord",
  "guild": "rlchat://bafyrei...",
  "target": "did:key:z6MkMuted...",
  "expiresAt": "2026-03-12T13:00:00Z",
  "issuedBy": "did:key:z6MkAdmin...",
  "sig": "base64url..."
}
```

**Message Delete** — a signed `DeleteEvent` inner payload from a keyholder with Admin authority over the channel. Relays drop the original envelope from cache on receipt. The message CID remains in the IPLD history DAG as a tombstone entry — the `DeleteEvent` becomes the history record at that position, preserving causal chain integrity while removing content.

**Moderation Log** — all moderation actions are appended to a signed IPLD linked list. The tail CID is referenced in the Guild state document. This log is readable by guild members and provides an auditable record of who moderated whom and when.

---

## 10. Voice and Video (VTC)

RLCHAT supports real-time group voice and video conferencing as a first-class channel type. The design uses WebRTC for media transport, MLS-encrypted signaling for all control messages, and an optional SFU for scalable multi-party sessions. Media never transits Relays.

### 10.1 Voice Channel Type

A channel with `"type": "voice"` is a VTC room. It has all the properties of a text channel (MLS group, channel CID, history) plus a persistent **call state** — a real-time record of who is currently in the call and their media states.

A voice channel is always "open" — there is no concept of starting or ending a call. Participants join and leave; the room exists as long as the channel exists.

Transport constraints apply by topology:

- **Clearnet / overlay (Tailscale, WireGuard):** Full VTC supported. Overlay networks provide ICE host candidates directly; NAT traversal is handled by the overlay.
- **Tor:** VTC is severely degraded. UDP is unavailable over Tor; only TURN-over-TCP paths are possible, adding 200–600ms latency. Clients operating in Tor-only mode SHOULD warn users before joining a voice channel and MAY disable VTC participation entirely. Text channels, presence, and call state gossip are unaffected.

### 10.2 Call State

Call state is ephemeral, gossip-propagated, and not stored in IPLD history. It is maintained as a set of `ParticipantState` records, one per active participant, gossiped on `rlchat/channel/<channelToken>/v1` alongside presence events.

```json
{
  "@context": "https://rlchat.protocol/ns/v1",
  "@type": "ParticipantState",
  "sender": "did:key:z6Mk...",
  "channel": "rlchat://bafyrei.../voice/lounge",
  "status": "joined",
  "audioMuted": false,
  "videoEnabled": true,
  "screenSharing": false,
  "handRaised": false,
  "ts": "2026-03-12T12:00:00.000Z",
  "ttl": 15
}
```

`status` values: `joined`, `left`. A client that has not refreshed its `ParticipantState` within `ttl` seconds is considered to have left. Clients MUST re-publish their state at least every `ttl / 2` seconds while in a call.

`audioMuted`, `videoEnabled`, `screenSharing`, and `handRaised` are advisory UI hints gossiped to other participants, not enforced at the media layer. Media-level enforcement is the SFU's responsibility if one is present.

Call state events are delivered as MLS `PublicMessage` application data — authenticated by the sender's MLS credentials but not encrypted, since call state is visible to all channel members.

### 10.3 Join and Leave

**Join** — a client wishing to participate sends a `ParticipantState` with `status: "joined"` to the channel gossip topic, then initiates WebRTC negotiation with existing participants or the SFU.

**Leave** — a client sends `ParticipantState` with `status: "left"` and closes its WebRTC connections. Clients that disconnect without sending a leave (crash, network drop) are timed out by other participants after `ttl` seconds.

Join and leave do NOT change MLS group membership. A user can be a member of a voice channel's MLS group without being in an active call. Being in the call means having an active `ParticipantState` with `status: "joined"` and live WebRTC connections.

### 10.4 Signaling

All WebRTC signaling (SDP offer/answer, ICE candidates) is delivered as `VoiceSignal` inner payloads, MLS-encrypted to the voice channel's group:

- Signaling is E2EE — Relays cannot read SDP or ICE candidates.
- Signaling is authenticated — the MLS sender credential binds each signal to a verified DID.
- The DTLS-SRTP fingerprint in the SDP is authenticated by the MLS signature, cryptographically binding a participant's media stream to their DID.

```json
{
  "@context": "https://rlchat.protocol/ns/v1",
  "@type": "VoiceSignal",
  "signalType": "offer",
  "targetDID": "did:key:z6MkTarget...",
  "sdp": "v=0\r\no=- ...",
  "candidates": [],
  "ts": "2026-03-12T12:00:00.000Z"
}
```

`signalType` values: `offer`, `answer`, `candidate`, `candidate-end`. `targetDID` is the intended recipient — either another participant (mesh mode) or the SFU DID (SFU mode). All signals are broadcast to the channel MLS group; non-target recipients MUST ignore signals not addressed to them.

For ICE trickling, `candidate` signals are sent as individual messages as candidates are discovered. `candidate-end` signals that ICE gathering is complete.

### 10.5 Topology: Mesh vs. SFU

**Mesh (≤4 participants, recommended)** — each participant establishes a direct WebRTC PeerConnection to every other participant. No SFU is required. Latency is minimized; bandwidth scales as O(n²).

**SFU (>4 participants, recommended)** — participants connect to a Selective Forwarding Unit which receives each participant's streams and forwards them selectively. Bandwidth scales as O(n). The SFU does not decode or re-encode media — it forwards RTP packets based on subscriber requests (simulcast layers, spatial/temporal scalability).

The threshold of 4 is a recommendation. Clients MAY negotiate mesh topology for larger groups if all participants have sufficient bandwidth.

### 10.6 SFU Integration

#### SFU Identity and Trust

An SFU has a DID. Before an SFU can participate in a voice channel, its DID MUST be added to the channel's MLS group via a normal MLS Add commit signed by a channel Admin. An SFU that has not been admitted to the MLS group MUST NOT be used for that channel. Participants MUST verify the SFU's DID against the channel's MLS group membership before connecting.

#### SFU Discovery

Guild operators publish their SFU's DID and WebRTC endpoint in the Guild state document:

```json
"sfus": [
  {
    "@type": "SFUDescriptor",
    "did": "did:key:z6MkSFU...",
    "endpoint": "wss://sfu.example.com/rlchat/v1",
    "regions": ["us-west", "eu-central"],
    "maxParticipants": 500
  }
]
```

Clients select the SFU with the lowest latency region. Multiple SFUs MAY be listed for redundancy and regional load distribution.

#### SFU Signaling Flow

1. Client sends `VoiceSignal { signalType: "offer", targetDID: <sfuDID> }` to the channel.
2. SFU receives the offer (it is an MLS group member) and responds with `VoiceSignal { signalType: "answer", targetDID: <clientDID> }`.
3. ICE candidates are exchanged via `candidate` signals.
4. DTLS handshake completes over the established ICE path; the fingerprint from SDP is verified against the SFU's DID document.
5. SRTP media flows.

The SFU subscribes to the channel gossip topic to receive `ParticipantState` events and determine which streams to forward to which subscribers.

#### SFU Media Opacity

The SFU forwards SRTP packets without decrypting them. It can observe:

- Which participants are sending media (RTP SSRC → participant mapping)
- Packet timing and sizes (traffic analysis)
- Whether a stream is active or silent (RTP activity detection)

An SFU that forwards without decrypting is a routing device, not a surveillance device. For deployments requiring full end-to-end encrypted media at the packet level, see §10.9.

#### SFU Recording

An SFU MAY be granted explicit decryption rights for recording via a deliberate, auditable process:

1. A channel Admin sends a signed `RecordingGrant` inner payload to the channel:

```json
{
  "@context": "https://rlchat.protocol/ns/v1",
  "@type": "RecordingGrant",
  "sfuDID": "did:key:z6MkSFU...",
  "grantedBy": "did:key:z6MkAdmin...",
  "scope": "audio-only",
  "expiresAt": "2026-03-12T14:00:00Z",
  "sig": "base64url..."
}
```

2. Participants' clients, on receiving a valid `RecordingGrant`, derive a shared recording key from the current MLS epoch secret and deliver it to the SFU via an encrypted direct message.
3. The `RecordingGrant` is stored in the channel's IPLD history as a permanent, auditable record.
4. On `expiresAt` or on receipt of a signed `RecordingRevoke`, clients stop delivering recording keys. The SFU cannot decrypt subsequent media.

### 10.7 Simulcast and Bandwidth Adaptation

Clients SHOULD publish video in multiple simulcast layers (e.g., 1080p / 360p / 180p) to allow the SFU to forward appropriate quality to each subscriber based on available bandwidth. Layer selection is signaled via RTCP feedback from subscribers to the SFU.

For Scalable Video Coding (SVC) codecs (VP9, AV1), temporal and spatial scalability layers are used instead of discrete simulcast tracks. SFU implementations SHOULD support both simulcast (VP8, H.264) and SVC (VP9, AV1).

Audio is always single-layer. The SFU performs silence suppression detection (via Voice Activity Detection on the RTP stream) to reduce forwarded audio tracks to active speakers only, with a configurable active-speaker window (default: 3 simultaneous speakers).

### 10.8 Screen Sharing

Screen sharing is a video track with a declared purpose. The sharing participant sets `"screenSharing": true` in their `ParticipantState` and adds a second video transceiver to their PeerConnection with a `content` attribute of `"screen"` in the SDP:

```
a=content:screen
```

Clients receiving a screen share track SHOULD display it distinctly from camera video. Multiple participants MAY share simultaneously; the SFU forwards all active screen share tracks.

Screen share tracks use a separate simulcast configuration from camera video: typically high resolution (up to 1080p or 1440p), low frame rate (5–15 fps), with a high-quality spatial layer prioritized over temporal smoothness.

### 10.9 End-to-End Encrypted Media (Optional Extension)

The default SFU topology trusts the SFU to not analyze RTP packet content. For higher-threat deployments, **WebRTC Insertable Streams** (W3C) enable per-hop media encryption with participant-held keys, such that the SFU forwards ciphertext it cannot decrypt even at the packet level.

In this mode:

- Each participant holds a media encryption key derived from the MLS epoch secret: `HKDF(epochSecret, "media-key" || participantDID)`
- Outgoing media is encrypted by the sender's Insertable Streams transform before entering the RTP stack
- The SFU forwards encrypted RTP packets opaquely
- Each receiving participant's Insertable Streams transform decrypts using the sender's derived media key

Media keys rotate with MLS epochs. A participant whose MLS leaf is removed loses media key derivation capability for subsequent epochs.

This extension requires browser/runtime support for Insertable Streams (available in Chromium-based browsers; partial in Firefox). It is declared in the channel state as `"e2eeMedia": true`. Clients that do not support Insertable Streams MUST NOT join a channel with `e2eeMedia: true`.

### 10.10 DTLS-SRTP Identity Binding

WebRTC media is encrypted with DTLS-SRTP. In standard WebRTC, the DTLS certificate fingerprint in the SDP is unauthenticated and susceptible to substitution by a man-in-the-middle.

In RLCHAT, the SDP carrying the fingerprint is delivered as an MLS `VoiceSignal` inner payload signed by the sender's DID authentication key. Recipients MUST verify the MLS signature before processing the SDP. This means:

- The DTLS fingerprint is authenticated by the sender's DID.
- A relay or network attacker cannot substitute a different certificate without breaking the MLS signature.
- The media stream is cryptographically bound to the sending DID.

This closes the identity binding loop without requiring a PKI or certificate authority.

### 10.11 TURN Server Integration

WebRTC ICE fails for participants behind **symmetric NAT** — common in corporate networks, mobile carriers, and some ISPs. In symmetric NAT, the external IP:port mapping changes per destination, so ICE hole-punching fails and a TURN (Traversal Using Relays around NAT) relay is required as a fallback.

TURN servers relay media packets between participants who cannot establish a direct path. A TURN server is a dumb packet relay — it forwards whatever it receives without knowledge of stream identity or content. In SRTP deployments, the TURN server cannot read media; it sees only opaque encrypted packets.

#### TURN Server Identity

TURN servers in RLCHAT have DIDs, published in the Guild state document alongside SFUs:

```json
"turnServers": [
  {
    "@type": "TURNDescriptor",
    "did": "did:key:z6MkTURN...",
    "uri": "turns:turn.example.com:5349",
    "transport": "tcp",
    "regions": ["us-west", "eu-central"],
    "credentialScheme": "rlchat-hmac-did"
  }
]
```

`uri` follows the standard TURN URI format (RFC 7065). `turns:` (TLS) is required; `turn:` (plaintext) MUST NOT be used. `transport` is `tcp` or `udp`; TCP is preferred for firewall traversal.

#### TURN Credentials

RLCHAT replaces standard username/password TURN credentials with **DID-based HMAC credentials** (`credentialScheme: "rlchat-hmac-did"`) to avoid credentials that could identify a user to the TURN operator:

1. The TURN server publishes a time-scoped HMAC key in its `TURNDescriptor`, rotated every 24 hours: `hmacKey = HKDF(turnMasterSecret, "turn-key" || floor(unixtime / 86400))`
2. A client computes: `username = floor(unixtime / 86400) || ":" || randomNonce` and `credential = HMAC-SHA256(hmacKey, username)`
3. The client presents these credentials in the ICE `candidate` for the TURN allocation.
4. The TURN server verifies the HMAC without learning the client's DID or any persistent identity.

The TURN operator sees: a valid HMAC credential, a source IP, and opaque SRTP packets. The HMAC key rotation means captured credentials are useless after 24 hours.

The TURN server's published HMAC key material is signed by its DID and gossiped on `rlchat/guild/<guildCID>/v1`. Clients MUST verify the signature against the TURN server's DID document before using its credentials.

#### ICE Candidate Priority

Clients MUST follow standard ICE candidate priority ordering:

1. Host candidates (direct LAN)
2. Server-reflexive candidates (STUN, public IP via NAT)
3. Peer-reflexive candidates (discovered during connectivity checks)
4. Relay candidates (TURN)

TURN candidates are used only if all higher-priority paths fail. Clients SHOULD include at least one TURN candidate in all offers to ensure connectivity for symmetric NAT participants.

#### TURN Credential Distribution

TURN credentials are short-lived and not sensitive. They MAY be distributed as plaintext in the outer `RoutingEnvelope` as a `TURNCredentialHint` alongside the `VoiceSignal`, or fetched directly from the TURN server's HTTP endpoint before signaling begins.

For `e2eeMedia: true` channels, TURN credential computation uses the MLS epoch secret as an additional HMAC input: `credential = HMAC-SHA256(hmacKey, username || epochSecret[:16])`. A participant removed from the MLS group loses the ability to compute valid TURN credentials for subsequent epochs.

---

## 11. Relay Behavior

### 11.1 Relay Knowledge Constraints

A conformant Relay is explicitly designed to know as little as possible. The following is both a design target and a compliance requirement: a Relay operator responding to a legal demand MUST be able to honestly testify that:

- Users are not registered — there is no identity registration or account system.
- Channel membership is not visible at the relay layer — `channelToken` is epoch-rotating and non-reversible.
- Sender identity is unknown for any message — sealed sender means the sender DID is inside the MLS ciphertext.
- Nothing is retained after delivery beyond the configured retention window, and nothing past an envelope's expiry hint.
- Forwarded and cached encrypted blobs are opaque.

Any protocol extension or relay implementation that makes any of these statements false introduces legal liability for operators and a surveillance surface for adversaries. Such extensions MUST be explicitly opt-in and clearly documented as degrading the relay's metadata-blindness guarantees.

### 11.2 Relay-Blind Fanout

Relays route messages by `channelToken`, not by channel CID or member identity. The routing table maps `channelToken` → set of subscriber connections. Relays MUST NOT:

- Maintain a mapping from `channelToken` to channel CID
- Maintain a mapping from `channelToken` to member DIDs
- Log sender/recipient pairs for any message
- Retain message envelopes beyond the configured retention window or message expiry, whichever is sooner

The `channelToken` rotates with every MLS epoch. A relay that captures routing tables across epochs cannot correlate them without also capturing the epoch secrets, which it does not have access to.

### 11.3 Conformance Requirements

A conformant Relay MUST:

- Implement WebSocket transport (§8.2); WebTransport is RECOMMENDED
- Implement the client-relay authentication handshake (§8.6)
- Implement the KeyPackage Store API (§6.1.1)
- Implement the Peer API and relay-to-relay authentication (§3.5)
- Route messages by `channelToken` only; never attempt to resolve tokens to identities
- Cache message envelopes up to the lesser of: configured retention window (default 30 days) or the envelope's `expiryHint`
- Delete cached envelopes on receipt of a valid signed `DeleteEvent` for their CID
- Pin IPFS content for channels it serves within the retention window
- Validate outer envelope structure and `channelToken` format before forwarding; drop malformed envelopes silently
- Maintain a local Relay identity (DID) for signing Relay-level attestations
- Enforce ban records received via guild gossip (§9.5)
- Enforce timeout records for the specified duration (§9.5)
- Enforce per-`channelToken` rate limits as the primary spam control mechanism; per-IP limits MUST NOT be the sole mechanism
- Publish a Relay Manifest at `/.well-known/rlchat-relay` (§3.5.1)
- Maintain heartbeat polling of peer relays (§3.5.6)
- Support IPv6 on all endpoints; use bracket notation for IPv6 literals in advertised URIs

A conformant Relay MUST NOT:

- Attempt to decrypt MLS ciphertext
- Log or retain sender DIDs
- Use per-IP rate limiting as the sole spam control mechanism
- Reuse a consumed KeyPackage
- Modify gossipsub messages in transit

A conformant Relay SHOULD:

- Announce itself on `rlchat/discovery/v1` with a signed `RelayAd` including all available endpoint URIs
- Operate a Tor hidden service endpoint to protect operator IP and support Tor-connected clients
- Maintain peering connections to at least 3 other known Relays
- Offer an HTTP API for history fetch (`GET /rlchat/history/v1/<channelToken>?before=<cid>&limit=50`)
- Implement gossipsub peer scoring to limit amplification attacks

Relay federation is permissionless. Any Relay that speaks the protocol MAY join the mesh.

---

## 12. Relay Economics

Relays incur real costs: bandwidth, compute, storage, legal exposure, and abuse handling. RLCHAT specifies two complementary funding mechanisms: service agreements for organized communities, and micropayments for public/anonymous traffic. A third option — proof-of-work — is available for channels that want spam deterrence without any payment infrastructure.

All three mechanisms are **optional extensions** to the core protocol. A relay that serves no paying traffic requires no payment infrastructure.

### 12.1 Payment Schemes

#### PaymentPointer

All payment destinations in RLCHAT are expressed as a `PaymentPointer` — an abstract type carrying a scheme identifier and a scheme-specific address:

```json
{
  "@type": "PaymentPointer",
  "scheme": "mob",
  "address": "3CN5..."
}
```

Defined schemes, in preferred order for v0.1 implementations:

| Scheme       | Network                        | Best for                          | Notes                                                                                                          |
|:-------------|:-------------------------------|:----------------------------------|:---------------------------------------------------------------------------------------------------------------|
| `mob`        | MobileCoin                     | Micropayments, service agreements | **Preferred for v0.1.** Private by default (CryptoNote one-time addresses, no public tx graph); ~5s finality  |
| `cashu`      | Cashu ecash over Lightning     | High-frequency micropayments      | Chaumian blind tokens; relay holds a spent-token DB per trusted mint; bearer instrument, works offline         |
| `bolt12`     | Lightning Network              | Service agreements, settlements   | Reusable offers; routing reliability degrades for sub-sat amounts; no native browser support without custodial LSP |
| `bolt11`     | Lightning Network              | Single-use invoice fallback       | Use only when counterparty cannot receive BOLT 12                                                              |
| `xmr`        | Monero                         | Large periodic settlements        | ~2min block time; not suitable for per-message fees                                                            |
| `onchain-btc`| Bitcoin                        | Large periodic settlements        | High latency and fees; last resort for settlement only                                                         |
| `pow`        | Hashcash-style PoW             | Spam deterrence, no payment       | No money changes hands; see §12.4                                                                              |

Implementations MUST support at least one of `mob` or `cashu` for micropayment-capable channels. `bolt12` SHOULD be supported for service agreements. `pow` requires no payment infrastructure and any implementation MAY support it.

MobileCoin is preferred for v0.1 because every transaction uses CryptoNote one-time addresses and RingCT, making the payment graph non-public. This aligns with RLCHAT's threat model: a relay accepting MOB payments cannot be shown via payment graph analysis to be receiving funds from a specific user. Lightning payments, even over Tor, leak payment graph information to routing nodes. Cashu is comparably private but introduces mint trust. MOB has no routing problem, no channel liquidity to manage, and finality in seconds.

#### GuildTreasury

A guild MAY declare a treasury — a payment destination that receives a fraction of message fees and relay fee-sharing. The treasury is a `PaymentPointer` in the Guild state document, not a custodian.

```json
"treasury": {
  "@type": "GuildTreasury",
  "paymentPointer": {
    "@type": "PaymentPointer",
    "scheme": "mob",
    "address": "3CN5..."
  },
  "description": "wolfSSL Dev infrastructure fund",
  "feeShareBps": 1000
}
```

`feeShareBps` is the basis points (0–10000) of relay service agreement revenue the relay is expected to route to the treasury. A guild treasury MAY declare multiple `PaymentPointer` entries under different schemes:

```json
"treasury": {
  "@type": "GuildTreasury",
  "paymentPointers": [
    { "@type": "PaymentPointer", "scheme": "mob",    "address": "3CN5..." },
    { "@type": "PaymentPointer", "scheme": "cashu",  "address": "https://mint.example.com" },
    { "@type": "PaymentPointer", "scheme": "bolt12", "address": "lno1pg..." }
  ],
  "feeShareBps": 1000
}
```

Clients and relays select the first scheme they support from the list.

### 12.2 Relay Service Agreements

A `RelayServiceAgreement` is a bilaterally signed document between a guild owner DID and a relay DID specifying channels served, SLA terms, price, and fee-share obligation:

```json
{
  "@context": "https://rlchat.protocol/ns/v1",
  "@type": "RelayServiceAgreement",
  "id": "urn:rlchat:rsa:bafyrei...",
  "relay": "did:key:z6MkRelay...",
  "guild": "rlchat://bafyrei...",
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

`channels` is a list of channel path globs; `"*"` means all current and future channels in the guild. The agreement is gossiped on `rlchat/guild/<guildCID>/v1` and stored in the guild's IPLD state. Multiple agreements covering the same guild (from multiple relays) are valid and encouraged for redundancy.

Relays publish their service tiers and accepted payment schemes in their `RelayAd`:

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

Prices are denominated in picoMOB (10⁻¹² MOB) for precision. Relays that accept multiple schemes SHOULD publish exchange-rate-equivalent prices for each.

### 12.3 Message Micropayments

Micropayments attach a small fee to individual message delivery, providing relay revenue for public traffic and spam deterrence. They are optional and channel-scoped via `messageFeePolicy` in the channel state document:

```json
"messageFeePolicy": {
  "@type": "MessageFeePolicy",
  "scheme": "mob",
  "feeAmount": "1000",
  "feeDenomination": "picoMOB",
  "relayShareBps": 7000,
  "guildShareBps": 2000,
  "freeMessageQuota": 100,
  "senderRefundOnReply": true
}
```

`relayShareBps` + `guildShareBps` MUST sum to ≤ 10000. The remainder is burned to a provably unspendable address. `senderRefundOnReply`: if a recipient replies to a message, the sender's fee is refunded. `freeMessageQuota` is messages per MLS epoch a member may send without payment; after exhaustion, payment is required.

A channel MAY declare multiple fee policies under different schemes:

```json
"messageFeePolicy": [
  { "@type": "MessageFeePolicy", "scheme": "mob",   "feeAmount": "1000", "feeDenomination": "picoMOB", ... },
  { "@type": "MessageFeePolicy", "scheme": "cashu", "feeAmount": "1",    "feeDenomination": "sat",     ... },
  { "@type": "MessageFeePolicy", "scheme": "pow",   "difficulty": 18,                                  ... }
]
```

Clients satisfy whichever policy they support. A client that supports none of the declared schemes MUST NOT post to that channel.

#### Payment Flow

When a channel requires payment, a sending client attaches a `MessagePayment` to the outer `RoutingEnvelope` before submission:

```json
{
  "@type": "MessagePayment",
  "scheme": "mob",
  "relayPaymentProof": "base64url...",
  "guildPaymentProof": "base64url...",
  "ts": "2026-03-12T12:00:00.000Z"
}
```

Both payments are made before submitting the envelope. The relay verifies only its own payment proof before forwarding; it does not verify or intermediate the guild payment. The sender pays both destinations directly:

```
Sender
  ├── relayShareBps × feeAmount → Relay payment pointer
  └── guildShareBps × feeAmount → Guild treasury pointer
```

For `mob`: `relayPaymentProof` is a MOB transaction receipt (key image + amount commitment). For `cashu`: a spent-token proof presented to the relay's trusted mint list. For `bolt12`/`bolt11`: a Lightning payment preimage.

The relay tracks free quota consumption per `channelToken` per epoch. Guild admins MAY grant extended free quotas to specific roles via a signed `QuotaGrant` message gossiped to the channel topic.

### 12.4 Proof-of-Work Spam Deterrence

Channels that want spam deterrence without payment infrastructure MAY use proof-of-work instead of or alongside monetary fees:

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

The relay verifies the PoW before forwarding. Difficulty 18 requires ~262,000 hash operations — roughly 10–50ms on a modern CPU, imperceptible to a human sender, economically prohibitive for bulk flooding. Difficulty is tunable by channel admins via a signed channel state mutation.

PoW provides spam deterrence only, not relay revenue. It is appropriate for high-trust private channels that want rate limiting without monetization.

### 12.5 Payment Flow Summary

| Direction                        | Mechanism                             | Purpose                                           |
|:---------------------------------|:--------------------------------------|:--------------------------------------------------|
| Guild owner → Relay              | `RelayServiceAgreement` recurring payment | Reliable relay service, history retention, SLA |
| Relay → Guild treasury           | Fee-share from service agreement revenue  | Community sustainability fund                  |
| Message sender → Relay           | `MessagePayment` proof-of-payment         | Relay revenue for public traffic, spam deterrence |
| Message sender → Guild treasury  | `MessagePayment` proof-of-payment         | Community fund, spam deterrence                |
| Message sender → (none)          | `PowProof`                                | Spam deterrence only, no revenue               |

All flows are optional. A self-hosted zero-fee deployment uses none of them.

---

## 13. Security Considerations

### 13.1 Forward Secrecy

MLS provides forward secrecy by design. Each epoch derives a new application secret. Compromise of a member's current key material does not expose prior messages.

### 13.2 Post-Compromise Security

MLS `Update` proposals ratchet the tree forward, healing from compromise. Guild operators SHOULD enforce periodic key rotation (recommended: 7-day maximum epoch lifetime).

### 13.3 Relay Trust and Legal Exposure

Relays are untrusted for message content and deliberately blind to metadata.

**What a relay can observe:**
- That a connection was made from an IP address at a given time
- That messages matching a `channelToken` were forwarded (opaque blob; no content, no identity)
- Cached message envelopes within the retention window (opaque, MLS-encrypted, sender DID sealed inside)
- The existence and approximate size of a gossipsub topic mesh

**What a relay cannot observe:**
- Message content (MLS E2EE; relay never holds keys)
- Sender identity for any message (sealed sender; sender DID inside MLS ciphertext)
- Channel identity from `channelToken` (epoch-rotating HKDF derivation, non-reversible without epoch secret)
- Group membership (no membership list at relay layer)
- Message graphs or conversation structure

**What a relay cannot do:**
- Forge messages (sender DID and signature are inside the sealed envelope, verified by recipients)
- Silently modify history (IPLD content addressing detects tampering)
- Correlate routing tables across epochs without epoch secrets

Clients SHOULD connect to multiple Relays simultaneously. A single relay going dark does not partition a user from their channels as long as at least one other relay serving that `channelToken` is reachable.

### 13.4 Metadata Leakage

The sealed sender design eliminates sender identity from the relay layer. Residual metadata leakage points:

**IP address** — a relay sees the connecting IP. Clients requiring IP-level anonymity SHOULD connect via Tor (using the relay's `.onion` endpoint where available) or a trusted front-end proxy. Clients on WireGuard-based overlays present the overlay's internal IP to the relay, revealing overlay membership but not the physical IP.

**Timing correlation** — a global passive adversary watching both sender and relay can correlate message timing. This is a known limitation of all low-latency messaging protocols. Mixing/batching (as in Katzenpost) defeats timing analysis but is incompatible with Discord-like UX latency targets. Accepted tradeoff. Tor users face additional timing exposure from circuit construction and per-hop latency signatures.

**Gossipsub topic subscription** — relays and mesh peers observe which `channelTokens` a peer subscribes to. Since tokens rotate per epoch, long-term correlation requires capturing multiple epochs' tokens and correlating externally. Clients MAY subscribe to decoy `channelTokens` (derived from non-existent channels using valid HKDF derivation) to obscure their actual channel membership pattern. Clients requiring strong subscription privacy SHOULD maintain a fixed subscription count (padding with decoys to a constant) and rotate decoy selections each epoch.

**Tor gossipsub fingerprinting** — as noted in §8.3, gossipsub peer scoring observes message timing and subscription behavior independently of IP. A client connecting via Tor is not fully anonymous at the gossipsub layer.

**Channel token to channel CID** — an adversary who obtains the epoch secret (e.g., via member compromise) can compute the token for any channel they know the CID of. This is acceptable: epoch secret compromise already implies full message compromise for that epoch; the token mapping adds no new capability.

### 13.5 Denial of Service

Gossipsub v1.1 includes peer scoring and flood control. Relays MUST enforce per-`channelToken` rate limits on message publication. Spam control is local relay policy — there is no global reputation system, by design, as global reputation systems become censorship infrastructure.

---

## 14. JSON-LD Context

The canonical RLCHAT JSON-LD context is published at:

```
https://rlchat.protocol/ns/v1
```

It maps all RLCHAT message types and properties to globally unique IRIs and declares their relationship to relevant external vocabularies (schema.org, W3C DID, ActivityStreams where applicable).

All RLCHAT messages MUST include `"@context": "https://rlchat.protocol/ns/v1"` or an equivalent inline context. Processors that do not perform full JSON-LD expansion MAY treat the context as a version tag, but MUST NOT reject messages that include additional `@context` entries for extension vocabularies.

---

## 15. Extension Points

The protocol is designed to be extended without breaking existing clients:

- Unknown `@type` values in inner payloads MUST be ignored by clients that do not understand them (forward compatibility).
- Guild state documents MAY include extension fields prefixed with a registered namespace.
- New channel types MAY be introduced by extending the channel `type` enum in the JSON-LD context.
- Transport encodings beyond CBOR/JSON MAY be negotiated via WebTransport stream headers.

---

## 16. Interoperability

### 16.1 MIMI Native Interop

MIMI (More Instant Messaging Interoperability) is an IETF working group producing a protocol for cross-system E2EE messaging using MLS as the shared key agreement layer. RLCHAT and MIMI share RFC 9420 as their cryptographic foundation, making interoperability a content format and delivery protocol problem rather than a gateway problem. E2EE is preserved end-to-end across the boundary.

#### Shared MLS Group

In MIMI interop mode, a single MLS group spans both RLCHAT and the MIMI-compliant peer system. Members from both systems hold leaves in the same MLS tree and share the same epoch secrets. There is no re-encryption at the boundary — a message sent by an RLCHAT client is decryptable by a MIMI client using its own MLS implementation, and vice versa.

This requires compatible MLS ciphersuites. RLCHAT MUST support `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (ciphersuite 0x0001, the MIMI-mandated baseline) in addition to any other suites it implements. Channels operating in MIMI interop mode MUST use this ciphersuite.

#### Identity Mapping

RLCHAT users are identified by DID; MIMI users are identified by MIMI URIs (of the form `mimi://provider/user-id`). For a cross-system MLS group, each leaf node's credential carries both identifiers:

```json
{
  "@type": "CrossSystemCredential",
  "rlchatDID": "did:key:z6Mk...",
  "mimiURI": "mimi://example.com/alice",
  "sig": "base64url..."
}
```

The credential is signed by the RLCHAT authentication key. MIMI clients verify the MIMI URI portion; RLCHAT clients verify the DID portion. Neither side needs to understand the other's identifier format beyond treating it as an opaque string for display purposes.

#### Content Format Translation

RLCHAT inner payloads use JSON-LD (`@type: ChatMessage` etc.). MIMI defines its own content format (`draft-ietf-mimi-content`). A channel in MIMI interop mode MUST negotiate a shared content format. Two modes are supported:

**MIMI content format mode** — the channel uses the MIMI content format as the canonical inner payload. RLCHAT clients serialize outgoing messages to MIMI content format and deserialize incoming MIMI content to their local display model. RLCHAT-specific features not representable in MIMI content format are carried as MIMI content extensions using the MIMI extension mechanism.

**RLCHAT content format mode** — the channel uses RLCHAT JSON-LD as the canonical inner payload. MIMI clients that support RLCHAT content format (via a registered MIMI content type) participate natively. MIMI clients that do not support RLCHAT content format receive a fallback plain-text rendering negotiated at join time.

The content format in use is declared in the channel state document:

```json
"mimiInterop": {
  "@type": "MIMIInteropConfig",
  "enabled": true,
  "contentFormat": "mimi-v1",
  "mimiProvider": "example.com",
  "mimiRoomURI": "mimi://example.com/rooms/engineering"
}
```

#### Delivery Service Bridging

In MIMI interop mode, RLCHAT Relays act as MIMI delivery service endpoints for their served channels. MLS Commits and Welcome messages are exchanged between RLCHAT Relays and MIMI provider infrastructure via the MIMI delivery protocol. Gossipsub fanout handles RLCHAT-side delivery; the MIMI protocol handles the cross-provider leg.

The RLCHAT Relay serving a MIMI-interop channel registers itself as the MIMI delivery service endpoint for that channel's MLS group with the MIMI provider. MLS handshake messages (Proposals, Commits, KeyPackages) flow bidirectionally between the two delivery services.

#### Limitations

MIMI interop is currently limited by the MIMI specification's own draft status. RLCHAT implementations SHOULD track the MIMI drafts and update their interop implementation as the specs stabilize. Channel state documents carrying `mimiInterop` configurations SHOULD include a `mimiSpecVersion` field to allow clients to detect and handle version skew.

MIMI interop does not currently specify voice/video interop. VTC channels cannot operate in MIMI interop mode until MIMI adds a media signaling specification.

---

### 16.2 Matrix Gateway

Matrix interop is a **gateway**, not native interop. A Matrix gateway holds an RLCHAT DID, is admitted to the relevant channel MLS groups as a member, decrypts RLCHAT messages, re-encrypts them using Matrix's Megolm E2EE for delivery to Matrix users, and performs the reverse for the Matrix→RLCHAT direction. E2EE is broken at the gateway — the gateway holds plaintext. This MUST be disclosed to all participants (§16.3).

#### Gateway Identity and Admission

The Matrix gateway runs as an RLCHAT client with its own DID. It is added to channel MLS groups by a channel Admin via a normal MLS Add commit. The gateway's DID document includes a `service` entry identifying it as a gateway:

```json
{
  "service": [{
    "id": "did:key:z6MkGateway...#gateway",
    "type": "RLCHATMatrixGateway",
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

#### Message Flow: RLCHAT → Matrix

1. Gateway receives MLS-encrypted message from RLCHAT channel gossip topic.
2. Gateway decrypts using its MLS leaf key.
3. Gateway translates RLCHAT inner payload to Matrix event format:
   - `TextBody` → `m.room.message` with `msgtype: m.text`
   - `MediaBody` → `m.room.message` with `msgtype: m.image/m.file`; media fetched from IPFS and re-uploaded to Matrix media server
   - `EditEvent` → `m.room.message` with `m.new_content` relation
   - `DeleteEvent` → `m.room.redaction`
   - `ReactionEvent` → `m.reaction`
4. Gateway sends the translated event to the bridged Matrix room via the Matrix Client-Server API, attributed to a virtual Matrix user representing the RLCHAT sender (`@rlchat_z6Mk...:example.com`).
5. If the Matrix room has Megolm E2EE enabled, the gateway re-encrypts the event using Megolm before sending.

#### Message Flow: Matrix → RLCHAT

1. Gateway receives Matrix event via Matrix Application Service API or sync.
2. Gateway translates the Matrix event to RLCHAT inner payload format.
3. Gateway encrypts the payload using its MLS group membership.
4. Gateway publishes the outer `RoutingEnvelope` to the RLCHAT channel gossip topic.
5. RLCHAT clients see the message as coming from the gateway DID with a `bridgedFrom` field in the inner payload identifying the original Matrix sender's MXID:

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

#### Identity Mapping

RLCHAT DIDs map to Matrix virtual users with a deterministic MXID derived from the DID: `@rlchat_<did-fragment>:<gateway-homeserver>`. Matrix MXIDs map to RLCHAT gateway messages with `bridgedFrom.senderID` carrying the MXID. Display names are fetched from RLCHAT user profiles and Matrix profiles respectively and cached by the gateway.

#### Namespace Mapping

RLCHAT's nested channel namespace does not map cleanly to Matrix's flat room model. The gateway maps each RLCHAT channel path to a separate Matrix room. A guild with nested channels produces a Matrix Space containing one room per channel:

```
rlchat://bafyrei.../general             → !room1:example.com (in Space)
rlchat://bafyrei.../engineering/backend → !room2:example.com (in Space)
rlchat://bafyrei.../engineering/fips    → !room3:example.com (in Space)
```

Category channels (`type: category`) with no messages of their own map to Matrix Space sub-spaces rather than rooms.

#### E2EE Mismatch Handling

When the Matrix room has Megolm E2EE enabled, the gateway holds both MLS session state (for RLCHAT) and Megolm session state (for Matrix). The gateway is the trust boundary — it decrypts on one side and re-encrypts on the other. This is unavoidable for a gateway between two incompatible E2EE systems.

The gateway MUST NOT cache decrypted message content beyond the time needed for translation and re-encryption. It SHOULD operate in a memory-only mode with no persistent plaintext storage. Gateway operators SHOULD publish a transparency policy describing their plaintext handling.

When the Matrix room does not have Megolm E2EE enabled, the gateway sends plaintext to the Matrix server. This means the Matrix homeserver operator can read bridged messages. This MUST be disclosed to RLCHAT channel members (§16.3).

#### Implementation Approach

The recommended implementation uses the **Matrix Application Service API** rather than the Client-Server API. Application services receive all events in a room without polling, can register virtual users in bulk, and receive better rate limit treatment. The gateway registers as an application service on the Matrix homeserver with a namespace regex matching all virtual RLCHAT users.

Existing Matrix bridge frameworks (mautrix-go, mautrix-python) provide the application service scaffolding. The RLCHAT-specific work is the MLS client integration, the RLCHAT↔Matrix content format translation, and the IPFS↔Matrix media re-hosting.

---

### 16.3 Gateway Transparency

Any gateway admitted to an RLCHAT channel MUST be disclosed to all channel members. This is enforced at the protocol level.

**Channel state disclosure.** The `gateways` array in the channel state document (§16.2) is visible to all MLS group members. Clients MUST display a visible indicator when a channel has active gateways. The indicator MUST identify the gateway protocol and target system.

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

This event is stored in the channel's IPLD history as a permanent record.

**Client rendering.** Clients MUST render a persistent banner or channel badge indicating gateway presence. The banner MUST NOT be dismissible per-session without re-appearing on reconnect. Members who joined after a gateway was added receive the `SystemEvent` from history and see the indicator immediately on first load.

---

## 17. Compliance Logging

### 17.1 Overview

Organizations in regulated industries (financial services, healthcare, legal, government) are subject to message retention and audit requirements that conflict with the default RLCHAT model of E2EE with no relay-accessible content. RLCHAT supports compliance logging as an **optional, guild-level feature** that satisfies these requirements without being architecturally clumsy.

Mechanically, compliance logging is an MLS group member — a `ComplianceLogger` principal — that silently receives and archives all messages in every channel it is admitted to. It is structurally identical to a gateway (§16.2) but treated differently at the protocol and UI layers:

- It does not appear as a chat participant in client UI.
- It does not generate join/leave events in the message stream.
- Its presence is disclosed in guild metadata and MLS group membership, not in the message feed.
- It is added to channels automatically by the protocol when logging is enabled, without requiring per-channel Admin action.

### 17.2 Enabling Compliance Logging

Compliance logging is enabled in the Guild state document by the guild owner:

```json
"complianceLogging": {
  "@type": "ComplianceLoggingConfig",
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

`loggerDID` is the DID of the compliance logging principal; it MUST have a corresponding entry in the guild's `ComplianceLogger` registry (§17.3). `logStore` is the IPFS CID root of the compliance log. `scope` is `all-channels` or a list of channel path globs.

Once `complianceLogging.enabled` is set to `true` and gossiped to the guild topic, conformant clients MUST add the `loggerDID` to the MLS group of every channel matching `scope` on the next available Commit. The addition IS recorded in the MLS group membership but MUST NOT produce a UI-visible join notification.

Disabling compliance logging requires a signed Guild state mutation by the guild owner. Clients remove the logger DID from channel MLS groups via Remove commits. The `complianceLogging` history in the IPLD guild state chain retains a permanent record of when logging was enabled and disabled.

### 17.3 Logger Principal

The `ComplianceLogger` is a DID-identified principal operated by the guild's compliance infrastructure — typically an on-premise archival system or a regulated third-party compliance service. The logger's DID document identifies it as a compliance logger:

```json
{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:key:z6MkLogger...",
  "verificationMethod": [...],
  "service": [{
    "id": "did:key:z6MkLogger...#compliance",
    "type": "RLCHATComplianceLogger",
    "serviceEndpoint": "https://archive.acme-corp.internal/rlchat/v1",
    "operator": "Acme Corp Legal",
    "regulatoryFramework": ["FINRA 17a-4", "SEC 17a-4"]
  }]
}
```

`regulatoryFramework` is an informational array of the regulatory requirements the logger is operating under. Clients MAY display this to members who inspect the guild's compliance configuration.

The logger operates as a normal MLS client — it holds leaf credentials, participates in epoch ratchets, and receives `Welcome` messages when added to new channel groups. It is receive-only: it does not send messages, publish presence, or emit typing events.

### 17.4 Log Record Format

Every message received by the logger is written as a signed `ComplianceRecord` to the IPLD log:

```json
{
  "@context": "https://rlchat.protocol/ns/v1",
  "@type": "ComplianceRecord",
  "envelopeID": "urn:rlchat:msg:bafyrei...",
  "channel": "rlchat://bafyrei.../engineering/backend",
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

`plaintextPayload` is the decrypted inner payload, base64-encoded. `outerEnvelopeCID` links the compliance record to the tamper-evident message history. `loggerSig` is the logger's Ed25519 signature over the canonical record. `prevRecordCID` chains records into a linked list — inserting or deleting a record breaks the chain, making the log tamper-evident.

The log is organized as a per-channel IPLD DAG with a guild-level index mapping channel CIDs to their respective log chain heads. The index CID is stored in `complianceLogging.logStore` in the guild state.

### 17.5 Ephemeral Message Handling

Ephemeral messages (`TypingEvent`, `PresenceEvent`) are never logged. Messages with an `expiry` field present a tension between the sender's deletion intent and the compliance retention obligation.

The resolution is explicit and must be disclosed:

- If `complianceLogging.enabled` is `true`, message expiry is honored for relay caches and client display, but the compliance logger retains the plaintext for `retentionDays` regardless of the sender's `expiry` value.
- The Guild state document MUST include a human-readable `retentionNotice` field when compliance logging is enabled:

```json
"retentionNotice": "This guild is subject to regulatory message retention. Messages are archived for 2555 days regardless of expiry settings."
```

- Clients MUST display this notice to members when they first join a compliance-logging-enabled guild, and MUST make it accessible from the guild's information panel at any time.

### 17.6 Voice and Video Logging

VTC logging (audio/video recording) is handled separately from message logging and is covered by the `RecordingGrant` mechanism in §10.6. Compliance logging as defined in this section covers text channels, reactions, edits, deletions, and file attachments only.

An organization requiring VTC compliance recording MUST issue a `RecordingGrant` for the compliance logger's DID on relevant voice channels. The same logger DID MAY hold both text compliance membership and VTC recording grants, but these are governed by separate mechanisms and MUST be separately authorized.

### 17.7 Member Disclosure

Compliance logging is disclosed in guild metadata but not surfaced in the message stream. Conformant clients MUST:

- Display a compliance logging indicator in the guild information panel when `complianceLogging.enabled` is `true`.
- Display the `retentionNotice` to new members on first join.
- Allow members to inspect the `ComplianceLoggingConfig` including `loggerDID`, `loggerLabel`, `retentionDays`, and `regulatoryFramework` from the guild settings UI.
- NOT display a join/leave notification in any channel's message feed when the logger DID is added or removed from an MLS group.

The logger's MLS group membership is visible to any client that inspects the raw MLS group state. The logger is not cryptographically hidden, only UI-silent. A technically sophisticated member can always verify that a logger is present.

---

## 18. Cross-Guild Channel Sharing

### 18.1 Overview

A channel MAY be shared across guild boundaries, giving members of multiple guilds access to the same message stream, history, and MLS group. From a member's perspective in either guild, the shared channel appears as a normal channel in their guild's sidebar.

RLCHAT channel sharing is structurally simpler than Slack Connect because channels are already identified by content-addressed CID. A channel shared between Guild A and Guild B is the same MLS group, the same IPLD history DAG, and the same `channelToken` — there is no synchronization problem because there is no duplication.

### 18.2 Home Guild and Guest Guilds

Every shared channel has exactly one **home guild** — the guild whose namespace contains the channel's canonical path and whose admin is responsible for channel state mutations. There MAY be one or more **guest guilds** whose members access the channel via a local alias path.

The home/guest distinction determines:

- Namespace ownership (home guild owns the path)
- Channel state mutations (home guild admin signs them)
- Compliance logging (home guild's `complianceLogging` config applies to all members)
- Channel deletion (only home guild owner can delete)

Guest guild members have full read/write access to the channel's message stream, subject to the roles negotiated in the `ChannelShareAgreement` (§18.3). They are first-class MLS group members.

### 18.3 Channel Share Agreement

Sharing a channel requires bilateral authorization: the home guild admin and the guest guild admin both sign a `ChannelShareAgreement`.

```json
{
  "@context": "https://rlchat.protocol/ns/v1",
  "@type": "ChannelShareAgreement",
  "id": "urn:rlchat:csa:bafyrei...",
  "homeGuild": "rlchat://bafyrei.../",
  "homeChannel": "rlchat://bafyrei.../engineering/backend",
  "guestGuild": "rlchat://bafyxyz.../",
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

`guestAlias` is the channel path under which the shared channel appears in the guest guild's sidebar — a local alias only. `guestRoles` is the list of guest guild roles whose members are admitted to the channel's MLS group. `guestPermissions` defines the capability constraints applied to guest guild members in this channel.

The agreement is stored as an IPLD node, CID-referenced from both guild state documents, and gossiped on both `rlchat/guild/<homeGuildCID>/v1` and `rlchat/guild/<guestGuildCID>/v1`.

### 18.4 Member Admission

When a `ChannelShareAgreement` is established and gossiped, conformant clients from the guest guild whose roles match `guestRoles` are eligible to join the shared channel's MLS group. Admission follows the standard MLS Add flow, initiated by either:

- A home guild admin issuing a Welcome to the guest member directly, or
- A guest guild admin issuing a bulk Welcome on behalf of all eligible members (requires the guest admin to already be an MLS group member, admitted by the home guild admin as part of agreement setup).

The recommended flow is: home guild admin admits the guest guild admin first; guest guild admin then admits their eligible members. This distributes the Commit workload and avoids requiring the home admin to manage foreign guild membership individually.

Guest members appear in the channel's participant list with a visual indicator of their home guild (a guild icon or badge). Clients SHOULD display the member's display name from their own guild's profile with the foreign guild indicator making affiliation clear.

### 18.5 Namespace Resolution

A guest guild member sees the channel at `guestAlias` in their guild sidebar. Internally, the client resolves this alias to the home channel's CID and connects to the home channel's MLS group and gossip topic. All protocol operations (message send, history fetch, MLS operations) use the home channel's identity.

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

If the agreement is revoked (§18.7), the alias entry is removed from the guest guild state and clients remove the channel from their sidebar on next state refresh.

### 18.6 Relay Coordination

The home channel's gossip topic is where all messages flow. Guest guild members subscribe via their own Relays. No special relay configuration is required if both guilds' Relays participate in the same gossipsub mesh. For private guilds on isolated networks (e.g., separate Tailscale overlays), explicit relay peering must be established. The `ChannelShareAgreement` MAY include a `relayHints` array suggesting peering endpoints:

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
  "@context": "https://rlchat.protocol/ns/v1",
  "@type": "ChannelShareRevocation",
  "agreementCID": "bafyrei...",
  "revokedBy": "did:key:z6MkRevoker...",
  "revokedByGuild": "rlchat://bafyrei.../",
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
5. Guest guild members lose the ability to decrypt new messages immediately (MLS epoch advances on the Remove commits); they retain locally cached history up to the revocation epoch.

The revocation is signed by the revoking party's admin key. The counter-party does not need to co-sign.

### 18.8 Compliance Logging Across Guild Boundaries

The home guild's compliance logging configuration (§17) applies to all messages in the shared channel regardless of sender guild affiliation. Guest guild members MUST be notified of this at channel join time. The client displays the home guild's `retentionNotice` to guest members on first entry, clearly attributing it to the home guild.

If the guest guild also has compliance logging enabled, its logger is added to the shared channel's MLS group subject to home guild admin approval — a separate MLS Add commit is required. Both loggers may simultaneously hold membership. The home guild admin MAY reject a guest guild's compliance logger by declining to issue a Welcome.

### 18.9 Voice Channel Sharing

Voice channels MAY be shared using the same `ChannelShareAgreement` mechanism. All VTC semantics (§10) apply unchanged — the shared voice channel has one MLS group, one call state gossip stream, and one SFU if configured. The SFU used is the home guild's SFU. Guest guild members connect to the home guild's SFU directly.

If the home guild does not have an SFU configured and the shared voice channel exceeds the mesh threshold (§10.5), the home guild admin is responsible for provisioning one. The `ChannelShareAgreement` MAY specify a minimum SFU capacity as a precondition for guest guild participation.

---

## Appendix A: Dependency Summary

| Component                     | Specification                                                                 |
|:------------------------------|:------------------------------------------------------------------------------|
| E2EE group key management     | RFC 9420 (MLS)                                                                |
| Message framing               | JSON-LD (W3C)                                                                 |
| Identity                      | W3C DID Core, `did:key`, `did:web`                                            |
| Content addressing            | IPFS / IPLD (CIDv1, dag-cbor)                                                 |
| Peer discovery / fanout       | libp2p gossipsub v1.1                                                         |
| Primary transport             | WebTransport (RFC 9000)                                                       |
| Fallback transport            | WebSocket (RFC 6455)                                                          |
| Voice/video                   | WebRTC                                                                        |
| Wire encoding                 | CBOR (RFC 8949)                                                               |
| Payments (preferred)          | MobileCoin (MOB)                                                              |
| Payments (micropayment alt)   | Cashu ecash over Lightning                                                    |
| Payments (service agreements) | Lightning Network BOLT 12                                                     |
| Spam deterrence (no payment)  | Hashcash-style PoW                                                            |
| Native cross-system interop   | MIMI (RFC 9764, draft-ietf-mimi-content, draft-ietf-mimi-protocol)            |
| Matrix gateway                | Matrix Application Service API (MSC2190)                                      |
| Relay-to-relay authentication | RFC 9421 HTTP Message Signatures                                               |
| Relay bootstrap DNS           | DNS-SD / SRV / TXT records                                                    |

## Appendix B: Open Questions

1. **SFU trust model for voice** — the SFU holds decryption rights for voice streams when recording is enabled. The mechanism by which a guild grants and auditably revokes recording rights to an SFU DID needs a dedicated sub-specification.

2. **Cross-guild identity and reputation** — a user banned from one guild can freely join another. Whether this is a feature or a gap depends on use case. A voluntary cross-guild reputation attestation format, and whether `ChannelShareAgreement` should carry cross-guild ban propagation as an option, are open questions.

3. **Push notifications** — mobile clients require a persistent connection or a push proxy to receive messages when backgrounded. APNs and FCM require a centralized intermediary that conflicts with the relay-blind metadata model. A privacy-preserving push proxy design (analogous to Signal's approach) is needed before RLCHAT is viable as a primary mobile messaging client.
