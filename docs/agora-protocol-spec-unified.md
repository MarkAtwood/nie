# Agora Protocol Specification v0.2 (Draft)

**Version:** 0.2 (Draft)
**Date:** 2026-04-21
**Status:** Draft amendment incorporating DM Channel Type and Compliance Logging patch (§9.6, §17.1, §17.2, §17.5, §17.7, §17.8) and Enterprise Identity Provisioning (§2.5)

---

## Version Policy

All versioned protocol surfaces in this specification are at **v1** for the initial release. The version appears as a path prefix on HTTP endpoints (`/v1/agora/...`), as a topic prefix on gossip topics (`v1/agora/...`), in JSON-LD context URLs (`/ns/v1`), and in document `schemaVersion` fields.

A breaking change to any one surface increments only that surface's version; all other surfaces remain at their current version and are unaffected. Clients and relays MUST reject messages or connections whose version they do not support and MUST NOT silently coerce an unknown version to a known one.

Version negotiation is defined per surface:

- **Transport endpoints** — the URL path version is fixed at connection time; a client connects to `/v1/agora/wt` or `/v1/agora/ws` and the relay either accepts or returns HTTP 404/410.
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
| **RFC 9750 (MLS Architecture)** | Informational architecture reference for MLS deployment concepts |
| **JSON-LD** | Typed, namespace-aware message framing |
| **libp2p gossipsub v1.1** | Peer discovery, room advertisement, live message fanout |
| **IPLD** | Content-addressed data model (CIDv1 dag-cbor); relay-hosted CAS for blob storage |
| **WebTransport (RFC 9000)** | Primary transport for browsers and native clients |
| **WebSocket (RFC 6455)** | Fallback transport, and the only transport available over Tor |
| Payment schemes (optional) | Relay economics and message micropayments; scheme-agnostic — see §12 |

Agora does **not** define a central server. It defines a protocol that servers — called **Relays** — implement to form a federated, permissionless mesh. Users are not locked to any particular Relay. Relays gossip with each other. Clients may connect to multiple Relays simultaneously and reconcile state across them.

### Design Principles

**Relay blindness.** A conformant Relay deliberately cannot read message content, identify senders, or map channel tokens to channel identities or member lists. This is not just policy — it is a structural property of the protocol. A Relay operator served a subpoena should be able to honestly say they hold no useful data.

**Federated, not centralized.** Anyone can run a Relay. Any Relay that speaks the protocol can join the mesh. There is no registration, no whitelist, no governing authority over who participates.

**Content addressing.** All persistent state — messages, space definitions, profiles, channel history — is stored in IPFS/IPLD and addressed by content hash (CID). History is tamper-evident by construction. Two Relays storing the same message store the same CID; deduplication is automatic.

**MLS everywhere.** MLS (RFC 9420) is the sole key agreement mechanism. It provides forward secrecy, post-compromise security, and multi-device membership natively. Every channel is an MLS group. Signaling, moderation records, and compliance logs all flow through MLS-authenticated channels.

---

## 2. Identity

### 2.1 User DID

Every user has a **Decentralized Identifier (DID)** as their persistent identity. DIDs are self-certifying: possession of the private key proves identity without any registry or certificate authority. The recommended methods are:

- **`did:key`** — derives the DID directly from the public key. Entirely self-contained, no DNS dependency, works offline. Preferred for individuals.
- **`did:web`** — anchors identity to a DNS domain. Appropriate for organizations that want verifiable institutional identity tied to their domain name.

A user's DID document contains two key roles:

- **`authentication`** key — Ed25519 key used to sign all protocol messages, space state mutations, and moderation actions.
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

**The recovery key is the root of trust for identity recovery.** Its private key MUST NOT leave a secure offline boundary — paper backup, air-gapped device, or hardware security key. It MUST NOT be imported into any networked device or software keystore under any circumstances during normal operation.

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

The `SocialRecoveryConfig` is stored in the user's profile IPLD chain. `recoveryCommitment` is a SHA-256 hash of `S` used to verify share reconstruction without revealing `S` before recovery begins.

**Recovery:** The user contacts `threshold` guardians out-of-band and requests their shares. Each guardian decrypts their encrypted share using their X25519 key and transmits it to the recovering user. The user reconstructs `S` from the shares, verifies it against `recoveryCommitment`, then uses `S` to derive a new signing key and publish a `RecoveryAssertion` signed with it.

`S` itself is never stored anywhere — it exists only transiently during setup (to split) and recovery (to reconstruct). Guardians hold encrypted shares; relays hold nothing related to recovery.

**Guardian obligations:** Guardians SHOULD confirm their designation when first asked. The account owner SHOULD periodically verify that all guardians remain reachable and responsive, and should re-key shares when a guardian becomes unreachable or leaves the system.

**Reference implementations for SSS:** [`hashicorp/vault` SSS](https://github.com/hashicorp/vault/tree/main/shamir) (Go), [`secrets.js`](https://github.com/grempe/secrets.js) (JS), [`sharks` crate](https://crates.io/crates/sharks) (Rust).

#### 2.4.3 Encrypted Backup

A client MAY export an encrypted backup of device key material and MLS state to a user-chosen location — a local file, cloud storage, IPFS, or any other storage the user controls. The backup is encrypted with a user-chosen passphrase using Argon2id key derivation:

```
backupKey = Argon2id(passphrase, salt, m=65536, t=3, p=4)
backup    = AEAD_AES_256_GCM(backupKey, backupPayload)
```

`backupPayload` is a CBOR-encoded structure. Its contents depend on the key storage model in use:

**Software keystore (extractable keys).** All key material is available for export:
- All device Ed25519 private keys
- All device X25519 private keys
- Current MLS key material for all group memberships
- The recovery key private key (if one was generated and held in software — see §2.4.1)
- Timestamp and DID

**HSM / Secure Enclave / non-extractable keys.** Private keys cannot be exported by design. The backup contains only:
- The MLS group state exported via the MLS key export interface (RFC 9420 §8)
- Public keys and DID document
- Timestamp and DID

A backup from a non-extractable-key environment restores MLS continuity but cannot restore the private keys themselves. Restoring identity on a new device requires either (a) the social recovery mechanism (§2.4.2), or (b) generating a new device keypair and having an existing device add it as a new MLS leaf.

Clients SHOULD clearly communicate to the user which type of backup their platform produces. The backup file is self-describing: it includes the Argon2id parameters, the DID, and a `backupType` field (`"full"` or `"stateOnly"`).

Clients SHOULD prompt users to export an encrypted backup at account creation and after any significant key rotation event. Clients MUST NOT store the backup passphrase anywhere on the device.

**Reference implementations for Argon2id:** [`golang.org/x/crypto/argon2`](https://pkg.go.dev/golang.org/x/crypto/argon2) (Go), [`argon2` npm package](https://www.npmjs.com/package/argon2) (JS/Node), [`argon2` crate](https://crates.io/crates/argon2) (Rust), [`argon2-cffi`](https://pypi.org/project/argon2-cffi/) (Python).

#### 2.4.4 Recovery Precedence and Conflict Resolution

If multiple recovery mechanisms are triggered simultaneously and produce conflicting `RecoveryAssertion` messages, the conflict is resolved by timestamp: the earlier valid `RecoveryAssertion` wins. Relays that observe a second `RecoveryAssertion` for the same DID within 24 hours of the first MUST reject it and flag the conflict in their logs.

### 2.5 Enterprise Identity Provisioning (SAML / OIDC)

In enterprise deployments, user identities are managed by the organization via an existing Identity Provider (IdP) — Microsoft Entra ID, Okta, Ping, or any SAML 2.0 / OIDC-compliant IdP. This section specifies how `did:web` identities are provisioned by the organization and how device keys are registered by user agents against that identity, maintaining the correct trust separation: the organization controls the identity namespace and can revoke it; the device controls the private key material and the organization cannot impersonate the user.

#### 2.5.1 Trust Separation

The fundamental constraint this section enforces:

- **The organization provisions and owns the `did:web` document.** It controls the DNS domain, the HTTPS endpoint serving the document, and therefore has revocation authority — it can retire any DID it controls by taking down or blanking the document.
- **The user agent generates and owns device private keys.** Private keys are generated inside the device's secure hardware boundary (Secure Enclave, StrongBox, TPM) and never leave it. The organization cannot generate, hold, or retrieve these keys. The organization cannot impersonate a user even with full control of the `did:web` document.
- **Device public keys are registered into the `did:web` document** via an authenticated provisioning endpoint. Authentication uses the IdP token (proving user identity to the org); authorization uses an existing device key signature (proving key possession) or the IdP token alone for first-device enrollment.

This mirrors how S/MIME and WebAuthn work in enterprise: the org manages the certificate or credential binding; the private key never leaves the user's hardware.

#### 2.5.2 DID Namespace and Document Hosting

The organization provisions `did:web` identities in a controlled namespace:

```
did:web:{orgDomain}:users:{localIdentifier}
```

Resolution: `GET https://{orgDomain}/users/{localIdentifier}/did.json`

Examples:
- `did:web:acme.com:users:alice` → `GET https://acme.com/users/alice/did.json`
- `did:web:acme.com:users:alice.chen` → `GET https://acme.com/users/alice.chen/did.json`

The `localIdentifier` SHOULD be derived from the user's IdP principal (UPN, username, or employee ID) and MUST be stable for the lifetime of the account. It MUST NOT be reassigned to a different person after the original user departs.

The DID document is served by the organization's **DID Provisioning Service** — a lightweight HTTPS service, typically deployed alongside the organization's IdP or directory service. The service:

- Maintains the authoritative DID document for each user in a backing store (LDAP attribute, database, or directory extension)
- Serves documents at the well-known URL path
- Accepts authenticated device key registration requests (§2.5.4)
- Accepts authenticated device revocation requests (§2.5.5)
- Publishes DID document updates to the Agora gossipsub discovery mesh (§3)

#### 2.5.3 Initial Provisioning (Onboarding)

When a user is onboarded to Agora, the organization creates a stub DID document containing no device keys. This happens in the same workflow as email account creation — automated via HR system integration or the IdP's provisioning API (SCIM 2.0 is the standard mechanism):

```json
{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:web:acme.com:users:alice",
  "verificationMethod": [],
  "authentication": [],
  "keyAgreement": [],
  "service": [{
    "id": "did:web:acme.com:users:alice#agora",
    "type": "AgoraRelay",
    "serviceEndpoint": "wss://relay.acme.com/v1/agora/ws"
  }]
}
```

The stub document is valid and resolvable. It has no keys, so no one can authenticate as Alice yet. The document becomes operational when Alice's first device key is registered in §2.5.4.

The provisioning service MUST record the creation timestamp and provisioning operator identity in an audit log.

#### 2.5.4 Device Key Registration

When Alice installs the Agora client on a new device, the client performs the following enrollment sequence:

**Step 1 — Key generation.** The client generates a new device keypair in the secure hardware boundary:
- Ed25519 keypair for `authentication` (signing)
- X25519 keypair for `keyAgreement` (MLS key packages, HPKE)

Neither private key leaves the secure enclave. The client holds only the public keys for transmission.

**Step 2 — IdP authentication.** The client initiates an SAML 2.0 or OIDC authentication flow against the organization's IdP. The user authenticates (password + MFA) and the client receives an IdP token.

**Step 3 — Registration request.** The client sends a signed registration request to the DID Provisioning Service:

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "DeviceKeyRegistrationRequest",
  "did": "did:web:acme.com:users:alice",
  "deviceLabel": "Alice's MacBook Pro",
  "deviceEd25519PublicKey": "base64url(Ed25519 pubkey)",
  "deviceX25519PublicKey": "base64url(X25519 pubkey)",
  "platform": "macOS",
  "secureEnclaveAttested": true,
  "ts": "2026-03-12T12:00:00.000Z",
  "idpToken": "base64url(SAML assertion or OIDC id_token)",
  "existingDeviceSig": "base64url(...) | absent for first device"
}
```

`existingDeviceSig` is a signature over the canonical serialization of the other fields, made by an existing registered device key. For first-device enrollment it is absent. For subsequent devices it MUST be present — the IdP token alone authorizes adding a device only on first enrollment; subsequent enrollment requires proof of an existing authorized device.

`secureEnclaveAttested` is `true` if the platform supports hardware attestation of key generation. When `true`, the provisioning service SHOULD verify the attestation before accepting the key.

**Step 4 — Provisioning service validation.** The service:
1. Verifies the IdP token signature against the IdP's public key
2. Verifies the token is issued for the user matching the `did` in the request
3. Verifies the token is not expired and was issued for the Agora provisioning service audience
4. For non-first-device enrollment: verifies `existingDeviceSig` against a currently registered device key in the DID document
5. Checks that the user account is active (not suspended or offboarded)
6. Checks that the number of registered devices does not exceed the org's configured limit (default: 10)

**Step 5 — DID document update.** On successful validation, the service adds the new device keys to the DID document:

```json
{
  "verificationMethod": [
    {
      "id": "did:web:acme.com:users:alice#device-{deviceKeyFingerprint}",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:web:acme.com:users:alice",
      "publicKeyMultibase": "z...",
      "meta": {
        "deviceLabel": "Alice's MacBook Pro",
        "platform": "macOS",
        "registeredAt": "2026-03-12T12:00:00.000Z",
        "secureEnclaveAttested": true
      }
    },
    {
      "id": "did:web:acme.com:users:alice#device-{deviceKeyFingerprint}-x25519",
      "type": "X25519KeyAgreementKey2020",
      "controller": "did:web:acme.com:users:alice",
      "publicKeyMultibase": "z..."
    }
  ],
  "authentication": ["did:web:acme.com:users:alice#device-{deviceKeyFingerprint}"],
  "keyAgreement": ["did:web:acme.com:users:alice#device-{deviceKeyFingerprint}-x25519"]
}
```

`deviceKeyFingerprint` is the first 16 bytes of the SHA-256 hash of the Ed25519 public key, hex-encoded.

**Step 6 — Gossip publication.** The provisioning service gossips the updated DID document hash on `v1/agora/discovery`.

**Step 7 — KeyPackage upload.** The newly enrolled client generates an initial batch of MLS KeyPackages (§6.1) and uploads them to its configured relay, completing enrollment.

#### 2.5.5 Device Revocation

Device revocation can be initiated by the user (lost or retired device) or by the organization (employee departure, security incident).

**User-initiated revocation.** From any other enrolled device, the user sends:

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "DeviceRevocationRequest",
  "did": "did:web:acme.com:users:alice",
  "revokeDeviceKeyID": "did:web:acme.com:users:alice#device-{fingerprint}",
  "reason": "device-lost | device-retired | security-incident",
  "ts": "2026-03-12T12:00:00.000Z",
  "requestingSig": "base64url(signature by a surviving device key)"
}
```

**Organization-initiated revocation.** An IT administrator authenticates to the provisioning service admin interface and submits a revocation for any device key or for the entire DID (full account suspension):

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "AdminRevocationRequest",
  "did": "did:web:acme.com:users:alice",
  "revokeDeviceKeyID": "did:web:acme.com:users:alice#device-{fingerprint}",
  "revokeAll": false,
  "reason": "employee-offboarding | security-incident | policy-violation",
  "adminDID": "did:web:acme.com:users:it-admin",
  "adminSig": "base64url(...)",
  "ts": "2026-03-12T12:00:00.000Z"
}
```

`revokeAll: true` removes all device keys from the DID document, effectively suspending the account. The DID document remains resolvable but has no `authentication` keys.

**Revocation mechanics.** On receipt of a valid revocation request, the provisioning service:

1. Removes the specified `verificationMethod` entry and its references from `authentication` and `keyAgreement`
2. Records the revocation in the audit log with timestamp, reason, and initiator
3. Gossips a `DeviceRevocation` control message on `v1/agora/discovery` carrying the revoked key ID and a signature by the provisioning service's own signing key
4. Notifies the user's remaining enrolled devices via their push handles (if push proxy is configured)

Relays that receive a valid `DeviceRevocation` message MUST immediately invalidate any cached session tokens for the revoked key ID (§8.6).

**MLS remediation.** Revocation of a device key does not automatically remove that device's MLS leaf nodes from all groups. The revoked device's client (if still running) SHOULD issue `Remove` self-proposals on all its group memberships. If the device is genuinely lost, other group members MUST issue `Remove` commits when they detect the key is revoked. Space administrators SHOULD run periodic reconciliation to ensure revoked device keys have no active MLS leaves in their channels.

#### 2.5.6 Offboarding

When an employee leaves, the organization performs a full account suspension:

1. IdP account is disabled (blocks new IdP token issuance)
2. Admin issues `revokeAll: true` revocation via the provisioning service
3. The DID document is updated to remove all device keys
4. The provisioning service gossips the revocation
5. The organization retains the DID document (does not delete it) for the regulatory retention period
6. After the retention period, the document MAY be blanked (empty `verificationMethod`) but MUST NOT be removed — the URL must remain resolvable to avoid dangling references in archived compliance records

#### 2.5.7 Provisioning Service DID Document

The provisioning service itself is a DID-bearing principal:

```json
{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:web:acme.com:agora:provisioning",
  "verificationMethod": [{
    "id": "did:web:acme.com:agora:provisioning#signing-1",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:web:acme.com:agora:provisioning",
    "publicKeyMultibase": "z..."
  }],
  "authentication": ["did:web:acme.com:agora:provisioning#signing-1"]
}
```

Every DID document update the provisioning service publishes MUST include a `provisionerSig` field: an Ed25519 signature over the canonical CBOR serialization of the updated DID document, signed by the provisioning service's key. Clients and relays MUST verify this signature when processing DID document updates received via gossip.

This creates a two-party integrity guarantee: the user's device key proves the user authorized the key, and the provisioner's signature proves the organization accepted and recorded the registration. Neither can forge the other's contribution.

#### 2.5.8 Relationship to §2.4 Recovery Mechanisms

For enterprise `did:web` identities, the recovery mechanisms of §2.4 interact with organizational authority as follows:

- **Recovery key (§2.4.1):** Valid, but the recovery key can only rotate device keys — it cannot override an organization-initiated `revokeAll`. Recovery keys are appropriate for individual-initiated recovery (lost device, not offboarding).

- **Social recovery (§2.4.2):** Valid for user-initiated recovery. The provisioning service accepts a `RecoveryAssertion` signed by the social recovery reconstructed key as equivalent to an IdP token for first-device enrollment, provided the `recoveryCommitment` in the DID document verifies.

- **Encrypted backup (§2.4.3):** Valid. The backup restores MLS state and device keys. The restored device still needs to be enrolled via §2.5.4 to update the DID document with the restored public key.

- **Org-initiated recovery (helpdesk):** When a user loses all devices and has no recovery key or guardians, the organization can initiate recovery on their behalf: an admin issues a provisioning request (with `existingDeviceSig` absent, substituted by admin authorization) to add a new device key to the user's DID document. This path MUST be logged in the audit trail — it is a privileged operation.


---

## 3. Topology

### 3.1 Participants

- **Client** — a user agent (web browser, desktop application, mobile app). Connects to one or more Relays. Has access to the user's cryptographic keys and MLS state, either directly (software keystore) or via a co-located secure boundary (OS Secure Enclave, hardware security key, HSM). Responsible for all encryption and decryption operations; those operations SHOULD be performed inside the secure boundary wherever the platform supports it.
- **Relay** — an always-on server that participates in gossipsub, caches recent messages within a configured retention window, serves WebTransport and WebSocket endpoints for clients, and optionally pins IPFS content. Anyone may operate a Relay; no permission is required.
- **Peer** — any participant in the gossipsub mesh, including both Relays and clients with persistent connections.

### 3.2 Space and Channel Hierarchy

A **Space** is a named collection of channels, analogous to a Discord server. A **Channel** is a named, typed stream of messages within a Space.

Every channel has a **mode** that determines its encryption and membership model:

| Mode | MLS group | Who can post | Encrypted | Use case |
|---|---|---|---|---|
| `interactive` | All members (≤ 200) | All members | Yes — full MLS E2EE | Team channels, DMs, small communities |
| `community` | Active speakers only (≤ `speakerCap`) | Space members in speaker group | Yes — full MLS E2EE for speakers | Large community channels |
| `broadcast` | None | Space admins / designated posters | No — signed but readable | Announcements, release notes |

Space membership does not imply channel membership in any mode. A space may have thousands of members while a channel's active MLS group remains small.

Space and Channel identifiers are **namespaced paths**:

```
agora://<space-id>/<channel-path>
```

Where `<space-id>` is the CID of the Space's root state document, and `<channel-path>` is a slash-delimited path supporting arbitrary nesting:

```
agora://bafyrei.../general
agora://bafyrei.../engineering/backend
agora://bafyrei.../engineering/backend/incidents
agora://bafyrei.../voice/lounge
```

Channel nesting is structural only — a parent channel (such as `engineering`) can itself be a message channel, a category header, or both. The namespace is a tree; there is no enforced depth limit.

### 3.3 Space State Document

The Space state document is stored as an IPLD DAG node. Its CID changes on every mutation. The Space's identity is anchored to its genesis CID; subsequent state is represented as a signed chain of mutations, each referencing the prior state CID in its `prevStateCID` field. This makes the Space history tamper-evident: replacing any intermediate state document breaks the chain.

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "SpaceState",
  "schemaVersion": "1",
  "id": "agora://bafyrei...",
  "name": "wolfSSL Dev",
  "iconCID": "bafyrei...",
  "owner": "did:key:z6Mk...",
  "channels": [
    {
      "path": "general",
      "type": "text",
      "mode": "interactive",
      "name": "general"
    },
    {
      "path": "announcements",
      "type": "text",
      "mode": "broadcast",
      "name": "Announcements"
    },
    {
      "path": "community",
      "type": "text",
      "mode": "community",
      "name": "Community",
      "speakerCap": 200,
      "idleEvictDays": 7
    },
    {
      "path": "engineering",
      "type": "category",
      "name": "Engineering",
      "children": [
        { "path": "engineering/backend", "type": "text", "mode": "interactive" },
        { "path": "engineering/fips",    "type": "text", "mode": "interactive" }
      ]
    },
    {
      "path": "voice/lounge",
      "type": "voice"
    }
  ],
  "roles": [...],
  "customEmoji": [],
  "vtcCompliance": {},
  "mlsGroupID": "base64url...",
  "prevStateCID": "bafyrei...",
  "seq": 42,
  "sig": "base64url..."
}
```

`sig` is an Ed25519 signature over the canonical CBOR serialization of the document (per §14.1), signed by the Space owner's authentication key or a delegated admin's key.

### 3.4 Deployment Topologies

Agora is transport-agnostic at the application layer. The following deployment topologies are explicitly supported:

**Public internet (default)** — Relays are clearnet HTTPS/WSS servers with public IPv4 and/or IPv6 addresses. Clients connect over the public internet. This is the baseline configuration assumed throughout this specification unless otherwise noted.

**Tor hidden service** — A Relay MAY operate as a Tor v3 hidden service, publishing a `.onion` address in its `RelayAd` alongside or instead of a clearnet endpoint. Clients connecting via Tor MUST use the WebSocket transport (§8.2); WebTransport requires QUIC over UDP and is unavailable over Tor.

**Private overlay (Tailscale / WireGuard / Headscale)** — A Relay MAY operate exclusively on a WireGuard-based overlay network. The Relay's `RelayAd` lists overlay-internal hostnames or `100.x.x.x` addresses; these are only resolvable inside the overlay. This is the recommended topology for private organizational deployments where all members are already on a common overlay. A fully self-contained deployment — Relay + SFU + TURN + Headscale, all on-premise — has zero dependency on any external infrastructure.

**Dual-stack (clearnet + overlay)** — A Relay MAY publish both clearnet and overlay endpoints. Clients on the overlay prefer the overlay path; external clients use the clearnet path. Both sets of clients share the same space state and message history.

**Managed / SaaS** — A relay operator (the "managed provider") provisions and operates a dedicated Agora relay fleet on behalf of a customer. Each customer receives their own isolated deployment — separate relay processes, separate database, separate blob store — not a shared multi-tenant instance. The customer controls, or delegates control of, the DNS name that roots their deployment; the managed provider's infrastructure hosts it (typically via CNAME or DNS delegation). The managed provider's identity appears as `operatorDID` in each relay manifest (§3.5.1), but `relayDID` is anchored to the customer's DNS domain, not the provider's. This preserves namespace ownership: if the customer migrates to self-hosted, their DNS name and all derived identities (`did:web:<customer-domain>:users:...`) are portable without re-enrollment.

**IPv6** — All Relay endpoints SHOULD support IPv6. Relay URIs MUST use bracket notation for IPv6 address literals (`wss://[2001:db8::1]/v1/agora/ws`). ICE gathers both IPv4 and IPv6 host candidates; dual-stack clients race both address families.

#### 3.4.1 Discoverability and DNS Namespace Root

A deployment's ability to participate in the public Agora mesh depends on whether it has a DNS root:

**Discoverable deployments** (public internet, managed/SaaS, dual-stack) SHOULD be anchored to a DNS name. That name is the root of the deployment's identity namespace: relay DIDs are `did:web:<domain>`, organizational user DIDs are `did:web:<domain>:users:...`, and the relay manifest is served at `https://<domain>/.well-known/agora-relay`. Any two deployments with distinct DNS names have non-overlapping identity namespaces by construction; no registry or authority is required to prevent conflicts.

**Non-discoverable deployments** (private overlay, air-gapped, Tor-only) have no DNS root requirement. Relay DIDs are `did:key:...`; user DIDs are `did:key:...` or `did:web` anchored to an internal-only domain. These deployments cannot join the public gossipsub mesh or federate with external organizations. This is an explicit architectural trade-off, not a misconfiguration.

No registry, whitelist, or certificate authority governs which DNS names may root an Agora deployment. DNS ownership is the sole claim to a namespace.

### 3.5 Relay-to-Relay Peering and Authentication

Relays form a gossipsub mesh with each other for fanout. This section specifies how Relays discover each other, authenticate, establish trust levels, and maintain the mesh. The model follows a well-known manifest endpoint, RFC 9421 HTTP Message Signatures for relay-to-relay authentication, graduated trust levels, and zero-configuration bootstrap from any single known peer.

**Transport for relay-to-relay communication.** libp2p supports multiple transports; Relays SHOULD prefer **QUIC-v1** (`/ip4/.../udp/.../quic-v1` multiaddr) for gossipsub connections, with TCP (`/ip4/.../tcp/...`) as the fallback for environments where UDP is blocked. QUIC eliminates head-of-line blocking between gossip streams and removes TCP from the relay-to-relay data path entirely. The Peer API (§3.5.2) SHOULD be served over **HTTP/3** (QUIC); Relays MUST also support HTTP/1.1 or HTTP/2 over TLS as a fallback and SHOULD advertise HTTP/3 availability via `Alt-Svc: h3="<port>"` response headers. Relay operators that cannot expose UDP MAY operate TCP-only, but MUST declare this in their manifest `capabilities` by omitting `gossipsub-quic-v1`.

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
    "peerAPI":         "https://relay.example.com/v1/agora/peer",
    "gossipQuic":      "/ip4/203.0.113.42/udp/9001/quic-v1",
    "jmap":            "https://relay.example.com/jmap"
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
  "acceptedSchemes": ["cashu", "pow"],
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

`sig` is the Relay operator's Ed25519 signature over the canonical CBOR serialization of the manifest, excluding the `sig` field. Peer Relays MUST verify this signature before accepting the manifest.

`knownPeers` is the Relay's current peer list. This serves as a mesh map: a new Relay fetching any existing Relay's manifest obtains a list of further Relays to contact, enabling rapid mesh joining without a central directory server.

**Relay DID and DNS binding.** For relays operating on the public internet (§3.4), `relayDID` SHOULD be a `did:web` anchored to the relay's DNS domain rather than a `did:key`:

```json
"relayDID": "did:web:relay.example.com"
```

The relay MUST serve a conformant DID document at `https://relay.example.com/.well-known/did.json`. This creates a verifiable binding: the manifest at `/.well-known/agora-relay` is signed by the key declared in the DID document, and the DID document SHOULD include a `service` entry pointing back to the manifest URL. Any peer that resolves `did:web:relay.example.com` can verify that the key material and the DNS domain are controlled by the same entity.

For relays operating exclusively on a private overlay, Tor hidden service, or air-gapped network — where no public DNS name exists or is desired — `relayDID` MAY be `did:key:...`. These relays do not participate in the public mesh and do not require DNS binding.

**Operator vs. customer identity.** The `operatorDID` field records the identity of the party that operates the relay infrastructure. For self-hosted deployments, `operatorDID` and the relay's controlling entity are the same. For managed/SaaS deployments (§3.4), they differ: `relayDID` is anchored to the customer's DNS domain; `operatorDID` is the managed provider's DID. This distinction is relevant to legal exposure (§13.3) and compliance logging (§17).

`capabilities` is an array of capability strings declaring what features this Relay supports:

| Capability | Meaning |
|---|---|
| `gossipsub-v1.1` | Participates in libp2p gossipsub v1.1 mesh over TCP |
| `gossipsub-quic-v1` | Participates in libp2p gossipsub v1.1 mesh over QUIC-v1 (preferred) |
| `peer-api-h3` | Peer API is served over HTTP/3 (QUIC); `Alt-Svc: h3` header is present |
| `keypackage-store-v1` | Hosts the KeyPackage Store API (§6.1.1) |
| `keypackage-forwarding-v1` | Supports inter-relay KeyPackage forwarding |
| `keypackage-ipfs-supply-v1` | Can replenish the KeyPackage store from a DID's IPFS supply CID (§6.1.1) |
| `tor-hidden-service-v1` | Reachable via a `.onion` endpoint |
| `sfu-v1` | Hosts an SFU for voice channel routing |
| `compliance-logging-v1` | Supports compliance logger DID admission (§17) |
| `peer-api-v1` | Implements the Peer API v1 (§3.5.2) |
| `push-proxy-v1` | Operates a push notification proxy (§8.7) |
| `jmap-v1` | Exposes the JMAP Management and Sync API (§8.8) |

#### 3.5.2 Peer API

Relays expose a **Peer API** at the URL declared in `endpoints.peerAPI` for relay-to-relay operations. All Peer API requests (except `manifest` and `health`, which are unauthenticated) are signed using RFC 9421 HTTP Message Signatures (§3.5.3).

Relays SHOULD serve the Peer API over HTTP/3 and advertise this via `Alt-Svc: h3="9001"` (or the appropriate port) on all HTTP responses. A connecting Relay that receives an `Alt-Svc` header SHOULD upgrade to HTTP/3 for subsequent requests. Relays MUST continue to accept HTTP/1.1 and HTTP/2 over TLS on the same `peerAPI` URL for peers that cannot use QUIC.

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

**Method 1 — Known peer URL.** The operator provides one or more peer Relay URLs in the startup configuration. The new Relay fetches `/.well-known/agora-relay` from each, verifies the manifest signature, sends `POST /v1/agora/peer/announce` with its own manifest, and on acceptance fetches `GET /v1/agora/peer/peers` to discover further Relays.

**Method 2 — Directory document.** The Relay fetches any Agora Relay directory document (§4.4.1) and contacts each listed Relay using Method 1.

**Method 3 — DNS-SD.** The Relay queries both `_agora-relay._udp.<domain>` (QUIC, preferred) and `_agora-relay._tcp.<domain>` (TCP fallback) SRV records:

```
_agora-relay._udp.example.com. SRV 10 0 9001 relay.example.com.
_agora-relay._tcp.example.com. SRV 20 0 443  relay.example.com.
_agora.relay.example.com.      TXT "did=did:key:z6MkRelay... manifest=https://relay.example.com/.well-known/agora-relay"
```

Lower SRV priority value means higher preference; QUIC (UDP) is preferred. Relays SHOULD publish both records. Relays that cannot expose UDP MUST publish only the TCP record.

**Method 4 — IPNS fallback.** The Relay resolves `/ipns/agora.protocol/relays/v1` for a community-maintained signed bootstrap list. This is the last resort.

A Relay is considered mesh-joined when it has Level 1 or higher trust with at least 3 peers and is participating in gossipsub fanout. It SHOULD continue discovering peers until it has at least 6 active connections (gossipsub's default mesh degree `D`).

#### 3.5.6 Mesh Maintenance

**Heartbeat.** Relays MUST poll `GET /peer/v1/health` from each peer every 60 seconds. A peer that returns `unhealthy` or fails to respond for 3 consecutive checks (180 seconds total) is marked unreachable. Its gossipsub connection is dropped; it remains in `knownPeers` for 7 days before removal, in case it recovers.

**Manifest refresh.** Relays re-fetch peer manifests every hour to detect key rotation and endpoint changes. A manifest whose `sig` no longer verifies is treated as a trust failure and the peer is downgraded to Level 0 pending re-verification.

**Key rotation overlap.** When rotating its signing key, a Relay MUST publish both the old and new keys in its manifest with a minimum 48-hour overlap, marking the old key with `"status": "deprecated"`. Peer Relays accept signatures from deprecated keys during this overlap window.

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

Receiving Relays verify the signature, independently fetch the new Relay's manifest, and decide whether to initiate peering. The announcement is a hint, not an authorization.

---

## 4. Discovery

### 4.1 Gossip Protocol

Agora uses **libp2p gossipsub v1.1** for peer discovery, space and channel advertisement, live message delivery, and MLS handshake message delivery (Welcome, Commit, Proposal).

Each gossipsub **topic** maps to a specific scope:

| Topic pattern | Purpose |
|---|---|
| `v1/agora/discovery` | Global space/user advertisements |
| `v1/agora/space/<spaceCID>` | Space-scoped events: joins, state updates, moderation records |
| `v1/agora/channel/<channelToken>` | Per-channel messages and ephemeral presence/typing events |
| `v1/agora/mls/<groupID>` | MLS handshake messages: Welcome, Commit, Proposal |

The `v1/` prefix is the gossip protocol version for that topic family. A future breaking change to message framing on a topic introduces a `v2/` prefix. Relays MUST subscribe to all versions of topics they serve. Clients negotiate which version to publish on via the `negotiated.gossipVersion` field in the `RelayChallenge` (§8.6). During a version transition period, Relays bridge messages between `v1/` and `v2/` topic variants for the same channel.

**Reference implementations for libp2p gossipsub:**
- Go: [`go-libp2p-pubsub`](https://github.com/libp2p/go-libp2p-pubsub)
- Rust: [`libp2p` crate, `gossipsub` module](https://docs.rs/libp2p/latest/libp2p/gossipsub/)
- JS: [`@chainsafe/libp2p-gossipsub`](https://github.com/ChainSafe/js-libp2p-gossipsub)

### 4.2 Discovery Advertisements

A **SpaceAd** or **UserAd** message is gossiped periodically (default TTL: 60 seconds; re-advertised at 45 seconds to avoid expiry gaps):

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "SpaceAd",
  "spaceCID": "bafyrei...",
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

`relayHints` are connection hints only — clients are not required to use them and SHOULD attempt direct peer connections first. `relayHints` MAY include `.onion` addresses, clearnet HTTPS/WSS URIs, overlay-internal hostnames, and IPv6 address literals.

### 4.3 Relay Discovery Bootstrap

To bootstrap into the gossip network, a client needs at least one known peer. Agora supports the following bootstrap mechanisms, attempted in order:

1. **Directory sources** — user-configured URLs serving `RelayDirectory` or `SpaceDirectory` documents (§4.4); the primary bootstrap mechanism in practice.
2. **Previously cached relay list** — Relays successfully contacted in a prior session, stored locally with a staleness TTL of 7 days.
3. **Mainline DHT** — Relays announce themselves on the BitTorrent Mainline DHT (BEP-5) under a well-known infohash derived from `SHA1("agora-relay-v1")`; clients perform a `get_peers` lookup to find announcing relays (§4.4.6).
4. **DNS-SD** — `_agora._tcp` mDNS for LAN or overlay discovery.

### 4.4 Directory Documents

A **directory document** is a static JSON-LD file served at any reachable URL. It lists Spaces, Relays, or both, and MAY include references to other directory documents by URL. Users configure one or more directory source URLs in their client. Clients fetch and merge all configured sources on startup and refresh on a configurable interval (default: 1 hour).

Directory documents require no special server infrastructure. A file committed to a public GitHub repository and served via `raw.githubusercontent.com` or GitHub Pages is a valid directory source. So is an IPFS CID, a Cloudflare R2 bucket, a `.onion` URL, or any HTTPS endpoint returning valid JSON.

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
      "acceptedSchemes": ["cashu", "pow"],
      "tiers": [
        { "label": "free",     "maxBandwidthMbps": 1,  "price": { "scheme": "pow", "amount": "0" }    },
        { "label": "standard", "maxBandwidthMbps": 10, "price": { "scheme": "cashu", "amount": "500", "denomination": "sat" } }
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

#### 4.4.2 Space Directory

A `SpaceDirectory` lists Spaces available for browsing or joining:

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "SpaceDirectory",
  "schemaVersion": "1",
  "id": "https://raw.githubusercontent.com/example/agora-spaces/main/spaces.json",
  "name": "Open Source Projects",
  "maintainer": "did:key:z6MkMaintainer...",
  "published": "2026-03-12T00:00:00Z",
  "ttl": 3600,
  "sig": "base64url...",
  "spaces": [
    {
      "@type": "SpaceDirectoryEntry",
      "spaceCID": "bafyrei...",
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
    "https://raw.githubusercontent.com/other-org/spaces/main/spaces.json"
  ]
}
```

`inviteURL` is a human-readable join link; the join flow itself is handled by the Space's invite mechanism (§9.3). `spaceCID` is the authoritative space identity — clients verify this against the space's genesis state document when connecting.

#### 4.4.3 Combined Directory

A single document MAY contain both `relays` and `spaces` arrays, typed as `AgoraDirectory`:

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "AgoraDirectory",
  "relays": [ ... ],
  "spaces": [ ... ],
  "includes": [ ... ]
}
```

#### 4.4.4 Client Behavior

On startup, the client fetches all configured directory sources in parallel. Results are merged: Relay lists are deduplicated by `did`; Space lists are deduplicated by `spaceCID`. The client attempts connection to the highest-priority available Relay (ordered by user preference, then by `tiers[0].price.amount` ascending as a proxy for accessibility). Previously cached Relays from prior sessions are used immediately while directory fetches are in flight.

Failed fetches are retried with exponential backoff (base 30 seconds, maximum 1 hour). A source that consistently fails for 7 days is flagged in the UI as unreachable; it is NOT silently removed from the configured source list. The user decides whether to remove it.

Clients MUST NOT auto-add directory sources from space state documents, relay advertisements, or any other protocol message without explicit user confirmation. Auto-population of directory sources is a privilege escalation vector.

#### 4.4.5 Content-Addressed Directories

A directory document MAY be addressed by CID instead of (or in addition to) an HTTPS URL:

```
ipfs://bafyrei.../relays.json
```

Clients resolve `ipfs://` URIs by fetching the blob from any relay's CAS endpoint (`GET /v1/agora/blob/{cid}`) or via their configured relay mesh.

#### 4.4.6 Mainline DHT Discovery

Agora uses the BitTorrent Mainline DHT (BEP-5, BEP-44) for two complementary purposes: relay bootstrapping and user endpoint discovery. Both are opportunistic — clients MUST degrade gracefully when UDP is unavailable (corporate firewalls, restrictive NAT) and fall back to other discovery mechanisms.

##### Relay Bootstrapping (BEP-5)

Relay operators announce their relay on Mainline by performing a BEP-5 `announce_peer` for the well-known infohash:

```
infohash = SHA1("agora-relay-v1")  // hex: to be assigned at spec finalisation
```

The announced port is the relay's WebSocket port. Clients discovering a relay via this mechanism MUST still verify the relay's DID and TLS certificate before use (§4.4.7); a Mainline announcement is a hint, not an authorization.

Relay operators SHOULD re-announce every 30 minutes. Clients performing a cold-start bootstrap issue a `get_peers` lookup for this infohash and attempt connection to returned peers.

##### User Endpoint Discovery (BEP-44 / Pkarr)

A `did:key` user MAY publish a BEP-44 mutable item on Mainline to advertise their current relay endpoints, profile CID, and KeyPackage supply CID. This enables contact initiation without requiring a shared directory or prior relay knowledge.

**Key derivation.** The BEP-44 key is the user's raw 32-byte ed25519 authentication public key, extracted directly from their `did:key` identifier. No additional key material is required.

**Record format.** The BEP-44 value is a compact DNS packet (Pkarr format) containing TXT resource records:

```
_agora.             TXT  "v=1"
_relay._agora.      TXT  "wt=https://relay1.example.com/v1/agora/wt"
_relay._agora.      TXT  "wt=https://relay2.example.com/v1/agora/wt"
_profile._agora.    TXT  "cid=bafyrei..."
_kp._agora.         TXT  "cid=ipfs://bafyrei.../keypackages.cbor;n=50"
```

Multiple `_relay._agora` TXT records are permitted; clients treat them as an ordered preference list. All fields are optional except `v`.

| Record | Key | Value | Required |
|---|---|---|---|
| `_agora` | `v` | Schema version (`1`) | Yes |
| `_relay._agora` | `wt` or `ws` | WebTransport or WebSocket relay endpoint URL | No |
| `_profile._agora` | `cid` | `ipfs://` URI of the user's current profile IPLD node | No |
| `_kp._agora` | `cid` | `ipfs://` URI of the user's KeyPackage supply batch; `n` = count | No |

The total DNS packet MUST fit within 1000 bytes (BEP-44 value limit). In practice a record with two relay endpoints, a profile CID, and a KeyPackage CID occupies approximately 350–400 bytes.

**Verification.** BEP-44 mutable items are self-certifying: the DHT node returns the value together with the ed25519 signature, and the lookup key is the public key itself. Clients MUST verify the signature before using any field. A valid signature proves the record was produced by the holder of the DID's authentication key.

**Lookup procedure.**
1. Decode the `did:key` identifier to recover the raw 32-byte ed25519 public key.
2. Issue a BEP-44 `get` query for that key.
3. Verify the returned signature against the key.
4. Parse TXT records and use relay endpoints, profile CID, or KeyPackage supply CID as needed.

**Publication and refresh.** Clients SHOULD publish their record on first login and re-publish every 2 hours. BEP-44 mutable items have no explicit TTL but decay from the DHT within approximately 2 hours without re-announcement. Stale or absent records are not an error — clients fall back to other discovery mechanisms.

**Scope.** This mechanism applies only to `did:key` users. `did:web` users have a domain-anchored DID document served over HTTPS; their relay endpoints are discoverable via standard DID resolution and do not require Mainline publication.

#### 4.4.7 Trust Model

Being listed in a directory confers no trust. A Relay in a directory is trusted only to the extent that its DID verifies against its TLS certificate and signed advertisements. A Space in a directory is trusted only to the extent that its `spaceCID` verifies against its genesis state document. A malicious directory entry pointing at a rogue Relay produces a DID mismatch at connection time and is rejected.

Directory maintainers are identified by their `maintainer` DID and signature. There is no global authority over directory content. Multiple competing directories can coexist and are all valid. Clients merge them all.

---

## 5. Message Ordering

### 5.1 Ordering Model

Agora uses **best-effort causal ordering**. Gossipsub does not guarantee total message order and does not need to. The requirement is that messages arrive in approximately the right order on average, with clients able to reconstruct causal order locally.

Each message envelope carries a `seq` (monotonically increasing integer per sender per channel) and an optional `causalRefs` array of message CIDs that the sender had observed before composing the message. This gives clients enough information to:

- Detect gaps (missing `seq` values from a given sender)
- Buffer out-of-order arrivals and flush the buffer when gaps close
- Detect and display causal relationships for reply threading and reaction targets

Clients SHOULD buffer messages for up to 500ms waiting for a gap to close before rendering out-of-order. After 500ms, the client should display what is available and backfill visually when the missing message eventually arrives.

**MLS Commit ordering.** MLS Commits (which advance the group epoch) require stricter ordering than application messages. Clients MUST buffer application messages from a new epoch until the Commit that opened that epoch has been received and processed. Relays MAY provide **sequence attestations** — signed sequence numbers over a channel's message stream — as an optional ordering anchor for clients that require it.

**Space state ordering.** Space state mutations are ordered by a `seq` field on the `SpaceState` document and a Lamport timestamp. Concurrent non-conflicting mutations (e.g., two admins each independently adding a different channel) are merged by taking the union. Conflicting mutations (e.g., two admins simultaneously changing the same user's role) are resolved last-writer-wins using the `seq` value. In a true simultaneous tie, the mutation signed by the higher-authority key wins (owner beats admin).


---

## 6. Messaging

### 6.1 MLS Group Structure

Each channel's encryption model is determined by its **mode** (§3.2). `interactive` and `community` channels each have their own MLS group; `broadcast` channels use a signature-only model with no MLS group. In all cases, space membership does not imply channel membership — each channel manages its own state independently.

This section covers `interactive` and `community` channels. `broadcast` channels are specified in §6.1.4.

**`interactive` mode** (§3.2): full MLS group, all channel members hold leaves. Maximum 200 members. Standard §6.1 behavior applies without modification.

**`community` mode** (§3.2): MLS group limited to active speakers. Space members outside the speaker group can observe the gossipsub topic but cannot decrypt messages until admitted. See §6.1.2.

Each channel manages its own MLS epoch independently. This enables per-channel access control (e.g., private channels within a public space) without any additional mechanism; it is a direct consequence of the MLS design.

MLS operations follow RFC 9420 exactly:

- **`KeyPackage`** — uploaded to the Relay KeyPackage Store (§6.1.1); rotated on each new device session and after each use.
- **`Welcome`** — sent to new members via `v1/agora/mls/<groupID>` or direct encrypted delivery.
- **`Commit`** — a state-advancing operation (Add, Remove, Update); gossiped to all current group members.
- **`Proposal`** — a pre-commit operation that may be included in a subsequent Commit by any authorized member.

The **Delivery Service** role (as defined in RFC 9420 §4) is performed by the gossipsub mesh in combination with the Relay KeyPackage Store. The **Authentication Service** role is performed by DID verification — MLS leaf node credentials are bound to DID verification keys, so verifying an MLS credential means verifying a DID.

**Reference implementations for MLS (RFC 9420):**
- Rust: [`openmls`](https://github.com/openmls/openmls) — the most complete open-source implementation
- C/C++: [`mlspp`](https://github.com/cisco/mlspp) (Cisco)

### 6.1.1 KeyPackage Store

IPFS alone is insufficient for KeyPackage distribution. IPFS provides no delivery guarantees, no availability SLA, and — critically — no mechanism for a sender to atomically fetch-and-consume a KeyPackage to prevent reuse. Two concurrent senders fetching the same KeyPackage from IPFS would both construct valid-looking Welcomes, but the second would fail MLS validation at the recipient because the leaf credential is bound to a single use. Relays MUST therefore implement a **KeyPackage Store** — an authenticated key-value endpoint that makes consumption atomic and provides the availability properties IPFS cannot.

The KeyPackage availability problem has three layers that must be addressed together: the relay's baseline behavior (what it does by default), the operator's contractual commitment (what it promises in a service agreement), and the client's self-healing supply chain (what happens when the user is offline). This section specifies all three.

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

#### Relay Default Behavior (Baseline, No SLA)

In the absence of a `RelayServiceAgreement` with a `keyPackageSLA` clause (§12.2), a relay operates in **best-effort mode**: it stores and serves KeyPackages on a best-effort basis with no durability, availability, or minimum-count guarantees beyond the session in which they were uploaded.

Best-effort mode is appropriate for:
- Private organizational deployments where the relay is operator-controlled and users are online frequently.
- Development and testing.
- Small spaces where channel membership changes are infrequent.

Best-effort mode is **not appropriate** for large public spaces or any deployment where a user may be offline for days or weeks and needs to be addable to new channels on their return.

Even in best-effort mode, a relay MUST NOT:
- Return a previously consumed KeyPackage on a subsequent `GET` (consumption is always atomic and permanent).
- Silently drop stored KeyPackages before the session ends without notifying the owning DID.

#### Relay Service Agreement SLA (Contractual Guarantee)

A `RelayServiceAgreement` (§12.2) MAY include a `keyPackageSLA` clause that extends the relay's obligations beyond best-effort:

```json
"keyPackageSLA": {
  "minimumCount": 20,
  "alertThreshold": 5,
  "alertMechanism": "push",
  "guaranteedRetentionDays": 90,
  "replenishFromIPFS": true
}
```

**`minimumCount`** — the relay commits to maintaining at least this many live, unconsumed KeyPackages per DID it serves under this agreement. This is not a hard real-time guarantee but an obligation to alert the client promptly when supply drops and to attempt IPFS-based replenishment before returning 404.

**`alertThreshold`** — when the stored count for a DID falls at or below this value, the relay MUST notify the owning DID. The notification mechanism is declared in `alertMechanism`:
- `"push"` — the relay sends a push proxy wake-up (§8.7) with `urgency: "high"`.
- `"gossip"` — the relay publishes a `KeyPackageLowAlert` message to `v1/agora/discovery`.
- `"both"` — both mechanisms are attempted.

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "KeyPackageLowAlert",
  "targetDID": "did:key:z6Mk...",
  "relayDID": "did:key:z6MkRelay...",
  "currentCount": 3,
  "alertThreshold": 5,
  "ts": "2026-03-12T12:00:00Z",
  "sig": "base64url..."
}
```

`KeyPackageLowAlert` is gossiped only to `v1/agora/discovery`, not to any channel topic — it contains no channel or space information.

**`guaranteedRetentionDays`** — the relay will retain uploaded KeyPackages (without consuming them) for at least this many days from the upload timestamp. After this period, unexpired KeyPackages are still valid but the relay MAY evict them under storage pressure, and MUST alert the owning DID before doing so.

**`replenishFromIPFS`** — if `true`, the relay will attempt to fetch fresh KeyPackages from the owning DID's declared IPFS supply endpoint before returning 404 on a fetch or before triggering an alert. This is the relay self-healing from IPFS without requiring the user to be online.

Violation of a `keyPackageSLA` clause constitutes a breach of the service agreement. Enforcement is by relay selection — space owners and users choose relays that honor their declared terms.

#### IPFS as Durable Supply (Client-Controlled)

The relay store handles atomic consumption. IPFS handles durable supply. These roles are deliberately separate: IPFS is a write-many supply source, not a consumption endpoint. The same KeyPackage must never be consumed from two places.

A client MAY publish a batch of pre-generated KeyPackages to IPFS and register the CID in their DID document's `service` endpoints:

```json
{
  "service": [{
    "id": "did:key:z6Mk...#keypackage-supply",
    "type": "AgoraKeyPackageSupply",
    "serviceEndpoint": "ipfs://bafyrei.../keypackages.cbor",
    "uploadedAt": "2026-03-12T00:00:00Z",
    "count": 50
  }]
}
```

`serviceEndpoint` is an IPFS CID URL pointing to a CBOR-encoded array of RFC 9420 KeyPackage TLS-serialized objects — the same wire format accepted by `PUT /v1/agora/kp/{did}`. The `count` field is informational; the actual count is authoritative at the CID.

This CID is immutable — publishing new KeyPackages to IPFS produces a new CID. Clients rotate the `serviceEndpoint` in their DID document by publishing a new KeyPackage batch to IPFS and updating the service entry with the new CID and `uploadedAt`. The old CID remains valid and accessible but is superseded.

**Relay self-replenishment flow.** When a relay with `replenishFromIPFS: true` in its service agreement is about to return 404 on `GET /kp/{did}` (or has dropped below `alertThreshold`), it:

1. Resolves the target DID document and checks for an `AgoraKeyPackageSupply` service entry.
2. If found, fetches the CBOR KeyPackage array from IPFS via its configured gateway.
3. Imports the batch into the local relay store via the same path as a client `PUT` — each KeyPackage is stored individually, deduplication checked by ref hash.
4. Returns to the original `GET /kp/{did}` request now that supply is replenished, consuming one atomically as normal.
5. Publishes a `KeyPackageSupplyImported` gossip message to `v1/agora/discovery` so that other relays serving the same DID know the supply has been refreshed:

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "KeyPackageSupplyImported",
  "targetDID": "did:key:z6Mk...",
  "relayDID": "did:key:z6MkRelay...",
  "importedCount": 50,
  "sourceCID": "bafyrei...",
  "ts": "2026-03-12T12:00:00Z",
  "sig": "base64url..."
}
```

The relay MUST verify the imported KeyPackages before adding them to the store. Corrupted or expired packages from IPFS are silently dropped; only valid packages are stored.

**Client workflow.** To take advantage of IPFS supply, the client:

1. At account setup or after a key rotation event, generates a large batch of KeyPackages (50–200 is reasonable).
2. Uploads the batch to IPFS and pins it (via their own IPFS node, a pinning service, or a relay with IPFS pinning enabled).
3. Updates their DID document's `serviceEndpoint` for `AgoraKeyPackageSupply` to the new CID.
4. Uploads a subset (20–50) to their connected relays' stores via `PUT /v1/agora/kp/{did}` for fast-path access.

The IPFS batch is a **reserve tank** — the relay draws from it when the fast-path store runs low, without requiring the client to be online.

**Important:** a relay fetching from the IPFS supply CID and consuming packages from it into its local store is the only authorized consumption path for IPFS packages. Senders MUST NOT fetch directly from the IPFS supply CID and attempt to construct Welcomes from it — the atomic consumption guarantee applies only to the relay's `GET /v1/agora/kp/{did}` endpoint. Any Welcome constructed using a KeyPackage sourced directly from IPFS (bypassing the relay store) MUST be rejected by recipients as potentially reused.

#### KeyPackage Replication Across Relays

A client connected to multiple Relays SHOULD upload its KeyPackages to all of them. When a sender needs to fetch a KeyPackage to issue a Welcome, it contacts the target user's preferred Relay (declared in their DID document's `service` endpoints). If that Relay has no KeyPackages for the target, it SHOULD attempt to fetch one from other known Relays serving the same space before returning 404.

Inter-relay KeyPackage forwarding uses a simple pull model:

```
GET /v1/agora/kp/{did}?forward=true
```

The `forward=true` parameter instructs the Relay to attempt peer-relay fetching before returning 404. If `replenishFromIPFS` is also enabled, the relay attempts IPFS replenishment after peer-relay fetching fails, before finally returning 404. Relays that support forwarding declare `"keypackage-forwarding-v1"` in their capabilities.

#### KeyPackage Exhaustion

If all KeyPackages for a target DID have been consumed and no fresh ones are available from peer relays or IPFS supply, the sender MUST NOT reuse a previously consumed KeyPackage. Instead:

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

3. When the target comes online, their client sees the `KeyPackageRequest`, generates fresh KeyPackages, uploads them to both IPFS and the relay store, and the waiting sender completes the Welcome flow.

`KeyPackageRequest` messages are ephemeral (not stored in IPLD history) and MUST NOT identify which channel or space triggered the request.

#### KeyPackage Validation

Recipients of a Welcome MUST validate the KeyPackage used to construct it:

- The signature verifies against the sender's DID authentication key.
- `KeyPackage.leaf_node.credential` contains a valid DID matching the sender.
- The KeyPackage has not expired (`leaf_node.lifetime.not_after`).
- The ciphersuite matches the group's declared ciphersuite.

A Welcome constructed with an invalid or expired KeyPackage MUST be rejected. A Welcome constructed using a KeyPackage sourced directly from an IPFS supply CID (rather than consumed via the relay store API) MUST also be rejected.

### 6.1.2 Community Channel Mode

A `community` channel has a bounded MLS group called the **speaker group**. Only members of the speaker group can post or decrypt messages. Space members outside the speaker group can subscribe to the channel's gossipsub topic but will receive ciphertext they cannot decrypt until they are admitted.

**Speaker group bounds.** The `speakerCap` field in the channel state (default 200, maximum 500) is the hard upper limit on simultaneous MLS group members. A channel admin MUST NOT issue an Add commit that would push membership above `speakerCap`.

**Idle eviction.** A speaker who has not sent any `ApplicationMessage` in the channel within `idleEvictDays` days (default 7) is eligible for eviction. The channel's designated **SpeakerBot** (a DID listed in the channel state as `speakerBot`) issues periodic Remove commits for idle speakers. If no `speakerBot` is configured, channel admins perform evictions manually. Eviction is not punitive — evicted members are eligible for immediate re-admission when they next request to speak.

**SpeakRequest.** A space member who is not currently in the speaker group and wants to post sends a `SpeakRequest` gossip message to the channel topic:

```json
{
  "@type": "SpeakRequest",
  "channelCid": "bafyrei...",
  "requesterDid": "did:key:z6Mk...",
  "ts": "2026-04-22T09:00:00Z",
  "sig": "base64url..."
}
```

`sig` is the requester's Ed25519 signature over the canonical CBOR of the message body (excluding `sig`). The SpeakerBot or a channel admin responds by issuing a standard MLS Add commit using a KeyPackage from the requester's store. If the speaker group is at capacity, the SpeakerBot SHOULD first evict the longest-idle current speaker before adding the requester.

**Admission latency.** Admission requires one round of MLS Add + Welcome delivery. Clients in `community` channels SHOULD display a "waiting to join" indicator if the user tries to post before their Welcome has been processed.

**History access.** A member who was evicted and later re-admitted receives a new Welcome for the new MLS epoch. They can decrypt messages from epochs in which they held a leaf node; they cannot decrypt messages sent during periods when they were not in the group. This is the correct behavior — they were not a group member during those periods. Clients SHOULD display a clear indicator when history is unavailable for a given time range.

**Compliance logging.** Compliance loggers (§17) in `community` channels are passive members (§6.1.3) and MUST NOT be subject to idle eviction. The SpeakerBot MUST check for a passive member leaf before evicting any member.

### 6.1.3 Passive Members

A **passive member** is an MLS group member that holds a leaf credential and participates in epoch ratchets — receiving all application messages and group state updates — but MUST NOT issue Commits or Proposals. Passive members are indistinguishable from standard members at the MLS wire protocol layer; the constraint is behavioral, not cryptographic.

**Use cases in Agora.** Compliance loggers (§17) and VTC recorders (§10.12) are passive members. Both hold leaf credentials, receive all application messages in their admitted groups, and never modify group state.

**KeyPackages.** Passive members require KeyPackages to receive Welcome messages. Because passive members never initiate group operations, they SHOULD publish last-resort KeyPackages (`draft-ietf-mls-extensions-09`, §last-resort-keypackage) — KeyPackages marked for reuse when the single-use supply is exhausted — rather than maintaining a large single-use supply. Relays MUST serve a passive member's last-resort KeyPackage when no single-use packages remain.

**Idle eviction.** Passive members MUST NOT be subject to idle eviction (§6.1.2). A passive member generates no traffic by design; evicting one on that basis would silently break the compliance capture chain.

**Future standard alignment.** This concept anticipates `draft-ietf-mls-partial-00` ("Partial MLS"), which defines an MLS extension allowing receive-only participants to carry only membership proofs rather than the full ratchet tree, reducing overhead for large groups. That draft expired without a successor. When a partial client standard is published, Agora implementations SHOULD upgrade passive member implementations to native partial client support; the behavioral contract (no Commits, no Proposals, full message receipt) is identical.

### 6.1.4 Broadcast Channel Mode

A `broadcast` channel carries no MLS group. Messages are **signed but not encrypted** — they are readable by any space member who knows the channel token. The security property provided is authenticity (was this posted by an authorized poster?) not confidentiality.

**Authorized posters.** The set of authorized posters for a broadcast channel is determined by space role: any space member holding a role listed in the channel state's `broadcasterRoles` array may post. Typically this is a dedicated `broadcaster` role held by admins or a bot.

**Message structure.** Broadcast messages use the standard outer routing envelope (§6.2) but with no inner MLS encryption. The `innerPayload` field carries a plaintext-signed JSON-LD body:

```json
{
  "@type": "BroadcastMessage",
  "channelCid": "bafyrei...",
  "body": {
    "@type": "TextBody",
    "content": "v2.1.0 released — see release notes for details.",
    "mimeType": "text/markdown;variant=commonmark"
  },
  "senderDid": "did:key:z6Mk...",
  "ts": "2026-04-22T09:00:00Z",
  "sig": "base64url..."
}
```

`sig` is the sender's Ed25519 signature over the canonical CBOR of the message body (excluding `sig`). Recipients MUST verify `sig` against the sender's DID document before displaying the message. Recipients MUST also verify that `senderDid` holds a space role listed in `broadcasterRoles`.

**Relay handling.** The Relay stores broadcast messages as signed blobs, identical to any other channel message. Because broadcast messages are not encrypted, the Relay CAN read their content — this is an intentional and declared property of broadcast channels. Clients MUST display a visible indicator (e.g., a megaphone icon) on broadcast channels to make clear to users that messages in this channel are not confidential.

**No MLS group means no KeyPackage consumption** for broadcast channels. Senders do not need to consume a recipient's KeyPackage to post. There are no Welcome or Commit messages for broadcast channels.

**Compliance logging.** Broadcast channel messages are already plaintext; no special compliance logger admission is required. The Relay stores them as durable signed records. For FINRA/MiFID purposes, broadcast messages in a space with compliance logging enabled are automatically captured to the compliance archive.

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

`channelToken` is a one-way derivation from the channel CID and the current MLS epoch secret: `HKDF(epochSecret, "channel-token" || channelCID)`. It rotates with every epoch. Relays use it for topic routing without learning the actual channel identifier or any member identity.

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
| `TextBody` | Formatted text; `format` field declares the content type (see §6.7) |
| `MediaBody` | Reference to IPFS-hosted media (CID + MIME type + size) |
| `EmbedBody` | URL unfurl card (title, description, image CID) |
| `ReactionEvent` | Emoji reaction add/remove targeting a message CID (see §6.8) |
| `EditEvent` | Replacement body for a prior message CID |
| `DeleteEvent` | Tombstone for a prior message CID |
| `PinEvent` | Pin a CID to the channel's persistent pin list (§6.6) |
| `UnpinEvent` | Remove a CID from the channel's pin list (§6.6) |
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

### 6.5 Message History

Message history is stored as an IPLD linked list. Each message envelope CID is appended to the channel's history DAG, and the channel state document tracks the latest history CID.

Clients fetch history by walking the IPLD DAG backwards from the latest CID. Relays SHOULD pin recent history within their configured retention window (default 30 days). Long-term archival beyond the retention window is the responsibility of space operators or interested members.

IPFS provides content-addressed deduplication automatically — the same message (same CID) stored at multiple Relays is inherently deduplicated.

**Reference implementations for IPFS/IPLD:**
- Go: [`go-ipfs`](https://github.com/ipfs/go-ipfs), [`go-ipld-prime`](https://github.com/ipld/go-ipld-prime)
- JS: [`helia`](https://github.com/ipfs/helia), [`@ipld/dag-cbor`](https://github.com/ipld/js-dag-cbor)
- Rust: [`rust-ipfs`](https://github.com/rs-ipfs/rust-ipfs), [`libipld`](https://github.com/ipld/libipld)

### 6.6 Pinned Content

Channels support a **pin list** — a set of CID references in the channel's IPLD state that mark specific content as persistent and surfaced. Pinning is a preservation signal: pinned CIDs are exempt from relay retention expiry and are surfaced by clients as a dedicated "pinned messages" view.

#### What Can Be Pinned

Any content that already has a CID may be pinned:

- A message envelope CID (a specific chat message, a file share, a thread root)
- A media attachment CID (an image, document, or other file already stored in IPFS)
- An archived external URL — clients MUST archive external URLs to IPFS and pin the resulting CID rather than the URL itself. URLs rot; CIDs do not. The `label` field carries the human-readable original URL or description.

Pinning does not copy data. It records a reference that tells relays and clients "this CID must be retained and displayed prominently."

#### Pin List in Channel IPLD State

The channel's IPLD state document includes a `pins` array. Each entry is a signed pin record:

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "ChannelState",
  "channelCID": "bafyrei...",
  "latestHistoryCID": "bafyrei...",
  "pins": [
    {
      "cid": "bafyrei...",
      "pinnedBy": "did:key:z6Mk...",
      "pinnedAt": "2026-03-12T12:00:00Z",
      "label": "onboarding guide",
      "sig": "base64url..."
    },
    {
      "cid": "bafyrei...",
      "pinnedBy": "did:key:z6MkAdmin...",
      "pinnedAt": "2026-03-12T10:00:00Z",
      "label": "https://example.com/rules (archived)",
      "sig": "base64url..."
    }
  ],
  "pinLimit": 50
}
```

`sig` is the pinner's Ed25519 signature over the canonical CBOR serialization of the pin entry fields (excluding `sig` itself). Pins are attributable and tamper-evident — adding or removing a pin without a valid signature MUST be rejected.

`pinLimit` is the maximum number of simultaneous pins for the channel. Default is 50. Space Admins may set a different limit via a signed `ChannelStateMutation`. Relays MUST reject `PinEvent` messages that would cause the pin count to exceed `pinLimit`.

#### Authorization

- **Any current MLS group member** MAY add a pin (`PinEvent`).
- **Space/Channel Admins and the original pinner** MAY remove a pin (`UnpinEvent`). Other members MAY NOT remove pins they did not add.
- Pin operations on channels where the pinner is not a current MLS group member MUST be rejected by relays.

#### PinEvent and UnpinEvent

Pin and unpin operations are MLS application messages with the following inner payload types:

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "PinEvent",
  "cid": "bafyrei...",
  "label": "onboarding guide",
  "pinnedBy": "did:key:z6Mk...",
  "ts": "2026-03-12T12:00:00Z",
  "sig": "base64url..."
}
```

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "UnpinEvent",
  "cid": "bafyrei...",
  "unpinnedBy": "did:key:z6MkAdmin...",
  "ts": "2026-03-12T12:30:00Z",
  "sig": "base64url..."
}
```

Both are stored in the channel's IPLD history DAG — the audit trail records who pinned and unpinned what and when, non-repudiably.

#### Retention Exemption

Pinned CIDs are **permanently exempt from relay retention expiry**. A relay serving a channel MUST NOT evict any CID that appears in the channel's current `pins` array, regardless of:

- The configured retention window
- The `expiryHint` on the original envelope
- Storage pressure

The relay MUST continue to serve pinned CIDs via IPFS until they are explicitly unpinned via a valid `UnpinEvent`. If a relay is running low on storage, it MUST evict unpinned content before considering eviction of pinned content, and MUST alert the space operator before evicting anything from the pin list.

The retention exemption applies only to the pinned CID itself — not to the full IPLD history DAG. Relays are required to retain the pinned CID and its directly referenced content (e.g., a media attachment CID referenced by a pinned message envelope).

#### Message Expiry Interaction

A pinned message whose inner payload contains an `expiry` timestamp presents a conflict: the sender requested deletion, but a subsequent pinner requested retention. The resolution: **explicit unpinning is required before expiry takes effect on a pinned CID**. A relay MUST NOT evict a pinned CID on expiry. The channel admin responsible for the pin SHOULD unpin expired content; if they do not, the content persists until explicitly unpinned. Clients SHOULD warn admins when a pinned message's inner payload expiry has passed without an unpin action.

This is a deliberate policy choice: pinning is an admin override of sender expiry. Users who post content they intend to be ephemeral should be aware that an admin may pin it. Channels with strict expiry requirements SHOULD configure a `noPin` policy (a boolean flag in channel state, default false) that disables the pin feature entirely for that channel.

### 6.7 TextBody Content Format

#### 6.7.1 Baseline Format: CommonMark

The `body` field of a `ChatMessage` inner payload carries a `TextBody` object. The `format` field of `TextBody` declares the content type of the `text` field. The baseline and default format is **CommonMark** ([spec.commonmark.org](https://spec.commonmark.org/)), specifically the most recent stable release at the time of implementation (currently 0.31.2).

```json
{
  "@type": "TextBody",
  "text": "**hello** from `agora`",
  "format": "text/markdown;variant=commonmark"
}
```

Clients MUST support CommonMark rendering. Clients that cannot render CommonMark MUST display the `text` field verbatim.

**Permitted CommonMark features:** All constructs defined in the CommonMark spec are in-scope. No extensions are included in the baseline. The following are explicitly **not** in the CommonMark baseline and MUST NOT be rendered unless negotiated as an extension (§6.7.2):

- Tables (GFM extension)
- Strikethrough (GFM extension)
- Task list items (GFM extension)
- Footnotes
- Math / LaTeX blocks
- Raw HTML blocks or inline HTML

Clients MUST strip or escape any raw HTML in a CommonMark `text` field rather than rendering it. A `text` field containing raw HTML is not a conformance violation at the protocol layer, but clients MUST treat it as literal text.

#### 6.7.2 Extension Formats

Additional `format` values MAY be defined as named extensions. An extension format is identified by a MIME-type-style string in the `format` field. Clients that do not recognize a `format` value MUST fall back to rendering `text` verbatim.

Reserved extension format strings:

| `format` value | Meaning |
|---|---|
| `text/markdown;variant=commonmark` | CommonMark baseline (default) |
| `text/markdown;variant=gfm` | GitHub Flavored Markdown (CommonMark + tables, strikethrough, task lists) |
| `text/plain` | Literal plaintext; no markup rendering |

The `format` field is extensible: implementations MAY define additional values using reverse-domain namespacing (e.g., `text/markdown;variant=com.example.custom`). Unknown `format` values MUST be treated as `text/plain` by conformant clients.

If `format` is absent, clients MUST treat the `text` field as `text/markdown;variant=commonmark`.

#### 6.7.3 Compliance Logger Behavior

Compliance loggers (§17) store the raw `text` field as-is in `plaintextPayload`. The `format` field is preserved alongside it. Loggers are not required to render or interpret the markup — the stored `text` is the authoritative record.

#### 6.7.4 Format Capability Advertisement

A sender composing a message has no way to know whether a recipient can render a non-baseline `format` value unless capabilities are advertised. Agora provides two complementary advertisement mechanisms: a persistent declaration in the DID document and an ephemeral declaration in the client handshake.

**DID document declaration (persistent)**

A client MAY publish its supported text formats as a service entry in its DID document:

```json
{
  "id": "did:key:z6Mk...#text-formats",
  "type": "AgoraTextFormatCapabilities",
  "serviceEndpoint": "inline",
  "supportedTextFormats": [
    "text/markdown;variant=commonmark",
    "text/markdown;variant=gfm",
    "text/plain"
  ]
}
```

**ClientHello declaration (ephemeral)**

The `supportedTextFormats` field in `ClientHello` (§8.6) declares the current connected device's rendering capabilities for the duration of the session. On receiving a `ClientHello` with `supportedTextFormats`, the Relay SHOULD cache this information keyed by DID + deviceKey for the session duration and make it available to other authenticated clients via the capability query endpoint:

```
GET /v1/agora/caps/{did}
```

Response:

```json
{
  "@type": "ClientCapabilities",
  "did": "did:key:z6Mk...",
  "online": true,
  "supportedTextFormats": [
    "text/markdown;variant=commonmark",
    "text/markdown;variant=gfm",
    "text/plain"
  ],
  "source": "session",
  "cachedAt": "2026-03-12T12:00:00Z"
}
```

`source` is `"session"` if the data comes from a live `ClientHello`, or `"did-document"` if the Relay fell back to the DID document service entry because no live session is present. If neither source is available, the Relay returns a 404 and the sender SHOULD assume baseline CommonMark only.

Relays MUST NOT cache `ClientHello` capability data beyond the session. On disconnect, the cached entry is discarded.

**Sender behavior**

When composing a message with a non-baseline `format`, a conformant client SHOULD:

1. Query `/v1/agora/caps/{did}` for each recipient (in DM groups) or check the DID document (in space channels, where per-member querying at compose time is impractical).
2. If all reachable recipients declare support for the chosen format, send with that format.
3. If any recipient's capabilities are unknown or do not include the chosen format, either fall back to `text/markdown;variant=commonmark` or send with the preferred format and accept that some recipients will display raw markup.

In space channels with many members, per-member capability queries at compose time are not required. Clients MAY display a warning when a non-baseline format is selected without blocking the send.

**Multi-device considerations**

A user's devices may have different rendering capabilities. The DID document entry SHOULD reflect the union of all active devices' capabilities — declaring a format only if all devices the user actively uses can render it. The `ClientHello` entry reflects the specific device currently connected and MAY differ from the DID document entry.

### 6.8 Emoji and Reactions

#### 6.8.1 Emoji in Message Text

Unicode emoji are valid UTF-8 content in any `TextBody` `text` field. No special handling is required.

**Shortcodes** (`:thumbsup:`, `:wolfssl_logo:`) are a client-side rendering convenience, not a wire format. Shortcodes MUST NOT appear on the wire in `TextBody.text` unless the sender intentionally wants the literal text to appear. Clients that support shortcode input MUST expand shortcodes to their Unicode codepoint(s) (for standard emoji) or to a custom emoji reference (for space emoji, see §6.8.4) before constructing the `TextBody`.

**ZWJ sequences and skin tone modifiers** are treated as atomic units. A `ReactionEvent` targeting a message with `"emoji": "👍🏽"` (thumbs up + medium skin tone) is a distinct reaction from `"emoji": "👍"` (thumbs up, no modifier). Clients SHOULD display them as separate reaction types.

#### 6.8.2 ReactionEvent Schema

A reaction is an MLS application message of type `ReactionEvent`:

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "ReactionEvent",
  "targetCID": "bafyrei...",
  "emoji": "👍",
  "action": "add",
  "senderDID": "did:key:z6Mk...",
  "ts": "2026-03-12T12:00:00.000Z",
  "sig": "base64url..."
}
```

`targetCID` is the `envelopeID` CID of the message being reacted to. `emoji` is either a Unicode emoji string (one or more codepoints forming a single grapheme cluster, including ZWJ sequences and modifier sequences) or a custom emoji reference string of the form `:space:<shortcode>:` (see §6.8.4). `action` is `"add"` or `"remove"`. `sig` is the sender's Ed25519 signature over the canonical CBOR serialization of the other fields.

`targetCID` MUST refer to a message in the same MLS group. Reactions targeting messages in other groups or channels are invalid and MUST be rejected by clients.

#### 6.8.3 Reaction Semantics

**One reaction per emoji per sender per target.** A sender MAY NOT add the same `emoji` value to the same `targetCID` more than once. A second `"action": "add"` for the same `(senderDID, targetCID, emoji)` tuple is a no-op; clients MUST deduplicate and MUST NOT display it as a separate reaction.

**Reaction state is derived from the ordered event stream.** Clients reconstruct the current reaction set for a message by replaying all `ReactionEvent` messages targeting that CID in `seq` order. The canonical reaction state at any point is:

```
reactionSet[(targetCID, emoji, senderDID)] = last action seen for that tuple
```

**Aggregation.** Clients SHOULD aggregate reactions by `emoji` value, displaying a count and (on hover or tap) the list of sender display names. A reaction count of zero MUST NOT be displayed.

**Reactions on deleted messages.** If the `targetCID` has been tombstoned by a `DeleteEvent`, clients MUST NOT display reactions for it. Reactions in the event stream targeting a deleted message CID are silently ignored on render.

**Reactions and compliance logging.** `ReactionEvent` messages are logged by the compliance logger identically to `ChatMessage` messages — they are MLS application messages and the logger holds group membership.

#### 6.8.4 Custom Emoji

Spaces MAY define custom emoji — space-specific images referenced by shortcode. Custom emoji are IPFS-hosted and declared in the space state document.

**Space state declaration:**

```json
"customEmoji": [
  {
    "shortcode": "wolfssl_logo",
    "imageCID": "bafyrei...",
    "mimeType": "image/png",
    "width": 64,
    "height": 64,
    "addedBy": "did:key:z6MkAdmin...",
    "addedAt": "2026-03-12T00:00:00Z"
  }
]
```

`shortcode` MUST match `[a-z0-9_]{1,32}` — lowercase alphanumeric and underscores, 1–32 characters. Shortcodes MUST be unique within a space. `imageCID` is the IPFS CID of the image file. `mimeType` MUST be `image/png`, `image/gif`, or `image/webp`. Images SHOULD be square and SHOULD be 64×64 or 128×128 pixels.

**Wire format for custom emoji reactions:**

When a custom emoji is used in a `ReactionEvent`, the `emoji` field uses the reference string:

```json
"emoji": ":space:wolfssl_logo:"
```

Clients resolve `:space:<shortcode>:` by looking up `shortcode` in the current space's `customEmoji` array, fetching the image from IPFS at `imageCID`, and rendering it inline. Clients that cannot resolve the shortcode MUST display the literal reference string `:space:wolfssl_logo:` as a fallback.

**Custom emoji in message text:**

Custom emoji MAY appear inline in `TextBody.text` using the same `:space:<shortcode>:` reference syntax. Clients resolve and render them inline alongside the surrounding text.

**Custom emoji management:**

Adding or removing a custom emoji is a signed `SpaceState` mutation by a Space Admin or Owner. The `customEmoji` array in the space state document is the authoritative list. Removing a custom emoji from the array does not delete the IPFS content, but clients MUST stop rendering it after the next space state refresh.

Spaces SHOULD pin custom emoji image CIDs to prevent relay eviction.

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

Agora uses two complementary transport surfaces that serve different access patterns:

**Live stream** (§8.1–§8.7) — WebTransport (QUIC) or WebSocket. Optimized for real-time delivery: new message events, MLS handshake messages (Commits, Proposals, Welcomes), presence, and typing indicators. Required for any client that needs low-latency delivery.

**JMAP Management API** (§8.8) — Standard HTTPS request/response with EventSource push. Optimized for history retrieval, state sync, programmatic access, and search. Clients that need only history (bots, compliance tools, search indexers) can use JMAP without opening a live stream connection.

A full-featured client uses both. The live stream delivers new events; JMAP fills history on startup and provides a clean sync model for catching up after a disconnect.

### 8.1 Primary Transport: WebTransport

Clients connect to Relays via **WebTransport** (IETF RFC 9000 / HTTP/3 over QUIC). WebTransport provides:

- Multiplexed bidirectional streams over a single QUIC connection
- Reliable ordered streams for MLS handshake messages and persistent message delivery
- Unreliable datagrams for presence and typing events (low-latency, loss-tolerant)

Endpoint: `https://<relay-host>/v1/agora/wt`

WebTransport requires QUIC, which runs over UDP. It is unavailable in any environment that proxies only TCP — including Tor (see §8.3).

**Reference implementations for WebTransport:** Native browser support in Chromium-based browsers and Firefox 114+. Server-side: [`webtransport-go`](https://github.com/marten-seemann/webtransport-go), [`wtransport`](https://github.com/BiagioFesta/wtransport) (Rust).

### 8.2 Fallback Transport: WebSocket

For environments where QUIC or HTTP/3 is blocked or unavailable:

Endpoint: `wss://<relay-host>/v1/agora/ws`

WebSocket carries the same message framing over a single multiplexed binary stream. Multiplexing is handled by a lightweight channel ID prefix on each frame. WebSocket is the mandatory transport for Tor-connected clients.

### 8.3 Tor Transport Constraints

Tor proxies TCP only. This has the following protocol-level consequences:

**WebTransport unavailable.** Clients connecting via Tor MUST use WebSocket. Clients MUST NOT attempt WebTransport when operating through a SOCKS5 proxy identifiable as Tor. Clients SHOULD detect transport failure and fall back to WebSocket without requiring user intervention.

**VTC severely degraded.** WebRTC ICE relies on UDP for STUN hole-punching and optimal media transport. Over Tor, UDP is unavailable. The only viable VTC path over Tor is TURN-over-TCP through a TURN server reachable via a `.onion` address or a Tor-friendly clearnet endpoint. Media latency over Tor circuits (typically 200–600ms round-trip) renders real-time audio/video unusable for most participants. Clients SHOULD display a warning when VTC is attempted over Tor, and MAY disable VTC participation entirely in Tor-only mode.

**Gossipsub fingerprinting.** Connecting to gossipsub via Tor provides IP-level anonymity but gossipsub peer scoring observes message timing and topic subscription patterns. A sufficiently persistent observer correlating topic subscription events across Tor circuits may be able to fingerprint clients by behavior. Clients requiring strong anonymity SHOULD rotate Tor circuits periodically and SHOULD subscribe to decoy topics (§13.4).

**Rate limiting.** A Relay receiving connections from Tor exit nodes sees the exit node's IP address, not the client's IP. Relays MUST use per-`channelToken` rate limits and PoW/payment requirements as the primary spam control mechanism. Per-IP limits MUST NOT be the sole mechanism.

**Hidden service Relays.** A Relay operating as a Tor v3 hidden service publishes its `.onion` address in its `RelayAd.relayHints`. Clients with Tor available SHOULD prefer `.onion` endpoints when available — they provide end-to-end Tor routing without depending on an exit node.

### 8.4 Frame Format

All frames are CBOR-encoded (compact binary), with a JSON-LD-compatible schema. Clients MAY use JSON encoding for debugging purposes; Relays MUST accept both JSON and CBOR.

Frame structure:

```
[version: u8, type: u8, topic: string, payload: bytes]
```

`version` values: `0x01` = frame format v1 (this specification). A Relay that receives a frame with an unknown `version` byte MUST discard it and MAY close the connection.

`type` values: `0x01` Gossip, `0x02` MLS, `0x03` Ephemeral, `0x04` Control.

**Reference implementations for CBOR:** [`cbor2`](https://pypi.org/project/cbor2/) (Python), [`cbor` crate](https://crates.io/crates/cbor) (Rust), [`cbor-js`](https://github.com/paroga/cbor-js) (JS), [`fxamacker/cbor`](https://github.com/fxamacker/cbor) (Go).

### 8.5 Direct Peer Connections

Clients MAY establish direct WebRTC data channels to each other, bypassing Relays entirely. The `VoiceSignal` mechanism (§10.4) is used for ICE negotiation. Direct peer connections are mandatory for voice and video (media MUST NOT transit Relays) and optional for text messaging (latency optimization).

On WireGuard-based overlays (Tailscale, Headscale), direct peer connections benefit from overlay-managed NAT traversal. Overlay-internal `100.x.x.x` addresses appear as ICE host candidates and are preferred over STUN-discovered public addresses when both peers are on the same overlay network.

### 8.6 Client-Relay Authentication

A Relay needs to know which DID it is talking to for three purposes: ban enforcement (reject connections from banned DIDs), per-DID rate limiting, and KeyPackage Store ownership (§6.1.1). Authentication is performed once per connection via a signed challenge-response handshake that establishes a session token for the lifetime of the connection.

Authentication is **optional for read-only operations** (fetching space state, reading history, subscribing to gossip topics). It is **required for write operations** (publishing messages, uploading KeyPackages, submitting MLS Commits) and for accessing the KeyPackage Store write API.

#### Handshake Protocol

Authentication is initiated by the client immediately after transport connection. It uses a `0x04` Control frame.

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
  "supportedTextFormats": ["text/markdown;variant=commonmark", "text/markdown;variant=gfm", "text/plain"],
  "ts": "2026-03-12T12:00:00.000Z"
}
```

`deviceKey` is the device's Ed25519 public key, which MUST match a verification method listed in the DID document for the declared DID.

`supportedTextFormats` is an optional array of `TextBody` format strings (§6.7) that this client can render. If absent, the client is assumed to support only `text/markdown;variant=commonmark` and `text/plain`. The Relay does not use this field internally — it is included so that the Relay can make it available to other connected clients composing messages to this DID (see §6.7.4). Clients SHOULD include this field on every connection.

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

`relaySig` is the Relay's Ed25519 signature over `nonce || relayDID || ts`. This simultaneously authenticates the Relay to the client. `expiresIn` is in seconds; the client must respond within this window.

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
4. The DID is not in the Relay's ban list for any space the Relay serves

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
- Fetch public space state and history
- Receive messages on subscribed topics

Anonymous connections MUST NOT:
- Publish messages to any topic
- Upload KeyPackages
- Submit MLS operations
- Access KeyPackage Store write endpoints

#### DID Document Freshness

The Relay caches DID documents to avoid resolving them on every connection. Cached DID documents have a TTL of 1 hour. Clients revoking a device key SHOULD notify their connected Relays via a signed `DeviceRevocation` control frame to accelerate cache invalidation:

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

Mobile clients backgrounded by the OS cannot maintain a persistent WebTransport or WebSocket connection. Agora supports an optional **Push Notification Proxy** that enables mobile wake-up notifications without exposing message content, channel identity, or sender identity to the notification infrastructure.

Push proxies are entirely optional. Relays MAY designate one; clients MAY register with one. Clients that maintain persistent connections (desktop clients, server-side bots) do not need them.

#### 8.7.1 Privacy Model

The fundamental constraint: APNs (Apple) and FCM (Google) are centralized services that require a server-side component that knows which device token to wake up. The goal is to limit what the proxy learns to the minimum necessary for its function.

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

The `pushHandle` is the separation layer: the Relay knows DID → pushHandle; the proxy knows pushHandle → device token. Neither party has both mappings.

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

4. Registers `{ pushHandle, proxyEndpoint }` with their Relay, authenticated via the session token from §8.6:

```
POST /v1/agora/push/register
{
  "pushHandle":    "base64url...",
  "proxyEndpoint": "https://push.example.com/v1/agora/push"
}
```

**Registration renewal:** Push registrations have a TTL (default 30 days). Clients MUST renew before expiry. APNs/FCM device tokens may also change; clients MUST re-register with the proxy when they receive a new device token.

#### 8.7.4 Wake-Up Flow

When a Relay receives a message for a channel and the intended recipient client is not currently connected, the Relay:

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

3. The proxy maps `pushHandle → deviceToken` and sends a zero-content push notification to APNs or FCM.

Both payloads are content-free silent pushes. The OS wakes the app; the app reconnects to its Relay and receives queued messages over the authenticated session.

`urgency: "high"` is used for direct messages or @mentions; `urgency: "normal"` is used for general channel traffic. Since the Relay cannot inspect sealed content to determine urgency, the sending client attaches an advisory urgency hint to the outer `RoutingEnvelope`:

```json
"pushUrgency": "high" | "normal"
```

This field is unauthenticated and advisory — Relays use it as-is.

#### 8.7.5 Proxy Authentication and Rate Limiting

The push proxy MUST verify the RFC 9421 signature on all wake-up requests against the sending Relay's manifest. Wake-up requests from unknown or untrusted Relay DIDs MUST be rejected.

Proxies SHOULD rate-limit wake-up requests per `pushHandle` to prevent a rogue Relay from spamming a client device (for example: 1 push per 5 seconds per handle, with a burst allowance of 3).

#### 8.7.6 Handle Rotation

A client MAY rotate its `pushHandle` at any time for privacy or after suspected handle compromise. Rotation procedure:

1. Generate a new `pushHandle`.
2. Register `{ new pushHandle, deviceToken }` with the proxy.
3. Register `{ new pushHandle, proxyEndpoint }` with the Relay (relay atomically replaces old handle).
4. Delete the old `pushHandle` from the proxy: `DELETE /v1/agora/push/register/{pushHandle}`.

### 8.8 JMAP Management and Sync API

Agora Relays expose a [JMAP](https://jmap.io) (RFC 8620) API for history retrieval, state synchronization, and programmatic access. JMAP provides a proven sync model — state tokens, `/changes` deltas, batched method calls, ResultReferences, and EventSource push — without requiring a persistent connection.

#### 8.8.1 Endpoints

A Relay that declares the `jmap-v1` capability MUST expose the following endpoints under the base URL declared in `endpoints.jmap` in its manifest:

```
GET  /.well-known/jmap                           Session object (unauthenticated)
POST /jmap/api                                   JMAP request/response
GET  /jmap/events                                EventSource push stream (authenticated)
POST /jmap/upload/{accountId}                    Blob upload (authenticated)
GET  /jmap/download/{accountId}/{blobId}/{name}  Blob download (authenticated)
POST /jmap/auth                                  Obtain a bearer token (see §8.8.2)
```

#### 8.8.2 Authentication

JMAP requests are authenticated with a **bearer token** obtained via the same DID challenge-response mechanism as the live stream (§8.6), adapted for HTTP:

**Step 1 — POST /jmap/auth** with a `ClientHello` JSON body (identical structure to §8.6).

**Step 2** — The Relay responds with a `RelayChallenge` JSON body.

**Step 3 — POST /jmap/auth** with a `ClientAuth` body (DID signature over the challenge nonce).

**Step 4** — The Relay responds with:
```json
{
  "token": "base64url(32 random bytes)",
  "expiresAt": "2026-04-22T13:00:00Z",
  "accountId": "a-self"
}
```

The token TTL is 24 hours. Clients MUST present it on all subsequent JMAP requests as `Authorization: Bearer <token>`. Token refresh follows the same three-step flow.

Clients that already have an authenticated live stream connection MAY request a JMAP token via a `JmapTokenRequest` control frame (§8.6) to avoid a second round-trip.

**Pay-per-use access via x402.** Relay HTTP endpoints — JMAP, blob download, KeyPackage store, and the Peer API — MAY additionally support the x402 protocol for pay-per-use access without prior DID authentication. Under x402, an unauthenticated request to a gated endpoint returns HTTP 402 with an `X-Payment-Required` header describing the accepted rails and amount. The client pays via any accepted rail and retries with an `X-Payment` proof header. The relay validates the proof and responds with the resource, optionally including a signed bearer token valid for a session or further request quota. x402 access is appropriate for autonomous agents, API integrations, and clients that need programmatic access to relay services without a persistent authenticated session. See also §12.1.

#### 8.8.3 Capability and Session Object

**Capability URI:** `urn:agora:v1`

Every JMAP request MUST include `"urn:ietf:params:jmap:core"` and `"urn:agora:v1"` in the `using` array.

The Session object returned by `GET /.well-known/jmap`:

```json
{
  "capabilities": {
    "urn:ietf:params:jmap:core": {
      "maxSizeUpload": 104857600,
      "maxConcurrentUpload": 4,
      "maxSizeRequest": 10485760,
      "maxConcurrentRequests": 4,
      "maxCallsInRequest": 16,
      "maxObjectsInGet": 500,
      "maxObjectsInSet": 500,
      "collationAlgorithms": ["i;unicode-casemap"]
    },
    "urn:agora:v1": {
      "maxMessageBodyBytes": 65536,
      "maxAttachmentBytes": 104857600,
      "supportedBodyTypes": ["text/plain", "text/markdown;variant=commonmark"]
    }
  },
  "accounts": {
    "a-self": {
      "name": "did:key:z6Mk...",
      "isPersonal": true,
      "isReadOnly": false,
      "accountCapabilities": { "urn:agora:v1": {} }
    }
  },
  "primaryAccounts": { "urn:agora:v1": "a-self" },
  "username": "did:key:z6Mk...",
  "apiUrl": "https://relay.example.com/jmap/api",
  "downloadUrl": "https://relay.example.com/jmap/download/{accountId}/{blobId}/{name}?accept={type}",
  "uploadUrl": "https://relay.example.com/jmap/upload/{accountId}",
  "eventSourceUrl": "https://relay.example.com/jmap/events?types={types}&closeafter={closeafter}&ping={ping}",
  "state": "s-1"
}
```

#### 8.8.4 Object Types

##### Message

A single MLS-encrypted message blob as stored by the Relay. **The `encryptedPayload` field is always MLS ciphertext — the Relay cannot read it.** Clients decrypt using their local MLS group state.

```
id              String     ULID (time-sortable, server-assigned)
channelCid      String     Permanent channel identity (IPFS CID)
encryptedPayload String    base64url — MLS ciphertext (ApplicationMessage or Proposal/Commit)
mlsEpoch        UInt       MLS epoch in which the message was encrypted
seqNo           UInt       Sequence number within the epoch (for client-side ordering)
receivedAt      UTCDate    Relay's clock — authoritative for stable sort order
expiresAt       UTCDate|null  null = no configured expiry
```

##### Channel

A space channel as known to the Relay. Channel metadata is derived from the public (unencrypted) space state document (§3.3).

```
id              String     Channel CID (permanent identity)
spaceCid        String     Parent space CID
name            String     Display name from space state
topic           String|null
type            String     "text" | "voice" | "dm"
mode            String     "interactive" | "community" | "broadcast" (§3.2)
channelToken    String     Current gossipsub routing token — use this to subscribe on the live stream
speakerCap      UInt|null  Community channels only: maximum simultaneous MLS group members
idleEvictDays   UInt|null  Community channels only: idle eviction threshold in days
createdAt       UTCDate
lastMessageAt   UTCDate|null
```

##### Space

A space as known to the Relay, derived from the public space state document.

```
id              String     Space CID (permanent identity)
name            String
description     String|null
iconCid         String|null  IPFS CID of space icon blob
channelIds      String[]   Channel ids (ordered by space state)
memberCount     UInt
createdAt       UTCDate
```

##### KeyPackage

An MLS KeyPackage held in the Relay's KeyPackage Store (§6.1.1). Exposed here for CRUD access without using the low-level REST endpoint directly. The same atomic-consumption semantics apply: `KeyPackage/get` with `consume: true` atomically removes the package from the store.

```
id              String     Server-assigned opaque id
ownerDid        String     DID of the user who uploaded this package
packageData     String     base64url — raw MLS KeyPackage bytes
createdAt       UTCDate
expiresAt       UTCDate|null
```

#### 8.8.5 Methods

All methods follow RFC 8620 conventions. `/get`, `/set`, `/changes`, and `/query` have their standard semantics. Methods marked **read-only** have no `/set`.

| Method | Notes |
|---|---|
| `Message/get` | Fetch by ids. Returns encrypted blobs. |
| `Message/changes` | State-token delta. Returns added/updated/destroyed ids since a given state. |
| `Message/query` | Filter by `channelCid`; sort by `receivedAt` (default) or `seqNo`. |
| `Message/queryChanges` | RFC 8620 extended query-delta. |
| `Channel/get` | Fetch by ids. |
| `Channel/changes` | Delta since state token. |
| `Channel/query` | Filter by `spaceCid`; sort by name or `createdAt`. |
| `Space/get` | Fetch by ids. |
| `Space/changes` | Delta since state token. |
| `Space/query` | Filter/sort. |
| `KeyPackage/get` | Fetch by ids. Pass `"consume": true` in args to atomically consume (same guarantee as REST `GET /v1/agora/kp/{did}`). |
| `KeyPackage/set` | Upload new packages (`create`); destroy expired ones. Owner DID must match authenticated session. |
| `KeyPackage/changes` | Delta for the authenticated user's own packages. |

**Batching and ResultReferences.** Standard RFC 8620 §9 batching applies. Multiple method calls in a single request execute in order; `#`-prefixed argument keys reference results of prior calls via RFC 6901 JSON Pointers.

Example — fetch a space then query its channels in one round-trip:

```json
{
  "using": ["urn:ietf:params:jmap:core", "urn:agora:v1"],
  "methodCalls": [
    ["Space/get", {"accountId": "a-self", "ids": ["bafyrei..."]}, "0"],
    ["Channel/query", {
      "accountId": "a-self",
      "#filter": {
        "resultOf": "0",
        "name": "Space/get",
        "path": "/list/0/id"
      }
    }, "1"]
  ]
}
```

#### 8.8.6 Relay Blindness Preservation

The Relay's blindness properties (§11.1) are fully preserved under the JMAP API:

- **Message content.** `Message/encryptedPayload` is always MLS ciphertext. The Relay stores and serves it without decrypting. A subpoena against the Relay yields only ciphertext.
- **Channel identity.** The Relay builds its `channelCid`→`channelToken` mapping from public space state documents. This mapping is already part of normal relay operation (routing requires it); exposing it via JMAP reveals nothing new.
- **Sender identity.** No sender identity appears in any JMAP object. `encryptedPayload` contains a sealed MLS ApplicationMessage; the sender is sealed inside the ciphertext.
- **Space state.** Space and channel metadata is derived from public signed documents — the same documents any gossipsub participant can observe.

#### 8.8.7 EventSource Push

The Relay emits `StateChange` events on the EventSource stream when any tracked object type's state advances. Clients use these as a trigger to call the corresponding `/changes` method — they do not carry content.

```
event: state
data: {"changed": {"a-self": {"Message": "s-43", "Channel": "s-7", "Space": "s-3"}}}
```

Only object types whose state has changed are included in a given event. The live stream (§8.1–§8.2) provides lower-latency delivery for new messages; EventSource is the appropriate trigger for history-sync clients and background processes that do not maintain a live stream connection.

#### 8.8.8 Scope: JMAP vs Live Stream

| Operation | JMAP (§8.8) | Live Stream (§8.1–§8.7) |
|---|---|---|
| History retrieval and sync | ✓ | — |
| Space / channel metadata queries | ✓ | — |
| KeyPackage CRUD | ✓ | ✓ (also REST endpoint) |
| Programmatic / bot access | ✓ | — |
| Blob upload / download | ✓ | — |
| New message delivery | — | ✓ |
| MLS handshake (Commit / Proposal / Welcome) | — | ✓ |
| Presence and typing indicators | — | ✓ |
| Push notification registration | — | ✓ |
| DID auth handshake | ✓ (`/jmap/auth`) | ✓ (control frame) |

---

## 9. Access Control and Moderation

### 9.1 Keyholders

Agora uses a three-tier authority model. Each tier's permissions are enforced cryptographically — an operation not signed by a key with the required authority MUST be rejected by conformant Relays and clients.

**Space Owner** — holds the signing key for the Space state document. The Space Owner has sole authority to transfer or delete the space, grant or revoke the Admin role, and sign Space state mutations affecting top-level structure. There is exactly one Space Owner at any time. Ownership transfer is executed via a signed `SpaceState` mutation that replaces the `owner` DID, signed by the current owner.

**Channel/Space Admin** — a role granted by the owner and recorded in the Space state document. Admins can sign Space state mutations within their granted scope, issue invites, execute moderation operations within channels they administer, and add or remove members from channel MLS groups within their scope.

**MLS Group Committer** — by default, any current MLS group member may issue Commit messages (RFC 9420 default). Space operators MAY restrict Commit authority to a designated keyholder set via a `commitPolicy` field in the channel state. Restricting commits to a smaller set is recommended for large public channels to prevent epoch racing and Commit conflicts.

### 9.2 Space Roles

Roles beyond Owner and Admin are defined freely in the Space state document and enforced through MLS group membership. A user's assigned role determines which channel MLS groups they are added to when they join. Role assignment is a Space state mutation signed by an Admin or Owner.

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

Invites are signed tokens linking a specific DID (or an open link) to a Space and an optional role:

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "SpaceInvite",
  "space": "agora://bafyrei...",
  "issuedTo": "did:key:z6MkInvitee...",
  "role": "member",
  "issuedBy": "did:key:z6MkAdmin...",
  "expiresAt": "2026-04-12T00:00:00Z",
  "maxUses": 1,
  "sig": "base64url..."
}
```

Link-based invites (no `issuedTo` field) are supported for public spaces. These use a short random token that resolves to a signed invite document via the issuing Relay. Link-based invites support a `maxUses` limit; setting `maxUses: 0` means unlimited uses until the expiry date.

### 9.4 Private Channels

A channel is private if its MLS group membership is a strict subset of the Space's member list. The channel's existence MAY be hidden from non-members — the channel path is omitted from the Space state document served to non-members, and the access-controlled view is signed by the space owner or a delegated admin. Non-members have no way to enumerate private channels they are not members of.

### 9.5 Moderation Operations

All moderation operations are cryptographically signed and gossip-propagated on `v1/agora/space/<spaceCID>`. Relays that serve the affected space MUST enforce them on receipt of a valid signed record.

**Kick** — removes a member from one or more channel MLS groups without a space-level ban. The Admin issues MLS Remove commits for the target DID across the relevant channel groups. The member retains space membership and may be re-added to channels by an Admin.

**Ban** — removes a member from all space channel MLS groups and records a signed `BanRecord` in the space's moderation log:

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "BanRecord",
  "space": "agora://bafyrei...",
  "target": "did:key:z6MkBanned...",
  "reason": "spam",
  "bannedBy": "did:key:z6MkAdmin...",
  "ts": "2026-03-12T12:00:00Z",
  "sig": "base64url..."
}
```

Relays serving the space MUST reject message envelopes and MLS KeyPackage submissions from a banned DID.

**Timeout** — a time-bounded moderation action with an `expiresAt` field. Relays reject message publication from the target DID for that space until expiry. MLS group membership is not affected; the user remains a group member and can receive messages but cannot publish for the duration.

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "TimeoutRecord",
  "space": "agora://bafyrei...",
  "target": "did:key:z6MkMuted...",
  "expiresAt": "2026-03-12T13:00:00Z",
  "issuedBy": "did:key:z6MkAdmin...",
  "sig": "base64url..."
}
```

**Message Delete** — a signed `DeleteEvent` inner payload from a keyholder with Admin authority over the channel. Relays drop the original envelope from cache on receipt. The message CID remains in the IPLD history DAG as a tombstone entry.

**Moderation Log** — all moderation actions are appended to a signed IPLD linked list. The tail CID is referenced in the Space state document. This log is readable by space members and provides an auditable record of who moderated whom and when, with no ability to retroactively delete entries.

### 9.6 Direct Message Channels

A **Direct Message (DM) channel** is an MLS group established between two or more users outside of any Space's channel hierarchy. DM groups are not owned by any Space and do not appear in any Space state document. They are identified by a `DMGroupCID` — the IPFS CID of the `DMGroupDescriptor` document — and are addressed on gossipsub at `v1/agora/dm/<dmGroupToken>`, where `dmGroupToken` is derived identically to a channel token (HKDF-SHA256 over the MLS group ID with label `"agora-dm-token"`).

**DMGroupDescriptor schema:**

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "DMGroupDescriptor",
  "schemaVersion": "1",
  "dmGroupID": "urn:agora:dmgroup:<uuid>",
  "created": "2026-03-12T00:00:00Z",
  "createdBy": "did:key:z6MkCreator...",
  "members": [
    "did:key:z6MkAlice...",
    "did:key:z6MkBob..."
  ],
  "complianceLoggers": [],
  "sig": "base64url..."
}
```

`members` is the initial member DID list. `complianceLoggers` is the list of `ComplianceLogger` DIDs that have been admitted to the group under §17.8. The `DMGroupDescriptor` is stored as an IPLD node and updated (new CID, new `sig`) on every membership or logger change.

**MLS group initialization:** The DM group creator generates a fresh MLS group, adds KeyPackages for each invited member, and publishes Welcome messages to each invitee's push notification handle or relay inbox. There is no Space admin in the invite path — any DM group member may add new members via standard MLS Add + Commit, subject to the consent mechanism in §9.6.1.

**Relay routing:** Because DM groups have no Space affiliation, Relays route DM traffic by `dmGroupToken` alone, identically to channel traffic. A Relay that does not know the `dmGroupToken` will not route DM traffic; the sending client SHOULD use the Relays known to be serving the recipient's DID (discoverable from the recipient's DID document relay hints).

**Cross-topology reachability.** DM reachability is determined by the recipient's relay hints, not by their DID method or the topology of either party's relay. A user with a `did:web:agency.gov` identity can initiate a DM with a user whose only relay hint is a `.onion` address; the initiating client connects to that `.onion` relay via Tor (if available) or routes through an intermediary relay that has Tor reachability. Neither relay learns the other party's identity — relay blindness (§11.1) holds across topology boundaries. The only requirement is that the initiating client, or a relay it controls, can reach at least one of the recipient's advertised relay hints. DID method, DNS anchoring, and relay topology are orthogonal to whether two users can exchange messages.

**History and storage:** DM message history is stored in IPFS/IPLD identically to channel history. The `DMGroupDescriptor` CID is the root. Members are responsible for pinning their own DM history; there is no Space-level pinning obligation.

#### 9.6.1 Member Addition Consent

Any DM group member MAY propose adding a new member via an MLS Add Proposal. The Add is not committed until a configurable consent threshold of existing members issues a matching Commit or explicit approval signal. The default consent model is **unanimous** for groups of 2–4 and **majority** for groups of 5 or more. The `DMGroupDescriptor` MAY declare a non-default `consentModel`.

This consent requirement applies equally to compliance logger additions initiated under §17.8 — the logger is added via the same MLS Add + Commit path, and the committing client is the regulated member's own user agent, not a remote admin.

#### 9.6.2 DM Group vs. Private Channel

A DM group and a private Space channel (§9.4) are structurally similar — both are MLS groups with a restricted membership set. The distinction is:

- A private channel is owned by a Space, appears in that Space's state document (for authorized members), and is subject to the Space's compliance logging configuration.
- A DM group is owned by its members collectively, has no Space parent, and is subject to compliance logging only through the per-member obligation in §17.8.

Users who need a persistent, named, multi-party private conversation with Space-level administration (roles, moderation, compliance) SHOULD use a private Space channel rather than a DM group.


---

## 10. Voice and Video (VTC)

Agora supports real-time group voice and video conferencing as a first-class channel type. The design uses WebRTC for media transport, MLS-encrypted signaling for all control messages, and an optional SFU (Selective Forwarding Unit) for scalable multi-party sessions. Media never transits Relays.

### 10.1 Voice Channel Type

A channel with `"type": "voice"` is a VTC room. It has all the properties of a text channel (MLS group, channel CID, history) plus a persistent **call state** — a real-time record of who is currently in the call and their media states.

A voice channel is always "open" — there is no concept of starting or ending a call. Participants join and leave; the room exists as long as the channel exists.

**Transport constraints.** VTC requires UDP for ICE and media:

- **Clearnet or overlay (Tailscale, WireGuard):** Full VTC supported. Overlay networks provide ICE host candidates directly; NAT traversal is handled by the overlay.
- **Tor:** VTC is severely degraded. UDP is unavailable over Tor; only TURN-over-TCP paths are possible, adding 200–600ms latency. Clients operating in Tor-only mode SHOULD warn users before joining a voice channel and MAY disable VTC participation entirely.

### 10.2 Call State

Call state is ephemeral, gossip-propagated, and not stored in IPLD history. It is maintained as a set of `ParticipantState` records, one per active participant, gossiped on `v1/agora/channel/<channelToken>`:

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

`audioMuted`, `videoEnabled`, `screenSharing`, and `handRaised` are advisory UI hints gossiped to other participants. They are not enforced at the media layer.

Call state events are delivered as MLS `PublicMessage` application data — authenticated by the sender's MLS credentials but not encrypted, since call state is visible to all channel members.

### 10.3 Join and Leave

**Join** — a client sends a `ParticipantState` with `status: "joined"` to the channel gossip topic, then initiates WebRTC negotiation with existing participants or the SFU.

**Leave** — a client sends `ParticipantState` with `status: "left"` and closes its WebRTC connections. Clients that disconnect without sending a leave message (crash, network drop) are timed out by other participants after `ttl` seconds.

Join and leave operations do NOT change MLS group membership. Being in the call means having an active `ParticipantState` with `status: "joined"` and live WebRTC connections.

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

`signalType` values: `offer`, `answer`, `candidate`, `candidate-end`. `targetDID` is the intended recipient. All signals are broadcast to the channel MLS group; non-target recipients MUST ignore signals not addressed to them.

The consequences of MLS-encrypted signaling:
- **E2EE signaling** — Relays cannot read SDP or ICE candidates.
- **Authenticated signaling** — the MLS sender credential binds each signal to a verified DID.
- **Authenticated DTLS fingerprint** — the DTLS-SRTP fingerprint in the SDP is authenticated by the MLS signature, closing the identity binding loop: a participant's media stream is cryptographically bound to their DID (see §10.10).

### 10.5 Topology: Mesh vs SFU

**Mesh (≤4 participants, recommended)** — each participant establishes a direct WebRTC PeerConnection to every other participant. No SFU is required. Signaling is peer-to-peer via the MLS channel. Latency is minimized; bandwidth scales as O(n²).

**SFU (>4 participants, recommended)** — participants connect to a Selective Forwarding Unit which receives each participant's streams and forwards them selectively. Bandwidth scales as O(n). The SFU does not decode or re-encode media — it forwards RTP packets based on subscriber requests.

The threshold of 4 is a recommendation. Clients MAY negotiate mesh topology for larger groups if all participants have sufficient bandwidth and consent.

### 10.6 SFU Integration

#### SFU Identity and Trust

An SFU has a DID, just like a user. Before an SFU can participate in a voice channel, its DID MUST be added to the channel's MLS group via a normal MLS Add commit, signed by a channel Admin. A participant's client MUST verify the SFU's DID against the channel's MLS group membership before connecting to it; an SFU not in the group MUST be rejected.

#### SFU Discovery

Space operators publish their SFU's DID and WebRTC endpoint in the Space state document:

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

**Reference SFU implementations:** [`mediasoup`](https://mediasoup.org/) (Node.js/Rust), [`Pion SFU`](https://github.com/pion/ion-sfu) (Go), [`LiveKit`](https://github.com/livekit/livekit) (Go, open-source).

#### SFU Signaling Flow

1. Client sends `VoiceSignal { signalType: "offer", targetDID: <sfuDID> }` to the channel.
2. SFU receives the offer (it is an MLS group member), responds with `VoiceSignal { signalType: "answer", targetDID: <clientDID> }`.
3. ICE candidates are exchanged via `candidate` signals.
4. DTLS handshake completes over the established ICE path — fingerprint from SDP is verified against the SFU's DID document.
5. SRTP media flows.

#### SFU Media Opacity

The SFU forwards SRTP packets without decrypting them. It cannot read audio or video content. It CAN observe:
- Which participants are sending media (RTP SSRC → participant mapping)
- Packet timing and sizes (traffic analysis)
- Whether a stream is active or silent

This is an accepted tradeoff. An SFU that forwards without decrypting is a routing device, not a surveillance device. The alternative — full E2EE media with per-participant keys — requires Insertable Streams (WebRTC IS) and is specified as an optional extension in §10.9.

#### SFU Recording

An SFU MAY be granted explicit decryption rights for recording. This is a deliberate, auditable, and reversible action requiring explicit admin authorization and participant disclosure. The full sub-protocol is specified in §10.12.

### 10.7 Simulcast and Bandwidth Adaptation

Clients SHOULD publish video in multiple simulcast layers (e.g., 1080p / 360p / 180p) to allow the SFU to forward the appropriate quality tier to each subscriber based on their available bandwidth. Layer selection is signaled via RTCP feedback from subscribers to the SFU.

For Scalable Video Coding (SVC) codecs (VP9, AV1), temporal and spatial scalability layers are used instead of discrete simulcast tracks. SFU implementations SHOULD support both simulcast (VP8, H.264) and SVC (VP9, AV1).

Audio is always single-layer. The SFU performs silence suppression detection via Voice Activity Detection on the RTP stream to forward only active speakers, with a configurable active-speaker window (default: 3 simultaneous speakers).

### 10.8 Screen Sharing

Screen sharing is a video track with a declared purpose. The sharing participant sets `"screenSharing": true` in their `ParticipantState` and adds a second video transceiver to their PeerConnection with a `content` attribute of `"screen"` in the SDP:

```
a=content:screen
```

Clients receiving a screen share track SHOULD display it distinctly from camera video. Multiple participants MAY share simultaneously; the SFU forwards all active screen share tracks.

Screen share tracks use a separate simulcast configuration from camera video: typically high resolution (up to 1080p or 1440p), low frame rate (5–15 fps).

### 10.9 End-to-End Encrypted Media (Optional Extension)

The default SFU topology trusts the SFU not to analyze RTP packet content. For higher-threat deployments, **WebRTC Insertable Streams** (W3C) enable per-hop media encryption with participant-held keys, such that the SFU forwards ciphertext it cannot decrypt even at the packet level.

In this mode:
- Each participant derives a media encryption key via the MLS exporter interface: `MLS-Exporter("agora-media-key", participantDID, 32)` (RFC 9420 §8.5).
- Outgoing media is encrypted by the sender's Insertable Streams transform before entering the RTP stack.
- The SFU forwards encrypted RTP packets opaquely.
- Each receiving participant's Insertable Streams transform decrypts using the sender's exported media key.

Media keys rotate with MLS epochs. A participant whose MLS leaf is removed loses their media key derivation capability for subsequent epochs.

This extension requires browser/runtime support for Insertable Streams (available in Chromium-based browsers; partial in Firefox). It is declared in the channel state as `"e2eeMedia": true`. Clients that do not support Insertable Streams MUST NOT join a channel with `e2eeMedia: true`.

### 10.10 DTLS-SRTP Identity Binding

WebRTC media is encrypted with DTLS-SRTP. The DTLS handshake uses a self-signed certificate; the certificate fingerprint is included in the SDP offer and answer. In standard WebRTC, this fingerprint is unauthenticated.

In Agora, the SDP carrying the fingerprint is delivered as a `VoiceSignal` inner payload, MLS-encrypted and signed by the sender's DID authentication key. Recipients verify the MLS signature before processing the SDP. This means:

- The DTLS fingerprint is authenticated by the sender's DID.
- A Relay or network attacker cannot substitute a different certificate without breaking the MLS signature.
- The media stream is cryptographically bound to the sending DID.

This closes the identity binding loop without requiring any PKI or certificate authority. The MLS group membership proof IS the identity assertion for media.

### 10.11 TURN Server Integration

WebRTC ICE succeeds with direct peer connectivity in most cases but fails for participants behind **symmetric NAT**. TURN servers relay media packets between participants who cannot establish a direct path.

#### TURN Server Identity

TURN servers in Agora have DIDs, published in the Space state document:

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

`uri` follows the standard TURN URI format (RFC 7065). `turns:` (TLS) is required; `turn:` (plaintext) MUST NOT be used.

**Reference implementations:** [`coturn`](https://github.com/coturn/coturn) is the standard open-source TURN/STUN server.

#### TURN Credentials

Standard TURN uses username/password credentials. Agora replaces this with **DID-based HMAC credentials** (`credentialScheme: "agora-hmac-did"`) to avoid any credential that could identify a user to the TURN operator:

1. The TURN server publishes a time-scoped HMAC key in its `TURNDescriptor`, rotated every 24 hours: `hmacKey = HKDF(turnMasterSecret, "turn-key" || floor(unixtime / 86400))`
2. A client computes: `username = floor(unixtime / 86400) || ":" || randomNonce` and `credential = HMAC-SHA256(hmacKey, username)`
3. The client presents these credentials in the ICE `candidate` for the TURN allocation.
4. The TURN server verifies the HMAC without learning the client's DID or any persistent identity.

The TURN operator sees: a valid HMAC credential, a source IP, and opaque SRTP packets. It cannot link the session to a DID, channel, or space.

#### ICE Candidate Priority

Clients MUST follow standard ICE candidate priority ordering:

1. Host candidates (direct LAN or overlay)
2. Server-reflexive candidates (STUN, public IP via NAT)
3. Peer-reflexive candidates (discovered during connectivity checks)
4. Relay candidates (TURN)

TURN candidates are only used if all higher-priority paths fail. Clients SHOULD include at least one TURN candidate in all offers to ensure connectivity for symmetric NAT participants.

#### TURN Credential Distribution

TURN credentials are short-lived and not sensitive. They MAY be distributed as plaintext in the outer `RoutingEnvelope` as a `TURNCredentialHint` alongside the `VoiceSignal`, or fetched directly from the TURN server's HTTP endpoint using the DID-HMAC scheme before signaling begins.

For `e2eeMedia: true` channels, TURN credential computation uses the MLS epoch secret as an additional HMAC input: `credential = HMAC-SHA256(hmacKey, username || epochSecret[:16])`. This binds TURN access to current MLS group membership.

### 10.12 Recording Grant Sub-Protocol

This section fully specifies the `RecordingGrant` mechanism referenced in §10.6 — the key delivery sub-protocol, the recording archive format, participant disclosure requirements, and compliance recording configuration.

#### 10.12.1 RecordingGrant Schema

A channel Admin issues a `RecordingGrant` as an MLS application message to the voice channel's MLS group:

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "RecordingGrant",
  "channelCID": "bafyrei...",
  "grantedTo": "did:key:z6MkRecorder...",
  "grantedBy": "did:key:z6MkAdmin...",
  "scope": "audio-video",
  "purpose": "compliance",
  "expiresAt": "2026-03-13T00:00:00Z",
  "participantDisclosure": "This call is being recorded for regulatory compliance by Acme Corp Compliance Archive.",
  "ts": "2026-03-12T12:00:00Z",
  "sig": "base64url..."
}
```

`grantedTo` is the DID of the recording principal. `scope` is `"audio-only"`, `"video-only"`, or `"audio-video"`. `purpose` is `"operational"` (ad-hoc recording by an admin) or `"compliance"` (regulatory retention obligation). `participantDisclosure` MUST be displayed to all channel participants before recording begins.

A `RecordingRevoke` terminates the grant early:

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "RecordingRevoke",
  "grantCID": "bafyrei...",
  "revokedBy": "did:key:z6MkAdmin...",
  "ts": "2026-03-12T14:00:00Z",
  "sig": "base64url..."
}
```

Both `RecordingGrant` and `RecordingRevoke` are stored in the channel's IPLD history DAG — the full grant and revocation history is permanently auditable.

#### 10.12.2 Key Delivery Sub-Protocol

The recording key is derived from the MLS exporter interface and delivered to the recorder's DID via an encrypted `RecordingKeyDelivery` message.

**Key derivation.** Each participant derives the recording key for the current MLS epoch as:

```
recordingKey = MLS-Exporter("agora-recording-key-v1", grantCID_bytes, 32)
```

where `grantCID_bytes` is the raw CID bytes of the `RecordingGrant` that authorized this recording session. Using the grant CID as context binds the key to the specific grant — different grants for the same channel in different epochs produce different keys. The derivation occurs entirely within the MLS stack; the epoch secret is never exposed to application code.

**Key delivery.** Each participant's client delivers the derived key to the recorder's DID via an MLS application message of type `RecordingKeyDelivery`, sent as a PrivateMessage targeted to the recorder's DID within the channel group:

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "RecordingKeyDelivery",
  "grantCID": "bafyrei...",
  "epoch": 17,
  "encryptedKey": "base64url...",
  "senderDID": "did:key:z6MkParticipant...",
  "ts": "2026-03-12T12:00:00Z",
  "sig": "base64url..."
}
```

`encryptedKey` is the 32-byte `recordingKey` encrypted to the recorder's X25519 `keyAgreement` key from its DID document, using HPKE (RFC 9180, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM). The HPKE `info` parameter is `"agora-recording-key-delivery-v1" || grantCID_bytes`.

**Delivery timing.** Clients MUST deliver a `RecordingKeyDelivery` message:
1. Immediately on receiving a valid `RecordingGrant`, for the current epoch
2. At each subsequent MLS epoch advance (key rotation), for the new epoch's derived key, for the duration of the grant
3. NOT after receiving a `RecordingRevoke` or after `expiresAt` has passed

The recorder collects `RecordingKeyDelivery` messages from each participant. It needs only one valid delivery per epoch to decrypt that epoch's media. However, clients MUST NOT withhold delivery; failing to deliver is a protocol violation for a participant who is in the call.

**Epoch gaps.** If the recorder misses a `RecordingKeyDelivery` for an epoch (e.g., it was offline), it cannot decrypt media from that epoch retroactively. The `VTCComplianceAuditEntry` (§10.12.6) records any epoch gaps detected by the compliance logger.

#### 10.12.3 Participant Disclosure

Before recording begins, participating clients MUST display the `participantDisclosure` string from the `RecordingGrant` as a non-dismissable system message in the voice channel's text feed and as a visible indicator in the call UI for the duration of the recording. The indicator MUST persist for the full duration of the grant.

A participant who joins a voice channel where a `RecordingGrant` is already active MUST be shown the disclosure immediately on join, before their audio or video is transmitted. Their client MUST NOT enable media transmission until the disclosure has been rendered.

For compliance grants (`"purpose": "compliance"`), the disclosure MUST include the `loggerLabel` and `retentionDays` from the space's `ComplianceLoggingConfig`:

> **This call is being recorded for regulatory compliance by [loggerLabel] and retained for [retentionDays] days.**

#### 10.12.4 Recording Archive Format

The recorder writes received media to IPFS and records metadata as a `VTCComplianceRecord`:

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "VTCComplianceRecord",
  "grantCID": "bafyrei...",
  "channelCID": "bafyrei...",
  "epoch": 17,
  "startTs": "2026-03-12T12:00:00Z",
  "endTs": "2026-03-12T12:45:00Z",
  "participants": [
    {
      "did": "did:key:z6MkAlice...",
      "joinTs": "2026-03-12T12:00:00Z",
      "leaveTs": "2026-03-12T12:45:00Z"
    },
    {
      "did": "did:key:z6MkBob...",
      "joinTs": "2026-03-12T12:05:00Z",
      "leaveTs": "2026-03-12T12:45:00Z"
    }
  ],
  "mediaCID": "bafyrei...",
  "mediaFormat": "audio/ogg;codec=opus",
  "scope": "audio-video",
  "recorderSig": "base64url...",
  "prevRecordCID": "bafyrei..."
}
```

`mediaCID` is the IPFS CID of the recorded media file. `prevRecordCID` chains records into the same append-only IPLD structure used for text compliance (§17.4), making the recording archive tamper-evident. `recorderSig` is the recorder's Ed25519 signature over the canonical CBOR serialization of all other fields.

Media SHOULD be stored as Opus audio in an Ogg or WebM container (audio-only recordings) or VP8/VP9/AV1 video with Opus audio in a WebM container (audio-video recordings). The recorder MUST decode the SRTP streams using the delivered recording keys and re-encode to the archive format before writing to IPFS. The raw SRTP packets MUST NOT be stored.

Per-epoch media files are stored separately (one `mediaCID` per epoch) and linked by the `VTCComplianceRecord` chain.

#### 10.12.5 VTC Compliance Configuration

To enable automatic compliance recording for a space's voice channels, the space owner adds a `vtcCompliance` block to the space state document:

```json
"vtcCompliance": {
  "@type": "VTCComplianceConfig",
  "schemaVersion": "1",
  "enabled": true,
  "recorderDID": "did:key:z6MkRecorder...",
  "recorderLabel": "Acme Corp VTC Compliance Recorder",
  "scope": "audio-video",
  "retentionDays": 2555,
  "autoGrant": true,
  "enabledBy": "did:key:z6MkOwner...",
  "enabledAt": "2026-03-12T00:00:00Z",
  "sig": "base64url..."
}
```

`recorderDID` is the DID of the compliance recording principal. `autoGrant` when `true` causes conformant clients to automatically issue a `RecordingGrant` for `recorderDID` on every voice channel in the space when a call begins, without requiring per-call admin action.

When `autoGrant` is `true`, the `RecordingGrant` is issued by the first Admin or Owner client that observes the call starting. The grant `expiresAt` is set to the call end plus a configurable grace period (default 5 minutes) to capture any reconnecting participants.

The recorder operates as a passive member (§6.1.3) of each voice channel's MLS group — it holds a leaf credential, receives all MLS application messages (including `RecordingKeyDelivery` messages), and does not issue Commits or Proposals. The recorder whose DID is declared in `vtcCompliance.recorderDID` MUST have a `KeyPackageEndpoint` service entry in its DID document (same requirement as the text compliance logger, §17.8.2) and MUST pre-upload an HPKE public key in its DID document's `keyAgreement` entry.

#### 10.12.6 VTC Compliance Audit Entry

The space's IPLD compliance audit chain receives a `VTCComplianceAuditEntry` for each compliance recording session:

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "VTCComplianceAuditEntry",
  "channelCID": "bafyrei...",
  "grantCID": "bafyrei...",
  "recorderDID": "did:key:z6MkRecorder...",
  "callStart": "2026-03-12T12:00:00Z",
  "callEnd": "2026-03-12T12:45:00Z",
  "epochsRecorded": [17, 18, 19],
  "epochsGapped": [],
  "participantCount": 4,
  "vtcRecordCIDs": ["bafyrei...", "bafyrei..."],
  "sig": "base64url..."
}
```

`epochsGapped` is an array of epoch numbers for which no `RecordingKeyDelivery` was received, resulting in an unrecorded segment. An empty array means complete capture. Non-empty arrays are compliance gaps that must be reported to the compliance officer.

#### 10.12.7 VTC Compliance in DM Voice Groups

A DM group (§9.6) may include a voice channel component. The obligation from §17.8 extends to voice: a regulated Space member participating in a DM voice group MUST add the space's `recorderDID` to the DM group's MLS group and issue a `RecordingGrant` for the recorder before any voice media is transmitted, following the same mechanics as §10.12.2. The `DMGroupDescriptor` `complianceLoggers` array records both text logger DIDs and VTC recorder DIDs.

Participant disclosure (§10.12.3) applies in DM voice groups identically to space voice channels. Non-regulated DM participants receive the disclosure notice and MAY leave before transmitting media.


---

## 11. Relay Behavior

### 11.1 Relay Knowledge Constraints

A conformant Relay is explicitly designed to know as little as possible about the traffic it routes. The following is both a design target and a compliance requirement: a Relay operator responding to a legal demand or subpoena MUST be able to honestly testify to all of the following:

- I do not know who my users are (no identity registration, no account system, no persistent user records).
- I do not know who is in any group (channel membership is not visible at the relay layer; `channelToken` is epoch-rotating and non-reversible without the epoch secret).
- I do not know who sent any message (sealed sender design; sender DID is inside the MLS ciphertext).
- I store nothing after delivery beyond the configured retention window, and nothing with a message expiry past that expiry — except CIDs explicitly pinned by channel members, which are retained until unpinned by a valid signed `UnpinEvent`.
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
- Enforce ban records received via space gossip (§9.5).
- Enforce timeout records for their specified duration (§9.5).
- Respect `expiryHint` on cached message envelopes (§6.4).
- Apply per-`channelToken` rate limits (§13.5).
- Publish a Relay Manifest at `/.well-known/agora-relay` (§3.5.1).
- Maintain heartbeat polling of peer relays (§3.5.6).
- Route messages by `channelToken` only; never attempt to resolve tokens to identities.
- Cache message envelopes up to the lesser of: configured retention window (default 30 days) or the envelope's `expiryHint`.
- Delete cached envelopes on receipt of a valid signed `DeleteEvent` for their CID.
- Pin IPFS content for channels it serves within the retention window.
- Retain all CIDs listed in a channel's `pins` array indefinitely, regardless of retention window or `expiryHint`, until explicitly removed by a valid `UnpinEvent` (§6.6).
- Reject `PinEvent` messages that would cause the channel's pin count to exceed `pinLimit` (§6.6).
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

### 12.1 Payment Rails

#### PaymentPointer

All payment destinations in Agora are expressed as a `PaymentPointer` — an abstract type carrying a rail identifier and a rail-specific address. The protocol is not coupled to any single payment network; new rails can be registered via the Agora extension namespace.

```json
{
  "@type": "PaymentPointer",
  "scheme": "cashu",
  "address": "https://mint.example.com"
}
```

**Defined rails:**

| Rail | Network | Best for | Notes |
|---|---|---|---|
| `cashu` | Cashu ecash over Lightning | High-frequency micropayments | Chaumian blind tokens — mint cannot link issuance to redemption; bearer instrument, works offline |
| `bolt12` | Lightning Network | Service agreements, larger settlements | Reusable offers; routing reliability degrades for sub-sat amounts |
| `bolt11` | Lightning Network | Single-use invoice fallback | Use only when the counterparty cannot receive BOLT 12 |
| `pow` | Hashcash-style PoW | Spam deterrence, no payment | No money changes hands; see §12.4 |

Implementations that opt into micropayments MUST support at least one defined payment rail. `bolt12` SHOULD be supported for service agreements. `pow` is not a payment rail — it is a spam-deterrence alternative that requires no payment infrastructure; any implementation MAY support it independently.

#### Signed Bearer Tokens

Several of the defined rails — and any future rails following the same pattern — are instances of the **signed bearer token** model: a self-contained object, signed by an issuer, that proves entitlement to value or access by possession alone. Whoever holds the token can spend or present it; no live connection to the issuer is required at redemption time.

`cashu` is the primary example: a Cashu mint blindly signs tokens at issuance so it cannot link issuance to redemption; the token is the value, transferable by passing the object. Lightning payment preimages (`bolt12`/`bolt11`) are also bearer proofs — once a payment is made, the preimage proves it happened and can be presented to any verifier.

This pattern extends naturally to:

- **Pre-issued relay credits** — a relay signs a batch of credit tokens at purchase time; the client spends them per-message without any live payment network involvement. Useful for air-gapped or intermittently connected deployments.
- **Access tokens** — pay once via any rail, receive a signed token granting access to a channel or tier. The token is redeemable without re-contacting the payment network.
- **Game and application currency** — application-layer tokens signed by a trusted issuer (a game operator, a DAO, a relay cooperative) and redeemable within a defined scope.

New rails following the signed bearer token pattern MAY be registered in the Agora extension namespace using the rail identifier `bearer-<issuer-defined-name>`. The `PaymentPointer.address` for such rails is the issuer's verification endpoint or public key reference.

**x402 and L402.** x402 (HTTP 402 Payment Required) and its Lightning-specific predecessor L402 are standard HTTP handshake protocols for *obtaining* signed bearer tokens via payment. They sit above the payment rails, not beside them: a client requests a resource, receives an HTTP 402 response carrying payment terms (amount, rail, payment address), makes the payment via any accepted rail, and retries with a payment proof header. The server validates the proof and returns a signed bearer token granting access for a session or quota. x402 and L402 define the request/response handshake; the underlying value transfer uses an existing rail (`cashu`, `bolt12`, etc.). They are therefore a natural fit for automated and machine-to-machine access — including autonomous agents paying for relay services without human intervention.

#### SpaceTreasury

A Space MAY declare a treasury — a payment destination that receives a fraction of message fees and relay fee-sharing. The treasury is a `PaymentPointer` in the Space state document:

```json
"treasury": {
  "@type": "SpaceTreasury",
  "paymentPointers": [
    { "@type": "PaymentPointer", "scheme": "cashu",  "address": "https://mint.example.com" },
    { "@type": "PaymentPointer", "scheme": "bolt12", "address": "lno1pg..." }
  ],
  "description": "wolfSSL Dev infrastructure fund",
  "feeShareBps": 1000
}
```

`feeShareBps` is the basis points (0–10000) of relay service agreement revenue the Relay is expected to route to the treasury. Enforcement is by Relay selection — Space owners choose Relays that honor their declared fee-share terms.

### 12.2 Relay Service Agreements

A `RelayServiceAgreement` is a bilaterally signed document between a Space owner DID and a Relay DID specifying channels served, SLA terms, price, and fee-share obligation. It is the primary funding mechanism for organized communities.

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "RelayServiceAgreement",
  "id": "urn:agora:rsa:bafyrei...",
  "relay": "did:key:z6MkRelay...",
  "space": "agora://bafyrei...",
  "channels": ["*"],
  "retentionDays": 90,
  "bandwidthTierGbPerMonth": 100,
  "price": {
    "@type": "PaymentPointer",
    "scheme": "cashu",
    "address": "https://mint.example.com"
  },
  "billingCycleDays": 30,
  "feeShareBps": 1000,
  "spaceTreasuryPointer": {
    "@type": "PaymentPointer",
    "scheme": "bolt12",
    "address": "lno1pg..."
  },
  "validFrom": "2026-03-12T00:00:00Z",
  "validUntil": "2027-03-12T00:00:00Z",
  "keyPackageSLA": {
    "minimumCount": 20,
    "alertThreshold": 5,
    "alertMechanism": "both",
    "guaranteedRetentionDays": 90,
    "replenishFromIPFS": true
  },
  "relaySig": "base64url...",
  "spaceOwnerSig": "base64url..."
}
```

`channels` is a list of channel path globs. `"*"` means all current and future channels in the space. The agreement is gossiped on `v1/agora/space/<spaceCID>` and stored in the space's IPLD state. Multiple concurrent agreements (multiple Relays serving the same space) are valid and encouraged for redundancy.

`keyPackageSLA` is an optional clause that elevates the relay's KeyPackage Store behavior from best-effort to a contractual obligation (§6.1.1). When present, all fields are required and the relay's conformance to them is a term of the agreement.

Relays publish their service tiers and accepted payment rails in their `RelayAd`. Each tier carries a `price` object with a `scheme`, `amount`, and optional `denomination`; the relay MAY publish multiple tier variants for different accepted rails:

```json
{
  "@type": "RelayAd",
  "did": "did:key:z6MkRelay...",
  "endpoint": "https://relay.example.com",
  "acceptedSchemes": ["cashu", "bolt12", "pow"],
  "serviceTiers": [
    {
      "id": "hobbyist",
      "retentionDays": 7,
      "bandwidthTierGbPerMonth": 10,
      "price": { "scheme": "pow", "amount": "0" },
      "feeShareBpsMax": 0
    },
    {
      "id": "standard",
      "retentionDays": 30,
      "bandwidthTierGbPerMonth": 100,
      "price": { "scheme": "cashu", "amount": "1000", "denomination": "sat" },
      "feeShareBpsMax": 2000
    },
    {
      "id": "enterprise",
      "retentionDays": 365,
      "bandwidthTierGbPerMonth": 1000,
      "price": { "scheme": "bolt12", "amount": "10000", "denomination": "sat" },
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
    "scheme": "cashu",
    "feeAmount": "1",
    "feeDenomination": "sat",
    "relayShareBps": 7000,
    "spaceShareBps": 2000,
    "freeMessageQuota": 100,
    "senderRefundOnReply": true
  },
  {
    "@type": "MessageFeePolicy",
    "scheme": "pow",
    "difficulty": 18
  }
]
```

`relayShareBps` + `spaceShareBps` MUST sum to ≤ 10000. The remainder is burned to a provably unspendable address. `senderRefundOnReply`: if a recipient replies to a message, the sender's fee is refunded — a social mechanic incentivizing content worth responding to. `freeMessageQuota` is the number of messages per MLS epoch a member may send without payment.

#### Payment Flow

When a channel requires payment, the sending client attaches a `MessagePayment` to the outer `RoutingEnvelope` before submission:

```json
{
  "@type": "MessagePayment",
  "scheme": "cashu",
  "relayPaymentProof": "base64url...",
  "spacePaymentProof": "base64url...",
  "ts": "2026-03-12T12:00:00.000Z"
}
```

Both payments are made before submitting the envelope. The Relay verifies only its own payment proof before forwarding:

```
Sender
  ├── relayShareBps × feeAmount → Relay payment pointer
  └── spaceShareBps × feeAmount → Space treasury pointer
```

For `cashu`: `relayPaymentProof` is a spent-token proof presented to the Relay's trusted mint list. For `bolt12`/`bolt11`: it is a Lightning payment preimage.

The Relay tracks free quota consumption per `channelToken` per epoch. Space admins may grant extended free quotas to specific roles via a signed `QuotaGrant` message gossiped to the channel topic.

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

The Relay verifies the PoW before forwarding. Difficulty 18 requires ~262,000 SHA-256 hash operations — roughly 10–50ms on a modern CPU, imperceptible to a human sender, but economically prohibitive for bulk message flooding.

### 12.5 End-to-End Payment Flow Summary

| Direction | Mechanism | Purpose |
|---|---|---|
| Space owner → Relay | `RelayServiceAgreement` recurring payment | Reliable relay service, history retention, SLA |
| Relay → Space treasury | Fee-share from service agreement revenue | Community sustainability fund |
| Message sender → Relay | `MessagePayment` proof-of-payment | Relay revenue for public traffic, spam deterrence |
| Message sender → Space treasury | `MessagePayment` proof-of-payment | Community fund, spam deterrence |
| Message sender → (none) | `PowProof` | Spam deterrence only, no revenue |

All flows are optional. A self-hosted zero-fee deployment uses none of them. A large public space with anonymous users may use all of them simultaneously across different channels.


---

## 13. Security Considerations

### 13.1 Forward Secrecy

MLS provides forward secrecy by design. Each epoch derives a new application secret via the MLS key schedule. Compromise of a member's current epoch key material does not expose prior messages, which were encrypted under previous epoch secrets.

### 13.2 Post-Compromise Security

MLS `Update` proposals (triggered by devices or by time-based policy) ratchet the ratchet tree forward, healing from key compromise. A member whose keys were compromised but who subsequently performs an `Update` commit regains security — the compromised old key material cannot decrypt new messages. Space operators SHOULD enforce periodic key rotation (recommended: 7-day maximum epoch lifetime for active channels).

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

### 13.6 Key Storage: HSM and Secure Enclave Guidance

All private key operations in Agora (signing, key agreement, MLS leaf operations) SHOULD be performed inside a hardware-backed secure boundary wherever the platform provides one. The protocol is designed so that no operation requires extracting raw private key bytes to application memory.

**Platform secure boundaries and recommended APIs:**

| Platform | Boundary | API |
|---|---|---|
| macOS / iOS | Secure Enclave (T-series / M-series) | `SecKey` / CryptoKit `SecureEnclave.P256` |
| Android | StrongBox / TEE | `AndroidKeyStore` with `PURPOSE_SIGN` / `PURPOSE_AGREE_KEY` |
| Linux server | TPM 2.0 or hardware HSM | PKCS#11 (`opensc-pkcs11`, `SoftHSM2` for dev), or `tpm2-pkcs11` |
| YubiKey / hardware security key | Secure element | PKCS#11, PIV, or OpenPGP card interface |
| Browser | Platform Authenticator | WebAuthn `PRF` extension (for key derivation); `SubtleCrypto` with non-extractable `CryptoKey` (`extractable: false`) |

**Conformance requirements by operation:**

- **Authentication key signing** (Ed25519 / P-256) — MUST use hardware-backed key where available. On platforms that do not support Ed25519 in the secure boundary (notably Secure Enclave, which supports P-256 only), P-256 (`ES256`) MAY be used as the authentication key algorithm for that device. The DID document MUST reflect the actual key type in use.

- **MLS leaf operations** (KeyPackage generation, Commit signing, Update proposals) — MUST use keys held in the secure boundary. `openmls` supports pluggable crypto backends; implementations SHOULD provide a backend that delegates to the platform keystore rather than holding raw key bytes.

- **MLS key schedule / epoch secrets** — these are MLS-internal derived values, not persistent keys. They exist transiently in MLS stack memory during epoch processing and SHOULD NOT be exposed to application code. All operations requiring epoch secret access MUST use the MLS exporter interface (RFC 9420 §8.5) rather than accessing the epoch secret directly.

- **X25519 key agreement** (for encrypting social recovery shares, HPKE operations) — SHOULD use hardware-backed key agreement where the platform supports it. Where hardware X25519 is unavailable, software implementation in a sandboxed process is the fallback.

- **Recovery key** — see §2.4.1. This key MUST NOT be in any software keystore. Its signing operation occurs exactly once per recovery event, on an air-gapped device or hardware security key, and the output (`RecoveryAssertion`) is transferred to the networked environment by QR code, USB, or similar one-way channel.

**What the spec does NOT require from application code:** application code MUST NOT have access to raw private key bytes for any of the above. API calls should be of the form "sign this payload with key handle K" or "agree on a shared secret using key handle K and this public key", with the output being a signature or shared secret — not a key.

**Relay operator key storage:** Relay signing keys SHOULD be held in an HSM or TPM-backed keystore on the relay host. Cloud HSM services (AWS CloudHSM, GCP Cloud HSM, Azure Dedicated HSM) are appropriate for hosted relay deployments. At minimum, keys SHOULD be stored in the OS keyring rather than on-disk in plaintext.

### 13.7 Non-Repudiation and Organizational Non-Impersonation

Agora provides a stronger non-repudiation guarantee than any conventional enterprise messaging platform, and a structural property that prevents silent organizational impersonation of users. Both properties emerge from the architecture rather than from policy.

#### 13.7.1 Why Conventional Enterprise Platforms Cannot Provide This

In all conventional enterprise messaging and email systems — Microsoft Teams, Slack, Zoom, Exchange/Outlook with S/MIME, Google Workspace — the organization controls the root of trust end-to-end:

- **IdP-based systems (Teams, Slack, Zoom):** An IdP administrator can generate tokens asserting any identity in the tenant. There is no cryptographic artifact in a sent message that ties it to the sender's specific device key rather than to their organizational identity as asserted by the IdP. The organization can produce messages attributed to any user.
- **Enterprise S/MIME:** Standard enterprise deployment involves the CA generating the keypair and holding a copy in key escrow. The CA has the private key. The organization can sign messages as any user whose keypair it escrowed.
- **Exchange mailboxes:** `SendAs` and `FullAccess` permissions are a normal administrative operation. No cryptographic barrier prevents an Exchange admin from sending mail as any user in the tenant.

In all of these systems, impersonation by the organization leaves no mandatory cryptographic trace in the messages themselves.

#### 13.7.2 The Agora Architecture

Agora separates the identity namespace from the signing key material at a structural level:

- **DID document (org-controlled):** The organization controls `did:web:{orgDomain}:users:{id}` — it can add, remove, and update key entries in the document (§2.5). This is the identity namespace.
- **Private key material (device-controlled):** Ed25519 signing keys are generated inside the device's secure enclave and never leave it (§13.6). The DID document contains only the public key. The organization receives no copy of the private key at any point — there is no enrollment flow that transmits private key material to the provisioning service (§2.5.4).
- **Per-message signing:** Every Agora message is signed by the sender's device key. The signing key fingerprint is embedded in the message's MLS authenticated data — it is bound to the ciphertext and cannot be altered without invalidating the message's authentication tag.

Consequence: **the organization cannot sign a message as Alice without access to Alice's private key, which it does not have.** The DID document update authority (org-controlled) and the signing authority (device-controlled) are held by different parties and involve different, non-interchangeable key material.

#### 13.7.3 The Residual Organizational Capability

The organization retains one path to producing a message attributable to Alice's DID: it can register a new device key via the admin enrollment path (§2.5.8, helpdesk recovery) and sign messages with that key. This operation:

1. **Creates a new DID document entry** with a distinct `deviceKeyFingerprint` and registration timestamp, different from Alice's existing device entries.
2. **Is recorded in the provisioning audit log** (§2.5.5).
3. **Is detectable** by any party that compares the signing key fingerprint in a message against the DID document entry that was active at the time of message creation.

This is materially stronger than conventional systems. Silent impersonation — producing a message indistinguishable from one Alice sent herself — is not possible. Detectable impersonation — registering a new device key under Alice's DID — requires a logged admin action and produces a cryptographic artifact that auditors and Alice herself can inspect.

Implementations SHOULD surface device registration events to the DID subject (Alice) via out-of-band notification (email, push) at the time of admin-initiated registration. This converts a detectable-in-principle property into a detectable-in-practice one.

#### 13.7.4 Non-Repudiation for Compliance

The combination of per-message device-key signatures and a tamper-evident IPLD compliance archive (§17) provides non-repudiation stronger than email with DKIM or S/MIME in typical enterprise deployment:

- **DKIM** authenticates the sending domain, not the individual sender. An admin with access to the DKIM private key can sign mail on behalf of any address at that domain.
- **Enterprise S/MIME** with key escrow allows the key custodian (typically the organization) to produce valid signatures for any escrowed identity.
- **Agora device-key signatures** can only be produced by the specific hardware device that holds the private key. The compliance archive records both the message content and the signing key fingerprint. A regulator or court can verify that a specific message was produced by a specific device key, and can cross-reference that key's registration in the DID document's audit history.

This property is relevant for FINRA Rule 17a-4, SEC Rule 17a-4, and MiFID II recordkeeping requirements, where the integrity and authenticity of retained communications are material.

---

## 14. JSON-LD Context and Canonicalization

The canonical Agora JSON-LD context is published at:

```
https://agora.protocol/ns/v1
```

It maps all Agora message types and properties to globally unique IRIs and declares their relationship to relevant external vocabularies (schema.org, W3C DID Core, ActivityStreams where applicable).

All Agora messages MUST include `"@context": "https://agora.protocol/ns/v1"` or an equivalent inline context. Processors that do not perform full JSON-LD expansion MAY treat the context URL as a version tag, but MUST NOT reject messages that include additional `@context` entries for extension vocabularies.

The context URL is versioned: `/ns/v1` is the v1 schema. A breaking change to the type system produces `/ns/v2`. The context URL is frozen once published — `/ns/v1` will always describe the v1 schema without modification.

### 14.1 Canonicalization and Signing Pipeline

All signatures over JSON-LD documents in this specification use the following normative pipeline:

1. **Expand** the document using the Agora JSON-LD context, resolving all terms to absolute IRIs. Use a strict JSON-LD 1.1 processor. Unknown terms MUST be dropped during expansion, not passed through.
2. **Serialize** the expanded document to RDF N-Quads (one quad per line, no trailing blank line).
3. **Canonicalize** the N-Quads dataset using **URDNA2015** (W3C RDF Dataset Normalization Algorithm). This deterministically renames blank nodes and sorts quads, producing a stable byte string regardless of input key ordering or whitespace.
4. **Hash** the canonical N-Quads byte string with **SHA-256**, producing a 32-byte digest.
5. **Sign** the digest with **Ed25519** using the signer's authentication key. The signature is 64 bytes (RFC 8032).

The resulting signature is encoded as **base64url** (no padding) and placed in the document's `proof.signatureValue` field (W3C Data Integrity Proofs format), or carried out-of-band in the enclosing envelope depending on context.

This pipeline is identical to **W3C Data Integrity Proofs** with the `eddsa-rdna-2022` cryptosuite, which is the signing layer used by the W3C Verifiable Credentials ecosystem. Implementations SHOULD use an existing conformant library rather than implementing the pipeline from scratch.

**Reference implementations:**
- TypeScript/JS: [`jsonld`](https://github.com/digitalbazaar/jsonld.js) + [`rdf-canonize`](https://github.com/digitalbazaar/rdf-canonize) (Digital Bazaar — the W3C reference implementations)
- Go: [`go-jsonld-signatures`](https://github.com/go-jsonld-signatures) or FFI binding to the above for correctness during initial development
- Rust: [`json-ld` crate](https://crates.io/crates/json-ld) + [`rdf-types`](https://crates.io/crates/rdf-types) + [`ssi` crate (Spruce Systems)](https://github.com/spruceid/ssi)

**Test vectors:** The Agora repository MUST include a `test-vectors/canonicalization/` directory containing at minimum: (a) five representative Agora document types in their pre-signing JSON-LD form, (b) the expected N-Quads output after expansion and URDNA2015 normalization, and (c) the expected SHA-256 digest. Implementations MUST pass all test vectors before signing or verification code is considered conformant.

### 14.2 Context Document Caching

Because URDNA2015 requires a JSON-LD expansion step, implementations need access to the context document at `https://agora.protocol/ns/v1`. Fetching this document over the network at signing or verification time is unacceptable for latency and offline operation.

Implementations MUST cache the context document locally. The canonical context document for each published version is pinned by its SHA-256 hash, which is included in this specification and in the Agora repository. Implementations MUST verify the cached document against the pinned hash before use.

Implementations MUST NOT fetch the context document from the network during signature verification of an untrusted message — this is a denial-of-service vector (an adversary could stall verification by making the context URL slow or unreachable). The context document MUST be loaded from the local cache only.

---

## 15. Extension Points

The protocol is designed to be extended without breaking existing clients:

- Unknown `@type` values in inner payloads MUST be ignored by clients that do not understand them (forward compatibility).
- Space state documents MAY include extension fields prefixed with a registered namespace.
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

**Reference specifications:** `draft-ietf-mimi-arch-02` (MIMI architecture, expired), `draft-ietf-mimi-content-08` (content format, active), `draft-ietf-mimi-protocol-05` (delivery service protocol, expired).

#### Shared MLS Group

In MIMI interop mode, a single MLS group spans both Agora and the MIMI-compliant peer system. Members from both systems hold leaves in the same MLS tree and share the same epoch secrets. There is no re-encryption at the boundary. A message sent by an Agora client is decryptable by a MIMI client using its own MLS implementation, and vice versa.

This requires that both systems use compatible MLS ciphersuites. Agora MUST support `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (ciphersuite 0x0001, the MIMI-mandated baseline) in addition to any other suites it implements. Channels operating in MIMI interop mode MUST use this ciphersuite.

#### Identity Mapping

Agora users are identified by DID (`did:key` or `did:web`). MIMI defines its own identifier scheme: MIMI URIs of the form `mimi://provider/user-id`. This is a bespoke URI scheme minted by the MIMI WG rather than an adoption of any existing identity standard. It is functionally equivalent to `did:web` — a domain-scoped opaque user identifier with no standardized resolution mechanism beyond DNS — but is a distinct namespace with no interoperability with DID resolvers or any other identity infrastructure.

The consequence for Agora is that MIMI interop requires carrying two parallel identifiers for every user in a cross-system MLS group: the Agora DID (which has a resolution spec, a key material binding, and is used for all Agora-internal operations) and the MIMI URI (which the MIMI delivery service requires to route messages and manage room membership). There is no way to derive one from the other or collapse them into a single identifier without either Agora abandoning DIDs or MIMI adopting them.

Each leaf node's credential in a MIMI-interop MLS group therefore carries both:

```json
{
  "@type": "AgoraMIMICredential",
  "did": "did:key:z6Mk...",
  "mimiURI": "mimi://example.com/alice",
  "sig": "base64url..."
}
```

The credential is signed by the Agora authentication key. Agora clients verify the DID and signature. MIMI clients verify the MIMI URI portion and MUST treat the `did` field as an unknown extension — the `draft-ietf-mimi-content` spec does not explicitly specify that unknown credential fields are to be ignored rather than rejected, which is a known interoperability risk. Agora implementations SHOULD monitor MIMI client behavior for strict credential validation that rejects unknown fields; if this occurs in practice, the fallback is to strip the `did` field from credentials presented to MIMI clients and maintain a side-channel mapping from MIMI URI to Agora DID in the relay's session state.

For display purposes, neither side needs to parse the other's identifier format — MIMI URIs are rendered as opaque display strings in Agora clients, and Agora DIDs are rendered as opaque display strings in MIMI clients.

#### Content Format

Agora inner payloads use JSON-LD (`@type: ChatMessage` etc.). MIMI defines its own content format (`draft-ietf-mimi-content-08`). A channel in MIMI interop mode MUST negotiate a shared content format. Two modes are supported:

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
  "mimiSpecVersion": "draft-ietf-mimi-content-08"
}
```

#### Delivery Service Bridging

MIMI defines a delivery service protocol (`draft-ietf-mimi-protocol-05`) for cross-provider message routing. In MIMI interop mode, Agora Relays act as MIMI delivery service endpoints for their served channels. MLS Commits and Welcome messages are exchanged between Agora Relays and MIMI provider infrastructure via the MIMI delivery protocol. Gossipsub fanout handles Agora-side delivery; the MIMI protocol handles the cross-provider leg.

The Agora Relay serving a MIMI-interop channel registers itself as the MIMI delivery service endpoint for that channel's MLS group with the MIMI provider. MLS handshake messages (Proposals, Commits, KeyPackages) flow bidirectionally between the two delivery services.

#### Limitations

MIMI interop is currently limited by the MIMI specification's own draft status. As of April 2026, the content format (`draft-ietf-mimi-content-08`) is active; the architecture (`draft-ietf-mimi-arch-02`) and delivery service protocol (`draft-ietf-mimi-protocol-05`) drafts have both expired without replacement, indicating the WG is stalled on the delivery layer. The MLS WG's own federation draft (`draft-ietf-mls-federation-03`, expired September 2023) was also abandoned without a successor; cross-system MLS federation has no active IETF standardization track as of this writing. Agora implementations SHOULD track the MIMI drafts and update their interop implementation as the specs stabilize. Channel state documents carrying `mimiInterop` configurations MUST include a `mimiSpecVersion` field to allow clients to detect and handle version skew.

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
3. Gateway encrypts the payload using its MLS group membership.
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

**Reference implementations:** [`mautrix-go`](https://github.com/mautrix/go) and [`mautrix-python`](https://github.com/mautrix/python) provide the application service scaffolding.

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

Organizations in regulated industries (financial services, healthcare, legal, government) are subject to message retention and audit requirements that conflict with the default Agora model of E2EE with relay-opaque content. Agora supports compliance logging as an **optional, space-level feature** that satisfies these requirements without architectural kludges.

Mechanically, compliance logging is implemented as a **passive member** (§6.1.3) — a `ComplianceLogger` principal — that silently receives and archives all messages in every MLS group it is admitted to. This applies to Space channels (§9) and Direct Message groups (§9.6) alike. It is structurally identical to a gateway (§16.2) but treated differently at the protocol and UI layers:

- It does not appear as a chat participant in client UI.
- It does not generate join/leave events in the message stream.
- Its presence is disclosed in space metadata and MLS group membership, but not in the message feed.
- It is added to channels automatically when logging is enabled, without requiring per-channel Admin action.

The result is compliant message capture that is cryptographically sound and tamper-evident, without a "Logger Bot joined #engineering" message appearing in every channel.

### 17.2 Enabling Compliance Logging

Compliance logging is enabled in the Space state document by the space owner:

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

The `scope` field governs which Space channels receive the logger. The value `"all-channels"` causes the logger to be added to every channel in the Space, including channels created after compliance logging is enabled. A glob list (e.g., `["engineering/*", "legal/*"]`) limits logging to matching channel paths.

`scope` does **not** govern DM groups. DM group compliance logging is governed entirely by §17.8, which imposes an obligation on the regulated member's user agent independent of Space channel scope configuration.

Once `complianceLogging.enabled` is set to `true` and gossiped to the space topic, conformant clients MUST add the `loggerDID` to the MLS group of every channel matching `scope` on the next available Commit. This addition IS recorded in the MLS group membership (verifiable by any MLS-aware client) but MUST NOT produce a UI-visible join notification.

Disabling compliance logging requires a signed Space state mutation by the space owner. Clients remove the logger DID from channel MLS groups via Remove commits. The `complianceLogging` history in the IPLD space state chain retains a permanent record of when logging was enabled and disabled.

### 17.3 Logger Principal

The `ComplianceLogger` is a DID-identified principal operated by the space's compliance infrastructure — typically an on-premise archival system or a regulated third-party compliance service (e.g., a FINRA-registered archiving vendor).

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

`regulatoryFramework` is an informational array of the regulatory requirements under which the logger operates. Clients MAY display this to members who inspect the space's compliance configuration.

The logger operates as a passive member (§6.1.3). It holds leaf credentials, participates in epoch ratchets, and receives `Welcome` messages when added to new channel groups. It does not send messages, publish presence events, generate typing indicators, or issue Commits or Proposals.

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

The log is organized as a per-channel IPLD DAG, with a space-level index mapping channel CIDs to their respective log chain heads.

### 17.5 Ephemeral Message and Expiry Handling

Ephemeral messages (`TypingEvent`, `PresenceEvent`) are never logged — they are excluded by type at the logger.

Messages with an `expiry` field present a deliberate tension: the sender expressed an intent for the message to be deleted, but the compliance obligation may override that intent. The resolution is explicit and must be disclosed:

- If `complianceLogging.enabled` is `true`, message expiry is honored for relay caches and client display, but the compliance logger retains the plaintext for `retentionDays` regardless of the sender's `expiry` value. This applies equally in DM groups where a compliance logger is present under §17.8 — the DM group member's expiry preference is honored in relay caches and client display, but the compliance logger retains the plaintext for the regulated member's `retentionDays` regardless.
- The Space state document MUST include a human-readable `retentionNotice` field when compliance logging is enabled:

```json
"retentionNotice": "This space is subject to regulatory message retention. Messages are archived for 2555 days regardless of expiry settings."
```

- Clients MUST display this notice to members when they first join a compliance-logging-enabled space, and MUST make it accessible from the space's information panel at any time.

This is the correct behavior for a regulated environment. The sender's expiry preference is preserved in the client and relay layers; the compliance layer overrides it with explicit disclosure.

### 17.6 Voice and Video Compliance Logging

VTC compliance recording is governed by the `RecordingGrant` mechanism and the `VTCComplianceConfig` space configuration, both fully specified in §10.12.

**Relationship to text compliance logging.** Text compliance logging (§17.1–§17.5) and VTC compliance recording (§10.12) are parallel mechanisms operating over the same MLS group. They are separately authorized and separately archived, but both feed into the same space IPLD compliance audit chain. A space with both `complianceLogging.enabled: true` and `vtcCompliance.enabled: true` captures the complete communication record — text, reactions, edits, deletions, and voice/video — in a unified, tamper-evident audit chain.

**Scope.** §17.1–§17.5 cover: text messages in space channels, reactions, edit events, delete events, file attachments, and DM text messages for regulated members (§17.8). §10.12 covers: audio and video media streams in space voice channels and DM voice groups for regulated members (§10.12.7).

**Same logger DID or separate.** The `complianceLogging.loggerDID` and `vtcCompliance.recorderDID` MAY be the same DID or different DIDs. Using the same DID is operationally simpler but requires the compliance principal to support both text archiving (passive member, §6.1.3) and VTC recording (HPKE key receipt and media decryption). Using separate DIDs allows specialist infrastructure for each function. Either configuration is conformant.

**`retentionDays` alignment.** The `vtcCompliance.retentionDays` SHOULD match `complianceLogging.retentionDays` to avoid a regulatory gap where text records are retained longer than corresponding voice records of the same conversation. If they differ, the longer value governs the overall retention obligation for the channel.

### 17.7 Member Disclosure

Compliance logging is not hidden from members. It is disclosed in space metadata and MLS group membership (which is visible to any technically capable member). Conformant clients MUST:

- Display a compliance logging indicator in the space information panel when `complianceLogging.enabled` is `true`.
- Display the `retentionNotice` to new members on first join.
- Allow members to inspect the full `ComplianceLoggingConfig` including `loggerDID`, `loggerLabel`, `retentionDays`, and `regulatoryFramework` from the space settings UI.
- NOT display a join/leave notification in any channel's message feed when the logger DID is added or removed from an MLS group.

The logger's MLS group membership is visible to any client that inspects raw MLS group state. This is intentional — the logger is not cryptographically hidden, only UI-silent. A technically capable member can always verify that a compliance logger is present.

In DM groups where a compliance logger is present under §17.8, disclosure obligations are governed by §17.8.4 rather than this section. The Space information panel disclosure requirements in this section apply only to Space channels.

### 17.8 Compliance Logging for Direct Message Groups

#### 17.8.1 Obligation

A Space member subject to compliance logging (i.e., a member of a Space where `complianceLogging.enabled` is `true`) carries that compliance obligation into every DM group they participate in, regardless of whether the DM group has any Space affiliation.

The compliance obligation follows the regulated user, not the channel. A regulated user who conducts business communication via DM is not exempt from their Space's retention requirements by virtue of using a DM group rather than a Space channel.

A conformant client for a regulated Space member MUST:

1. Add the Space's `loggerDID` to the MLS group of every DM group the regulated member creates or joins, prior to sending or receiving any application messages in that group.
2. Re-add the logger if it is removed by another member (see §17.8.3).
3. Notify all other DM group members of the logger's presence before their first message is sent (see §17.8.4).

The client MUST NOT permit the regulated member to send any application message in a DM group until the compliance logger has been admitted to the MLS group and the disclosure notice has been displayed to all members.

#### 17.8.2 MLS Mechanics

Logger addition in a DM group follows the standard MLS Add + Commit path:

1. The regulated member's client fetches a fresh `KeyPackage` for the Space's `loggerDID` from the logger's relay inbox or a published KeyPackage store.
2. The client issues an MLS Add Proposal for the logger DID.
3. The client immediately commits the proposal (no consent threshold applies to compliance logger additions — the regulated member's obligation is unilateral and does not require co-member approval).
4. The client updates the `DMGroupDescriptor` to add the logger DID to the `complianceLoggers` array and publishes the updated descriptor CID.
5. The logger's infrastructure issues a `Welcome` response, completing the logger's admission to the MLS group.

If the regulated member is joining an existing DM group (rather than creating one), steps 2–5 are performed at join time, before the member sends any application messages. Messages sent by other members before the regulated member joined are not retroactively accessible to the logger — the logger's archive begins at the MLS epoch of its admission.

**KeyPackage availability:** The logger's DID document MUST publish a `KeyPackageEndpoint` service entry so that client user agents can fetch fresh KeyPackages programmatically:

```json
{
  "id": "did:key:z6MkLogger...#keypackages",
  "type": "AgoraKeyPackageEndpoint",
  "serviceEndpoint": "https://archive.acme-corp.internal/v1/agora/keypackages"
}
```

The endpoint MUST return a fresh, unused `KeyPackage` on each GET request. Reusing KeyPackages breaks MLS forward secrecy guarantees and is a conformance violation.

#### 17.8.3 Logger Removal Prohibition

Once a compliance logger has been admitted to a DM group by a regulated member, no member — including the regulated member — MAY issue an MLS Remove commit for the logger DID for the duration of the regulatory retention period.

A conformant client for a regulated Space member MUST:

- Refuse to commit an MLS Remove proposal targeting the Space's `loggerDID`.
- On receiving a committed Remove for the Space's `loggerDID` (issued by another DM group member), immediately re-add the logger via the §17.8.2 procedure and notify the regulated member's Space admin of the removal attempt. The re-add creates a new MLS epoch; messages in the epoch between removal and re-add are not captured by the logger. The Space admin MUST be notified so they can assess the compliance gap.

This prohibition is enforced by the regulated member's client. It cannot be enforced protocol-wide — a non-regulated member's client can issue a Remove. The regulated member's client is responsible for detecting and remedying the gap.

DS-level enforcement (§17.8.9) strengthens this guarantee at group creation but does not prevent subsequent logger removal by other group members. The gap between removal and re-add represents a period of non-capture; its duration depends on how quickly the regulated member's client detects the removal event.

#### 17.8.4 Disclosure to DM Group Members

Before any regulated member sends a message in a DM group with a compliance logger present, their client MUST display a disclosure notice to all DM group members. The notice MUST be delivered as a system message visible to all current group members before the first application message in the epoch where the logger is admitted:

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "ComplianceDisclosureNotice",
  "dmGroupID": "urn:agora:dmgroup:<uuid>",
  "loggerDID": "did:key:z6MkLogger...",
  "loggerLabel": "Acme Corp Compliance Archive",
  "retentionDays": 2555,
  "regulatoryFramework": ["FINRA 17a-4", "SEC 17a-4"],
  "issuedBy": "did:key:z6MkRegulatedMember...",
  "ts": "2026-03-12T00:00:00Z",
  "sig": "base64url..."
}
```

The disclosure notice is an MLS application message of type `ComplianceDisclosureNotice` sent in the same epoch as the logger's admission commit, prior to any other application messages. Clients MUST render it as a visible system notification — not a suppressable status line — with wording equivalent to:

> **[Display name of regulated member]'s messages in this conversation are subject to regulatory retention by [loggerLabel] for [retentionDays] days.**

Non-regulated members have no obligation to remain in the DM group after disclosure. They MAY leave the group (via standard MLS Remove self-proposal) at any time. Their messages prior to their departure remain in the compliance logger's archive for the regulated member's retention period.

#### 17.8.5 Multiple Regulated Members in a Single DM Group

If a DM group contains members from two or more compliance-logging Spaces, each regulated member's client MUST add their respective Space's logger DID to the group. The group may have multiple compliance logger DIDs present simultaneously.

Each logger receives the full message stream from its admission epoch forward, regardless of which regulated member's messages it was originally added to capture. A logger from Space A captures messages from Space B members and vice versa — the MLS group membership does not discriminate by sender. This is the correct behavior: both Spaces have independent retention obligations that apply to their respective regulated members' participation in the conversation.

The `complianceLoggers` array in the `DMGroupDescriptor` lists all admitted logger DIDs. Each regulated member's client MUST verify on group join that their Space's logger DID is present in this array, and add it if absent.

#### 17.8.6 Cross-Space DM: Regulated Member with Non-Space Participant

A DM group between a regulated Space member and a participant who has no Space affiliation (or a Space without compliance logging) is treated identically to §17.8.4. The non-space participant receives the same disclosure notice. The compliance obligation applies to the regulated member's participation regardless of the counterparty's affiliation.

#### 17.8.7 Offline and Deferred Join Scenarios

If a regulated member is offline when added to a DM group by another member, the compliance logger addition and disclosure notice MUST be performed by the regulated member's client when they next come online and process the pending MLS Welcome, before their client sends any application messages in the group.

Clients MUST queue the logger addition and disclosure as the first operations to perform on a pending DM group join, ahead of any queued outbound messages. If the client has queued outbound messages (e.g., drafted while offline), those messages MUST NOT be sent until the logger admission commit has been completed and acknowledged.

#### 17.8.8 Audit Trail

The regulated member's Space MUST record each DM group compliance logger admission in its IPLD compliance audit chain. The audit record is a `DMComplianceAuditEntry`:

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "DMComplianceAuditEntry",
  "dmGroupID": "urn:agora:dmgroup:<uuid>",
  "dmGroupDescriptorCID": "bafyrei...",
  "loggerDID": "did:key:z6MkLogger...",
  "admittedBy": "did:key:z6MkRegulatedMember...",
  "admittedAt": "2026-03-12T00:00:00Z",
  "removalAttempts": [],
  "sig": "base64url..."
}
```

`removalAttempts` is an array of timestamps and initiator DIDs for any Remove commits targeting the logger that the regulated member's client detected and remedied per §17.8.3. This gives the Space admin and compliance officer a complete record of logger presence in DM groups, including any attempted circumvention.

#### 17.8.9 DS-Level Enforcement (Recommended)

Client-side enforcement (§17.8.1–§17.8.2) depends on the regulated member's client being conformant. Two DS-level mechanisms provide enforcement independent of client behavior. **Mechanism B (External Commit) is preferred.**

**Note on relay metadata.** The relay already routes `Welcome` messages to recipient inboxes and therefore already knows which user DIDs are participating in any new group — this is an inherent property of operating as both KDS and DS. DS enforcement does not expose new metadata to the relay; it acts on metadata the relay already holds as part of normal routing.

##### Mechanism A: Welcome Inspection at Group Creation

When the relay receives the initial `Welcome` bundle for a new DM group:

1. The relay maps each `KeyPackageRef` in the `Welcome` envelope to a DID using its KDS index (the relay holds this mapping because it serves as the Key Distribution Service and issued or cached the `KeyPackage` when it was published).
2. If any recipient DID is a regulated member of a compliance-logging Space, the relay verifies the Space's `loggerDID` is also present in the `KeyPackageRef` list.
3. If the `loggerDID` is absent, the relay rejects the group creation with error `COMPLIANCE_LOGGER_REQUIRED` and does not route the `Welcome` to any recipient.

The client must still fetch the logger's `KeyPackage` and include it (steps 1–4 of §17.8.2). What Mechanism A adds is that the relay catches a client that failed to do so — the group simply cannot be created without the logger.

**Coverage: group creation only.** When a regulated member *joins* an existing DM group rather than creating one, there is no new group creation event for the relay to intercept. Client-side enforcement (§17.8.2) applies to the join case under Mechanism A.

**Coupling requirement.** This mechanism requires the relay to operate as both KDS and DS with shared KPRef→DID state. In deployments where KDS and DS are separate infrastructure components, an authenticated query path from DS to KDS is required.

##### Mechanism B: Compliance Logger External Commit (Preferred)

RFC 9420 §11.2.1 defines External Commits: a mechanism by which a new member joins an existing group using the group's `GroupInfo`, without being added by any current member. Because the relay already holds `GroupInfo` for every active group (required for standard group joins), the compliance logger infrastructure can self-join any DM group involving a regulated user with no client involvement.

**Procedure:**

1. The relay creates the new DM group normally, accepting the `Welcome` and routing it to invited members.
2. Before delivering any application messages for the group, the relay checks whether any member DID is a regulated member of a compliance-logging Space.
3. If yes, the relay enters **compliance hold**: application messages for this group are accepted and stored but not delivered until the logger has joined.
4. The relay notifies the compliance logger infrastructure via an authenticated internal event, providing the group's `GroupInfo`.
5. The logger performs an External Commit, joining the group as a passive member (§6.1.3).
6. The relay releases held messages; normal delivery resumes.

The client does not fetch the logger's `KeyPackage`, does not issue the Add commit, and cannot prevent logger admission. This mechanism is independent of client software version and configuration.

**Coverage: creation and join.** The relay applies the same compliance hold procedure when it detects a regulated member joining an existing group (by inspecting the Commit that adds them), not only at group creation.

**Hold timeout.** The relay MUST apply a compliance hold timeout (recommended: 5 seconds; configurable per Space). If the logger does not complete its External Commit within the timeout, the relay MUST NOT release held messages. It MUST surface an alert to the Space admin and compliance officer. The DM group remains in compliance hold until the logger joins or the Space admin takes remedial action. Silent timeout-and-release is a conformance violation.

**Availability: last-resort KeyPackages.** A compliance logger MUST pre-publish a set of last-resort `KeyPackage`s with the relay (per §6.1.3 passive member guidance) so that External Commits can be completed promptly without a live round-trip to the logger's `KeyPackageEndpoint`. The relay SHOULD alert the compliance operator when the last-resort set falls below a configurable threshold. If no `KeyPackage`s are available when a compliance hold fires and the timeout expires, this is a compliance outage that MUST be reported — not a silent capture gap.

**Removal gap.** Neither Mechanism A nor Mechanism B prevents a non-regulated group member from issuing an MLS `Remove` for the logger after admission. The regulated member's client remains responsible for detecting and remedying that removal (§17.8.3). The gap between removal and re-add is an inherent limitation of the current MLS group management model; future DS extension mechanisms may address per-commit enforcement.

#### §17.8 Conformance Summary

The following table summarizes the conformance requirements for DM group compliance logging:

| Requirement | Applies To | MUST / SHOULD |
|---|---|---|
| Add Space `loggerDID` to DM group before first message | Regulated member's client | MUST |
| Fetch fresh KeyPackage per logger addition | Regulated member's client | MUST |
| Display `ComplianceDisclosureNotice` to all DM members before first message | Regulated member's client | MUST |
| Re-add logger if removed by another member | Regulated member's client | MUST |
| Notify Space admin of logger removal attempt | Regulated member's client | MUST |
| Queue logger addition before queued outbound messages on deferred join | Regulated member's client | MUST |
| Publish `DMComplianceAuditEntry` to Space IPLD chain | Regulated member's client | MUST |
| Publish `KeyPackageEndpoint` in logger DID document | Compliance logger operator | MUST |
| Provide fresh (non-reused) KeyPackage per request | Compliance logger operator | MUST |
| Enforce logger inclusion via Welcome inspection at group creation (Mechanism A) | Relay operator (regulated deployment) | SHOULD |
| Enforce logger inclusion via External Commit with compliance hold (Mechanism B, preferred) | Relay operator (regulated deployment) | SHOULD |
| Use DM group for persistent named multi-party private conversation | Any user | SHOULD use private channel instead |


---

## 18. Cross-Space Channel Sharing

### 18.1 Overview

A channel MAY be shared across Space boundaries, giving members of multiple Spaces access to the same message stream, history, and MLS group. From any member's perspective in either Space, the shared channel appears as a normal channel in their sidebar — there is no visible workspace transition or foreign-context indicator.

Agora channel sharing is structurally simpler than analogous features in centralized systems (like Slack Connect) because channels are already identified by content-addressed CID rather than opaque server-internal IDs. A channel shared between Space A and Space B is the same MLS group, the same IPLD history DAG, and the same `channelToken` — there is no synchronization problem because there is no duplication.

### 18.2 Home Space and Guest Spaces

Every shared channel has exactly one **home space** — the Space whose namespace contains the channel's canonical path and whose admin is responsible for channel state mutations. There MAY be one or more **guest spaces** whose members access the channel via a local alias path.

The home/guest distinction governs:
- Namespace ownership (home space owns the path)
- Channel state mutations (home space admin signs them)
- Compliance logging (home space's configuration applies to all members, including guests)
- Channel deletion (only the home space owner can delete)

Guest space members have full read/write access to the channel's message stream, subject to the roles negotiated in the `ChannelShareAgreement` (§18.3). They are first-class MLS group members — not observers or read-only participants unless the agreement specifies otherwise.

### 18.3 Channel Share Agreement

Sharing a channel requires bilateral authorization: the home space admin and the guest space admin both sign a `ChannelShareAgreement`. Neither side can unilaterally impose sharing on the other.

```json
{
  "@context": "https://agora.protocol/ns/v1",
  "@type": "ChannelShareAgreement",
  "schemaVersion": "1",
  "id": "urn:agora:csa:bafyrei...",
  "homeSpace": "agora://bafyrei.../",
  "homeChannel": "agora://bafyrei.../engineering/backend",
  "guestSpace": "agora://bafyxyz.../",
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

`guestAlias` is the channel path under which the shared channel appears in the guest space's sidebar. It is a local display alias only — the channel's canonical identity remains `homeChannel`. `guestRoles` is the list of guest space roles whose members are eligible for admission. `guestPermissions` defines the capability constraints applied to guest space members in this channel, independently of their role in their own space.

The agreement is stored as an IPLD node, CID-referenced from both space state documents, and gossiped on both `v1/agora/space/<homeSpaceCID>` and `v1/agora/space/<guestSpaceCID>`.

### 18.4 Member Admission

When a `ChannelShareAgreement` is established and gossiped, conformant clients from the guest space whose roles match `guestRoles` are eligible to join the shared channel's MLS group. Admission follows the standard MLS Add flow, initiated either by:

- A home space admin issuing a Welcome to the guest member directly, or
- A guest space admin issuing a bulk Welcome on behalf of all eligible members (this requires that the guest admin is themselves already an MLS group member, admitted by the home space admin as part of agreement setup).

The recommended flow is: home space admin admits the guest space admin first; guest space admin then admits their eligible members. This distributes the Commit workload and avoids requiring the home admin to manage foreign space membership individually.

Guest members appear in the channel participant list with a visual indicator of their home space (a space icon or badge), distinguishable from home space members. Clients SHOULD display the member's display name from their own space's profile, with the foreign space indicator making affiliation clear.

### 18.5 Namespace Resolution

A guest space member sees the channel at `guestAlias` in their space sidebar. Internally, the client resolves this alias to the home channel's CID and connects to the home channel's MLS group and gossip topic. The alias is purely a display and navigation convenience — all protocol operations (message send, history fetch, MLS operations) use the home channel's identity.

The guest space's state document records the alias mapping:

```json
"sharedChannels": [
  {
    "@type": "SharedChannelAlias",
    "aliasPath": "shared/wolfssl-backend",
    "homeChannelCID": "bafyrei...",
    "agreementCID": "bafyrei...",
    "homeSpaceCID": "bafyrei..."
  }
]
```

Clients resolve `guestAlias` → `homeChannelCID` before any protocol operation. If the agreement is revoked (§18.7), the alias entry is removed from the guest space state and clients remove the channel from their sidebar on next state refresh.

### 18.6 Relay Coordination

The home channel's gossip topic (`v1/agora/channel/<channelToken>`) is where all messages flow. Guest space members subscribe to this topic via their own Relays. For this to work, the guest space's Relays must be peered with (or able to reach) the home channel's Relays.

No special Relay configuration is required if both spaces' Relays participate in the same gossipsub mesh — this is the common case for public or semi-public spaces. For private spaces whose Relays are isolated (e.g., on a private Tailscale overlay), explicit Relay peering must be established between the home and guest space operators. The `ChannelShareAgreement` MAY include a `relayHints` array suggesting peering endpoints:

```json
"relayHints": [
  "wss://relay.home-space.example.com",
  "wss://relay.guest-space.example.com"
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
  "revokedBySpace": "agora://bafyrei.../",
  "reason": "partnership-ended",
  "ts": "2026-03-12T00:00:00Z",
  "sig": "base64url..."
}
```

On revocation:

1. The revoking admin issues MLS Remove commits for all members of the foreign space from the channel's MLS group.
2. The alias entry is removed from the guest space's state document.
3. The `ChannelShareRevocation` is gossiped on both space topics and stored in both space IPLD state chains.
4. Clients of the guest space remove the channel from their sidebar on next state refresh.
5. Guest space members lose the ability to decrypt new messages immediately (the MLS epoch advances on the Remove commits); they retain locally cached history up to the revocation epoch.

Either admin may revoke unilaterally; the counter-party does not need to co-sign the revocation.

### 18.8 Compliance Logging Across Space Boundaries

The home space's compliance logging configuration (§17) applies to all messages in the shared channel regardless of the sender's space affiliation. A guest space member sending a message in a compliance-logged shared channel has that message captured by the home space's compliance logger.

Guest space members MUST be notified of this at channel join time. The client displays the home space's `retentionNotice` to guest members on first entry to the shared channel, clearly attributing it to the home space:

> "This channel is hosted by [Home Space Name] and is subject to their message retention policy: [retentionNotice text]"

If the guest space also has compliance logging enabled, its logger MAY also be added to the shared channel's MLS group, subject to home space admin approval (an additional MLS Add commit is required). Both loggers may simultaneously hold membership. The home space admin MAY reject a guest space's compliance logger by declining to issue a Welcome; in that case the guest space admin is responsible for any resulting regulatory non-compliance on their side.

### 18.9 Voice Channel Sharing

Voice channels MAY be shared using the same `ChannelShareAgreement` mechanism. All VTC semantics (§10) apply unchanged — the shared voice channel has one MLS group, one set of call state gossip, and one SFU if configured. The SFU used is the home space's SFU (declared in the home space state document). Guest space members connect to the home space's SFU directly.

If the home space does not have an SFU configured and the shared voice channel exceeds the mesh threshold (§10.5), the home space admin is responsible for provisioning one. The `ChannelShareAgreement` MAY specify a minimum SFU capacity as a precondition for guest space participation.

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
| Payments | Cashu ecash, Lightning (BOLT12/BOLT11) | `cashu-ts` (JS), `nutshell` (Python), LDK/LND; see §12 |
| Payments (service agreements) | Lightning Network BOLT 12 | Core Lightning, LND |
| Spam deterrence (no payment) | Hashcash-style PoW | SHA-256 (standard library) |
| Native cross-system interop | MIMI (drafts; delivery layer stalled as of 2026-04) | TBD (spec in progress) |
| Matrix gateway | Matrix Application Service API | `mautrix-go`, `mautrix-python` |
| Relay bootstrap DNS | DNS-SD / SRV / TXT records | Standard DNS libraries |
| JSON-LD canonicalization | URDNA2015 | `rdf-canonize` (JS), `ssi` (Rust) |

---

## Appendix B: Open Questions

1. **Cross-space identity and reputation** — there is currently no mechanism for carrying moderation history or reputation across Space boundaries. A user banned from one Space can freely join another. Whether this is a feature (clean-slate by design, prevents monoculture moderation) or a gap (enables bad actors to evade consequences) depends on use case. A voluntary cross-space reputation attestation format is worth considering as an optional extension.

2. **Push notification proxy conformance** — §8.7 specifies the push proxy protocol but does not define conformance requirements for proxy operators (logging policy, data retention, handle-to-token mapping security). A push proxy operator specification analogous to the Relay operator conformance requirements may be warranted for deployments where push proxy trust is a concern.

3. **Transport independence** — IP is the default transport for Agora relay communication, not an architectural requirement. Agora message envelopes are self-authenticating CBOR blobs: content-addressed, MLS-encrypted end-to-end, and verifiable by the recipient without trusting the carrier. A relay that receives a valid envelope over any medium can forward it into the gossipsub mesh; the carrier never has access to useful content and the recipient never has to trust the carrier. This is a first-class property of the design, not an edge case.

   Relay-to-relay synchronization can therefore occur over any medium that can carry bits:

   - **IP internet** — the default; WebTransport (QUIC) and WebSocket as specified
   - **Overlay networks** — WireGuard, Tailscale, Tor; already specified in §3.4
   - **LoRa / Meshtastic** — long-range low-bandwidth radio mesh; viable for text-scale message traffic in areas without IP infrastructure
   - **HF and packet radio** — AX.25, amateur packet networks; applicable for remote, maritime, and disaster deployments
   - **Sneakernet** — physical media (USB, hard drive); content-addressing provides automatic deduplication; a courier syncing two isolated relays daily is a legitimate and complete deployment
   - **Satellite store-and-forward** — non-IP satellite uplinks; batch upload/download on orbital pass
   - **Delay-Tolerant Networking (DTN)** — the Bundle Protocol (RFC 9171) is the IETF standard for store-carry-forward over high-latency or intermittently connected links; Agora envelopes are structurally compatible with DTN bundles and the protocol's tolerance for message reordering makes it a natural fit for deep-space, submarine, and other extreme-latency deployments
   - **Bluetooth mesh / WiFi Direct** — infrastructure-free short-range peer-to-peer
   - **SMS / GSM data** — CBOR envelopes encoded for narrow-band transport

   The practical implications include: disaster-resilient deployments that fall back to radio or mesh when IP infrastructure fails; censorship-resistant relay sync that continues over radio or physical courier when IP is interdicted; and space-capable deployments where relay sync occurs over high-latency deep-space links with the DTN Bundle Protocol as the carrier.

   Two application-layer extensions are specified for non-IP transport contexts: a native email transport profile (AETP; see the community-maintained extension registry) and a batch store-and-forward format for UUCP, rsync, sneakernet, HF radio, and similar carriers. Both apply to application messages only — MLS handshake messages (Welcome, Commit, Proposal) require ordered, timely delivery and MUST use the primary gossipsub path when available. Capability strings: `slow-transport-email-v1`, `slow-transport-batch-v1`.

---

*End of specification.*
