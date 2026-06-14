# Tool Specification: `agora-enroll`

**Version:** 0.1 Draft
**Depends On:** Agora Protocol Spec v0.1, `discord2agora` spec v0.1
**Status:** Pre-implementation design

---

## 1. Purpose

`agora-enroll` is the user-facing counterpart to `discord2agora`. It authenticates a user via Discord OAuth2, generates or recovers their Agora DID and device keypair, and registers that DID against their provisional member record in a target Space. The result is a fully-enrolled Agora identity ready for immediate use.

Two delivery targets are supported:

- **Browser app** (`enroll.agora.example.com` or self-hosted) — zero install, WebAuthn-primary, covers the majority of users.
- **CLI binary** (`agora-enroll`) — for operators, power users, and users who require explicit keystore control.

Both targets share the same backend protocol; the browser and CLI are different frontends to the same enrollment flow.

---

## 2. System Components

```
┌─────────────────────────────────────────────────────────────┐
│  User Device                                                │
│                                                             │
│  ┌──────────────────┐    ┌──────────────────────────────┐  │
│  │  Browser App     │    │  CLI Binary                  │  │
│  │  (WebCrypto /    │    │  (OS keychain / file /       │  │
│  │   WebAuthn)      │    │   PKCS#11)                   │  │
│  └────────┬─────────┘    └──────────────┬───────────────┘  │
│           │                             │                   │
└───────────┼─────────────────────────────┼───────────────────┘
            │  HTTPS                      │  HTTPS
            ▼                             ▼
┌─────────────────────────────────────────────────────────────┐
│  Enrollment Service  (operator-hosted)                      │
│                                                             │
│  - Discord OAuth2 callback handler                          │
│  - Provisional member registry (from discord2agora output)  │
│  - DID registration endpoint                                │
│  - Relay notification (MLS Add trigger)                     │
└────────────────────────┬────────────────────────────────────┘
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
        Discord API            Agora Relay
        (OAuth2)               (Space state,
                                MLS group)
```

The Enrollment Service is stateless beyond the provisional member list. It MUST NOT hold private keys or session state between requests (beyond a short-lived OAuth2 state token), and it MUST NOT have write access to the Relay beyond submitting signed MLS Add commits on behalf of the enrolling user.

---

## 3. Enrollment Flow

Both browser and CLI follow the same logical sequence:

1. **Discord OAuth2** — user authenticates with Discord; the tool obtains their Discord user ID.
2. **Lookup** — the tool queries the Enrollment Service to confirm the Discord user ID is in the provisional member list.
3. **Key operation** — the tool generates a new DID and keypair (create path) or loads an existing one (update path).
4. **Registration** — the tool POSTs the DID and a signed proof-of-possession to the Enrollment Service.
5. **MLS Add** — the Enrollment Service submits an MLS Add commit to the Relay for the new member.
6. **Keyfile export** — the tool produces the combined recovery keypair and state backup file for the user to save.
7. **Confirmation** — the tool displays the space URI and the user's DID.

---

## 4. Discord OAuth2

### 4.1 Scopes

```
identify
```

`identify` is the only required scope. The tool needs the user's Discord ID and username; it does not require email, space membership read, or any write permissions.

### 4.2 Browser Flow (PKCE)

Standard OAuth2 Authorization Code flow with PKCE. The browser app:

1. Generates a `code_verifier` (cryptographically random, 43–128 chars).
2. Derives `code_challenge = BASE64URL(SHA256(code_verifier))`.
3. Redirects to Discord's authorization endpoint with `response_type=code`, `code_challenge_method=S256`, and a short-lived `state` token stored in `sessionStorage`.
4. Discord redirects back to the enrollment app's callback URL with `code`.
5. The app exchanges `code` and `code_verifier` for an access token via the Enrollment Service backend (the client secret lives on the server, not in the browser).
6. The Enrollment Service returns only the Discord user ID and username to the browser; the access token stays server-side and is discarded after the `/users/@me` call.

The `state` token MUST be a 32-byte random value, base64url-encoded, stored in `sessionStorage`. It MUST be verified on callback and then deleted. It MUST NOT be stored in `localStorage` or a cookie.

### 4.3 CLI Flow (Loopback)

Standard OAuth2 loopback redirect (RFC 8252 §7.3):

1. The CLI binds a listener on `http://127.0.0.1:<random-port>/callback`.
2. The CLI opens the system browser to Discord's authorization endpoint with `redirect_uri=http://127.0.0.1:<port>/callback`.
3. Discord redirects to the loopback listener with `code`.
4. The CLI exchanges `code` for an access token directly (client ID only, no client secret — the CLI is a public client).
5. The CLI calls `/users/@me`, extracts Discord user ID and username, and discards the token.

Discord explicitly permits loopback redirect URIs for installed applications. The port is OS-assigned (random) to avoid conflicts. The operator MUST register the loopback URI in Discord's developer portal either with a wildcard port or a fixed registered port.

---

## 5. Key Generation — Browser Path (WebAuthn-Primary)

### 5.1 Authenticator-Bound Key

The browser uses the WebAuthn API to create a credential bound to the user's hardware authenticator (security key, platform authenticator via Touch ID, Windows Hello, etc.):

```javascript
const credential = await navigator.credentials.create({
  publicKey: {
    challenge: enrollmentChallenge,      // 32 bytes from Enrollment Service
    rp: { name: "Agora Enrollment", id: rpId },
    user: {
      id: discordUserIdBytes,            // Discord user ID as bytes
      name: discordUsername,
      displayName: discordUsername
    },
    pubKeyCredParams: [
      { type: "public-key", alg: -8 },   // Ed25519 (preferred)
      { type: "public-key", alg: -7 }    // P-256 (fallback)
    ],
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "required"
    },
    attestation: "none"
  }
});
```

Ed25519 (`alg: -8`) is preferred because Agora uses Ed25519 natively. P-256 (`alg: -7`) is the fallback for authenticators that do not support Ed25519 (most platform authenticators on Windows and older Android). When P-256 is used, the DID document uses a `P-256` verification method type instead of `Ed25519VerificationKey2020`; all other protocol behavior is identical.

DID derivation from the WebAuthn credential:

```javascript
const publicKeyBytes = credential.response.getPublicKey(); // COSE-encoded
const rawPublicKey = coseToRaw(publicKeyBytes);            // strip COSE wrapper
const did = `did:key:${multibaseEncode('ed25519-pub', rawPublicKey)}`;
```

The private key never exists in JavaScript. `getPublicKey()` returns only the public key; the DID is derived entirely from public material.

### 5.2 Recovery Keypair

Alongside the WebAuthn credential, the browser generates a software Ed25519 keypair via the WebCrypto API. This keypair serves as the Agora spec §2.4.1 recovery key:

```javascript
const recoveryKeyPair = await crypto.subtle.generateKey(
  { name: "Ed25519" },
  true,              // extractable — required for keyfile export
  ["sign", "verify"]
);
```

This key is extractable because it must be written to the keyfile. It MUST exist in browser memory only long enough to be exported into the keyfile and registered in the DID document. After keyfile production, all references MUST be dropped. It MUST NOT be persisted to `localStorage`, `IndexedDB`, or any other browser storage.

### 5.3 DID Document Assembly

The DID document combines the WebAuthn-bound primary key and the software recovery key:

```json
{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:key:z6Mk...",
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
  "authentication": ["did:key:z6Mk...#keys-1"],
  "keyAgreement": [...],
  "recoverableIdentity": ["did:key:z6Mk...#recovery-1"]
}
```

The `authentication` key is the WebAuthn-bound key. The `recoverableIdentity` key is the software recovery key. The `keyAgreement` key is a fresh X25519 keypair generated by the browser (WebCrypto, extractable, included in the keyfile alongside the recovery key).

### 5.4 Enrollment Challenge

Before key generation, the browser MUST fetch a short-lived challenge from the Enrollment Service:

```
GET /v1/enroll/challenge?discord_user_id=<id>
→ { "challenge": "<32-byte-base64url>", "expires": "<iso8601>", "space": "<agora-uri>" }
```

The challenge is used as the WebAuthn `challenge` field, binding the credential creation to this specific enrollment session. The Enrollment Service MUST verify the challenge on registration. Challenges expire in 5 minutes and are single-use; the service MUST mark a challenge consumed on first use.

---

## 6. Key Generation — CLI Path

### 6.1 Keystore Selection

On first run, the CLI prompts the user to select a keystore backend:

```
Where should your Agora keys be stored?

  [1] OS keychain  (Keychain on macOS, Credential Manager on Windows, libsecret on Linux)
  [2] Encrypted file  (~/.agora/keystore.enc)
  [3] Hardware key via PKCS#11  (YubiKey, SoftHSM, etc.)

Choice [1]:
```

The selection is stored in `~/.agora/config.toml` as `keystore_backend`. Subsequent runs use the configured backend without re-prompting.

### 6.2 OS Keychain Backend

Stores the Ed25519 private key bytes (raw, 32 bytes) under service name `agora` and account name equal to the DID. Platform implementations:

- **macOS:** Security framework (`SecItemAdd` / `SecItemCopyMatching`)
- **Windows:** DPAPI via `CryptProtectData` stored in Credential Manager
- **Linux:** libsecret (Secret Service API); falls back to `~/.agora/keystore.enc` with a warning if no Secret Service is available

### 6.3 Encrypted File Backend

An Argon2id-derived key from a user passphrase encrypts the key material:

```
backupKey = Argon2id(passphrase, salt, m=65536, t=3, p=4)
ciphertext = AES-256-GCM(backupKey, keyMaterial)
```

`keyMaterial` is a CBOR struct containing the Ed25519 private key, X25519 private key, DID, and creation timestamp. The file format matches the Agora spec §2.4.3 encrypted backup format (`backupType: "full"`).

The passphrase is prompted at key generation and at each subsequent use. It MUST NOT be stored anywhere. The CLI MUST require the passphrase to be confirmed twice at generation.

### 6.4 PKCS#11 Backend

The CLI uses the PKCS#11 interface to generate a key on the hardware token. The private key is non-extractable (stays on device). The public key is retrieved for DID derivation. Supported mechanisms: `CKM_EDDSA` (Ed25519), `CKM_ECDSA` (P-256 fallback). The PKCS#11 library path is configurable in `~/.agora/config.toml`:

```toml
[keystore]
backend = "pkcs11"
pkcs11_lib = "/usr/lib/x86_64-linux-gnu/libykcs11.so"
pkcs11_slot = 0
```

Common defaults are pre-configured for YubiKey (`libykcs11.so`), SoftHSM2 (`libsofthsm2.so`), and OpenSC (`opensc-pkcs11.so`).

### 6.5 Key Generation (Non-PKCS#11)

For the OS keychain and encrypted file backends, the CLI generates keys from the OS CSPRNG:

```go
privKey := ed25519.GenerateKey(rand.Reader)   // stdlib crypto/ed25519
x25519Priv := generateX25519(rand.Reader)      // golang.org/x/crypto/curve25519
did := deriveDIDKey(privKey.Public())
```

---

## 7. Keyfile Format

Both browser and CLI produce a single downloadable keyfile — the user's backup artifact. It uses a JSON envelope (chosen over binary for human-inspectability and cross-tool compatibility):

```json
{
  "version": "1",
  "type": "agora-keyfile",
  "did": "did:key:z6Mk...",
  "createdAt": "2026-03-13T00:00:00Z",
  "source": "discord-enrollment",
  "discordUserId": "123456789012345678",
  "discordUsername": "alice",
  "kdf": {
    "algorithm": "argon2id",
    "salt": "<base64url>",
    "m": 65536,
    "t": 3,
    "p": 4
  },
  "recoveryKeypair": {
    "description": "Ed25519 recovery key — use only if you lose access to your authenticator",
    "encryptedPrivateKey": "<base64url-AES256GCM-ciphertext>",
    "publicKeyMultibase": "zRECOVERY..."
  },
  "keyAgreementKeypair": {
    "description": "X25519 key agreement key",
    "encryptedPrivateKey": "<base64url-AES256GCM-ciphertext>",
    "publicKeyMultibase": "zABC..."
  },
  "stateBackup": {
    "description": "MLS group state — restores space membership continuity",
    "backupType": "stateOnly",
    "encryptedState": "<base64url-AES256GCM-ciphertext>"
  },
  "primaryKeyType": "webauthn",
  "primaryKeyCredentialId": "<base64url>",
  "primaryKeyPublicMultibase": "z6Mk...",
  "rpId": "enroll.agora.example.com"
}
```

For the CLI with an extractable keystore backend, `primaryKeyType` is `"software"` and the file additionally includes:

```json
"primaryKeypair": {
  "description": "Ed25519 primary signing key",
  "encryptedPrivateKey": "<base64url-AES256GCM-ciphertext>",
  "publicKeyMultibase": "z6Mk..."
}
```

For PKCS#11, `primaryKeyType` is `"pkcs11"` and `primaryKeypair` is omitted (non-extractable); only `primaryKeyPublicMultibase` is present.

**Passphrase derivation:** A single Argon2id invocation produces a 64-byte output. The first 32 bytes encrypt `recoveryKeypair.encryptedPrivateKey`; the second 32 bytes encrypt `keyAgreementKeypair.encryptedPrivateKey`. When a `primaryKeypair` is present, a third 32-byte block is derived with a distinct context label. The `stateBackup` uses a fourth block. This avoids key reuse without requiring multiple passphrase entries.

**Filename:** `agora-<displayName>-<YYYY-MM-DD>.keyfile.json`. The `.keyfile.json` double extension is intentional — systems that hide extensions will display `.keyfile`, which is less likely to be opened naively than `.json` alone.

---

## 8. Registration Protocol

After key generation, the client sends a signed registration request to the Enrollment Service:

```
POST /v1/enroll/register
Content-Type: application/json

{
  "did": "did:key:z6Mk...",
  "discordUserId": "123456789012345678",
  "challenge": "<challenge from §5.4>",
  "proofOfPossession": "<base64url Ed25519 signature over canonical proof payload>",
  "webauthnAssertion": { ... },   // present only in browser/WebAuthn path
  "keyPackage": "<base64url MLS KeyPackage>",
  "spaceURI": "agora://bafyrei.../"
}
```

**Proof payload** (the data signed to produce `proofOfPossession`):

```json
{
  "did": "did:key:z6Mk...",
  "discordUserId": "123456789012345678",
  "challenge": "<challenge>",
  "spaceURI": "agora://bafyrei.../",
  "ts": "2026-03-13T00:00:00Z"
}
```

In the WebAuthn path, `proofOfPossession` is the WebAuthn assertion signature (the authenticator signs the challenge), and `webauthnAssertion` carries the full assertion object for verification. In the CLI software key path, `proofOfPossession` is a direct Ed25519 signature by the primary key.

The `keyPackage` is an MLS KeyPackage generated by the client's MLS library using the X25519 key agreement key. The Enrollment Service uses this to construct the MLS Add commit.

### 8.1 Enrollment Service Validation

On receipt of a registration request, the Enrollment Service MUST:

1. Verify the challenge exists, has not expired, and has not been consumed.
2. Verify `discordUserId` matches the active Discord OAuth2 session for this request.
3. Look up `discordUserId` in the provisional member list; return 404 if not found.
4. Check the provisional record's `status` field; if `"enrolled"`, return 409 with the existing DID (idempotent re-enrollment is allowed, but the DID MUST NOT change).
5. Verify `proofOfPossession` against the DID's primary verification method.
6. In the WebAuthn path, additionally verify the WebAuthn assertion against the RP origin and the challenge.
7. Validate the MLS KeyPackage is well-formed and uses a supported ciphersuite.
8. Mark the challenge consumed.
9. Update the provisional member record: `did = <did>`, `status = "enrolled"`, `keyPackage = <keyPackage>`.
10. Construct and submit an MLS Add commit to the Relay (see §8.2).
11. Return success with the space URI and the user's MLS Welcome message.

### 8.2 MLS Add Commit

The Enrollment Service holds the space enrollment agent's MLS credentials — specifically, the ability to issue Add commits. This is either the space owner's signing key (if delegated) or a dedicated enrollment agent key added to the space's MLS group at setup time. The service constructs:

```
MLSMessage {
  Add { KeyPackage: <from registration request> }
}
```

This is committed to the Relay via the standard Agora channel state update endpoint. The Relay processes the commit, advances the MLS epoch, and the new member can receive and decrypt space messages from this epoch forward.

The Welcome message generated by the Add commit is returned to the enrolling client in the registration response. The client uses it to initialize its local MLS state.

---

## 9. Update Path (Re-enrollment)

A user who already has a DID (from a prior enrollment or manual setup) can update their record. The flow is identical to the create path except:

- At step 4 of §8.1: if the provisional record already has a DID, the service MUST verify that the new registration's DID matches the existing one. A DID change is not permitted through this flow — it requires a `RecoveryAssertion` (Agora spec §2.4.1).
- Adding a new device (second hardware key, new phone) uses the standard Agora multi-device enrollment flow from the existing device, not this tool.

The update path's primary use case is a user who enrolled but lost their keyfile and needs to re-download it. The tool re-generates the keyfile from the existing registered keypair if it is still accessible via the user's authenticator or CLI keystore.

---

## 10. Error Handling

| Condition | Browser UX | CLI UX |
|---|---|---|
| Discord user not in provisional list | "Your Discord account (@username) isn't on the list for this space. Ask the space admin to run the enrollment sync." | Same message; exit 1 |
| Already enrolled, same DID | "You're already enrolled. Here's your space link: [uri]. Re-download your keyfile?" | Prompt to re-export keyfile |
| Already enrolled, DID mismatch | "This Discord account is already enrolled with a different identity. Contact your space admin." | Same message; exit 1 |
| WebAuthn not supported | Fall back to software key generation with a prominent security warning | N/A |
| WebAuthn cancelled by user | "Enrollment paused. Come back when you have your security key ready." | N/A |
| Challenge expired | Re-fetch challenge automatically and retry once; display error on second failure | Same |
| Relay unreachable | "Your identity was created but couldn't be registered with the space yet. Your keyfile is safe. Try again later." | Same |
| Keyfile passphrase mismatch (CLI) | N/A | Re-prompt up to 3 times, then abort |

---

## 11. Enrollment Service API

Endpoints:

```
GET  /v1/enroll/challenge          Fetch enrollment challenge (§5.4)
POST /v1/enroll/register           Submit DID registration (§8)
GET  /v1/enroll/status/:discord_id Check enrollment status
POST /v1/enroll/sync               Operator: reload provisional member list from file
GET  /v1/enroll/space              Return space URI and display metadata for this enrollment instance
```

Configuration (`config.toml`):

```toml
[enrollment]
discord_client_id     = "..."
discord_client_secret = "..."
space_uri             = "agora://bafyrei.../"
relay_url             = "wss://relay.example.com"
provisional_members   = "/data/provisional-members.json"
admin_key             = "/secrets/enrollment-agent.key"
rp_id                 = "enroll.agora.example.com"
rp_origin             = "https://enroll.agora.example.com"
challenge_ttl_seconds = 300
```

`admin_key` is the enrollment agent's Ed25519 private key. This agent MUST be a member of the space's MLS group with permission to issue Add commits. It is added to the space at setup time; the `discord2agora` tool generates a placeholder enrollment agent entry in SpaceState when `--enrollment-service` is specified.

---

## 12. Browser App — Implementation Notes

**Framework:** Vanilla JS or Svelte. React MUST NOT be used — the key generation logic is security-sensitive, and a heavyweight component framework adds unnecessary attack surface and bundle complexity.

**WebCrypto availability:** Required. The app MUST check `window.crypto.subtle` on load and MUST display a hard error if absent (this only occurs on non-HTTPS origins, which MUST NOT occur in production).

**WebAuthn availability:** The app checks `window.PublicKeyCredential` and `PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()`. If WebAuthn is unavailable or the user has no platform authenticator, the app falls back to software key generation using `crypto.subtle.generateKey` with `extractable: true`, with a visible warning banner: "Your keys are software-generated and less secure than a hardware authenticator. Consider enrolling again with a security key."

**Key material lifetime:** All private key material (recovery keypair, X25519 keypair) is held only in `CryptoKey` objects with `extractable: true`. Material MUST be exported to the keyfile immediately after generation, and all references MUST be dropped after the keyfile download is initiated. The app MUST NOT retain key material beyond keyfile export.

**Service worker restrictions:** The enrollment page MUST NOT be served with a service worker that could cache responses containing key material. CSP headers MUST include `Cache-Control: no-store` on all enrollment API responses.

---

## 13. CLI — Implementation Notes

**Language:** Go. Same rationale as `discord2agora` — consistent toolchain, mature keychain libraries.

**Key dependencies:**

| Function         | Library                               |
|------------------|---------------------------------------|
| OS keychain      | `github.com/zalando/go-keyring`       |
| PKCS#11          | `github.com/miekg/pkcs11`             |
| Ed25519          | `crypto/ed25519` (stdlib)             |
| X25519           | `golang.org/x/crypto/curve25519`      |
| Argon2id         | `golang.org/x/crypto/argon2`          |
| MLS KeyPackage   | `openmls` via CGo or pre-built binary |
| Discord OAuth2   | `golang.org/x/oauth2`                 |
| CBOR             | `github.com/fxamacker/cbor/v2`        |

**Binary distribution:** Single static binary per platform (Linux/amd64, Linux/arm64, macOS/amd64, macOS/arm64, Windows/amd64). The PKCS#11 backend requires a platform-specific shared library (not bundled); all other backends are fully static.

---

## 14. Security Considerations

**Enrollment Service privilege.** The Enrollment Service holds the enrollment agent key, which grants the ability to add members to the space MLS group. Compromise of the Enrollment Service allows an attacker to add arbitrary DIDs to the space. The service MUST be hardened accordingly: minimal attack surface, no public write endpoints beyond the registration flow, rate-limited per Discord user ID. The enrollment agent key SHOULD be rotated after the initial enrollment wave completes, or the agent SHOULD be removed from the MLS group entirely if no further enrollments are expected.

**Discord OAuth2 scope.** Discord identity is used to match users to provisional records only. It does not serve as a trust anchor beyond confirming control of a Discord account. The cryptographic proof-of-possession is the binding between DID and enrollment.

**Keyfile passphrase strength.** Users who choose weak passphrases expose the recovery path. The browser and CLI MUST enforce a minimum entropy check (zxcvbn or equivalent) and MUST reject passphrases scoring below strength 3. Implementations MUST NOT enforce arbitrary character class rules, which reduce entropy by constraining the search space.

**Enrollment window.** The Enrollment Service SHOULD have a configurable window during which new enrollments are accepted. After initial migration, the operator SHOULD close enrollment and require out-of-band approval for new members. Leaving enrollment open indefinitely against the provisional list is a low-severity risk (an attacker would need a valid Discord account present on the list) but is unnecessary after migration is complete.

---

## 15. Open Questions

1. **Multi-space enrollment.** This spec handles enrollment into a single space per deployment. An operator running multiple spaces requires multiple Enrollment Service instances. A multi-space enrollment service that presents a list of spaces to the user after Discord auth is a useful extension.

2. **Provisional list sync.** The Enrollment Service loads the provisional member list from a static file. Users added to Discord after the initial `discord2agora` run will not be in the list. A `POST /v1/enroll/sync` endpoint is specified (§11), but the sync source — whether incremental re-execution of `discord2agora` or direct Discord API access — is not yet defined.

3. **Passphrase recovery.** If a user loses their keyfile passphrase, the recovery key is inaccessible. There is no protocol-level remedy. Operators SHOULD communicate this clearly during enrollment. A Shamir-based guardian recovery scheme (Agora spec §2.4.2) is a natural extension but is out of scope for this tool.

4. **WebAuthn credential ID storage.** The keyfile stores the WebAuthn credential ID (`primaryKeyCredentialId`). A user who loses the keyfile retains their authenticator but may not know which credential to use if multiple are present. A credential hint stored via the authenticator's `residentKey` (if `residentKey: "preferred"` was honored) mitigates this.

5. **Platform authenticator sync behavior.** Platform authenticators on Windows (Hello) and macOS/iOS (iCloud Keychain) may sync credentials across devices via the platform. This is both a feature (multi-device from day one) and a concern (credentials leave the device). The app SHOULD inform users of this behavior and SHOULD recommend a FIDO2 roaming authenticator (YubiKey, etc.) for higher-assurance deployments.
