# Tool Specification: `agora-enroll`

**Version:** 0.1 Draft  
**Depends On:** Agora Protocol Spec v0.1, `discord2agora` spec v0.1  
**Status:** Pre-implementation design

---

## 1. Purpose

`agora-enroll` is the user-facing counterpart to `discord2agora`. It authenticates a user via Discord OAuth2, generates or recovers their Agora DID and device keypair, and registers that DID against their provisional member record in a target Guild. The result is a fully-enrolled Agora identity that a client can use immediately.

Two delivery targets:

- **Browser app** (`enroll.agora.example.com` or self-hosted) — zero install, WebAuthn-primary, covers the majority of users
- **CLI binary** (`agora-enroll`) — for operators, power users, and users who want explicit keystore control

Both targets share the same backend protocol. The browser and CLI are different frontends to the same enrollment flow.

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
        (OAuth2)               (Guild state,
                                MLS group)
```

The Enrollment Service is stateless beyond the provisional member list. It does not hold private keys, does not hold session state between requests (beyond a short-lived OAuth2 state token), and does not have write access to the Relay beyond submitting signed MLS Add commits on behalf of the enrolling user.

---

## 3. Enrollment Flow — Overview

Both browser and CLI follow the same logical sequence:

1. **Discord OAuth2** — user authenticates with Discord; tool obtains their Discord user ID
2. **Lookup** — tool queries Enrollment Service: is this Discord user ID in the provisional member list?
3. **Key operation** — tool generates a new DID+keypair (create path) or loads an existing one (update path)
4. **Registration** — tool POSTs the DID and a signed proof-of-possession to the Enrollment Service
5. **MLS Add** — Enrollment Service submits an MLS Add commit to the Relay for the new member
6. **Keyfile export** — tool produces the combined recovery keypair + state backup file for the user to save
7. **Confirmation** — tool displays the guild URI and the user's DID

---

## 4. Discord OAuth2

### 4.1 Scopes

```
identify
```

That is the only required scope. The tool needs the user's Discord ID and username. It does not need email, guild membership read, or any write permissions.

### 4.2 Browser Flow (PKCE)

Standard OAuth2 Authorization Code flow with PKCE. The browser app:

1. Generates a `code_verifier` (cryptographically random, 43–128 chars)
2. Derives `code_challenge = BASE64URL(SHA256(code_verifier))`
3. Redirects to Discord's authorization endpoint with `response_type=code`, `code_challenge_method=S256`, and a short-lived `state` token (stored in `sessionStorage`, not `localStorage`)
4. Discord redirects back to the enrollment app's callback URL with `code`
5. App exchanges `code` + `code_verifier` for an access token via the Enrollment Service backend (the client secret lives on the server, not in the browser)
6. Enrollment Service returns only the Discord user ID and username to the browser — the access token stays server-side and is discarded after the `/users/@me` call

The `state` token is a 32-byte random value, base64url-encoded, stored in `sessionStorage`. It is verified on callback and then deleted. It is never stored in `localStorage` or a cookie.

### 4.3 CLI Flow (Loopback)

Standard OAuth2 loopback redirect (RFC 8252 §7.3):

1. CLI binds a listener on `http://127.0.0.1:<random-port>/callback`
2. Opens the system browser to Discord's authorization endpoint with `redirect_uri=http://127.0.0.1:<port>/callback`
3. Discord redirects to the loopback listener with `code`
4. CLI exchanges `code` for an access token directly (client_id only, no client_secret — CLI is a public client)
5. CLI calls `/users/@me`, extracts Discord user ID and username, discards token

Discord explicitly permits loopback redirect URIs for installed applications. The port is random (OS-assigned) to avoid conflicts; Discord's developer portal must have the loopback URI registered with a wildcard port or the operator must register a fixed port.

---

## 5. Key Generation — Browser Path (WebAuthn-Primary)

### 5.1 Authenticator-Bound Key (Primary)

The browser uses the WebAuthn API to create a credential bound to the user's hardware authenticator (security key, platform authenticator via Touch ID / Windows Hello, etc.):

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
    attestation: "none"                  // no attestation; we don't need it
  }
});
```

**Algorithm preference:** Ed25519 (`alg: -8`) is preferred because Agora uses Ed25519 natively. P-256 (`alg: -7`) is the fallback for authenticators that don't support Ed25519 (most platform authenticators on Windows and older Android). If P-256 is used, the DID document uses a `P-256` verification method type instead of `Ed25519VerificationKey2020`; all other protocol behavior is identical.

**DID derivation from WebAuthn credential:**

```javascript
const publicKeyBytes = credential.response.getPublicKey(); // COSE-encoded
const rawPublicKey = coseToRaw(publicKeyBytes);            // strip COSE wrapper
const did = `did:key:${multibaseEncode('ed25519-pub', rawPublicKey)}`;
```

The private key never exists in JavaScript. `getPublicKey()` returns only the public key. The DID is derived entirely from public material.

### 5.2 Recovery Keypair (Software-Generated)

Alongside the WebAuthn credential, the browser generates a software Ed25519 keypair using the WebCrypto API. This keypair serves as the Agora spec §2.4.1 recovery key:

```javascript
const recoveryKeyPair = await crypto.subtle.generateKey(
  { name: "Ed25519" },
  true,              // extractable — must be, for keyfile export
  ["sign", "verify"]
);
```

This key is extractable because it needs to go into the keyfile. It exists in browser memory only long enough to be exported into the keyfile and then registered in the DID document. After keyfile production, the browser should drop all references and allow GC. It is never persisted to `localStorage`, `IndexedDB`, or any browser storage.

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

The `authentication` key is the WebAuthn-bound key. The `recoverableIdentity` key is the software recovery key. The `keyAgreement` key is a fresh X25519 keypair generated by the browser (WebCrypto, extractable, goes into keyfile alongside the recovery key).

### 5.4 Enrollment Challenge

Before key generation, the browser fetches a short-lived challenge from the Enrollment Service:

```
GET /v1/enroll/challenge?discord_user_id=<id>
→ { "challenge": "<32-byte-base64url>", "expires": "<iso8601>", "guild": "<agora-uri>" }
```

The challenge is used as the WebAuthn `challenge` field, tying the credential creation to this specific enrollment session. The Enrollment Service verifies the challenge on registration. Challenges expire in 5 minutes and are single-use (the service marks them consumed on first use).

---

## 6. Key Generation — CLI Path

### 6.1 Keystore Selection at Init Time

On first run, the CLI prompts:

```
Where should your Agora keys be stored?

  [1] OS keychain  (Keychain on macOS, Credential Manager on Windows, libsecret on Linux)
  [2] Encrypted file  (~/.agora/keystore.enc)
  [3] Hardware key via PKCS#11  (YubiKey, SoftHSM, etc.)

Choice [1]:
```

The selection is stored in `~/.agora/config.toml` as `keystore_backend`. Subsequent runs use the configured backend without re-prompting.

### 6.2 OS Keychain Backend

Stores the Ed25519 private key bytes (raw, 32 bytes) under the service name `agora` and account name equal to the DID. Uses:

- macOS: Security framework (`SecItemAdd` / `SecItemCopyMatching`)
- Windows: DPAPI via `CryptProtectData` stored in Credential Manager
- Linux: libsecret (Secret Service API); falls back to `~/.agora/keystore.enc` if no Secret Service is available, with a warning

### 6.3 Encrypted File Backend

Argon2id-derived key from a user passphrase encrypts the key material:

```
backupKey = Argon2id(passphrase, salt, m=65536, t=3, p=4)
ciphertext = AES-256-GCM(backupKey, keyMaterial)
```

`keyMaterial` is a CBOR struct containing the Ed25519 private key, X25519 private key, DID, and creation timestamp. File format matches the Agora spec §2.4.3 encrypted backup format (`backupType: "full"`).

The passphrase is prompted at key generation and at each use. It is never stored anywhere. The CLI confirms the passphrase twice at generation.

### 6.4 PKCS#11 Backend

The CLI uses the PKCS#11 interface to generate a key on the hardware token. Private key is non-extractable (stays on device). Public key is retrieved for DID derivation. Supported mechanisms: `CKM_EDDSA` (Ed25519), `CKM_ECDSA` (P-256 fallback). The PKCS#11 library path is configurable in `~/.agora/config.toml`:

```toml
[keystore]
backend = "pkcs11"
pkcs11_lib = "/usr/lib/x86_64-linux-gnu/libykcs11.so"
pkcs11_slot = 0
```

Common defaults are pre-configured for YubiKey (`libykcs11.so`), SoftHSM2 (`libsofthsm2.so`), and OpenSC (`opensc-pkcs11.so`).

### 6.5 Key Generation (non-PKCS#11)

For OS keychain and encrypted file backends, the CLI generates keys using the OS CSPRNG directly:

```go
privKey := ed25519.GenerateKey(rand.Reader)   // stdlib crypto/ed25519
x25519Priv := generateX25519(rand.Reader)      // golang.org/x/crypto/curve25519
did := deriveDIDKey(privKey.Public())
```

---

## 7. Combined Keyfile Format

Both browser and CLI produce a single downloadable/exportable keyfile. This is the user's backup artifact. They should treat it like a password manager export — store it somewhere safe, not in Dropbox root, not emailed to themselves.

The file is a JSON envelope (chosen over binary for human-inspectability and cross-tool compatibility):

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
    "description": "MLS group state — restores guild membership continuity",
    "backupType": "stateOnly",
    "encryptedState": "<base64url-AES256GCM-ciphertext>"
  },
  "primaryKeyType": "webauthn",
  "primaryKeyCredentialId": "<base64url>",
  "primaryKeyPublicMultibase": "z6Mk...",
  "rpId": "enroll.agora.example.com"
}
```

For the CLI with an extractable keystore backend, `primaryKeyType` is `"software"` and the file includes:

```json
"primaryKeypair": {
  "description": "Ed25519 primary signing key",
  "encryptedPrivateKey": "<base64url-AES256GCM-ciphertext>",
  "publicKeyMultibase": "z6Mk..."
}
```

For PKCS#11, `primaryKeyType` is `"pkcs11"` and `primaryKeypair` is omitted (non-extractable); only `primaryKeyPublicMultibase` is present.

**Passphrase derivation:** A single Argon2id invocation produces a 64-byte output. The first 32 bytes encrypt `recoveryKeypair.encryptedPrivateKey`, the second 32 bytes encrypt `keyAgreementKeypair.encryptedPrivateKey`. If a `primaryKeypair` is present, a third 32-byte block is derived with a different context label. The `stateBackup` uses a fourth block. This avoids key reuse without requiring the user to enter multiple passphrases.

**Filename:** `agora-<displayName>-<YYYY-MM-DD>.keyfile.json`. The `.keyfile.json` double extension is intentional — systems that hide extensions will show `.keyfile`, which is less likely to be double-clicked naively than `.json` alone.

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
  "guildURI": "agora://bafyrei.../"
}
```

**Proof payload** (what gets signed for `proofOfPossession`):

```json
{
  "did": "did:key:z6Mk...",
  "discordUserId": "123456789012345678",
  "challenge": "<challenge>",
  "guildURI": "agora://bafyrei.../",
  "ts": "2026-03-13T00:00:00Z"
}
```

In the WebAuthn path, `proofOfPossession` is the WebAuthn assertion signature (the authenticator signs the challenge). The `webauthnAssertion` field carries the full assertion object for verification. In the CLI software key path, `proofOfPossession` is a direct Ed25519 signature by the primary key.

The `keyPackage` is an MLS KeyPackage generated by the client's MLS library using the X25519 key agreement key. The Enrollment Service uses this to construct the MLS Add commit.

### 8.1 Enrollment Service Validation

On receipt of a registration request, the Enrollment Service:

1. Verifies the challenge exists, has not expired, and has not been consumed
2. Verifies `discordUserId` matches the active Discord OAuth2 session for this request
3. Looks up `discordUserId` in the provisional member list; returns 404 if not found
4. Checks the provisional record's `status` field; if `"enrolled"`, returns 409 with the existing DID (idempotent re-enrollment is allowed but the DID cannot change)
5. Verifies `proofOfPossession` against the DID's primary verification method
6. In the WebAuthn path, additionally verifies the WebAuthn assertion against the RP origin and the challenge
7. Validates the MLS KeyPackage is well-formed and uses a supported ciphersuite
8. Marks the challenge consumed
9. Updates the provisional member record: `did = <did>`, `status = "enrolled"`, `keyPackage = <keyPackage>`
10. Constructs and submits an MLS Add commit to the Relay (see §8.2)
11. Returns success with the guild URI and the user's MLS Welcome message

### 8.2 MLS Add Commit

The Enrollment Service holds the guild admin's MLS credentials (specifically, its ability to issue Add commits — this is either the guild owner's signing key if the owner delegates, or a dedicated enrollment agent key added to the guild's MLS group at setup time). It constructs:

```
MLSMessage {
  Add { KeyPackage: <from registration request> }
}
```

Commits this to the Relay via the standard Agora channel state update endpoint. The Relay processes the commit, advances the MLS epoch, and the new member can now receive and decrypt guild messages from this epoch forward.

The Welcome message generated by the Add commit is returned to the enrolling client in the registration response. The client uses it to initialize its local MLS state.

---

## 9. Update Path (Re-enrollment)

A user who already has a DID (from a prior enrollment or manual setup) can update their record. The flow is identical except:

- Step 3 of §8.1: if the provisional record already has a DID, the service verifies that the new registration's DID matches the existing one. A DID change is not permitted through this flow — it would require a `RecoveryAssertion` (Agora spec §2.4.1).
- If the user wants to add a new device (second hardware key, new phone), they use the standard Agora multi-device enrollment flow from their existing device, not this tool.

The update path's primary use case is a user who enrolled but lost their keyfile and needs to re-download it. The tool re-generates the keyfile from the existing registered keypair if it's still accessible via their authenticator or CLI keystore.

---

## 10. Error States and UX

| Condition | Browser UX | CLI UX |
|---|---|---|
| Discord user not in provisional list | "Your Discord account (@username) isn't on the list for this guild. Ask the guild admin to run the enrollment sync." | Same message, exit 1 |
| Already enrolled, same DID | "You're already enrolled. Here's your guild link: [uri]. Re-download your keyfile?" | Prompt to re-export keyfile |
| Already enrolled, DID mismatch | "This Discord account is already enrolled with a different identity. Contact your guild admin." | Same, exit 1 |
| WebAuthn not supported | Fall back to software key generation with prominent warning about reduced security | N/A |
| WebAuthn cancelled by user | "Enrollment paused. Come back when you have your security key ready." | N/A |
| Challenge expired | Re-fetch challenge automatically and retry once; if it fails again, show error | Same |
| Relay unreachable | "Your identity was created but couldn't be registered with the guild yet. Your keyfile is safe. Try again later." | Same |
| Keyfile passphrase mismatch (CLI) | N/A | Re-prompt up to 3 times, then abort |

---

## 11. Enrollment Service API

Full endpoint list:

```
GET  /v1/enroll/challenge          Fetch enrollment challenge (§5.4)
POST /v1/enroll/register           Submit DID registration (§8)
GET  /v1/enroll/status/:discord_id Check enrollment status
POST /v1/enroll/sync               Operator: reload provisional member list from file
GET  /v1/enroll/guild              Return guild URI and display metadata for this enrollment instance
```

The Enrollment Service is configured with:

```toml
[enrollment]
discord_client_id     = "..."
discord_client_secret = "..."
guild_uri             = "agora://bafyrei.../"
relay_url             = "wss://relay.example.com"
provisional_members   = "/data/provisional-members.json"
admin_key             = "/secrets/enrollment-agent.key"
rp_id                 = "enroll.agora.example.com"
rp_origin             = "https://enroll.agora.example.com"
challenge_ttl_seconds = 300
```

The `admin_key` is the enrollment agent's Ed25519 private key. This agent must be a member of the guild's MLS group with permission to issue Add commits. It is added to the guild at setup time (the `discord2agora` tool generates a placeholder enrollment agent entry in the GuildState when `--enrollment-service` is specified).

---

## 12. Browser App — Implementation Notes

**Framework:** Vanilla JS or Svelte. No React — the key generation logic is sensitive and a heavyweight component framework adds unnecessary surface area and bundle complexity.

**WebCrypto availability:** Required. The app checks `window.crypto.subtle` on load and displays a hard error if absent (this only happens on non-HTTPS origins, which should never occur in production).

**WebAuthn availability:** The app checks `window.PublicKeyCredential` and `PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()`. If WebAuthn is unavailable or the user has no platform authenticator, it falls back to software key generation using `crypto.subtle.generateKey` with `extractable: true`, with a visible warning banner: "Your keys are software-generated and less secure than a hardware authenticator. Consider enrolling again with a security key."

**Key material lifetime in browser memory:** All private key material (recovery keypair, X25519 keypair) is held only in `CryptoKey` objects with `extractable: true`. It is exported to the keyfile as soon as it's generated, and all references are dropped immediately after. The app does not retain key material after the keyfile download is initiated.

**No service worker caching of key material.** The enrollment page must not be served with a service worker that could cache responses containing key material. CSP headers must include `Cache-Control: no-store` on all enrollment API responses.

---

## 13. CLI — Implementation Notes

**Language:** Go. Same rationale as `discord2agora` — consistent toolchain, mature keychain libraries (`zalando/go-keyring` for OS keychain, `miekg/pkcs11` for PKCS#11).

**Key dependencies:**

| Function | Library |
|---|---|
| OS keychain | `github.com/zalando/go-keyring` |
| PKCS#11 | `github.com/miekg/pkcs11` |
| Ed25519 | `crypto/ed25519` (stdlib) |
| X25519 | `golang.org/x/crypto/curve25519` |
| Argon2id | `golang.org/x/crypto/argon2` |
| MLS KeyPackage | `openmls` via CGo or pre-built binary |
| Discord OAuth2 | `golang.org/x/oauth2` |
| CBOR | `github.com/fxamacker/cbor/v2` |

**Binary distribution:** Single static binary per platform (Linux/amd64, Linux/arm64, macOS/amd64, macOS/arm64, Windows/amd64). The PKCS#11 backend requires a platform-specific shared library (not bundled); all other backends are fully static.

---

## 14. Security Considerations

**The Enrollment Service is a privileged component.** It holds the enrollment agent key (capability to add members to the guild MLS group). Compromise of the Enrollment Service allows an attacker to add arbitrary DIDs to the guild. It should be hardened accordingly: minimal attack surface, no public write endpoints beyond the registration flow, rate-limited per Discord user ID, and the enrollment agent key should be rotated after the initial enrollment wave completes (or the agent removed from the MLS group entirely if no new members are expected).

**Discord OAuth2 is the authentication layer, not a trust anchor.** The tool uses Discord identity to match users to provisional records. It does not trust Discord for anything beyond "this person controls this Discord account." The cryptographic proof-of-possession is what actually binds the DID to the enrollment.

**The keyfile passphrase is the weakest link in the recovery path.** Users who choose weak passphrases are exposed. The browser and CLI should enforce a minimum entropy check (zxcvbn or equivalent) and refuse passphrases that score below strength 3. They should not enforce arbitrary character class rules — those reduce entropy by constraining the search space.

**Re-enrollment window.** The enrollment service should have a configurable window during which new enrollments are accepted. After the initial migration, the operator should close enrollment and require out-of-band approval for new members. Leaving enrollment open indefinitely against the provisional list is a low-severity risk (an attacker would need a valid Discord account that happens to be on the list) but unnecessary after migration is complete.

---

## 15. Open Questions

1. **Multi-guild enrollment.** This spec handles enrollment into a single guild per deployment. An operator running multiple guilds needs multiple Enrollment Service instances. A multi-guild enrollment service that presents a list of guilds to the user after Discord auth is a useful extension.

2. **Provisional list sync.** The Enrollment Service loads the provisional member list from a static file. If the operator adds new members to Discord after the initial `discord2agora` run, those users won't be in the list. A `POST /v1/enroll/sync` endpoint is specified (§11) but the sync source (re-running `discord2agora` incrementally, or direct Discord API) is not defined.

3. **Passphrase recovery.** If a user loses their keyfile passphrase, the recovery key is inaccessible. There is no protocol-level remedy. The operator should communicate this clearly during enrollment. A Shamir-based guardian recovery scheme (Agora spec §2.4.2) is a natural extension but is out of scope for this tool.

4. **WebAuthn credential ID storage.** The keyfile stores the WebAuthn credential ID (`primaryKeyCredentialId`). If the user loses the keyfile, they still have their authenticator but may not know which credential to use if they have multiple. A credential hint stored in the authenticator's `residentKey` (if `residentKey: "preferred"` was honored) mitigates this.

5. **Windows Hello and iCloud Keychain sync.** Platform authenticators on Windows (Hello) and macOS/iOS (iCloud Keychain) may sync credentials across devices via the platform. This is a feature (multi-device from day one) and a concern (credentials leave the device). The app should inform users of this behavior and suggest a FIDO2 roaming authenticator (YubiKey, etc.) for higher-assurance deployments.
