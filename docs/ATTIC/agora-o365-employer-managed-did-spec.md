# Specification: Employer-Managed DIDs via Microsoft Entra ID

**Version:** 0.1 Draft  
**Depends On:** Agora Protocol Spec v0.1, `agora-enroll` spec v0.1  
**Status:** Pre-implementation design

---

## 1. Architecture Overview

This spec defines how an organization using Microsoft 365 / Entra ID manages Agora `did:web` identities for its employees — provisioning them automatically at hire, updating claims on role changes, and revoking them at termination — without holding or touching employee private keys at any point.

Two components do the work:

**The DID Sidecar** is a lightweight HTTPS service registered as an Entra application. It owns the namespace `https://did.example.com/users/{upn}/did.json` and serves per-user `did:web` documents. It receives provisioning events from Graph Lifecycle Workflows via a Logic App bridge, and accepts authenticated device key registration requests from employees during Agora enrollment. It is the only component that mutates DID documents.

**Entra Verified ID** issues a signed `EmployeeCredential` verifiable credential to each enrolled employee's wallet (Microsoft Authenticator). The VC is the org's cryptographic attestation that the holder is a current employee with specific claims (department, role, clearance level). Agora guild admission requires a valid VC as a precondition for DID registration. VC revocation is the org's mechanism for immediately invalidating access without touching the DID document.

These two components are intentionally independent and address different concerns:

| Concern | Component |
|---|---|
| Org controls identity namespace and can revoke | DID Sidecar (tombstones DID document) |
| Org attests employee status with auditable trail | Entra Verified ID (EmployeeCredential) |
| Employee controls private key — org cannot impersonate | DID Sidecar (device key registered by client, never by org) |
| Immediate access revocation without DID tombstone | Entra Verified ID (VC revocation) |
| Specific device revocation (lost device) | DID Sidecar (tombstone one `verificationMethod` entry) |

```
┌─────────────────────────────────────────────────────────────────────┐
│  Microsoft Entra ID Tenant                                          │
│                                                                     │
│  ┌─────────────────────────┐   ┌──────────────────────────────┐    │
│  │  Lifecycle Workflows    │   │  Verified ID                 │    │
│  │  (Joiner/Mover/Leaver)  │   │  (EmployeeCredential issuer) │    │
│  └──────────┬──────────────┘   └──────────────┬───────────────┘    │
│             │ customTaskExtension              │ issuance API       │
│             ▼                                 ▼                    │
│  ┌──────────────────────┐      ┌──────────────────────────────┐    │
│  │  Azure Logic App     │      │  Entra Verified ID Service   │    │
│  │  (JML bridge)        │      │  (credential lifecycle)      │    │
│  └──────────┬───────────┘      └──────────────────────────────┘    │
│             │ HTTPS POST                                            │
└─────────────┼───────────────────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────────────────────┐
│  DID Sidecar  (operator-hosted, registered as Entra app)            │
│                                                                     │
│  GET  /users/{upn}/did.json       Serve DID document (public)      │
│  POST /v1/provision               JML event receiver                │
│  POST /v1/register-device-key     Device key registration           │
│  POST /v1/revoke-device-key       Device key tombstone (IT/MDM)     │
│  POST /v1/tombstone               Full DID revocation               │
│                                                                     │
│  Storage: per-user DID documents in Azure Blob or Postgres          │
│  Auth: Entra app registration, managed identity                     │
└─────────────────────────────────────────────────────────────────────┘
              │
              │  serves
              ▼
  did:web:did.example.com:users:alice          (Alice's Agora DID)
  did:web:did.example.com:users:bob            (Bob's Agora DID)
```

---

## 2. DID Naming Convention

Each employee's DID is:

```
did:web:did.example.com:users:<upn-encoded>
```

Where `<upn-encoded>` is the employee's Entra UPN with `@` replaced by `.at.` and all other non-alphanumeric characters replaced by `-`:

```
alice@example.com  →  did:web:did.example.com:users:alice.at.example.com
```

The `did:web` spec maps colons in the DID path to slashes in the URL path, so this resolves to:

```
https://did.example.com/users/alice.at.example.com/did.json
```

**UPN stability note:** UPNs can change (name changes, domain migrations). When a UPN changes (Mover event), the sidecar provisions a new DID document at the new path and publishes a signed `RecoveryAssertion` (Agora spec §2.4.1) from the old DID pointing to the new one, then tombstones the old document after a 30-day grace period. The old DID URI becomes a redirect stub that returns `410 Gone` with a `Link` header pointing to the new document. This is documented in §6.3.

---

## 3. DID Document Lifecycle

### 3.1 Document States

Each user's DID document moves through these states:

```
[not exist] → STUB → ACTIVE → SUSPENDED → TOMBSTONED
                ↑                  ↓            ↑
                └──────────────────┘            │
                     (re-activation)            │
                                                │
                    ACTIVE ──────────────────────┘
                           (direct tombstone on termination)
```

| State | Description | HTTP response at `/did.json` |
|---|---|---|
| `STUB` | Provisioned by Joiner workflow; no device keys yet | 200 with stub document (no `authentication` entries) |
| `ACTIVE` | At least one device key registered; fully functional | 200 with full document |
| `SUSPENDED` | VC revoked (e.g. leave of absence); device keys preserved | 200 with stub (keys stripped from response, preserved in DB) |
| `TOMBSTONED` | Employee terminated; DID permanently revoked | 410 Gone with signed tombstone document |

The stub document served during `STUB` state is a valid DID document with the org's revocation key as the sole `verificationMethod`, a `status: "pending-enrollment"` service entry, and no `authentication` or `keyAgreement` entries. Agora clients that resolve this DID during a guild Add operation will see no usable authentication key — the Add commit will fail gracefully, prompting enrollment.

### 3.2 Stub Document (pre-enrollment)

```json
{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:web:did.example.com:users:alice.at.example.com",
  "verificationMethod": [
    {
      "id": "did:web:did.example.com:users:alice.at.example.com#org-revocation-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:web:did.example.com",
      "publicKeyMultibase": "zORG_REVOCATION_KEY..."
    }
  ],
  "service": [
    {
      "id": "did:web:did.example.com:users:alice.at.example.com#enrollment",
      "type": "AgoraEnrollmentEndpoint",
      "serviceEndpoint": "https://enroll.example.com/v1/enroll"
    },
    {
      "id": "did:web:did.example.com:users:alice.at.example.com#status",
      "type": "AgoraEmployeeStatus",
      "serviceEndpoint": {
        "status": "pending-enrollment",
        "employeeId": "EMP-12345",
        "department": "Engineering"
      }
    }
  ],
  "controller": "did:web:did.example.com"
}
```

The `controller` field is the org's root DID (`did:web:did.example.com`), not the user's DID. This means the org has controller authority over the document — it can update or tombstone it without the user's private key. The user gains co-controller status when they register their first device key; from that point forward, both the user (via device key) and the org (via controller authority) can mutate the document, but only the user can sign messages as that identity.

### 3.3 Active Document (post-enrollment)

```json
{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:web:did.example.com:users:alice.at.example.com",
  "verificationMethod": [
    {
      "id": "did:web:did.example.com:users:alice.at.example.com#org-revocation-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:web:did.example.com",
      "publicKeyMultibase": "zORG_REVOCATION_KEY..."
    },
    {
      "id": "did:web:did.example.com:users:alice.at.example.com#device-macbook-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:web:did.example.com:users:alice.at.example.com",
      "publicKeyMultibase": "zDEVICE_KEY_1...",
      "meta": {
        "deviceLabel": "Alice's MacBook Pro",
        "registeredAt": "2026-03-13T00:00:00Z",
        "registeredVia": "webauthn"
      }
    },
    {
      "id": "did:web:did.example.com:users:alice.at.example.com#device-iphone-2",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:web:did.example.com:users:alice.at.example.com",
      "publicKeyMultibase": "zDEVICE_KEY_2...",
      "meta": {
        "deviceLabel": "Alice's iPhone 16",
        "registeredAt": "2026-03-13T06:00:00Z",
        "registeredVia": "webauthn"
      }
    },
    {
      "id": "did:web:did.example.com:users:alice.at.example.com#recovery-1",
      "type": "Ed25519VerificationKey2020",
      "controller": "did:web:did.example.com:users:alice.at.example.com",
      "publicKeyMultibase": "zRECOVERY_KEY...",
      "meta": {
        "deviceLabel": "Recovery key",
        "registeredAt": "2026-03-13T00:00:00Z",
        "registeredVia": "keyfile"
      }
    }
  ],
  "authentication": [
    "did:web:did.example.com:users:alice.at.example.com#device-macbook-1",
    "did:web:did.example.com:users:alice.at.example.com#device-iphone-2"
  ],
  "keyAgreement": [...],
  "recoverableIdentity": [
    "did:web:did.example.com:users:alice.at.example.com#recovery-1"
  ],
  "controller": [
    "did:web:did.example.com",
    "did:web:did.example.com:users:alice.at.example.com"
  ],
  "service": [
    {
      "id": "...#profile",
      "type": "AgoraProfile",
      "serviceEndpoint": "ipfs://bafyrei..."
    },
    {
      "id": "...#vc-status",
      "type": "EmployeeCredentialStatus",
      "serviceEndpoint": "https://verifiedid.did.msidentity.com/v1.0/.../status/..."
    }
  ]
}
```

The `meta` fields on device keys are non-standard extensions for operator tooling convenience — they help IT identify which key belongs to which device when issuing targeted revocations. They are informational only and carry no cryptographic weight. Agora clients MUST ignore unknown fields in `verificationMethod` entries.

---

## 4. Entra Verified ID: EmployeeCredential

### 4.1 Credential Schema

The org defines one credential type in Verified ID: `EmployeeCredential`. This is an org-signed assertion that the holder is a current employee with specific attributes.

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://did.example.com/credentials/employee/v1"
  ],
  "type": ["VerifiableCredential", "EmployeeCredential"],
  "issuer": "did:web:verifiedid.example.com",
  "issuanceDate": "2026-03-13T00:00:00Z",
  "expirationDate": "2027-03-13T00:00:00Z",
  "credentialSubject": {
    "id": "did:web:did.example.com:users:alice.at.example.com",
    "employeeId": "EMP-12345",
    "displayName": "Alice Smith",
    "department": "Engineering",
    "jobTitle": "Senior Engineer",
    "officeLocation": "Seattle",
    "employmentStatus": "active",
    "agoraRoles": ["member", "engineer"]
  },
  "credentialStatus": {
    "id": "https://verifiedid.did.msidentity.com/v1.0/<tenant>/status/<statusId>",
    "type": "StatusList2021Entry",
    "statusListIndex": "42",
    "statusListCredential": "https://verifiedid.did.msidentity.com/v1.0/<tenant>/statuslist"
  }
}
```

`agoraRoles` is a custom claim that the Enrollment Service reads to assign guild roles at enrollment time. Mover events update this claim by issuing a new VC with revised `agoraRoles` (and revoking the previous one).

`expirationDate` is one year from issuance. Annual re-issuance is automatic (triggered by a scheduled Lifecycle Workflow). This provides a natural re-attestation cadence without IT action for stable employees.

### 4.2 Issuance Flow

Issuance is initiated by the DID Sidecar after device key registration succeeds. The sidecar calls the Verified ID issuance API:

```
POST https://verifiedid.did.msidentity.com/v1.0/<tenant>/verifiableCredentials/createIssuanceRequest
Authorization: Bearer <app token>
Content-Type: application/json

{
  "includeQRCode": false,
  "authority": "did:web:verifiedid.example.com",
  "registration": {
    "clientName": "Agora Enrollment"
  },
  "callback": {
    "url": "https://enroll.example.com/v1/vc-callback",
    "state": "<enrollment-session-id>",
    "headers": { "Authorization": "Bearer <callback-token>" }
  },
  "type": "EmployeeCredential",
  "manifest": "https://verifiedid.example.com/v1.0/credentials/employee",
  "claims": {
    "employeeId": "EMP-12345",
    "displayName": "Alice Smith",
    "department": "Engineering",
    "jobTitle": "Senior Engineer",
    "officeLocation": "Seattle",
    "employmentStatus": "active",
    "agoraRoles": "member,engineer"
  }
}
```

Verified ID returns a deep link / QR code that the enrollment app presents to the user. The user taps it in Microsoft Authenticator, which adds the credential to their wallet. Verified ID calls back to the enrollment service when issuance completes.

The entire issuance flow happens after device key registration — the VC is the reward for completing enrollment, not a precondition for it. The precondition is a valid Entra OIDC token (proving the user can authenticate against the org's IdP), which is already required by the `agora-enroll` Teams auth adapter.

### 4.3 VC as Guild Admission Precondition (Optional Enforcement)

Guilds can optionally require a valid `EmployeeCredential` VC as an admission precondition. When this is configured, the Enrollment Service verifies the VC presentation before issuing the MLS Add commit:

```
POST /v1/enroll/register
{
  ...
  "vcPresentation": {
    "type": "VerifiablePresentation",
    "verifiableCredential": ["<JWT-encoded VC>"],
    "proof": { ... }
  }
}
```

The Enrollment Service validates:
1. VC issuer DID resolves to the expected org (`did:web:verifiedid.example.com`)
2. VC `credentialSubject.id` matches the registering DID
3. VC has not expired
4. VC status (StatusList2021) shows not revoked
5. VC `credentialSubject.employmentStatus` is `"active"`

This is optional because the Teams/Entra OIDC auth already establishes org membership. The VC check is belt-and-suspenders for high-security guilds. It also enables the Mover use case: a user whose department changes gets a new VC with updated `agoraRoles`, and guild admission policies can enforce role-based access based on VC claims rather than static provisional list entries.

---

## 5. Graph Lifecycle Workflow Integration

### 5.1 Integration Mechanism

Lifecycle Workflows support custom task extensions that call out to external systems via Azure Logic Apps, in either "launch and continue" (fire-and-forget) or "launch and wait" (synchronous with timeout) modes. The DID sidecar integration uses "launch and wait" for Joiner (so IT can confirm DID provisioning before the workflow completes) and "launch and continue" for Leaver (immediate tombstone, no need to wait for confirmation before revoking access).

A Microsoft Entra ID Governance license is required to use Lifecycle Workflows.

The Logic App is the bridge — it receives the workflow event from Entra, formats and signs a provisioning request, and calls the DID Sidecar's `/v1/provision` endpoint. The sidecar authenticates the request using the Logic App's managed identity token.

### 5.2 Joiner Workflow

**Trigger:** New user account created in Entra ID with `employeeHireDate` set.  
**Execution:** On or before hire date (configurable, default: day of hire).  
**Mode:** Launch and wait (30-second timeout).

Tasks in sequence:
1. Built-in: `EnableUserAccount`
2. Built-in: `AddUserToGroup` (add to Agora-users security group)
3. Custom: `ProvisionAgoraDID` (calls Logic App → DID Sidecar)
4. Built-in: `SendWelcomeEmail` (includes enrollment link)

The `ProvisionAgoraDID` Logic App payload:

```json
{
  "event": "joiner",
  "upn": "alice@example.com",
  "aadObjectId": "aad-uuid",
  "employeeId": "EMP-12345",
  "displayName": "Alice Smith",
  "department": "Engineering",
  "jobTitle": "Senior Engineer",
  "officeLocation": "Seattle",
  "agoraRoles": ["member", "engineer"],
  "guildURI": "agora://bafyrei.../"
}
```

DID Sidecar response (synchronous, within 30s):

```json
{
  "did": "did:web:did.example.com:users:alice.at.example.com",
  "state": "stub",
  "enrollmentURL": "https://enroll.example.com/?did=did%3Aweb%3A..."
}
```

The `enrollmentURL` is included in the welcome email sent by the subsequent built-in task. It pre-populates the enrollment app with the user's DID so they don't have to look it up.

### 5.3 Mover Workflow

**Trigger:** User attribute change — `department`, `jobTitle`, or membership in role-mapped security groups.  
**Mode:** Launch and continue.

The Mover event updates two things independently:

1. **DID document claims** — the sidecar updates the `status` service entry with new department/role attributes. (Note: these are informational only; the cryptographic keys are unchanged.)

2. **EmployeeCredential** — the sidecar calls the Verified ID API to revoke the existing VC and issue a new one with updated `agoraRoles`. The new VC is pushed to the user's wallet automatically if they have Authenticator configured for auto-accept from trusted issuers; otherwise they receive a notification.

Logic App payload:

```json
{
  "event": "mover",
  "upn": "alice@example.com",
  "aadObjectId": "aad-uuid",
  "changedAttributes": {
    "department": "Security",
    "jobTitle": "Security Engineer",
    "agoraRoles": ["member", "engineer", "security"]
  }
}
```

**Guild role update:** When `agoraRoles` changes, the Enrollment Service (notified by webhook from the sidecar) issues a guild role update commit for the user's existing MLS membership. This does not change the MLS group membership itself (the user stays in the guild) — only the Agora role claims in the guild state document are updated.

### 5.4 Leaver Workflow

**Trigger:** `employeeLeaveDateTime` reached, or on-demand execution for immediate termination.  
**Mode:** Launch and continue (fire-and-forget — do not wait for DID tombstone before revoking access).

On-demand workflow execution handles urgent events like termination without waiting for the scheduled run.

Two parallel actions execute immediately:

**Action A — VC Revocation (immediate):** The sidecar calls the Verified ID revocation API for the user's current `EmployeeCredential`. This takes effect within seconds. Any guild configured to require VC validation will reject the user's next message or MLS epoch participation check. This is the fast path — VC revocation is effective before the DID is tombstoned.

**Action B — DID Tombstone (within minutes):** The sidecar transitions the DID document to `TOMBSTONED` state, replacing it with a signed tombstone:

```json
{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:web:did.example.com:users:alice.at.example.com",
  "verificationMethod": [],
  "authentication": [],
  "service": [
    {
      "id": "...#tombstone",
      "type": "AgoraTombstone",
      "serviceEndpoint": {
        "reason": "employment-ended",
        "tombstonedAt": "2026-03-13T00:00:00Z",
        "tombstonedBy": "did:web:did.example.com"
      }
    }
  ],
  "controller": "did:web:did.example.com"
}
```

The HTTP endpoint returns `410 Gone` with this document as the body. Agora clients that receive a 410 on DID resolution MUST treat the identity as permanently invalid and issue MLS Remove commits for all groups that identity belongs to.

**Action C — MLS Removal (async, via Enrollment Service):** The sidecar notifies the Enrollment Service, which issues MLS Remove commits for the user from all guilds they are a member of. This is the cryptographic enforcement — after the Remove commits propagate, the user's device keys literally cannot decrypt new messages even if they retain a copy of their private key.

Logic App payload for Leaver:

```json
{
  "event": "leaver",
  "upn": "alice@example.com",
  "aadObjectId": "aad-uuid",
  "reason": "termination",
  "effectiveAt": "2026-03-13T00:00:00Z",
  "revokeVCImmediately": true,
  "tombstoneGracePeriodSeconds": 0
}
```

For voluntary departures, `tombstoneGracePeriodSeconds` may be set to a positive value (e.g. 86400 for a 24-hour grace) to allow orderly knowledge transfer. For involuntary terminations, it is 0.

### 5.5 Lost Device Workflow

This workflow is triggered on-demand by IT (via the Entra admin portal, the sidecar admin UI, or an MDM system like Intune via Graph API).

It does not use Lifecycle Workflows — it calls the DID Sidecar directly via an admin API call authenticated with an Entra admin token:

```
POST /v1/revoke-device-key
Authorization: Bearer <admin-token>
Content-Type: application/json

{
  "upn": "alice@example.com",
  "keyId": "did:web:did.example.com:users:alice.at.example.com#device-macbook-1",
  "reason": "lost-device",
  "revokedBy": "helpdesk@example.com"
}
```

The sidecar:
1. Removes the specified `verificationMethod` entry from the DID document
2. Removes it from the `authentication` array
3. Logs the revocation with timestamp, reason, and revoking admin
4. Notifies the Enrollment Service, which issues MLS Update commits to remove that device's leaf node from all groups

Other device keys (the user's phone, their recovery key) are unaffected. The user retains access via their other enrolled devices and can re-enroll the lost device after obtaining a replacement.

If the revoked key was the user's only device key, the document transitions to `STUB` state and the user must re-enroll. The user's DID is preserved — they do not lose guild membership, only the ability to send and receive messages until re-enrollment.

### 5.6 MFA Step-Up for Device Key Registration

Device key registration (the moment a new device public key is written to the DID document) is the highest-stakes operation in the system — a successful registration grants a new device full access to all the user's guilds. It requires step-up MFA regardless of the user's current session MFA state.

The DID Sidecar enforces this by requiring a step-up token: a short-lived Entra ID token issued with the `acr` claim set to `"mfa"` and the `amr` array including a phishing-resistant method (`"hwk"` for Windows Hello, `"fido"` for FIDO2/WebAuthn).

```
POST /v1/register-device-key
Authorization: Bearer <step-up-token>
Content-Type: application/json

{
  "upn": "alice@example.com",
  "devicePublicKey": "zDEVICE_KEY...",
  "deviceLabel": "Alice's MacBook Pro",
  "registeredVia": "webauthn",
  "vcPresentation": { ... },
  "proofOfPossession": "..."
}
```

The sidecar validates:
1. Token `acr` is `"mfa"` 
2. Token `amr` includes `"hwk"` or `"fido"` (password-only MFA is not sufficient)
3. Token `oid` matches the UPN in the request body
4. `vcPresentation` is a valid, non-expired, non-revoked `EmployeeCredential`
5. `proofOfPossession` is a valid Ed25519 signature by `devicePublicKey` over the canonical proof payload

Only after all five checks pass does the sidecar write the new key to the DID document.

---

## 6. DID Sidecar Service

### 6.1 Endpoints

```
# Public (no auth)
GET  /users/{upn-encoded}/did.json     Serve DID document

# Enrollment (Entra OIDC token, step-up MFA required)
POST /v1/register-device-key           Register a new device key
DELETE /v1/device-key/{keyId}          Self-service device key removal

# Admin (Entra admin token, Authentication Policy Administrator role)
POST /v1/provision                     JML event receiver (from Logic App)
POST /v1/revoke-device-key             IT-initiated device key tombstone
POST /v1/tombstone                     IT-initiated full DID tombstone
POST /v1/suspend                       Suspend DID (leave of absence, etc.)
POST /v1/reactivate                    Reactivate suspended DID
GET  /v1/audit/{upn}                   Full audit log for a user's DID
GET  /v1/status/{upn}                  Current DID state

# Enrollment Service webhook (internal, mTLS)
POST /v1/internal/enrollment-complete  Called by Enrollment Service post-MLS-Add
POST /v1/internal/mls-remove-ack       Acknowledgment of MLS Remove commit
```

### 6.2 Authentication

| Endpoint group | Auth mechanism | Required claims |
|---|---|---|
| Public DID documents | None | — |
| Device key registration | Entra OIDC bearer token | `acr: mfa`, `amr: [hwk|fido]`, `oid` matches UPN |
| Admin operations | Entra bearer token | `Authentication Policy Administrator` role or custom `AgoraDIDAdmin` app role |
| Logic App bridge | Entra managed identity token | `AgoraDIDProvisioner` app role |
| Enrollment Service webhook | mTLS with pre-shared cert | — |

### 6.3 Storage

The sidecar stores DID documents and audit logs. Two deployment options:

**Azure Blob Storage (preferred for Azure deployments):**  
One blob per user at `did-documents/{upn-encoded}/current.json`. Historical versions at `did-documents/{upn-encoded}/history/{seq}.json`. Audit log at `did-documents/{upn-encoded}/audit.jsonl`.

**PostgreSQL:**  
Table `did_documents(upn TEXT PK, state TEXT, document JSONB, seq INT, updated_at TIMESTAMPTZ)`. Table `did_audit(id BIGSERIAL, upn TEXT, event TEXT, actor TEXT, payload JSONB, ts TIMESTAMPTZ)`.

The sidecar's data store is the authoritative source. The DID documents it serves are derived directly from this store with no caching layer — stale DID documents are a security risk (a tombstoned identity served as active could allow a terminated employee to keep sending messages). Response headers include `Cache-Control: no-store, no-cache` on all DID document endpoints.

### 6.4 UPN Change Handling (Mover edge case)

When a UPN changes:

1. Sidecar provisions the new DID document at the new path (`STUB` state)
2. Sidecar publishes a `did:web` `alsoKnownAs` entry in the old document pointing to the new DID
3. Sidecar signs a `RecoveryAssertion` (Agora spec §2.4.1) using the org's revocation key, asserting that the new DID supersedes the old one
4. Gossips the `RecoveryAssertion` to the Relay(s) the user's guilds use
5. Old DID document transitions to `TOMBSTONED` after a 30-day grace period, with a `410 Gone` response and a `Link: <new-did-document-url>; rel="successor"` header

The user's Agora client detects the `RecoveryAssertion` on next connection, updates its local identity record, and the guild state reflects the new DID. The user does not need to re-enroll device keys — the sidecar copies all `verificationMethod` entries from the old document to the new one as part of the UPN change operation.

---

## 7. Entra App Registration

The DID Sidecar requires one Entra app registration with:

**Expose an API:**
```
Application ID URI: api://did.example.com
Scope: AgoraDIDAdmin   (for IT admin operations)
Scope: AgoraDIDProvisioner  (for Logic App managed identity)
```

**App roles:**
```
AgoraDIDAdmin        — assigned to helpdesk/IT security groups
AgoraDIDProvisioner  — assigned to Logic App managed identity
```

**API permissions (for the sidecar to call outbound):**
```
Microsoft Graph:
  User.Read.All              (read user attributes for provisioning)
  AuditLog.Read.All          (read sign-in logs for device registration audit)

Verified ID Service Admin:
  VerifiableCredential.Authority.ReadWrite   (issue/revoke EmployeeCredential)
  VerifiableCredential.Credential.Revoke     (revoke individual credentials)
```

All permissions are application permissions (not delegated) — the sidecar runs as a service with no user context.

---

## 8. License Requirements

| Feature | Required License |
|---|---|
| Lifecycle Workflows (JML automation) | Microsoft Entra ID Governance (P2+) |
| Entra Verified ID | Included in Microsoft Entra ID (all tiers for basic issuance) |
| Conditional Access (MFA step-up enforcement) | Microsoft Entra ID P1 |
| Custom task extensions (Logic App bridge) | Microsoft Entra ID Governance |
| Verified ID Face Check (for high-assurance re-enrollment) | Verified ID premium add-on |

The minimum viable deployment requires **Entra ID P1** (MFA step-up) and **Entra ID Governance** (Lifecycle Workflows). P2 adds risk-based conditional access, which can strengthen the step-up policy for device key registration.

---

## 9. Implementation Notes

### 9.1 Language and Stack

The DID Sidecar is a Go service deployed as an Azure Container App or Azure App Service. It uses:

| Function | Library |
|---|---|
| HTTP server | `net/http` (stdlib) |
| Entra token validation | `github.com/AzureAD/microsoft-authentication-library-for-go` |
| Azure Blob client | `github.com/Azure/azure-sdk-for-go/sdk/storage/azblob` |
| Verified ID API | HTTP client against `verifiedid.did.msidentity.com` |
| Ed25519 | `crypto/ed25519` (stdlib) |
| JSON-LD | `github.com/piprate/json-gold` |

### 9.2 Logic App

The JML Logic App is a Consumption-tier Logic App with:
- HTTP trigger (receives from Lifecycle Workflows custom task extension)
- Managed identity authentication to call DID Sidecar
- "Launch and wait" response sent back to Lifecycle Workflows on Joiner
- "Launch and continue" on Leaver (no response needed)

The Logic App contains no business logic — it is a thin authenticated bridge. All logic lives in the sidecar.

---

## 10. Open Questions

1. **Verified ID VC auto-accept in Authenticator.** Authenticator supports auto-accept of VCs from trusted issuers, but this requires the user to have configured the trust relationship. For a corporate deployment, this can be pushed via Intune MDM policy. The issuance UX during enrollment depends on this being configured; without it, the user gets a notification requiring manual tap. The spec assumes MDM-managed Authenticator; unmanaged devices need a documented fallback.

2. **StatusList2021 revocation scalability.** The Verified ID service uses StatusList2021 for VC revocation status. Each status list holds up to 131,072 entries and is served as a public URL. For large orgs this is fine. For orgs with privacy concerns about the status list being publicly enumerable (an external party can observe which entries are revoked over time), the Bitstring Status List spec (the StatusList2021 successor) adds encrypted status entries. This is worth monitoring.

3. **Non-Authenticator wallets.** The spec assumes Microsoft Authenticator as the VC wallet. The Verified ID service supports OID4VC-compliant third-party wallets in principle, but compatibility varies. Orgs that want employees to use a different wallet (e.g., a corporate-branded wallet) need to validate against the specific Verified ID API version in use.

4. **On-premises AD hybrid identity.** Orgs with on-premises AD synced to Entra via Entra Connect have UPNs controlled by on-prem AD. UPN changes on-prem propagate to Entra via sync, which can trigger the Mover workflow. The sync interval (default 30 minutes) introduces a lag between the on-prem change and the DID update. For terminations, this lag is a risk — the spec calls for immediate on-demand workflow execution to bypass the sync cycle, but this requires the termination to be processed in Entra ID directly (or the HR system to trigger both on-prem and Entra simultaneously).

5. **Intune integration for device key registration.** The spec requires phishing-resistant MFA (`hwk` or `fido`) for device key registration. On Intune-managed devices, Windows Hello for Business satisfies this automatically. On unmanaged or BYOD devices, a FIDO2 security key is the only option. The org must decide whether to allow BYOD enrollment or require managed devices — this is a policy decision that affects the enrollment UX significantly.
