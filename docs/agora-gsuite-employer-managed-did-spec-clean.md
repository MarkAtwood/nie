# Specification: Employer-Managed DIDs via Google Workspace

**Version:** 0.1 Draft
**Depends On:** Agora Protocol Spec v0.1, `agora-enroll` spec v0.1, O365 Employer-Managed DID spec v0.1
**Status:** Pre-implementation design

---

## 1. Architecture Overview

The Google Workspace architecture is structurally parallel to the O365 spec but collapses the two-component model (Verified ID + DID Sidecar) into one. Google has no native verifiable credential issuance platform and no declarative JML workflow engine. The DID Sidecar carries all three responsibilities that the O365 architecture distributes across three components:

| Concern | O365 Component | Google Workspace Component |
| ------- | -------------- | -------------------------- |
| DID document hosting | DID Sidecar | DID Sidecar |
| Org attestation / VC issuance | Entra Verified ID | DID Sidecar (self-issued VC) |
| JML lifecycle automation | Graph Lifecycle Workflows + Logic App | DID Sidecar (Directory API push + polling fallback) |

The VC layer uses the W3C VC Data Model with the org's own `did:web` as issuer. JML automation uses the Directory API push notification channel plus a daily reconciliation polling loop as a reliability backstop, because the push channel expires and has delivery lag.

```
┌──────────────────────────────────────────────────────────────┐
│  Google Workspace Tenant                                     │
│                                                              │
│  ┌────────────────────┐   ┌────────────────────────────┐    │
│  │  Admin SDK         │   │  Google OAuth 2.0 / OIDC   │    │
│  │  Directory API     │   │  (employee authentication) │    │
│  │  (Users resource)  │   └──────────────┬─────────────┘    │
│  └─────────┬──────────┘                  │                   │
│            │ push notifications           │ id_token          │
└────────────┼─────────────────────────────┼───────────────────┘
             │                             │
             ▼                             ▼
┌──────────────────────────────────────────────────────────────┐
│  DID Sidecar  (operator-hosted, registered as GCP OAuth app) │
│                                                              │
│  GET  /users/{email-encoded}/did.json   Serve DID document   │
│  GET  /.well-known/did.json             Org root DID         │
│  GET  /.well-known/did-configuration.json  Domain linkage    │
│  POST /v1/notify                        Directory API push   │
│  POST /v1/register-device-key           Device key reg       │
│  POST /v1/revoke-device-key             IT key tombstone      │
│  POST /v1/tombstone                     Full DID revocation   │
│  POST /v1/suspend                       Suspend DID           │
│  POST /v1/reactivate                    Reactivate DID        │
│  GET  /v1/credentials/:email/employee   Serve employee VC     │
│  GET  /v1/status/:email                 DID state            │
│  GET  /v1/audit/:email                  Audit log            │
│                                                              │
│  Background workers:                                         │
│  - Channel renewal (refreshes push subscription)            │
│  - Reconciliation poller (daily full Directory API scan)     │
│  - VC expiry reissuance (annual re-attestation)              │
└──────────────────────────────────────────────────────────────┘
```

---

## 2. Google Workspace API Access

### 2.1 OAuth Scopes

The DID Sidecar authenticates to Google using a service account with domain-wide delegation. The following scopes are required:

| Scope | Purpose |
| ----- | ------- |
| `https://www.googleapis.com/auth/admin.directory.user.readonly` | Read user records for provisioning |
| `https://www.googleapis.com/auth/admin.directory.user` | Watch Users resource for push notifications |
| `https://www.googleapis.com/auth/admin.directory.group.readonly` | Read group membership for role derivation |
| `https://www.googleapis.com/auth/admin.reports.audit.readonly` | Read Admin Audit log (login events, account changes) |

Domain-wide delegation MUST be granted in the Google Admin console (`Security → API controls → Domain-wide delegation`). The service account MUST be granted the `User Management Admin` role.

### 2.2 Push Notification Channel

The Directory API supports push notifications for changes to the Users resource via a webhook callback URL registered as a notification channel. The sidecar MUST register a channel on startup and renew it before expiry.

Channel registration request:

```http
POST https://admin.googleapis.com/admin/directory/v1/users/watch
Authorization: Bearer <service-account-token>
Content-Type: application/json

{
  "id": "agora-did-sidecar-channel-<uuid>",
  "type": "web_hook",
  "address": "https://did.example.com/v1/notify",
  "token": "<secret-token>",
  "expiration": <unix-ms + 7 days>
}
```

Push notification channels expire. The sidecar MUST run a background worker that renews the channel 24 hours before expiry. If renewal fails, the sidecar MUST fall back to the reconciliation poller (§2.3) until the channel is re-established. Channel expiry MUST trigger a monitoring alert; IT SHOULD be notified if the sidecar has operated in polling-only mode for more than one hour.

The webhook endpoint MUST verify incoming requests by comparing the `X-Goog-Channel-Token` header against the registered `token` value. Requests with an invalid or missing token MUST be rejected with HTTP 403.

Directory API push notifications are minimal: they carry the changed resource's ID and state (`exists` or `not_exists`), not the full user object. On receipt, the sidecar MUST fetch the full user record via `GET /admin/directory/v1/users/{userId}` before acting.

### 2.3 Reconciliation Poller

The reconciliation poller runs daily (configurable; default 02:00 local time) and performs a full directory scan:

```http
GET https://admin.googleapis.com/admin/directory/v1/users
    ?domain=example.com&maxResults=500&orderBy=email
```

The poller compares the full user list against the sidecar's DID document registry and reconciles discrepancies:

- A user present in the Directory but absent from the sidecar MUST be provisioned as a stub DID (Joiner missed by push).
- A user in the sidecar with `ACTIVE` or `STUB` state but suspended in the Directory MUST be transitioned to `SUSPENDED`.
- A user in the sidecar with `ACTIVE` or `STUB` state but deleted from the Directory MUST be tombstoned immediately.
- A user in the sidecar with `SUSPENDED` state but active in the Directory MUST be reactivated.

The reconciliation poller is the reliability backstop, not the primary path. Worst-case latency from a leaver event to DID tombstone via the poller is 24 hours (push channel down, event missed, poller not yet run). §4.4 documents VC revocation as the fast enforcement path for this reason.

---

## 3. DID Document Structure

The DID document structure is identical to the O365 spec (§3) with the following two differences.

### 3.1 DID Naming

Each employee DID uses their Google Workspace primary email encoded into the path:

```
alice@example.com  →  did:web:did.example.com:users:alice.at.example.com
```

The encoding rule is the same as O365: `@` maps to `.at.`; other non-alphanumeric characters map to `-`. The corresponding URL is:

```
https://did.example.com/users/alice.at.example.com/did.json
```

The `primaryEmail` field from the Directory API `users.list` resource is the canonical identifier. This is stable unless the user's primary email changes; email changes are treated as Mover events (§4.3).

### 3.2 Org Root DID

The org root DID is served at:

```
https://did.example.com/.well-known/did.json
```

This is the org's signing identity for EmployeeCredential issuance. It carries one key: the org's Ed25519 signing key, stored in Google Cloud KMS.

A Well-Known DID Configuration document, following the W3C CCG DID Configuration spec, links the org's DID to its domain:

```
https://did.example.com/.well-known/did-configuration.json
```

```json
{
  "@context": "https://identity.foundation/.well-known/did-configuration/v1",
  "linked_dids": [
    "<JWT signed by org signing key, binding did:web:did.example.com to https://did.example.com>"
  ]
}
```

This domain binding allows VC verifiers to confirm that the issuer DID is legitimately controlled by the domain operator without trusting any external registry.

---

## 4. JML Lifecycle Automation

There is no declarative workflow engine in the Google Workspace architecture. All JML logic resides in the sidecar's event handler, which processes Directory API push notifications and reconciliation scan results through the same code path.

### 4.1 Event Handler

```go
type DirectoryEvent struct {
    Kind             string   // "admin#directory#user"
    ID               string   // Google unique user ID (stable, unlike email)
    PrimaryEmail     string
    Suspended        bool
    Deleted          bool     // inferred from 404 on fetch after not_exists notification
    OrgUnitPath      string
    CustomAttributes map[string]interface{}
    Groups           []string // fetched separately from groups.list
}

func (s *Sidecar) handleEvent(event DirectoryEvent) error {
    existing := s.store.Get(event.ID)

    switch {
    case event.Deleted && existing != nil:
        return s.tombstone(existing, "directory-deletion")

    case event.Suspended && existing != nil && existing.State == StateActive:
        return s.suspend(existing, "directory-suspension")

    case !event.Suspended && existing != nil && existing.State == StateSuspended:
        return s.reactivate(existing)

    case existing == nil && !event.Deleted && !event.Suspended:
        return s.provision(event)  // new user

    case existing != nil && s.claimsChanged(existing, event):
        return s.updateClaims(existing, event)  // Mover
    }
    return nil
}
```

The handler MUST be idempotent: running it twice on the same event MUST produce the same result. Push notifications MAY be delivered more than once.

### 4.2 Joiner

Triggered by a push notification for a new user, or by the reconciliation poller finding a user in the Directory that is absent from the sidecar.

Actions:

1. Fetch the full user record including custom schema attributes (§4.6) and group memberships.
2. Derive Agora roles from group membership (§4.7).
3. Provision a stub DID document (state: `STUB`).
4. Store the user record in the sidecar DB keyed by Google user ID (stable through email changes).
5. Send an enrollment invitation email via Google Workspace SMTP relay or Gmail API, including an enrollment URL pre-populated with the user's DID.

The enrollment invitation email is sent using the Gmail API with domain-wide delegation, impersonating an admin account or a dedicated `noreply@example.com` address. Example:

```
Subject: Your Agora encrypted workspace is ready

Hi Alice,

Your organization has set up end-to-end encrypted communication via Agora.
Click the link below to enroll your device:

https://enroll.example.com/?did=did%3Aweb%3Adid.example.com%3Ausers%3Aalice.at.example.com

This link expires in 7 days. If you need a new link, contact IT.
```

### 4.3 Mover

Triggered by a push notification for an existing user with changed attributes (`orgUnitPath`, custom schema attributes, or group membership changes).

Group membership changes do not trigger a user-level push notification — the Directory API push fires only on user object changes. The sidecar MUST therefore poll `groups.list` on a configurable schedule (default: 1 hour) for users with active DID documents, comparing group membership against stored state. This is the primary limitation relative to the O365 Mover workflow, which triggers declaratively on group membership changes.

Actions:

1. Derive updated Agora roles from new group membership.
2. Update the `status` service entry in the DID document with new claims.
3. Revoke the existing `EmployeeCredential` VC (mark the status entry as revoked in the status list).
4. Issue a new `EmployeeCredential` VC with updated `agoraRoles` and department claims.
5. Notify the Enrollment Service via webhook to update space role assignments.

### 4.4 Leaver

Triggered by a push notification for a user with `suspended: true` (soft leaver) or a deleted user (hard leaver), or by the reconciliation poller finding a discrepancy.

Google has no real-time termination trigger equivalent to Entra Lifecycle Workflows' on-demand execution, and the push notification channel has delivery lag. The fast enforcement path is VC revocation, which the sidecar MUST execute immediately on receiving a suspension or deletion notification, before the DID is tombstoned.

**Phase 1 — Immediate** (on notification receipt; target latency: <30 seconds):

- Mark the `EmployeeCredential` status entry as revoked in the status list.
- Transition the DID document to `SUSPENDED` (soft leaver) or `TOMBSTONED` (hard leaver).
- Notify the Enrollment Service to initiate MLS Remove commits.

**Phase 2 — Confirmed** (after the reconciliation poller next runs, or on explicit IT action):

- Verify deletion or suspension state against the live Directory API.
- Confirm MLS Remove commits have propagated (via Enrollment Service ACK).
- Log the final leaver audit record.

**Soft vs. hard leaver:**

- `suspended: true` → transition to `SUSPENDED`; preserve device keys in DB. If the user is later reactivated (`suspended: false`), keys are restored and the document returns to `ACTIVE`.
- Deletion from Directory → tombstone immediately. Device keys are archived (not deleted) for compliance audit purposes.

**Worst-case latency:** If the push channel is down and the poller has not run, a terminated employee retains an active DID for up to 24 hours. This is an accepted operational risk. IT MUST call `POST /v1/tombstone` directly with an admin token for immediate effect when performing involuntary terminations, bypassing the automated path.

### 4.5 Lost Device

Initiated directly by IT via the sidecar admin API, identical to O365 spec §5.5:

```http
POST /v1/revoke-device-key
Authorization: Bearer <admin-token>
Content-Type: application/json

{
  "email": "alice@example.com",
  "keyId": "did:web:did.example.com:users:alice.at.example.com#device-macbook-1",
  "reason": "lost-device",
  "revokedBy": "helpdesk@example.com"
}
```

The admin token is a Google OAuth token with the `AgoraDIDAdmin` scope (§7), obtained via the standard Google OAuth device flow or browser-based consent for IT staff.

### 4.6 Custom Schema Attributes

Google Workspace supports custom schema attributes on user objects. The sidecar reads these for DID provisioning and VC claim population. Recommended schema:

```
Schema name: AgoraIdentity
Fields:
  - agoraRoles (string, multi-value)     — explicit role override
  - agoraDIDState (string)               — admin override for DID state
  - agoraEnrollmentExpiry (string, date) — enrollment link expiry date
```

Custom schemas are optional. When absent, roles are derived entirely from group membership (§4.7). The `agoraDIDState` field allows an admin to force-suspend or force-tombstone a DID from the Google Admin console without API access.

### 4.7 Role Derivation from Groups

When custom schema attributes are absent, the sidecar derives Agora roles from Google Workspace group membership using a configurable mapping:

```toml
[roles]
# Group email → Agora role name
"agora-admins@example.com"     = "admin"
"agora-moderators@example.com" = "moderator"
"agora-members@example.com"    = "member"
"agora-guests@example.com"     = "guest"
# Default role for users not in any of the above groups:
default = "member"
```

A user's Agora roles are the union of all matched group mappings. A user in both `agora-moderators` and `agora-members` has roles `["moderator", "member"]`.

---

## 5. EmployeeCredential Issuance

### 5.1 Self-Issued VC

The sidecar issues `EmployeeCredential` VCs directly, signed by the org root DID's Ed25519 key stored in Google Cloud KMS. The credential schema is identical to the O365 spec (§4.1) with the issuer DID changed:

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://did.example.com/credentials/employee/v1"
  ],
  "type": ["VerifiableCredential", "EmployeeCredential"],
  "issuer": "did:web:did.example.com",
  "issuanceDate": "2026-03-13T00:00:00Z",
  "expirationDate": "2027-03-13T00:00:00Z",
  "credentialSubject": {
    "id": "did:web:did.example.com:users:alice.at.example.com",
    "employeeId": "EMP-12345",
    "displayName": "Alice Smith",
    "department": "Engineering",
    "jobTitle": "Senior Engineer",
    "employmentStatus": "active",
    "agoraRoles": ["member", "engineer"]
  },
  "credentialStatus": {
    "id": "https://did.example.com/v1/status/2026#42",
    "type": "StatusList2021Entry",
    "statusListIndex": "42",
    "statusListCredential": "https://did.example.com/v1/status/2026"
  }
}
```

### 5.2 Status List

The sidecar maintains a StatusList2021 credential for VC revocation. The status list is a bitstring where each bit corresponds to one VC's revocation status, served publicly at:

```
GET https://did.example.com/v1/status/2026
→ StatusList2021Credential (JWT-encoded, signed by org key)
```

One status list is maintained per year (configurable), with a maximum of 131,072 entries. Status list indices are assigned at VC issuance and MUST NOT be reused. The status list MUST be regenerated and re-signed whenever a VC is revoked.

**Privacy note:** A public status list is observable — an external party can infer employee terminations by monitoring newly flipped bits. For orgs with privacy requirements, the Bitstring Status List spec (the StatusList2021 successor) supports encrypted status entries. Migration is a matter of changing the served format and updating the `type` field; the `statusListCredential` pointer in the credential schema is unchanged.

### 5.3 VC Delivery

The sidecar has no push wallet to deliver VCs to. Three delivery options are supported:

**Option A — Deep link in enrollment email:** The enrollment invitation includes a second link for VC acceptance. When clicked, the browser calls the sidecar's issuance endpoint, which returns the signed VC as a JSON file download for import into a W3C VC-compatible wallet.

**Option B — Agora client built-in wallet:** The Agora client (web or CLI) stores the `EmployeeCredential` in its local keystore alongside device keys and presents the VC automatically during space enrollment. This option requires no external wallet app and keeps the credential collocated with the keys it attests.

**Option C — OID4VCI:** The sidecar implements the OpenID for Verifiable Credential Issuance protocol, allowing any OID4VCI-compatible wallet to pull the VC via a standard issuance flow. This is the most interoperable option and the correct long-term path as wallet support matures.

For initial deployment, Option B is the recommended choice. Options A and C are extensions for orgs with existing wallet infrastructure.

### 5.4 VC Serving Endpoint

```http
GET /v1/credentials/{email-encoded}/employee
Authorization: Bearer <employee's Google OAuth token>

→ 200 OK
Content-Type: application/json

{
  "credential": "<JWT-encoded VC>",
  "format": "jwt_vc_json"
}
```

Only the credential subject MAY fetch their own VC (the token `sub` MUST match the credential subject's email). Admins with the `AgoraDIDAdmin` role MAY fetch any user's VC for audit purposes.

---

## 6. MFA Step-Up for Device Key Registration

Google does not provide `acr`/`amr` claims in standard OAuth tokens for most Workspace tiers. The step-up enforcement mechanism varies by Workspace edition.

**Enterprise Plus / Frontline:** Context-Aware Access (CAA) policies MAY require hardware security key (`FIDO2`) authentication as a condition for accessing specific OAuth scopes. A CAA policy SHOULD require `security_key` device assurance for the `AgoraDIDKeyRegistration` custom scope. When the enrollment app requests this scope, Google enforces the hardware key requirement at the OAuth consent step.

**Business Starter / Standard / Plus (no CAA):** The sidecar MUST enforce step-up via a challenge-response. On device key registration, the sidecar issues a 32-byte challenge, requires the user to sign it using their WebAuthn credential (browser path) or PKCS#11 key (CLI path), and verifies the signature before writing the key to the DID document. This is equivalent to the WebAuthn proof-of-possession check in the `agora-enroll` spec §5 and does not depend on the Google OAuth token carrying MFA claims.

The WebAuthn / PKCS#11 proof-of-possession check (as specified in `agora-enroll` §8) applies in both cases. CAA-based enforcement is an additional layer for Enterprise Plus deployments.

```toml
[enrollment]
mfa_enforcement = "webauthn-pop"   # always require WebAuthn proof-of-possession
# mfa_enforcement = "caa-scope"   # Enterprise Plus: rely on CAA + WebAuthn PoP
```

---

## 7. GCP App Registration and Service Account

### Service Account (Directory API access)

- Created in the GCP project linked to the Workspace tenant.
- Domain-wide delegation granted in Google Admin console.
- Scopes: as listed in §2.1.
- Key: JSON service account key stored in Secret Manager, rotated annually.

### OAuth 2.0 Client ID (employee authentication during enrollment)

- Application type: Web application.
- Authorized redirect URIs: `https://enroll.example.com/v1/enroll/callback`.
- Scopes requested at enrollment: `openid profile email`.

### Custom OAuth Scope (device key registration step-up, Enterprise Plus only)

- Defined as a custom app scope in the GCP project.
- Name: `AgoraDIDKeyRegistration`.
- CAA policy in Google Admin MUST require `security_key` device assurance for this scope.

### Cloud KMS (org root DID signing key)

- Key ring: `agora-did-keys`.
- Key: `org-root-signing-key` (Ed25519, HSM-backed).
- IAM: sidecar service account MUST have `roles/cloudkms.signerVerifier`.

### Secret Manager

- `agora-did-service-account-key`: service account JSON key.
- `agora-did-webhook-token`: Directory API push channel secret token.
- `agora-did-enrollment-client-secret`: OAuth client secret.

---

## 8. DID Sidecar Deployment

The sidecar deploys as a Cloud Run service or GKE workload. Cloud Run is recommended for most deployments: it handles TLS termination, scales automatically, and supports workload identity in place of a JSON key file.

```yaml
# cloud-run-service.yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: agora-did-sidecar
spec:
  template:
    metadata:
      annotations:
        run.googleapis.com/service-account: agora-did-sidecar@project.iam.gserviceaccount.com
    spec:
      containers:
        - image: gcr.io/project/agora-did-sidecar:latest
          env:
            - name: WORKSPACE_DOMAIN
              value: "example.com"
            - name: DID_BASE_URL
              value: "https://did.example.com"
            - name: KMS_KEY_NAME
              value: "projects/project/locations/global/keyRings/agora-did-keys/cryptoKeys/org-root-signing-key/cryptoKeyVersions/1"
            - name: STORAGE_BACKEND
              value: "cloudsql"    # or "cloudspanner" for higher scale
```

**Storage:** Cloud SQL (PostgreSQL) for most deployments. Schema is identical to the O365 sidecar PostgreSQL option.

**Background workers:** Cloud Scheduler triggers Cloud Tasks for the reconciliation poller and channel renewal worker. These run as separate invocations of the same service binary, not as persistent goroutines in the main serving instance.

---

## 9. Differences from O365 Architecture

| Aspect | O365 | Google Workspace |
| ------ | ---- | ---------------- |
| JML automation | Graph Lifecycle Workflows (declarative, UI-configurable) | Directory API push + sidecar event handler (code) |
| JML reliability | Push + Logic App retry + Entra audit log | Push + polling fallback (24h worst-case lag) |
| Immediate termination | On-demand Lifecycle Workflow execution (seconds) | IT calls `/v1/tombstone` directly (manual step) |
| VC issuance | Entra Verified ID (managed service, Authenticator wallet) | Sidecar self-issued VC, Agora client wallet |
| VC revocation speed | StatusList2021 via Verified ID (seconds) | StatusList2021 served by sidecar (seconds — same) |
| MFA step-up enforcement | Entra Conditional Access (`acr`/`amr` claims, all tiers) | CAA (Enterprise Plus only) or WebAuthn PoP (all tiers) |
| Org signing key | Azure Key Vault (managed) | Google Cloud KMS (managed — equivalent) |
| Hosting | Azure Container Apps / App Service | Cloud Run / GKE |
| License cost | Entra ID P1 + Entra ID Governance | Workspace Enterprise Plus for CAA; otherwise no extra license |
| Group membership change detection | Declarative (Mover workflow triggers on group change) | Polling (1-hour default lag for role updates) |

For high-security deployments where role changes require immediate enforcement, the group membership polling interval MAY be shortened to 5 minutes at the cost of increased Directory API quota consumption.

---

## 10. Implementation Notes

### 10.1 Shared Codebase with O365 Sidecar

The DID Sidecar is the same Go binary for both O365 and Google Workspace deployments. Platform-specific behavior is isolated behind interfaces:

```go
type IdentityProvider interface {
    // WatchUsers registers a push notification channel or polling subscription.
    WatchUsers(ctx context.Context, callbackURL string) error

    // GetUser fetches the current user record by stable ID.
    GetUser(ctx context.Context, id string) (*UserRecord, error)

    // ListUsers returns all active users in the domain.
    ListUsers(ctx context.Context) ([]*UserRecord, error)

    // GetGroupsForUser returns group names/emails for a user.
    GetGroupsForUser(ctx context.Context, id string) ([]string, error)
}

type CredentialSigner interface {
    // Sign produces an Ed25519 signature using the org root key.
    Sign(ctx context.Context, payload []byte) ([]byte, error)

    // PublicKey returns the org root signing public key.
    PublicKey(ctx context.Context) (ed25519.PublicKey, error)
}
```

Implementations:

- `EntraIdentityProvider` — uses Microsoft Graph
- `WorkspaceIdentityProvider` — uses Admin SDK Directory API
- `AzureKeyVaultSigner` — uses Azure Key Vault
- `CloudKMSSigner` — uses Google Cloud KMS

### 10.2 Key Dependencies (Google Workspace)

| Function | Library |
| -------- | ------- |
| Google Admin SDK | `google.golang.org/api/admin/directory/v1` |
| Google OAuth2 | `golang.org/x/oauth2/google` |
| Cloud KMS | `cloud.google.com/go/kms/apiv1` |
| Cloud SQL | `cloud.google.com/go/cloudsql` |
| W3C VC issuance | Internal implementation over `crypto/ed25519` |
| StatusList2021 | Internal implementation (bitstring + JWT signing) |

---

## 11. Open Questions

1. **Google Workspace Events API vs. Directory API push.** The newer Google Workspace Events API (`workspace.googleapis.com`) supports subscriptions to changes across Workspace applications and may eventually supersede the Directory API's per-resource push channels. It currently supports Chat, Meet, and limited Workspace resources; Directory/user events may be added. The sidecar's `IdentityProvider` interface is designed so migration is a drop-in replacement rather than a rewrite.

2. **Primary email as DID path.** Using the primary email in the DID path creates a forward dependency: if Google ever supports non-email-based primary identifiers, the naming convention breaks. The internal sidecar DB always keys on Google's stable user ID (the `id` field in the Directory API, which does not change with email changes). The DID path is derived from the current email at provisioning time and does not change unless an explicit Mover email-change event occurs. This is a known limitation.

3. **OID4VCI implementation scope.** §5.3 Option C identifies OID4VCI as the long-term VC delivery path but defers implementation. When implemented, the sidecar acts as an OID4VCI Authorization Server and Credential Issuer. The OAuth authorization server endpoint is the same Google OAuth app used for enrollment auth; the credential endpoint is `/v1/credentials/{email-encoded}/employee`. The primary outstanding question is wallet interoperability: no widely-deployed mobile wallet currently handles org-issued `EmployeeCredential` types with custom `credentialSubject` schemas.

4. **Restricted Workspace editions.** The Admin SDK Directory API is available on all Workspace editions, but domain-wide delegation requires a Super Admin to configure it. The service account JSON key approach (§7) works on all editions. The Cloud KMS dependency requires a linked GCP project, which is standard for Workspace Business/Enterprise but may require additional setup for legacy G Suite Basic accounts.

5. **HR system integration.** Both this spec and the O365 spec treat the directory as the system of record, but most orgs use an HRIS (Workday, BambooHR, etc.) as the upstream source of truth, synced into the directory. Sync lag between the HRIS and the directory adds latency on top of the push notification lag. For regulated environments where termination must be effective within minutes of an HRIS update, a direct HRIS webhook to the sidecar — bypassing the directory — is a candidate extension.
