# Specification: Employer-Managed DIDs — Universal Identity Provider Support

**Version:** 0.1 Draft
**Depends On:** Agora Protocol Spec v0.1, O365 DID Spec v0.1, Google Workspace DID Spec v0.1
**Status:** Pre-implementation design

---

## 1. Overview

This specification extends the DID Sidecar's `IdentityProvider` interface to cover four categories of identity infrastructure beyond O365 and Google Workspace.

| Category | Examples | Change Detection |
|---|---|---|
| **Cat 1** — Webhook-capable IdPs | Okta, JumpCloud, Ping Identity, OneLogin | Native event webhook / push |
| **Cat 2** — SCIM-only providers | Any SCIM 2.0 directory without push | Polling only |
| **Cat 3** — SAML-only / legacy IdPs | AD FS, Shibboleth, legacy Ping Federate | HR system, AD-LDAP, or manual IT |
| **Cat 4** — On-premises Active Directory | Any Windows AD forest without Entra sync | LDAP DirSync control or USNChanged polling |

All four categories produce the same output: a populated DID document at `did:web:did.example.com:users:{encoded-id}/did.json`, triggered by the same sidecar event handler introduced in the Google Workspace spec. The categories differ only in which `IdentityProvider` implementation feeds that handler and which JML source drives user lifecycle events.

The VC issuance model is identical to the Google Workspace spec: self-issued `EmployeeCredential` signed by the org root key, served via StatusList2021 for revocation. No external VC platform is required for any category.

---

## 2. Shared Architecture

The sidecar event handler and DID document lifecycle (STUB → ACTIVE → SUSPENDED → TOMBSTONED) are unchanged from the Google Workspace spec. The `IdentityProvider` implementation and `JMLSource` configuration are the only per-deployment variables.

```toml
# enrollment.toml

[sidecar]
did_base_url     = "https://did.example.com"
org_root_did     = "did:web:did.example.com"
signing_key_type = "file"            # or "awskms", "gcpkms", "azurekv", "pkcs11"
signing_key_path = "/secrets/org-root-ed25519.pem"

[identity_provider]
type = "okta"                        # okta | jumpcloud | ping | onelogin | scim | saml | ldap

[jml_source]
# Required when identity_provider has no lifecycle events of its own
# (Cat 3: saml-only) or when the operator designates HR as the primary trigger.
type = "none"                        # none | workday | bamboohr | ad-ldap | manual
```

One sidecar instance maps to one identity provider and one JML source. An org using Okta sets `identity_provider.type = "okta"` and `jml_source.type = "none"`; Okta event hooks drive the full lifecycle. An org using Shibboleth for authentication and Workday as HRIS sets `identity_provider.type = "saml"` and `jml_source.type = "workday"`.

---

## 3. Category 1 — Webhook-Capable IdPs

### 3.1 Covered Providers

| Provider | Event Mechanism | Relevant Events |
|---|---|---|
| **Okta** | Event Hooks (HTTPS POST, async) | `user.lifecycle.create`, `user.lifecycle.activate`, `user.lifecycle.deactivate`, `user.lifecycle.delete`, `user.lifecycle.suspend`, `user.lifecycle.unsuspend`, `group.user_membership.add`, `group.user_membership.remove` |
| **JumpCloud** | Webhooks (HTTPS POST, synchronous) | `user.create`, `user.update`, `user.delete`, `group.member.add`, `group.member.remove` |
| **Ping Identity** (PingOne) | Webhook subscriptions | `USER_CREATED`, `USER_UPDATED`, `USER_DELETED`, `POPULATION_CHANGED` |
| **OneLogin** | Events API + webhooks | `user.created`, `user.deactivated`, `user.deleted`, `role.add_user`, `role.remove_user` |

All four providers use the same sidecar webhook receiver (`POST /v1/notify`) with provider-specific payload adapters.

### 3.2 Okta (Reference Implementation)

Okta is the reference implementation for Cat 1. Other providers follow the same pattern with provider-specific field mappings.

**Webhook registration:**

```
POST https://{okta-domain}/api/v1/eventHooks
Authorization: SSWS {api-token}
Content-Type: application/json

{
  "name": "Agora DID Sidecar",
  "events": {
    "type": "EVENT_TYPE",
    "items": [
      "user.lifecycle.create",
      "user.lifecycle.activate",
      "user.lifecycle.deactivate",
      "user.lifecycle.delete",
      "user.lifecycle.suspend",
      "user.lifecycle.unsuspend",
      "group.user_membership.add",
      "group.user_membership.remove"
    ]
  },
  "channel": {
    "type": "HTTP",
    "version": "1.0.0",
    "config": {
      "uri": "https://did.example.com/v1/notify",
      "authScheme": {
        "type": "HEADER",
        "key": "Authorization",
        "value": "Bearer {sidecar-webhook-secret}"
      }
    }
  }
}
```

Okta requires a one-time GET verification before the hook becomes active. The sidecar handles this at `GET /v1/notify` by reading the `x-okta-verification-challenge` header and returning `{"verification": "<value>"}`.

**Event → action mapping:**

| Okta Event | Sidecar Action |
|---|---|
| `user.lifecycle.create` | Provision stub DID |
| `user.lifecycle.activate` | Provision stub DID (if not already provisioned) |
| `user.lifecycle.deactivate` | Suspend DID + revoke VC |
| `user.lifecycle.suspend` | Suspend DID + revoke VC |
| `user.lifecycle.unsuspend` | Reactivate DID + re-issue VC |
| `user.lifecycle.delete` | Tombstone DID |
| `group.user_membership.add` | Fetch updated groups, re-derive roles, re-issue VC |
| `group.user_membership.remove` | Fetch updated groups, re-derive roles, re-issue VC |

**Payload extraction:**

```go
type OktaEventHookPayload struct {
    Data struct {
        Events []struct {
            EventType string `json:"eventType"`
            Target []struct {
                ID          string `json:"id"`
                Type        string `json:"type"`
                AlternateID string `json:"alternateId"` // email
                DisplayName string `json:"displayName"`
            } `json:"target"`
        } `json:"events"`
    } `json:"data"`
}
```

The target with `type: "User"` carries the Okta user ID (`id`) and email (`alternateId`). The sidecar keys on the Okta user ID, which is stable through email changes, and fetches the full user profile via the Okta Users API on each event before acting.

**Reconciliation:** The sidecar's reconciliation poller queries the Okta System Log API (`GET /api/v1/logs?filter=eventType eq "user.lifecycle.*"`) daily for any lifecycle events that were missed, using a stored cursor on the `published` timestamp. This approach is more reliable than a full directory scan because it fetches only actual change events.

**Limitations:** Okta event hooks are asynchronous with up to a one-minute delivery delay and do not guarantee delivery — failed deliveries are retried but may be dropped after repeated failures. The System Log reconciliation poller is the reliability backstop.

### 3.3 JumpCloud

JumpCloud webhooks fire synchronously and block the admin operation until the sidecar responds with HTTP 200. The sidecar MUST respond within 10 seconds. To meet this requirement, the sidecar MUST respond 200 immediately, enqueue the event, and process it in a worker goroutine.

```toml
[identity_provider]
type           = "jumpcloud"
api_key        = "..."           # JumpCloud API key for profile fetches
webhook_secret = "..."           # HMAC-SHA256 secret for signature verification
org_id         = "..."
```

JumpCloud signs webhook payloads with HMAC-SHA256 over the request body. The sidecar MUST verify the `X-JumpCloud-Signature` header on every inbound request.

### 3.4 Ping Identity (PingOne)

PingOne uses a subscription model. The sidecar registers a subscription via:

```
POST https://api.pingone.com/v1/environments/{envId}/subscriptions
Authorization: Bearer {worker-app-token}

{
  "name": "Agora DID Sidecar",
  "enabled": true,
  "httpEndpoint": "https://did.example.com/v1/notify",
  "format": "ACTIVITY",
  "filterOptions": {
    "includedActionTypes": [
      "USER.CREATE", "USER.UPDATE", "USER.DELETE",
      "ROLE.USER_ROLE_ASSIGNMENT_CREATED",
      "ROLE.USER_ROLE_ASSIGNMENT_DELETED"
    ]
  }
}
```

PingOne verifies the endpoint with an initial POST containing `"verifyRequest": true`. The sidecar MUST echo the request body as the verification response.

### 3.5 OneLogin

OneLogin provides both a push-based webhook and a pull-based Events API. The Events API SHOULD be used as the primary source due to higher reliability, with a short polling interval (1 minute). Webhooks MAY be used as a fast-path supplement.

```
GET https://api.us.onelogin.com/api/2/events?event_type_id=1,2,13,35,36&since={cursor}
Authorization: bearer {access-token}
```

Relevant `event_type_id` values: 1 (user created), 2 (user updated), 13 (user deactivated), 35 (role added to user), 36 (role removed from user).

---

## 4. Category 2 — SCIM-Only Providers

### 4.1 Overview

SCIM 2.0 (RFC 7644) is a request/response provisioning protocol with no push notification model. The sidecar cannot register a webhook with a SCIM provider. Two modes are supported:

1. **SCIM server mode** — the sidecar exposes a SCIM 2.0 endpoint; the upstream provisioner pushes to it.
2. **SCIM client mode** — the sidecar polls the upstream SCIM server for changes.

The operator configures which mode is in use.

### 4.2 SCIM Server Mode

The sidecar exposes a SCIM 2.0-compliant Service Provider endpoint. The upstream IdP or provisioner (Okta, Azure AD, Workday, etc.) is configured to provision users to this endpoint.

**Endpoints:**

```
POST   /scim/v2/Users              Create user → provision stub DID
GET    /scim/v2/Users              List users (for reconciliation)
GET    /scim/v2/Users/{id}         Get user
PUT    /scim/v2/Users/{id}         Full replace → update claims, re-issue VC
PATCH  /scim/v2/Users/{id}         Partial update → update claims, re-issue VC
DELETE /scim/v2/Users/{id}         Hard delete → tombstone DID
POST   /scim/v2/Groups             Create group (role)
PUT    /scim/v2/Groups/{id}        Update group membership → re-derive roles
PATCH  /scim/v2/Groups/{id}        Partial group update → re-derive roles
DELETE /scim/v2/Groups/{id}        Delete group
```

**SCIM operation → sidecar action mapping:**

| SCIM Operation | User `active` Field | Sidecar Action |
|---|---|---|
| `POST /Users` | `true` | Provision stub DID |
| `PUT/PATCH /Users` | `false` | Suspend DID + revoke VC |
| `PUT/PATCH /Users` | `true` (was `false`) | Reactivate DID + re-issue VC |
| `PUT/PATCH /Users` (attribute changes) | `true` | Update claims, re-issue VC |
| `DELETE /Users` | — | Tombstone DID |
| `PATCH /Groups` (membership add) | — | Re-derive roles, re-issue VC |
| `PATCH /Groups` (membership remove) | — | Re-derive roles, re-issue VC |

Authentication to the SCIM endpoint uses Bearer token auth. The token is a pre-shared secret configured in the upstream provisioner and stored in the sidecar config. For Azure AD and Okta as upstream provisioners, this is the standard "provisioning secret token" in their SCIM connector configuration.

**User identifier mapping:** SCIM uses `externalId` (the upstream system's user ID) and `id` (the SCIM provider's internal ID). The sidecar MUST store `externalId` as the canonical user identifier and use it to construct the DID path. If `externalId` is absent, the sidecar MUST fall back to the `userName` attribute.

### 4.3 SCIM Client Mode

When the sidecar cannot expose a public endpoint (on-prem deployment, firewall-restricted), it polls the upstream SCIM server:

```
GET {scim-base-url}/Users?filter=meta.lastModified gt "{cursor}"&count=100
Authorization: Bearer {scim-token}
```

Cursoring on `meta.lastModified` is SCIM-standard for change detection. Not all SCIM servers implement this filter reliably. If a filtered query returns no results when changes are expected, the sidecar MUST fall back to a full diff (fetch all users, compare against stored state).

Deletion detection in SCIM client mode is unreliable — deleted users disappear from the user list without emitting a delete event. The sidecar detects deletions by computing the set difference between the last full sync and the current sync on each reconciliation pass and transitions those DIDs to `TOMBSTONED`.

```toml
[identity_provider]
type               = "scim-client"
scim_base_url      = "https://idp.example.com/scim/v2"
scim_token         = "..."
poll_interval      = "15m"
full_sync_interval = "24h"
```

### 4.4 Stable User ID Requirement

SCIM user identifiers MUST be stable through attribute changes (name changes, email changes, org unit moves). The sidecar MUST key DID documents on `externalId` if present, falling back to the SCIM server's internal UUID (`id`). The sidecar MUST NOT key on `userName` or `emails[].value` because these can change.

If a provider rotates user IDs on attribute changes, the sidecar treats the rotation as a deletion of the old user and creation of a new one, producing a new DID for the same person. The operator MUST configure `externalId` mapping to avoid this.

---

## 5. Category 3 — SAML-Only / Legacy IdPs

### 5.1 Overview

SAML-only IdPs (AD FS, Shibboleth, legacy Ping Federate) provide authentication but expose no user management API. The sidecar can verify a user's identity via SAML during enrollment using the existing SAML enrollment adapter, but it cannot receive JML events from the IdP itself.

For these deployments, JML MUST come from a separate source. Three options are available:

| JML Source | Mechanism | Latency |
|---|---|---|
| **HR system** (Workday, BambooHR) | HR system pushes employee events via webhook or SFTP | Near-real-time (webhook) or batch (SFTP) |
| **Active Directory** (LDAP) | DirSync or USNChanged polling against the underlying AD that feeds the IdP | Configurable poll interval (minimum 5 min) |
| **Manual IT** | IT calls the sidecar admin API directly | Immediate (human-dependent) |

These sources are not mutually exclusive. A production deployment SHOULD use at least two: the HR system as the primary source and AD-LDAP as the reconciliation backstop.

### 5.2 HR System: Workday

The sidecar exposes an inbound webhook endpoint for Workday HR events:

```
POST /v1/hr-event
Authorization: Bearer {workday-webhook-secret}
Content-Type: application/json

{
  "eventType": "HIRE" | "TERMINATE" | "TRANSFER" | "POSITION_CHANGE",
  "worker": {
    "workdayId": "abc123",
    "firstName": "Alice",
    "lastName": "Smith",
    "email": "alice@example.com",
    "employeeId": "EMP-12345",
    "department": "Engineering",
    "jobTitle": "Senior Engineer",
    "costCenter": "CC-001",
    "hireDate": "2026-03-13",
    "terminationDate": null,
    "managerEmail": "bob@example.com"
  }
}
```

**Event → action mapping:**

| Workday Event | Sidecar Action |
|---|---|
| `HIRE` | Provision stub DID, queue enrollment invite |
| `TERMINATE` | Tombstone DID, revoke VC |
| `TRANSFER` | Update claims (department, cost center), re-issue VC |
| `POSITION_CHANGE` | Update claims (job title, department), re-issue VC |
| `LEAVE_OF_ABSENCE` | Suspend DID, revoke VC |
| `RETURN_FROM_LEAVE` | Reactivate DID, re-issue VC |

The sidecar matches Workday workers to DID records using `email` as the primary key (`workdayId` is rarely surfaced in other systems). If the email changes (e.g., on a legal name change), the sidecar applies the same UPN-change handling as the O365 spec §6.4: a new DID path is provisioned, the old one is aliased, and it is eventually tombstoned.

Workday integration setup (Workday Studio outbound integration or Report-as-a-Service) is the responsibility of the operator's Workday administrator and is outside the scope of this specification. The sidecar endpoint accepts the payload above regardless of which Workday integration mechanism produces it.

### 5.3 HR System: BambooHR

Register a BambooHR webhook to monitor relevant employee fields:

```
POST https://api.bamboohr.com/api/gateway.php/{company}/v1/webhooks
Authorization: Basic {api-key}
Content-Type: application/json

{
  "name": "Agora DID Sidecar",
  "monitorFields": [
    "status", "department", "jobTitle", "workEmail",
    "terminationDate", "hireDate"
  ],
  "postFields": {
    "employeeId": "id",
    "firstName": "firstName",
    "lastName": "lastName",
    "email": "workEmail",
    "department": "department",
    "jobTitle": "jobTitle",
    "status": "status",
    "terminationDate": "terminationDate"
  },
  "url": "https://did.example.com/v1/hr-event",
  "format": "json",
  "frequency": { "hour": 1 },
  "limit": 0,
  "includeCompanyDomain": true
}
```

BambooHR delivers webhooks on a configurable frequency, not immediately on change; the minimum interval is one hour. The sidecar normalizes the BambooHR payload to the same `HREvent` struct used by all JML sources:

```go
type HREvent struct {
    EventType   string      // HIRE | TERMINATE | TRANSFER | POSITION_CHANGE | LEAVE | RETURN
    EmployeeID  string
    Email       string
    DisplayName string
    Department  string
    JobTitle    string
    HireDate    *time.Time
    TermDate    *time.Time
    Source      string      // "workday" | "bamboohr" | "manual" | "ldap" | "scim"
}
```

BambooHR does not emit discrete event types — it reports field changes. The sidecar infers the event type from field values: `status == "Inactive"` with `terminationDate` set → `TERMINATE`; `status == "Active"` with no prior record → `HIRE`; department or job title change → `TRANSFER`.

### 5.4 HR System: Generic SFTP Batch

For HRIS systems that export a nightly CSV or JSON file to an SFTP server, the sidecar includes a batch importer:

```toml
[jml_source]
type          = "sftp-batch"
host          = "sftp.example.com"
port          = 22
username      = "agora-importer"
identity_file = "/secrets/sftp-key"
remote_path   = "/exports/hr-daily.csv"
poll_interval = "1h"
format        = "csv"          # or "json"
csv_columns   = {
  employee_id = "EmployeeID",
  email       = "WorkEmail",
  status      = "EmploymentStatus",   # "Active" | "Terminated" | "OnLeave"
  department  = "Department",
  job_title   = "JobTitle",
  hire_date   = "HireDate",
  term_date   = "TerminationDate"
}
```

The importer downloads the file, diffs it against the previous import keyed on `employee_id`, and emits `HREvent` structs for each changed record: a record present in the new file but not the previous → `HIRE`; a record with `status == "Terminated"` that was previously `Active` → `TERMINATE`.

### 5.5 Manual IT Operations

The sidecar admin API provides full lifecycle control without any automated JML source. This is the minimum viable path for small organizations or during initial rollout before HR integration is complete.

All operations require a Bearer token with `AgoraDIDAdmin` scope.

```
POST /v1/admin/provision      Provision a new stub DID
POST /v1/admin/tombstone      Terminate a user
POST /v1/admin/suspend        Suspend a user
POST /v1/admin/reactivate     Reactivate a user
POST /v1/admin/update-claims  Update department/role claims
POST /v1/admin/revoke-device  Revoke a specific device key
GET  /v1/admin/status         List all DID states
GET  /v1/admin/audit/{email}  Audit log for a user
```

The admin API is documented with an OpenAPI spec. A minimal web UI SHOULD be provided for IT helpdesk use to support routine operations such as lost device revocation without requiring raw API calls.

---

## 6. Category 4 — On-Premises Active Directory (LDAP)

### 6.1 Change Detection Strategy

AD on-premises supports two change detection mechanisms with different privilege requirements:

| Mechanism | Privilege Required | Detects Deletions | Scope | Go Library |
|---|---|---|---|---|
| **DirSync control** | `DS-Replication-Get-Changes` (domain admin level) | Yes (tombstones included) | Entire naming context | `go-ldap/ldap/v3` `DirSync()` |
| **USNChanged polling** | `List + Read` on target subtree (least privilege) | Only via full sync diff | Subtree-scoped | `go-ldap/ldap/v3` LDAP search |

USNChanged SHOULD be used for least-privilege deployments. DirSync SHOULD be used for domain-joined service accounts where the elevated privilege is acceptable.

```toml
[identity_provider]
type = "ldap"

[ldap]
host              = "dc01.corp.example.com"
port              = 636
use_tls           = true
bind_dn           = "CN=AgoraSidecar,OU=ServiceAccounts,DC=corp,DC=example,DC=com"
bind_password     = "..."                 # or ldap_password_file
base_dn           = "OU=Users,DC=corp,DC=example,DC=com"
user_filter       = "(&(objectClass=user)(objectCategory=person))"
change_detection  = "usnchanged"          # or "dirsync"
poll_interval     = "5m"
full_sync_interval = "24h"
affiliate_dc      = "dc01.corp.example.com"  # USNChanged: must always bind to same DC
```

### 6.2 USNChanged Implementation

The USNChanged approach polls the directory for objects whose `uSNChanged` attribute exceeds the last processed value, bounded by `highestCommittedUSN` to avoid race conditions with concurrent writes.

Algorithm (run every `poll_interval`):

```go
func (p *LDAPProvider) PollChanges(ctx context.Context) ([]*UserRecord, error) {
    // 1. Read highestCommittedUSN from rootDSE before querying.
    rootDSE := p.fetchRootDSE()
    upperBound := rootDSE.HighestCommittedUSN

    // 2. Query for changed objects.
    filter := fmt.Sprintf(
        "(&%s(uSNChanged>=%d)(uSNChanged<=%d))",
        p.config.UserFilter,
        p.cursor + 1,
        upperBound,
    )
    results := p.ldapSearch(filter, userAttributes)

    // 3. Query Deleted Objects container for deletions.
    deletions := p.searchDeletedObjects(p.cursor + 1, upperBound)

    // 4. Advance cursor to upperBound, not to the max uSNChanged in results.
    p.cursor = upperBound

    return append(results, deletions...), nil
}
```

**Deletion detection:** AD moves deleted objects to `CN=Deleted Objects` rather than removing them immediately. Reading this container requires explicit `List Contents` permission on `CN=Deleted Objects` and the `LDAP_SERVER_SHOW_DELETED_OID` control. Deleted objects retain `objectGUID` and `lastKnownRDN` but lose most attributes. The sidecar maps `objectGUID` to the DID document on deletion.

**DC affinity:** `uSNChanged` is not replicated between domain controllers; values at two different DCs are independent. The sidecar MUST bind to the same DC on every poll, configured via `affiliate_dc`. If that DC is unreachable, the sidecar MUST wait rather than failing over to another DC, to prevent missed or duplicate events. After recovery, USNChanged resumes from the stored cursor.

**Attribute mapping:**

| AD Attribute | `UserRecord` Field |
|---|---|
| `objectGUID` | `stableID` (canonical key; never changes) |
| `userPrincipalName` | `upn` / DID path source |
| `mail` | `email` |
| `displayName` | `displayName` |
| `sAMAccountName` | `username` |
| `department` | `department` |
| `title` | `jobTitle` |
| `memberOf` | `groups` (DNs resolved to names) |
| `userAccountControl` bit 0x0002 | `disabled` flag |
| `pwdLastSet == 0` + `ACCOUNTDISABLE` | Suspended state |
| Object in Deleted Objects container | Deletion → tombstone |

`objectGUID` is the stable identifier and does not change on rename, move, or attribute modification. The DID path is derived from UPN at provisioning time; if UPN changes, the same UPN-change handling as the O365 spec §6.4 applies.

### 6.3 DirSync Implementation

DirSync is simpler to implement correctly — the cookie manages cursor state automatically — but requires `DS-Replication-Get-Changes`. The `go-ldap/ldap/v3` library provides native `DirSync()` support:

```go
func (p *LDAPProvider) PollDirSync(ctx context.Context) ([]*UserRecord, error) {
    req := &ldap.SearchRequest{
        BaseDN:     p.config.BaseDN,
        Scope:      ldap.ScopeWholeSubtree,
        Filter:     p.config.UserFilter,
        Attributes: userAttributes,
    }
    res, err := p.conn.DirSync(req, ldap.DirSyncObjectSecurity, 1000, p.cookie)
    if err != nil {
        return nil, err
    }
    p.cookie = res.Controls[0].(*ldap.ControlDirSync).Cookie
    p.storeCookie()  // persist to DB — loss of cookie requires full resync
    return mapEntries(res.Entries), nil
}
```

DirSync includes deleted objects (tombstones) automatically when the filter matches them. Tombstones retain only `objectGUID`, `isDeleted: TRUE`, and a few system attributes. The sidecar MUST map `isDeleted: TRUE` to a tombstone action.

**Cookie persistence:** The DirSync cookie MUST be persisted to durable storage (the same database as DID documents). Loss of the cookie — for example, after a crash — requires a full resync: the sidecar fetches all objects and diffs against stored state.

### 6.4 Service Account Requirements

**For USNChanged:**
- `List Contents` on the target OU
- `Read All Properties` on user objects in the OU
- `List Contents` on `CN=Deleted Objects,DC=...`
- `Read All Properties` on deleted objects

**For DirSync:**
- `DS-Replication-Get-Changes` extended right on the domain naming context root
- This right is equivalent to AD replication access; the minimum grant is membership in `Domain Admins` or explicit delegation of the extended right.

The service account MUST be a dedicated account in a dedicated OU with all interactive login rights stripped. The account password MUST be rotated at least annually and MUST be stored in a secrets manager (HashiCorp Vault, AWS Secrets Manager, or equivalent); it MUST NOT be stored in a config file.

### 6.5 Multi-Domain Forests

AD forests with multiple child domains require one LDAP connection per domain. The sidecar supports multiple LDAP targets:

```toml
[[ldap.domains]]
host    = "dc01.corp.example.com"
base_dn = "OU=Users,DC=corp,DC=example,DC=com"

[[ldap.domains]]
host    = "dc01.eu.example.com"
base_dn = "OU=Users,DC=eu,DC=example,DC=com"
```

Each domain runs its own polling goroutine with its own cursor. `objectGUID` is globally unique across domains within a forest, so there are no collision risks in the sidecar's user registry.

If a Global Catalog is available and the operator prefers a single connection point for the whole forest, the sidecar MAY query the GC on port 3268. In this case, the USNChanged connector MUST be used; DirSync cannot detect change events in sub-domains via the Global Catalog.

---

## 7. JML Source Composition

When `jml_source.type` is not `none`, the sidecar runs both the identity provider and the JML source concurrently, deduplicating events by user stable ID and timestamp. This handles the Cat 3 case (SAML authentication with a separate JML source) and is also applicable to Cat 4 (LDAP for fast change detection, HR system as the authoritative source for hire/terminate decisions).

**Deduplication:** If the same user receives the same action (provision/suspend/tombstone) from two sources within a 60-second window, the second action is a no-op. If two sources disagree within that window, the more restrictive action wins: tombstone beats provision; suspend beats reactivate.

**Trust hierarchy for conflicting events:**

```
HR system (Workday/BambooHR) > LDAP > SCIM > webhook IdP > manual
```

A Workday `TERMINATE` event always overrides a concurrent LDAP reactivation signal, which may reflect DC replication lag. Manual IT operations bypass the trust hierarchy — they are applied immediately and logged with a `manual-override` flag.

---

## 8. Auth Adapter Completeness

The enrollment auth adapter maps to the DID sidecar's `IdentityProvider` as follows:

| `agora-enroll` Auth Adapter | DID Sidecar `IdentityProvider` | Notes |
|---|---|---|
| `okta` | `OktaProvider` | Same Okta org — OAuth2 OIDC on enrollment, event hooks for JML |
| `teams` (Entra OIDC) | `EntraProvider` (O365 spec) | Same tenant |
| `slack` | None | Slack auth only for enrollment; no org-managed DID for Slack-primary orgs |
| `oidc` (generic) | `SCIMProvider` or `SAMLProvider` | Depends on which directory the OIDC issuer fronts |
| `saml` (generic) | `SAMLProvider` + separate JML source | Auth via SAML, JML from HR or AD |

The enrollment auth adapter and the sidecar identity provider are independent configurations. An org MAY use SAML for enrollment authentication while LDAP drives JML. When `externalId` or `objectGUID` cross-referencing is unavailable, the `email` field serves as the common key between the two subsystems.

---

## 9. Signing Key Options

The self-issued `EmployeeCredential` requires the org to hold an Ed25519 signing key. The sidecar supports the following signing key backends:

| Backend | `signing_key_type` | Notes |
|---|---|---|
| File (PEM) | `file` | Key on disk; operator is responsible for backup and rotation. Acceptable for lab/pilot only. |
| AWS KMS | `awskms` | HSM-backed; key ARN in config; uses `aws-sdk-go-v2` |
| Google Cloud KMS | `gcpkms` | As per Google Workspace spec |
| Azure Key Vault | `azurekv` | As per O365 spec |
| PKCS#11 (HSM) | `pkcs11` | On-prem HSM (Thales, SafeNet, YubiHSM) via `miekg/pkcs11` |
| HashiCorp Vault | `vault` | Vault Transit secrets engine; key never leaves Vault |

For on-prem deployments (Cat 3 and Cat 4), the PKCS#11 and HashiCorp Vault backends SHOULD be used.

---

## 10. Deployment Topologies

| Category | Network Requirement | Recommended Topology |
|---|---|---|
| Cat 1 (Okta/JumpCloud) | Public HTTPS endpoint for webhook receipt | Cloud-hosted (AWS, GCP, Azure, Fly.io) |
| Cat 2 (SCIM server mode) | Public HTTPS endpoint for SCIM push receipt | Cloud-hosted |
| Cat 2 (SCIM client mode) | Outbound HTTPS to SCIM server | On-prem or VPN-accessible |
| Cat 3 + HR webhook | Public HTTPS endpoint for HR system webhook | Cloud-hosted with VPN or private link for AD access |
| Cat 3 + SFTP batch | Outbound SFTP to HRIS server | On-prem or co-located |
| Cat 4 (LDAP) | Outbound LDAPS to domain controller (port 636) | On-prem, or cloud with VPN/Direct Connect |

For hybrid deployments (Cat 3 + Cat 4: SAML auth from cloud IdP, LDAP from on-prem AD), the sidecar runs on-prem with a reverse proxy exposing only the enrollment and webhook endpoints to the internet. The LDAP connection remains on the internal network.

```
Internet → [Reverse Proxy] → /v1/enroll/*      (enrollment)
                           → /v1/notify         (IdP webhook)
                           → /v1/hr-event       (HR webhook)
                           → /users/*/did.json  (DID document serving)

Internal only:
  LDAP polling  → DC on port 636
  DB            → PostgreSQL on internal network
  Signing key   → on-prem HSM via PKCS#11
```

---

## 11. Implementation Additions to Shared Codebase

New `IdentityProvider` implementations added to the shared Go binary:

```go
// Cat 1
type OktaProvider      struct { ... }
type JumpCloudProvider struct { ... }
type PingProvider      struct { ... }
type OneLoginProvider  struct { ... }

// Cat 2
type SCIMServerProvider struct { ... }   // sidecar acts as SCIM endpoint
type SCIMClientProvider struct { ... }   // sidecar polls upstream SCIM

// Cat 3 — no IdentityProvider; the existing SAML enrollment adapter handles auth.

// Cat 4
type LDAPProvider struct {
    mode   string  // "usnchanged" | "dirsync"
    conn   *ldap.Conn
    cursor int64   // USNChanged: last processed USN
    cookie []byte  // DirSync: opaque cookie
}
```

New `JMLSource` implementations:

```go
type WorkdayJMLSource   struct { ... }
type BambooHRJMLSource  struct { ... }
type SFTPBatchJMLSource struct { ... }
type ManualJMLSource    struct { ... }  // no-op source; admin API is the trigger
type LDAPJMLSource      struct { ... }  // same as LDAPProvider, used when IdP is SAML-only
```

New library dependencies:

| Function | Library |
|---|---|
| LDAP (DirSync + USNChanged) | `github.com/go-ldap/ldap/v3` |
| SCIM server | `github.com/elimity-com/scim` |
| SFTP client | `github.com/pkg/sftp` |
| AWS KMS | `github.com/aws/aws-sdk-go-v2/service/kms` |
| HashiCorp Vault | `github.com/hashicorp/vault/api` |
| PKCS#11 | `github.com/miekg/pkcs11` |

---

## 12. Open Questions

1. **Okta event hook delivery guarantees.** Okta event hooks are asynchronous and best-effort. The System Log API reconciliation poller covers missed events but has up to 24-hour latency. Regulated organizations requiring sub-minute termination enforcement SHOULD also call `POST /v1/admin/tombstone` directly when terminating an employee rather than relying solely on the Okta hook.

2. **SCIM Groups vs. flat role attributes.** Some IdPs encode roles as user profile attributes rather than group membership. The sidecar's SCIM implementation supports both patterns, but the role derivation configuration MUST explicitly specify which is in use rather than auto-detecting.

3. **AD multi-forest trust.** This spec covers multi-domain single-forest scenarios. Multi-forest trust relationships are not addressed. Each forest requires its own sidecar deployment with its own DID namespace; cross-forest enrollment uses the SAML adapter for authentication with the appropriate forest's LDAP as the JML source.

4. **Workday RaaS vs. Studio.** Workday supports both Report-as-a-Service (no coding required) and Studio (full EIB, more control) for outbound data. This spec does not prescribe which Workday integration type to use; the operator's Workday administrator selects based on existing expertise. The sidecar endpoint accepts the same payload regardless of which mechanism produces it.

5. **Air-gapped deployments.** A sidecar in a fully air-gapped environment cannot receive webhooks from cloud IdPs or push DID documents to a public IPFS node. The sidecar MAY operate in a fully internal mode, serving DID documents only on the internal network with the Agora Relay also internal. This eliminates cross-org federation. It is an explicit architectural trade-off for air-gapped deployments, consistent with Agora Protocol Spec Appendix B.
