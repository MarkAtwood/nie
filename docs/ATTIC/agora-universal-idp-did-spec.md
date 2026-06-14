# Specification: Employer-Managed DIDs — Universal Identity Provider Support

**Version:** 0.1 Draft  
**Depends On:** Agora Protocol Spec v0.1, O365 DID spec v0.1, Google Workspace DID spec v0.1  
**Status:** Pre-implementation design

---

## 1. Overview

This spec extends the DID Sidecar's `IdentityProvider` interface to cover four additional categories of identity infrastructure beyond O365 and Google Workspace:

| Category | Examples | Change detection mechanism |
|---|---|---|
| **Cat 1** — Webhook-capable IdPs | Okta, JumpCloud, Ping Identity, OneLogin | Native event webhook / push |
| **Cat 2** — SCIM-only providers | Any SCIM 2.0 directory without push | Polling only |
| **Cat 3** — SAML-only / legacy IdPs | AD FS, Shibboleth, legacy Ping Federate | JML from HR system, AD directly, or manual IT |
| **Cat 4** — On-premises Active Directory | Any Windows AD forest, no Entra sync | LDAP DirSync control or USNChanged polling |

All four categories produce the same output: a populated DID document at `did:web:did.example.com:users:{encoded-id}/did.json`, triggered by the same sidecar event handler introduced in the Google Workspace spec. The categories differ only in which `IdentityProvider` implementation feeds that handler, and which JML source drives user lifecycle events.

The VC issuance model is identical to the Google Workspace spec — self-issued `EmployeeCredential` signed by the org root key, served via StatusList2021 for revocation. No external VC platform is required for any of these categories.

---

## 2. Shared Architecture Recap

The sidecar event handler and DID document lifecycle (STUB → ACTIVE → SUSPENDED → TOMBSTONED) are unchanged from the Google Workspace spec. What changes per deployment is the `IdentityProvider` implementation and the `JMLSource` configuration.

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
# Only relevant when identity_provider has no lifecycle events of its own
# (cat 3: saml-only) or when operator wants HR as the primary trigger
type = "none"                        # none | workday | bamboohr | ad-ldap | manual
```

One sidecar instance = one identity provider + one JML source. An org with Okta as their IdP sets `identity_provider.type = "okta"` and `jml_source.type = "none"` — Okta's event hooks drive everything. An org with Shibboleth (auth only) and Workday as HRIS sets `identity_provider.type = "saml"` and `jml_source.type = "workday"`.

---

## 3. Category 1 — Webhook-Capable IdPs

### 3.1 Covered Providers

| Provider | Event mechanism | Relevant events |
|---|---|---|
| **Okta** | Event Hooks (HTTPS POST, async) | `user.lifecycle.create`, `user.lifecycle.activate`, `user.lifecycle.deactivate`, `user.lifecycle.delete`, `group.user_membership.add`, `group.user_membership.remove` |
| **JumpCloud** | Webhooks (HTTPS POST) | `user.create`, `user.update`, `user.delete`, `group.member.add`, `group.member.remove` |
| **Ping Identity** (PingOne) | Webhook subscriptions | `USER_CREATED`, `USER_UPDATED`, `USER_DELETED`, `POPULATION_CHANGED` |
| **OneLogin** | Event API + webhooks | `user.created`, `user.deactivated`, `user.deleted`, `role.add_user`, `role.remove_user` |

All four use the same sidecar webhook receiver endpoint (`POST /v1/notify`) with provider-specific payload adapters.

### 3.2 Okta Integration (Reference Implementation)

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

**Relevant event types → sidecar action mapping:**

| Okta event | Sidecar action |
|---|---|
| `user.lifecycle.create` | Provision stub DID |
| `user.lifecycle.activate` | Provision stub DID (if not yet provisioned) |
| `user.lifecycle.deactivate` | Suspend DID + revoke VC |
| `user.lifecycle.suspend` | Suspend DID + revoke VC |
| `user.lifecycle.unsuspend` | Reactivate DID + re-issue VC |
| `user.lifecycle.delete` | Tombstone DID |
| `group.user_membership.add` | Fetch updated groups, re-derive roles, update claims, re-issue VC |
| `group.user_membership.remove` | Same as add |

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

The target with `type: "User"` carries the Okta user ID (`id`) and email (`alternateId`). The sidecar keys on the Okta user ID — stable through email changes — and fetches the full user profile via the Okta Users API on each event before acting.

**Reconciliation:** Okta's System Log API (`GET /api/v1/logs?filter=eventType eq "user.lifecycle.*"`) provides a queryable audit trail. The sidecar's reconciliation poller queries this log daily for any lifecycle events it may have missed, using a stored cursor on `published` timestamp. This is more reliable than the Google Workspace approach (full directory scan) because it only fetches actual change events rather than diffing the whole user list.

**Limitations:** Okta event hooks are asynchronous and have up to a 1-minute delivery delay. They do not guarantee delivery — failed deliveries are retried but can be dropped after repeated failures. The System Log reconciliation poller is the reliability backstop.

### 3.3 JumpCloud

JumpCloud webhooks fire synchronously (they block the admin operation until the webhook receives a 200). The sidecar must respond within 10 seconds or JumpCloud retries. Process the event asynchronously: respond 200 immediately, enqueue the event, process in a worker goroutine.

Config:
```toml
[identity_provider]
type             = "jumpcloud"
api_key          = "..."           # JumpCloud API key for profile fetches
webhook_secret   = "..."           # HMAC-SHA256 secret for webhook signature verification
org_id           = "..."
```

JumpCloud signs webhooks with HMAC-SHA256 over the request body using the configured secret. Verify `X-JumpCloud-Signature` header on every inbound request.

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

PingOne verifies the endpoint with an initial POST containing `"verifyRequest": true`. The sidecar echoes the request body as the verification response.

### 3.5 OneLogin

OneLogin has both a push-based webhook and a pull-based Events API. Use the Events API as the primary source (more reliable) with a short polling interval (1 minute), falling back to webhooks as a fast-path supplement.

Events API polling:
```
GET https://api.us.onelogin.com/api/2/events?event_type_id=1,2,13,35,36&since={cursor}
Authorization: bearer {access-token}
```

Relevant `event_type_id` values: 1 (user created), 2 (user updated), 13 (user deactivated), 35 (role added to user), 36 (role removed from user).

---

## 4. Category 2 — SCIM-Only Providers

### 4.1 What SCIM Provides and Doesn't

SCIM 2.0 (RFC 7644) is a request/response provisioning protocol — the provisioner pushes user creates/updates/deletes to a SCIM endpoint. It has no event push model. The sidecar cannot register a webhook with a SCIM provider; instead it must either:

1. **Act as a SCIM server** — expose a SCIM 2.0 endpoint that the upstream provisioner pushes to, or
2. **Poll the SCIM server** — query the provider's SCIM API periodically for changes

Both modes are supported. The operator configures which mode is in use.

### 4.2 SCIM Server Mode (Sidecar as SCIM Endpoint)

The sidecar exposes a SCIM 2.0-compliant endpoint. The upstream IdP/provisioner (Okta, Azure AD, Workday, etc.) is configured to provision users into this endpoint. The sidecar acts as a SCIM Service Provider.

Endpoints exposed:

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

SCIM operations map to sidecar actions:

| SCIM operation | User `active` field | Sidecar action |
|---|---|---|
| `POST /Users` | `true` | Provision stub DID |
| `PUT/PATCH /Users` with `active: false` | `false` | Suspend DID + revoke VC |
| `PUT/PATCH /Users` with `active: true` (was false) | `true` | Reactivate DID + re-issue VC |
| `PUT/PATCH /Users` attribute changes | `true` | Update claims, re-issue VC |
| `DELETE /Users` | — | Tombstone DID |
| `PATCH /Groups` membership add | — | Re-derive roles, re-issue VC |
| `PATCH /Groups` membership remove | — | Re-derive roles, re-issue VC |

Authentication to the SCIM endpoint uses Bearer token auth. The token is a pre-shared secret configured in the upstream provisioner and stored in the sidecar's config. For Azure AD and Okta as upstream provisioners, this is the standard "provisioning secret token" in their SCIM connector configuration.

**User identifier mapping:** SCIM uses `externalId` (the upstream system's user ID) and `id` (the SCIM provider's internal ID). The sidecar stores `externalId` as the canonical user identifier for cross-referencing, and uses it to construct the DID path. If `externalId` is absent (some providers omit it), fall back to the `userName` attribute.

### 4.3 SCIM Polling Mode (Sidecar as SCIM Client)

When the sidecar cannot expose a public endpoint (on-prem deployment, firewall-restricted), it polls the upstream SCIM server:

```
GET {scim-base-url}/Users?filter=meta.lastModified gt "{cursor}"&count=100
Authorization: Bearer {scim-token}
```

Cursoring on `meta.lastModified` is SCIM-standard for change detection. Not all SCIM servers implement this filter reliably — some ignore it and return all users regardless. The sidecar falls back to full diff (fetch all users, compare against stored state) if the filtered query returns no results when changes are expected.

Deletion detection in SCIM polling mode is unreliable — deleted users disappear from the user list rather than emitting a delete event. The sidecar detects deletions by computing the set difference between the last full sync and the current full sync on each reconciliation pass. Deletions detected this way transition the DID to `TOMBSTONED`.

Config:
```toml
[identity_provider]
type         = "scim-client"
scim_base_url = "https://idp.example.com/scim/v2"
scim_token   = "..."
poll_interval = "15m"
full_sync_interval = "24h"
```

### 4.4 Stable User ID Requirement

SCIM user identifiers must be stable through attribute changes (name changes, email changes, org unit moves). The sidecar keys the DID document on the stable ID — `externalId` if present, `id` (the SCIM server's internal UUID) otherwise. It does not key on `userName` or `emails[].value` because these can change.

If a provider rotates user IDs on attribute changes (some legacy SCIM implementations do this), the sidecar will treat it as a deletion of the old user and creation of a new one. This produces a new DID for the same person. The operator must configure `externalId` mapping to avoid this.

---

## 5. Category 3 — SAML-Only / Legacy IdPs

### 5.1 The Problem

SAML-only IdPs (AD FS, Shibboleth, legacy Ping Federate) provide authentication but have no user management API. The sidecar can verify a user's identity via SAML during enrollment (the existing SAML enrollment adapter handles this), but it has no mechanism to receive JML events from the IdP itself.

For these deployments, JML must come from a separate source. Three options, operator-chosen:

| JML source | How it works | Latency |
|---|---|---|
| **HR system** (Workday, BambooHR) | HR system pushes employee events via webhook or SFTP | Near-real-time (webhook) or batch (SFTP) |
| **Active Directory** (LDAP) | LDAP DirSync / USNChanged polling against the underlying AD that feeds the IdP | Poll interval (configurable, min 5 min) |
| **Manual IT** | IT calls sidecar admin API directly | Immediate (human-dependent) |

These are not mutually exclusive. A production deployment should use at least two: HR system as the primary source and AD-LDAP as the reconciliation backstop.

### 5.2 HR System: Workday

Workday supports outbound event integrations via the Workday Studio integration framework. The sidecar exposes an inbound webhook endpoint for Workday HR events:

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

Event type → sidecar action mapping:

| Workday event | Sidecar action |
|---|---|
| `HIRE` | Provision stub DID, queue enrollment invite |
| `TERMINATE` | Tombstone DID, revoke VC |
| `TRANSFER` | Update claims (department, cost center), re-issue VC |
| `POSITION_CHANGE` | Update claims (job title, department), re-issue VC |
| `LEAVE_OF_ABSENCE` | Suspend DID, revoke VC |
| `RETURN_FROM_LEAVE` | Reactivate DID, re-issue VC |

The sidecar matches Workday workers to DID document records using `email` as the primary key (Workday `workdayId` is rarely surfaced in other systems). If email changes (name change), the sidecar treats it as a UPN change event (same as O365 spec §6.4) — new DID path provisioned, old one aliased and eventually tombstoned.

**Workday integration setup:** The Workday admin creates a Workday Studio outbound integration or a Report-as-a-Service (RaaS) integration that triggers on relevant HR events. The integration calls the sidecar's `/v1/hr-event` endpoint with the payload above. Workday Studio setup is out of scope for this spec; the operator's Workday administrator must configure it.

### 5.3 HR System: BambooHR

BambooHR supports webhooks for employee field changes via its API. Register:

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

BambooHR sends the webhook on a configurable frequency (not immediately on change — minimum 1 hour, typical production setting). The sidecar normalizes the BambooHR payload to the same `HREvent` struct as Workday:

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

BambooHR does not emit discrete event types — it reports field changes. The sidecar infers the event type from field values: `status == "Inactive"` with a `terminationDate` set → `TERMINATE`. `status == "Active"` with no prior record → `HIRE`. Department or job title change → `TRANSFER`.

### 5.4 HR System: Generic SFTP Batch

Some legacy HRIS exports a nightly CSV or JSON file to an SFTP server. The sidecar includes a batch importer that polls a configured SFTP path:

```toml
[jml_source]
type = "sftp-batch"
host = "sftp.example.com"
port = 22
username = "agora-importer"
identity_file = "/secrets/sftp-key"
remote_path = "/exports/hr-daily.csv"
poll_interval = "1h"
format = "csv"          # or "json"
csv_columns = {
  employee_id = "EmployeeID",
  email       = "WorkEmail",
  status      = "EmploymentStatus",   # "Active" | "Terminated" | "OnLeave"
  department  = "Department",
  job_title   = "JobTitle",
  hire_date   = "HireDate",
  term_date   = "TerminationDate"
}
```

The importer downloads the file, computes a diff against the previous import, and emits `HREvent` structs for each changed record. The diff keys on `employee_id`. A record present in the new file but not the previous → `HIRE`. A record with `status == "Terminated"` that was previously `Active` → `TERMINATE`.

### 5.5 Manual IT Operations

Even without any automated JML source, operators can drive all lifecycle events via the sidecar admin API. This is the minimum viable path for small organizations or during initial rollout before HR integration is complete.

IT-facing admin operations (all require bearer token with `AgoraDIDAdmin` scope):

```
POST /v1/admin/provision     Provision a new stub DID
POST /v1/admin/tombstone     Terminate a user
POST /v1/admin/suspend       Suspend a user
POST /v1/admin/reactivate    Reactivate a user
POST /v1/admin/update-claims Update department/role claims
POST /v1/admin/revoke-device Revoke a specific device key
GET  /v1/admin/status        List all DID states
GET  /v1/admin/audit/{email} Audit log for a user
```

The admin API is documented with an OpenAPI spec and should have a minimal web UI for IT helpdesk use — not all IT staff should need to make raw API calls for routine operations like lost device revocation.

---

## 6. Category 4 — On-Premises Active Directory (LDAP)

### 6.1 Change Detection Strategy

AD on-prem has two standard change detection mechanisms, with different privilege requirements and trade-offs:

| Mechanism | Privilege required | Detects deletions? | Scope | Go library |
|---|---|---|---|---|
| **DirSync control** | `DS-Replication-Get-Changes` (effectively domain admin) | Yes (tombstones included) | Entire naming context only | `go-ldap/ldap/v3` `DirSync()` |
| **USNChanged polling** | List + Read on target subtree (least privilege) | Only via full sync diff | Subtree-scoped | `go-ldap/ldap/v3` LDAP search |

**Recommended: USNChanged for least-privilege deployments, DirSync for domain-joined service accounts.**

The sidecar implements both and selects based on config:

```toml
[identity_provider]
type = "ldap"

[ldap]
host        = "dc01.corp.example.com"
port        = 636
use_tls     = true
bind_dn     = "CN=AgoraSidecar,OU=ServiceAccounts,DC=corp,DC=example,DC=com"
bind_password = "..."                 # or ldap_password_file
base_dn     = "OU=Users,DC=corp,DC=example,DC=com"
user_filter = "(&(objectClass=user)(objectCategory=person))"
change_detection = "usnchanged"       # or "dirsync"
poll_interval    = "5m"
full_sync_interval = "24h"
affiliate_dc     = "dc01.corp.example.com"  # USNChanged: must always bind to same DC
```

### 6.2 USNChanged Implementation

The USNChanged approach polls the directory for objects whose `uSNChanged` attribute exceeds the last processed value, bound by `highestCommittedUSN` to avoid race conditions with concurrent writes.

Algorithm (run every `poll_interval`):

```go
func (p *LDAPProvider) PollChanges(ctx context.Context) ([]*UserRecord, error) {
    // 1. Read highestCommittedUSN from rootDSE before querying
    rootDSE := p.fetchRootDSE()
    upperBound := rootDSE.HighestCommittedUSN

    // 2. Query for changed objects
    filter := fmt.Sprintf(
        "(&%s(uSNChanged>=%d)(uSNChanged<=%d))",
        p.config.UserFilter,
        p.cursor + 1,
        upperBound,
    )
    results := p.ldapSearch(filter, userAttributes)

    // 3. Query Deleted Objects container for deletions
    deletions := p.searchDeletedObjects(p.cursor + 1, upperBound)

    // 4. Update cursor to upperBound (not max uSNChanged in results)
    p.cursor = upperBound

    return append(results, deletions...), nil
}
```

**Deletion detection:** AD moves deleted objects to the `CN=Deleted Objects` container rather than removing them immediately (tombstoning). Reading this container requires explicit permission (`List Contents` on `CN=Deleted Objects`) and the `LDAP_SERVER_SHOW_DELETED_OID` control. Deleted objects retain `objectGUID` and `lastKnownRDN` but lose most attributes. The sidecar maps `objectGUID` → DID document on deletion.

**DC affinity:** `uSNChanged` is not replicated between domain controllers — reading it at two different DCs typically gives different values. The sidecar must bind to the same DC on every poll, stored in `affiliate_dc` config. If that DC is unreachable, the sidecar waits rather than failing over to another DC, to avoid missed or duplicate events. After DC recovery, USNChanged catches up from the last stored cursor.

**Attribute mapping:**

| AD attribute | `UserRecord` field |
|---|---|
| `objectGUID` | `stableID` (canonical key, never changes) |
| `userPrincipalName` | `upn` / DID path source |
| `mail` | `email` |
| `displayName` | `displayName` |
| `sAMAccountName` | `username` |
| `department` | `department` |
| `title` | `jobTitle` |
| `memberOf` | `groups` (DNs, resolve to names) |
| `userAccountControl` | `disabled` flag (bit 0x0002) |
| `pwdLastSet = 0` and `userAccountControl & ACCOUNTDISABLE` | Suspended state |
| Object in Deleted Objects container | Deletion → tombstone |

`objectGUID` is the stable identifier. It does not change on rename, move, or attribute modification. The DID path is derived from UPN at provisioning time; if UPN changes, the same UPN-change handling as the O365 spec (§6.4) applies.

### 6.3 DirSync Implementation

DirSync is simpler to implement correctly (the cookie handles cursor management automatically) but requires `DS-Replication-Get-Changes`. The `go-ldap/ldap/v3` library implements `DirSync()` natively:

```go
func (p *LDAPProvider) PollDirSync(ctx context.Context) ([]*UserRecord, error) {
    req := &ldap.SearchRequest{
        BaseDN: p.config.BaseDN,
        Scope:  ldap.ScopeWholeSubtree,
        Filter: p.config.UserFilter,
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

DirSync includes deleted objects (tombstones) automatically when the filter matches them. Tombstones only retain `objectGUID`, `isDeleted: TRUE`, and a few system attributes. Map `isDeleted: TRUE` → tombstone action.

**Cookie persistence:** The DirSync cookie must be persisted to durable storage (same DB as DID documents). Loss of the cookie on a crash requires a full resync from the beginning — the sidecar fetches all objects again and diffs against stored state.

### 6.4 Service Account Requirements

**For USNChanged:**
- `List Contents` on the target OU
- `Read All Properties` on user objects in the OU
- `List Contents` on `CN=Deleted Objects,DC=...`
- `Read All Properties` on deleted objects (for deletion detection)

**For DirSync:**
- `DS-Replication-Get-Changes` extended right on the domain naming context root
- This is the same right used by AD replication — effectively domain admin territory
- Minimum: member of `Domain Admins` or explicit delegation of the extended right

The service account should be a dedicated account in a dedicated OU with all interactive login rights stripped. Its password should be rotated annually at minimum, stored in a secrets manager (HashiCorp Vault, AWS Secrets Manager, or equivalent), never in a config file.

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

Global Catalog support: if a Global Catalog is available and the operator prefers a single connection point for the whole forest, the sidecar can query the GC on port 3268. However, the USNChanged connector must be used if the backend is a Global Catalog, because DirSync cannot detect change events in sub-domains via GC.

---

## 7. JML Source Composition

When `jml_source.type` is not `none`, the sidecar runs both the identity provider and the JML source concurrently, deduplicating events by user stable ID and timestamp. This handles the Cat 3 case (SAML auth + separate JML source) and is also useful for Cat 4 (LDAP for fast change detection, HR system as the authoritative source for hire/fire decisions).

Deduplication rule: if the same user receives the same action (provision/suspend/tombstone) from two sources within a 60-second window, the second action is a no-op. If two sources disagree (one says provision, one says tombstone within 60 seconds), the more restrictive action wins (tombstone beats provision; suspend beats reactivate).

**Trust hierarchy for conflicting events:**

```
HR system (Workday/BambooHR) > LDAP > SCIM > webhook IdP > manual
```

A Workday `TERMINATE` event always wins over a concurrent LDAP `reactivate` signal (which might reflect a DC replication lag). Manual IT operations always have explicit operator intent and bypass the trust hierarchy — they are applied immediately and logged with a `manual-override` flag.

---

## 8. Auth Adapter Completeness

The enrollment auth adapter (from the multi-source migration spec) maps to the DID sidecar's identity provider as follows:

| `agora-enroll` auth adapter | DID Sidecar `IdentityProvider` | Notes |
|---|---|---|
| `okta` | `OktaProvider` | Same Okta org — OAuth2 OIDC on enroll, event hooks for JML |
| `teams` (Entra OIDC) | `EntraProvider` (O365 spec) | Same tenant |
| `slack` | No sidecar provider needed | Slack auth only for enrollment; no org-managed DID for Slack-primary orgs |
| `oidc` (generic) | `SCIMProvider` or `SAMLProvider` | Depends on what directory the OIDC issuer fronts |
| `saml` (generic) | `SAMLProvider` + separate JML source | Auth via SAML, JML from HR or AD |

The enrollment auth adapter and the sidecar identity provider are independent configurations. An org can use SAML for enrollment authentication (so the enrollment app gets the user's identity without a separate OIDC flow) while LDAP drives JML. They share the `email` field as the common key when `externalId` / `objectGUID` cross-referencing is not available.

---

## 9. Signing Key Options

The self-issued `EmployeeCredential` requires the org to hold an Ed25519 signing key. For orgs without cloud KMS (Azure Key Vault, Google Cloud KMS), the sidecar supports:

| Backend | Config `signing_key_type` | Notes |
|---|---|---|
| File (PEM) | `file` | Simplest; key on disk, operator responsible for backup and rotation |
| AWS KMS | `awskms` | HSM-backed; key ARN in config; uses `aws-sdk-go-v2` |
| Google Cloud KMS | `gcpkms` | As per Google Workspace spec |
| Azure Key Vault | `azurekv` | As per O365 spec |
| PKCS#11 (HSM) | `pkcs11` | On-prem HSM (Thales, SafeNet, YubiHSM) via `miekg/pkcs11` |
| HashiCorp Vault | `vault` | Vault Transit secrets engine; key never leaves Vault |

For on-prem deployments (Cat 3/4), the PKCS#11 and HashiCorp Vault backends are the appropriate choices. File-based keys are acceptable for lab/pilot deployments only.

---

## 10. Deployment Topologies

The sidecar now needs to be reachable from both cloud IdPs (webhook delivery) and internal networks (LDAP polling, SCIM). Deployment options by category:

| Category | Network requirement | Recommended topology |
|---|---|---|
| Cat 1 (Okta/JumpCloud) | Public HTTPS endpoint for webhook receipt | Cloud-hosted (AWS, GCP, Azure, Fly.io) |
| Cat 2 (SCIM server mode) | Public HTTPS endpoint for SCIM push receipt | Cloud-hosted |
| Cat 2 (SCIM client mode) | Outbound HTTPS to SCIM server | On-prem or VPN-accessible |
| Cat 3 + HR webhook | Public HTTPS endpoint for HR system webhook | Cloud-hosted with VPN or private link for AD access |
| Cat 3 + SFTP batch | Outbound SFTP to HRIS server | On-prem or co-located |
| Cat 4 (LDAP) | Outbound LDAP/LDAPS to domain controller (port 636) | On-prem, or cloud with VPN/Direct Connect |

For hybrid deployments (Cat 3 + Cat 4: SAML auth from cloud IdP, LDAP from on-prem AD), the sidecar runs on-prem with a reverse proxy exposing only the enrollment and webhook endpoints to the internet. The LDAP connection stays on the internal network.

```
Internet → [Reverse Proxy] → /v1/enroll/*     (enrollment)
                           → /v1/notify        (IdP webhook)
                           → /v1/hr-event      (HR webhook)
                           → /users/*/did.json (DID document serving)

Internal only:
LDAP polling → DC on port 636
DB → PostgreSQL on internal network
Signing key → on-prem HSM via PKCS#11
```

---

## 11. Implementation Additions to Shared Codebase

New `IdentityProvider` implementations (added to the shared Go binary):

```go
// Cat 1
type OktaProvider    struct { ... }
type JumpCloudProvider struct { ... }
type PingProvider    struct { ... }
type OneLoginProvider struct { ... }

// Cat 2
type SCIMServerProvider struct { ... }   // sidecar acts as SCIM endpoint
type SCIMClientProvider struct { ... }   // sidecar polls upstream SCIM

// Cat 3 (no IdentityProvider — uses JMLSource instead)
// Auth is handled by the existing SAML enrollment adapter

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

New key dependencies:

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

1. **Okta event hook delivery guarantees.** Okta event hooks are asynchronous and best-effort. The System Log API reconciliation poller covers missed events but has up to a 24-hour latency. For regulated orgs that need guaranteed sub-minute termination enforcement, the operator should also call `POST /v1/admin/tombstone` directly as a belt-and-suspenders step when terminating an employee — not rely solely on the Okta hook.

2. **SCIM Groups vs flat role attributes.** The SCIM spec has a separate Groups resource for membership. Some IdPs encode roles as user profile attributes instead of group membership. The sidecar's SCIM implementation supports both patterns but the role derivation config needs to specify which. This should be explicit in the operator config rather than auto-detected.

3. **AD multi-forest trust.** The spec covers multi-domain single-forest scenarios. Multi-forest trust relationships (where users from forest A can authenticate to resources in forest B) are not addressed. Each forest would need its own sidecar deployment with its own DID namespace, and cross-forest enrollment would use the SAML adapter for auth with the appropriate forest's LDAP as the JML source.

4. **Workday RaaS vs Studio.** Workday has two integration frameworks for outbound data: Report-as-a-Service (simpler, no coding required) and Studio (full EIB, more control). The spec describes a generic webhook payload but does not dictate which Workday integration type to use. The operator's Workday administrator will choose based on their existing Workday expertise. The sidecar endpoint accepts the same payload regardless of which Workday mechanism produces it.

5. **LDAP over Tor / air-gapped networks.** The Agora protocol spec (Appendix B) notes planned support for air-gapped and slow-transport deployments. A sidecar deployment in a fully air-gapped environment cannot receive webhooks from cloud IdPs and cannot push DID documents to a public IPFS node. The sidecar can operate in a fully internal mode — serving DID documents only on the internal network, with the Agora Relay also on the internal network. This is architecturally sound but requires all guild participants to be on the same internal network or VPN, which eliminates cross-org federation. Documented as an explicit trade-off for air-gapped deployments.
