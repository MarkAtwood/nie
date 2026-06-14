# Agora Protocol — Microsoft Purview Bridge
## Implementation Specification v0.1

**Status:** Draft

**Scope:** This document specifies the Agora Purview Bridge — a compliance gateway that ingests Agora `ComplianceRecord` objects (§17.4) and VTC compliance archives (§10.12) into Microsoft Exchange Online mailboxes for processing by Microsoft Purview Communication Compliance, eDiscovery, retention policies, and litigation hold.

**Dependencies:** Agora Protocol Specification v0.1, §17 (Compliance Logging), §10.12 (VTC Recording), §9.6 (DM Groups).

---

## 1. Overview

### 1.1 Architecture

The Purview Bridge is a sidecar service that runs alongside the Agora `ComplianceLogger` principal (§17.3). It does not replace the logger — the Agora IPLD compliance archive (§17.4) remains the authoritative tamper-evident record. The bridge is a one-way export pipeline:

```
Agora MLS groups
      │
      ▼ (MLS decryption)
ComplianceLogger (§17.3)
      │
      ├── IPLD chain (§17.4)          ← authoritative Agora record
      │
      └── PurviewBridge               ← this spec
            │
            ▼ (RFC 822 MIME, base64)
      Exchange Online mailboxes
            │
            ▼
      Microsoft Purview
      (Communication Compliance,
       eDiscovery, Retention,
       Litigation Hold)
```

The bridge reads from the ComplianceLogger's local decrypted payload stream (or polls the IPLD chain) and writes each message as a synthetic MIME item into the target user's Exchange Online mailbox via the Microsoft Graph API. Purview then applies retention policies, Communication Compliance classifiers, and eDiscovery indexing to these items exactly as it does to native Exchange mail.

### 1.2 Scope of the Bridge

The bridge performs the following functions:

- Translates `ComplianceRecord` payloads into RFC 822 MIME format with Purview-indexed `x-` headers.
- Deposits items into the designated Exchange Online compliance mailbox for each Agora user mapped to an M365 identity.
- Handles text messages, edit events, delete events (tombstones), reactions, file attachments, and DM group messages.
- Exports VTC compliance metadata and recording references (not raw media — see §5).
- Maintains delivery ordering and idempotency; no duplicate items are created on retry.
- Propagates expiry and deletion tombstones to deposited items via Graph delete.
- Tracks bridge delivery state separately from the Agora IPLD chain.

The bridge does not perform the following:

- Replace the Agora IPLD chain as the tamper-evident compliance record.
- Store or re-encrypt MLS keys.
- Relay live message traffic — it processes from the logger's archive, not from the gossipsub mesh directly.
- Break E2EE for non-bridged channels — only channels with `complianceLogging.enabled: true` are processed.

### 1.3 Deployment Model

The bridge runs as a process co-located with or directly connected to the ComplianceLogger. It requires:

- Service principal credentials for the Microsoft 365 tenant (Entra ID app registration with `Mail.ReadWrite` and `MailboxItem.ImportExport` application permissions).
- A mapping table from Agora DIDs to Exchange Online UPNs (M365 user principal names).
- Network access to `https://graph.microsoft.com`.
- Read access to the ComplianceLogger's payload stream.

The bridge MUST NOT run on the relay. It is a compliance infrastructure component, not a protocol infrastructure component.

---

## 2. Microsoft 365 Provisioning

### 2.1 Entra ID App Registration

The bridge authenticates to Microsoft Graph using the OAuth 2.0 client credentials flow (application permissions, no user context). The app registration requires the following application permissions (not delegated):

- `Mail.ReadWrite` — create and delete messages in any user's mailbox.
- `MailboxItem.ImportExport` — import MIME items preserving original timestamps.
- `User.Read.All` — resolve UPNs for DID-to-M365 identity mapping lookups.

The bridge MUST authenticate using a certificate credential, not a client secret. Certificate rotation SHOULD be automated via Azure Key Vault or an equivalent HSM-backed credential store.

Tenant admin consent is required for all application permissions above. The bridge operator provisions consent once; it applies tenant-wide.

```powershell
# Provision service principal (run once per tenant, as Global Admin)
az login
az ad sp create --id <bridge-app-client-id>
# Grant admin consent in the Entra portal or via:
az ad app permission admin-consent --id <bridge-app-client-id>
```

### 2.2 Compliance Mailbox Folder

The bridge deposits items into a dedicated subfolder of each user's primary mailbox, not into their Inbox. This keeps Purview compliance items out of the user's active mail view while remaining fully indexed and policy-applicable.

**Folder name:** `Agora Compliance Archive`

The bridge creates this folder on first deposit for each user:

```http
POST https://graph.microsoft.com/v1.0/users/{upn}/mailFolders
Content-Type: application/json

{
  "displayName": "Agora Compliance Archive",
  "isHidden": true
}
```

Setting `isHidden: true` makes the folder invisible in Outlook but fully accessible to Purview policies, eDiscovery, and litigation hold. Items in hidden folders are indexed and retained identically to items in visible folders.

Subfolders within the archive folder are organized as follows:

```
Agora Compliance Archive/
  ├── Space: <spaceName>/
  │     ├── Channel: <channelName>/
  │     └── ...
  └── Direct Messages/
```

The bridge creates subfolders lazily on first message for each space/channel. Folder names are derived from the `channel` field in the `ComplianceRecord` (§17.4) and sanitized for Exchange folder name constraints (maximum 255 characters; the characters `\ / : * ? " < > |` are prohibited).

### 2.3 DID-to-M365 Identity Mapping

The bridge maintains a mapping table `{ agoraDID → m365UPN }`, populated by one of the following methods:

1. **SAML/OIDC attribute injection** (preferred for enterprise deployments): when a user authenticates to Agora via the enterprise IdP, their M365 UPN is included as a SAML attribute (`urn:oid:1.2.840.113549.1.9.1` / email) or OIDC claim (`upn` or `email`). The Agora client records this mapping at login time and includes it in the user's DID document service entry.

2. **Manual provisioning**: an admin-supplied CSV mapping `agoraDID,m365UPN` loaded at bridge startup. This is the fallback for environments without SAML/OIDC integration.

3. **Graph directory lookup**: for `did:web` identities where the DID domain matches the M365 tenant's verified domain, the bridge MAY resolve the UPN by querying `GET /users?$filter=mail eq '{didWebLocalPart}@{domain}'`.

If a `senderDID` in a `ComplianceRecord` has no M365 mapping, the bridge MUST deposit the item into a designated catch-all mailbox (`agora-compliance-catchall@<tenant>`) with the raw DID preserved in headers and MUST alert the compliance officer. Items in the catch-all mailbox are fully subject to Purview policies.

---

## 3. MIME Item Format

The bridge translates each `ComplianceRecord` (§17.4) into an RFC 822 MIME message deposited via the Graph API. Exchange and Purview treat these as email-like items and apply all compliance policies uniformly.

### 3.1 Graph API Deposit Call

```http
POST https://graph.microsoft.com/v1.0/users/{senderUPN}/mailFolders/{folderId}/messages
Content-Type: text/plain

{base64-encoded RFC 822 MIME message}
```

The entire RFC 822 message MUST be base64-encoded (standard base64, no line wrapping). The `Content-Type` header on the HTTP request MUST be `text/plain` — this is the Graph API MIME import path. Using `application/json` triggers JSON message creation, which does not support custom `x-` headers or original timestamps.

After creation, the message is in Draft state. The bridge MUST immediately call:

```http
POST https://graph.microsoft.com/v1.0/users/{senderUPN}/messages/{messageId}/send
```

This transitions the item out of Draft state and makes it fully subject to retention and litigation hold policies. Items in Draft state are excluded from some Purview policies.

If the `MailboxItem.ImportExport` permission is available, the bridge SHOULD use the import path instead, which preserves the original `Date:` header:

```http
POST https://graph.microsoft.com/v1.0/users/{senderUPN}/mailFolders/{folderId}/messages/import
Content-Type: text/plain

{base64-encoded RFC 822 MIME}
```

This path is preferred for regulated deployments where the archived item's timestamp must reflect the actual message send time rather than the bridge deposit time.

### 3.2 RFC 822 MIME Structure

```
MIME-Version: 1.0
Date: {ts from ComplianceRecord, RFC 2822 format}
Message-ID: <{envelopeID}@agora.compliance>
From: {senderDisplayName} <{senderDID}@agora.noreply>
To: {recipientUPN}
Subject: [Agora] {spaceName} / {channelName}
Content-Type: multipart/mixed; boundary="{boundary}"

x-agora-record-version: 1
x-agora-envelope-id: {envelopeID}
x-agora-channel-cid: {channelCID}
x-agora-space-cid: {spaceCID}
x-agora-sender-did: {senderDID}
x-agora-epoch: {epoch}
x-agora-seq: {seq}
x-agora-message-type: {type}
x-agora-ipld-prev-cid: {prevRecordCID}
x-agora-logger-sig: {loggerSig, base64url}
x-agora-logger-did: {loggerDID}
x-agora-space-name: {spaceName}
x-agora-channel-name: {channelName}
x-agora-expiry: {expiry if present, else absent}
x-agora-is-dm: {true|false}
x-agora-dm-group-id: {dmGroupCID if DM, else absent}

--{boundary}
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: quoted-printable

{plaintext rendering of message body}

--{boundary}
Content-Type: application/json; charset=utf-8
Content-Disposition: attachment; filename="agora-compliance-record.json"
Content-Transfer-Encoding: base64

{base64(plaintextPayload from ComplianceRecord)}

--{boundary}--
```

**`From:` address construction:** Exchange requires a syntactically valid RFC 5321 address in `From:`. Since Agora DIDs are not email addresses, the bridge synthesizes one as `{did-method}-{did-fragment-8chars}@agora.noreply`. The display name is the sender's Agora display name from their profile (fetched from IPFS at time of record processing, cached for 1 hour). Purview Communication Compliance searches use `x-agora-sender-did` for identity matching, not the synthetic `From:` address.

**`To:` address construction:** The `To:` field is the UPN of the user whose mailbox receives the item. For channel messages (non-DM), this is the compliance officer mailbox UPN. For DM messages, this is the regulated member's UPN. See §4.2 for DM routing.

### 3.3 Custom Header Index (`x-agora-*`)

Purview Communication Compliance and eDiscovery can search message properties including custom `x-` headers. The bridge defines the following header namespace:

| Header                        | Type    | Description                                                                                   |
|-------------------------------|---------|-----------------------------------------------------------------------------------------------|
| `x-agora-record-version`      | integer | Schema version of this MIME format. Currently `1`.                                            |
| `x-agora-envelope-id`         | string  | `envelopeID` from `ComplianceRecord`. URN. Unique per message; used for deduplication.        |
| `x-agora-channel-cid`         | string  | IPFS CID of the channel. Stable channel identity across epochs.                               |
| `x-agora-space-cid`           | string  | IPFS CID of the space genesis state.                                                          |
| `x-agora-sender-did`          | string  | Full DID of the sender. Primary identity field for Purview policy matching.                   |
| `x-agora-epoch`               | integer | MLS epoch in which the message was encrypted.                                                 |
| `x-agora-seq`                 | integer | Per-sender sequence number within epoch.                                                      |
| `x-agora-message-type`        | string  | Agora inner payload `@type`: `ChatMessage`, `EditEvent`, `DeleteEvent`, `ReactionEvent`, `FileMessage`. |
| `x-agora-ipld-prev-cid`       | string  | `prevRecordCID` from `ComplianceRecord`. Chain linkage.                                       |
| `x-agora-logger-sig`          | string  | `loggerSig` from `ComplianceRecord`, base64url. Proof of authentic capture.                   |
| `x-agora-logger-did`          | string  | DID of the ComplianceLogger that produced this record.                                        |
| `x-agora-space-name`          | string  | Human-readable space name, from space state at time of logging.                               |
| `x-agora-channel-name`        | string  | Human-readable channel name.                                                                  |
| `x-agora-expiry`              | string  | ISO 8601 expiry timestamp from inner payload, if present. Omitted if no expiry.               |
| `x-agora-is-dm`               | boolean | `true` if this record originated from a DM group (§9.6).                                     |
| `x-agora-dm-group-id`         | string  | CID of the `DMGroupDescriptor`, if `x-agora-is-dm: true`.                                    |
| `x-agora-vtc-session-id`      | string  | VTC session CID, if this record is a VTC compliance record (§5).                             |
| `x-agora-edit-target-id`      | string  | `envelopeID` of the original message, for `EditEvent` types.                                  |
| `x-agora-delete-target-id`    | string  | `envelopeID` of the deleted message, for `DeleteEvent` types.                                 |
| `x-agora-reaction-target-id`  | string  | `envelopeID` of the reacted-to message, for `ReactionEvent` types.                            |

Headers that are absent for a given message type MUST be omitted entirely, not written as empty strings. Purview keyword search operates on header values; empty strings produce false matches.

### 3.4 Message Body Text

The `text/plain` body part MUST contain a human-readable rendering of the message, usable by Purview Communication Compliance classifiers and investigators without Agora client software. Rendering rules by `@type`:

**`ChatMessage`:**
```
[{ts}] {senderDisplayName} ({senderDID}):
{text content, stripped of Markdown formatting}

[Raw Markdown preserved in attached JSON]
```

**`EditEvent`:**
```
[{ts}] {senderDisplayName} EDITED a message (original ID: {editTargetID}):
Before: [see original record]
After: {new text, stripped of Markdown}

[Raw JSON attached]
```

**`DeleteEvent`:**
```
[{ts}] {senderDisplayName} DELETED a message (original ID: {deleteTargetID}).
[Content removed per sender deletion. Original record in Agora IPLD chain.]
```

**`ReactionEvent`:**
```
[{ts}] {senderDisplayName} reacted to message {reactionTargetID} with: {emoji}
```

**`FileMessage`:**
```
[{ts}] {senderDisplayName} sent a file attachment:
  Name: {filename}
  Size: {size} bytes
  IPFS CID: {mediaCID}
  MIME type: {mimeType}

[File content attached if within size limit; see §3.5]
```

Markdown stripping for `text/plain` bodies: remove `**bold**`, `*italic*`, `~~strikethrough~~`, `` `code` ``, and heading markers. Preserve URLs as plain text. The raw Markdown is preserved in the attached JSON record (`agora-compliance-record.json`).

### 3.5 File Attachment Handling

When the inner payload is a `FileMessage` (or a `ChatMessage` with `attachments[]` present):

1. The bridge fetches the media CID from IPFS via the configured gateway.
2. If file size is ≤ 25 MB (Exchange attachment limit): include the file as a MIME attachment part in the multipart body.
3. If file size is > 25 MB: include only the metadata (CID, filename, size, MIME type) in the text body and attached JSON. The IPFS CID is permanent; auditors can retrieve the content independently.
4. File attachments MUST be included with their original filename, sanitized for MIME `Content-Disposition`.
5. The MIME type for the attachment part SHOULD match the file's declared MIME type; fall back to `application/octet-stream` if unknown.

IPFS fetch timeout is 10 seconds. On fetch failure, the bridge MUST log the failure, include the CID in the record, and deposit the item without the binary attachment. The bridge MUST NOT block the deposit pipeline on attachment fetch failures.

---

## 4. Message Routing in Exchange

### 4.1 Channel Messages (Space Channels)

Space channel messages are deposited into the regulated member's personal compliance archive folder, not a shared or system mailbox. This is the architecture Purview requires — compliance policies apply per-user, and the authoritative record lives in the user's mailbox under litigation hold.

If a channel has 40 members and 3 of them are regulated (i.e., their M365 identities are under Purview policy), the bridge deposits each channel message into all 3 regulated members' compliance archive folders. The message appears in each regulated member's archive as an independent Exchange item with identical content, carrying the same `x-agora-envelope-id` for deduplication.

Before depositing, the bridge SHOULD query for existing items to prevent duplicate deposits on restart or replay:

```http
GET https://graph.microsoft.com/v1.0/users/{upn}/mailFolders/{folderId}/messages
  ?$filter=internetMessageHeaders/any(h: h/name eq 'x-agora-envelope-id' and h/value eq '{envelopeID}')
  &$select=id
```

If a match is found, the deposit is skipped.

### 4.2 DM Group Messages (§9.6)

DM compliance logging (§17.8) deposits messages into the regulated member's compliance archive folder, under `Direct Messages/`. The counterparty's UPN appears in the `Subject:` line for discoverability.

For a two-party DM:
```
Subject: [Agora DM] {regulatedMemberDisplayName} ↔ {counterpartyDisplayName}
```

For a DM group with multiple participants:
```
Subject: [Agora DM] {p1}, {p2}, {p3} — Group DM
```

The `x-agora-dm-group-id` header carries the stable DM group CID for grouping related messages in eDiscovery searches.

### 4.3 Compliance Folder Retention

The Agora Compliance Archive folder MUST be included in the organization's Purview retention policy. The bridge operator configures this in the Purview portal:

| Setting              | Value                                                                       |
|----------------------|-----------------------------------------------------------------------------|
| Retention target     | All mailboxes, or a targeted distribution group covering regulated users    |
| Retention period     | Match `complianceLogging.retentionDays` from space state                    |
| Retention action     | Retain only (do not delete at policy expiry without explicit legal review)  |
| Litigation hold      | Apply to all regulated user mailboxes independently of retention policy     |

The bridge deposits items; Purview's own retention machinery governs their lifecycle from that point.

---

## 5. VTC Compliance Records (§10.12)

The bridge handles VTC compliance records differently from text records. Media files are not deposited into Exchange — they exceed practical size limits and are already archived in IPFS per §10.12.4. Instead, the bridge deposits a VTC compliance notification item: a lightweight MIME record that indexes the session in Purview and carries the link to the IPFS recording archive.

### 5.1 VTC Notification Item

For each `VTCComplianceRecord` chain entry, the bridge deposits the following MIME item:

```
MIME-Version: 1.0
Date: {session start time, RFC 2822}
Message-ID: <vtc-{vtcRecordCID}@agora.compliance>
From: Agora VTC Compliance <compliance@agora.noreply>
To: {regulatedMemberUPN}
Subject: [Agora VTC] {spaceName} / {channelName} — {durationMinutes}min call
Content-Type: multipart/mixed; boundary="{boundary}"

x-agora-record-version: 1
x-agora-message-type: VTCComplianceRecord
x-agora-vtc-session-id: {vtcRecordCID}
x-agora-channel-cid: {channelCID}
x-agora-space-cid: {spaceCID}
x-agora-logger-did: {recorderDID}
x-agora-logger-sig: {recorderSig, base64url}
x-agora-epoch: {epoch}
x-agora-vtc-media-cid: {mediaCID}
x-agora-vtc-media-format: {mediaFormat}
x-agora-vtc-epochs-recorded: {epochsRecorded, comma-separated}
x-agora-vtc-epochs-gapped: {epochsGapped, comma-separated, absent if empty}
x-agora-is-dm: {true|false}
```

**Text body:**
```
[{sessionStart}] Voice/video call in {spaceName} / {channelName}

Duration: {durationMinutes} minutes
Participants ({count}):
  - {displayName} ({did}), joined {joinTime}, left {leaveTime}
  - ...

Recording:
  IPFS CID: {mediaCID}
  Format: {mediaFormat}
  Epochs recorded: {epochsRecorded}
  Epochs with gaps (no key delivery): {epochsGapped or "none"}
  Recorder: {recorderLabel} ({recorderDID})
  Recorder signature: {recorderSig, truncated}

[Full VTCComplianceRecord attached as JSON]
```

**Attached JSON part:** The full `VTCComplianceRecord` JSON (§10.12.4), base64-encoded, attached as `agora-vtc-compliance-record.json`. This is the machine-readable record; the text body is for human investigators.

### 5.2 Media Retrieval for eDiscovery

When an eDiscovery investigator needs the actual recording:

1. Identify the `x-agora-vtc-media-cid` header on the VTC notification item in Exchange.
2. Retrieve the media file from IPFS via any configured gateway: `https://ipfs.io/ipfs/{mediaCID}` (or the organization's own IPFS gateway).
3. Verify the `recorderSig` in the attached JSON against the recorder's DID public key before treating the media as authentic.

IPFS CIDs are permanent and self-verifying; the bridge does not provide a separate retrieval mechanism. The `x-agora-vtc-media-cid` header is searchable in Purview eDiscovery and can be extracted programmatically from search results.

**Epoch gap handling:** If `x-agora-vtc-epochs-gapped` is non-empty, the recording has gaps. The eDiscovery workflow SHOULD retrieve the `VTCComplianceAuditEntry` from the Agora IPLD chain to confirm each gap is documented. A documented gap (logger offline during epoch) is distinct from an undocumented gap (gap with logger online), which may indicate a logger removal attempt. The `DMComplianceAuditEntry` `removalAttempts` field covers the latter case.

---

## 6. Edit, Delete, and Expiry Handling

### 6.1 Edit Events

When the bridge processes an `EditEvent` `ComplianceRecord`:

1. Deposit a new MIME item with `x-agora-message-type: EditEvent` and `x-agora-edit-target-id: {originalEnvelopeID}`.
2. Do NOT modify or delete the original deposited item. Exchange does not support in-place message editing, and compliance requirements demand that the original be preserved.
3. The text body of the edit item contains the new text. The attached JSON contains the full `EditEvent` inner payload, including `prevText` if present.

Purview eDiscovery returns both the original item and the edit item when searching by channel or sender, providing investigators with the full edit history.

### 6.2 Delete Events

When the bridge processes a `DeleteEvent` `ComplianceRecord`:

1. Deposit a new MIME item with `x-agora-message-type: DeleteEvent` and `x-agora-delete-target-id: {originalEnvelopeID}`.
2. Do NOT delete the original item from Exchange. Litigation hold prevents deletion regardless; items under hold cannot be deleted by application code. For items not under hold, the bridge MUST NOT delete — the original is part of the tamper-evident chain.
3. The text body of the delete item is: `Message deleted by sender at {ts}.`

The investigator view is: original item followed by the delete notification item. This matches how Exchange handles Teams message deletions natively.

### 6.3 Expiry Override (§17.5)

Per §17.5, compliance logging overrides sender expiry. The bridge implements this as follows:

- The `x-agora-expiry` header carries the sender's declared expiry timestamp for audit visibility.
- The bridge MUST NOT schedule or perform any deletion of deposited items based on this header.
- Exchange litigation hold and Purview retention policies prevent deletion of held items regardless of bridge behavior.
- Item disposition at the end of the regulatory retention period is managed by the compliance officer through Purview Records Management, not through the bridge.

---

## 7. Bridge State and Delivery Tracking

### 7.1 Delivery State Store

The bridge maintains a local delivery state store (SQLite or equivalent) with the following schema:

```sql
CREATE TABLE delivery_state (
  envelope_id       TEXT PRIMARY KEY,   -- x-agora-envelope-id
  record_cid        TEXT NOT NULL,      -- IPLD ComplianceRecord CID
  record_type       TEXT NOT NULL,      -- ChatMessage, EditEvent, etc.
  sender_did        TEXT NOT NULL,
  target_upn        TEXT NOT NULL,      -- Exchange UPN deposited to
  exchange_item_id  TEXT,               -- Graph API message ID after deposit
  folder_id         TEXT,               -- Exchange folder ID
  status            TEXT NOT NULL,      -- pending | deposited | failed | skipped
  attempt_count     INTEGER DEFAULT 0,
  last_attempt_ts   TEXT,
  error             TEXT,               -- last error message if failed
  created_ts        TEXT NOT NULL,
  deposited_ts      TEXT
);
```

Status values:

- **`pending`:** queued for deposit.
- **`deposited`:** successfully deposited and sent in Exchange.
- **`failed`:** all retry attempts exhausted; requires manual intervention.
- **`skipped`:** intentionally not deposited (e.g., message type excluded from bridge scope; DID has no M365 mapping and catch-all is disabled).

### 7.2 Retry Policy

Failed deposits retry with exponential backoff:

| Attempt | Delay      |
|---------|------------|
| 1       | immediate  |
| 2       | 30 seconds |
| 3       | 5 minutes  |
| 4       | 30 minutes |
| 5       | 2 hours    |
| 6+      | 6 hours    |

After 7 days without a successful deposit, the status transitions to `failed` and a compliance alert is raised. A record in `failed` state represents a compliance gap requiring investigation.

Graph API rate limits (Exchange Online: 10,000 requests per 10 minutes per app per tenant) constrain throughput during backlog catch-up. The bridge SHOULD implement a token bucket rate limiter at 900 requests/minute (15/second) to remain within limits.

### 7.3 IPLD Chain Cursor

The bridge tracks its read position in the IPLD compliance chain per channel as a cursor — the CID of the last-processed `ComplianceRecord`. On restart, the bridge resumes from the cursor.

Gap detection: if a `ComplianceRecord`'s `prevRecordCID` does not match the bridge's last-deposited CID for that channel, a chain gap exists. The bridge MUST alert on this condition and MUST attempt to backfill by walking the chain backwards from the current head to the last-known cursor position.

---

## 8. Authentication and Security

### 8.1 Graph API Authentication

The bridge authenticates using the OAuth 2.0 client credentials flow. Token acquisition:

```http
POST https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id={clientId}
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion={signed-JWT-from-certificate}
&scope=https://graph.microsoft.com/.default
```

Tokens are valid for 1 hour. The bridge caches the token and refreshes 5 minutes before expiry. Token material MUST be stored in memory only and MUST NOT be written to disk.

### 8.2 Bridge Process Security

- The bridge process MUST run as a dedicated service account with no network access beyond `graph.microsoft.com` and the ComplianceLogger's local socket.
- The delivery state store (SQLite) MUST reside on an encrypted volume (LUKS or equivalent).
- The certificate private key for Entra authentication MUST be stored in an HSM or TPM-backed keystore, never in a file. `PKCS#11` or `tpm2-pkcs11` are the required interfaces on Linux.
- Bridge logs MUST NOT contain message plaintext. Log `envelope_id`, `record_cid`, `sender_did`, and `status` only.

### 8.3 ComplianceLogger Payload Access

The bridge accesses decrypted `ComplianceRecord` payloads from the logger via a local Unix domain socket (preferred) or shared memory queue. The bridge MUST NOT have access to MLS epoch secrets or the logger's key material — it receives only already-decrypted and signed `ComplianceRecord` objects.

The interface is:

```
LocalSocket: /run/agora-compliance/records.sock
Protocol:    newline-delimited JSON stream
Each line:   { "recordCID": "...", "record": {ComplianceRecord} }
```

The bridge reads from this stream and processes records in order. If the bridge is offline, the logger buffers records to a local queue (configurable; default 10,000 records, approximately 50 MB). On bridge reconnect, the queue is drained in order.

---

## 9. Operational Monitoring

### 9.1 Required Metrics

The bridge MUST expose the following metrics (Prometheus format):

| Metric                                     | Type    | Description                                     |
|--------------------------------------------|---------|-------------------------------------------------|
| `agora_bridge_records_received_total`      | counter | Records received from ComplianceLogger          |
| `agora_bridge_records_deposited_total`     | counter | Records successfully deposited to Exchange      |
| `agora_bridge_records_failed_total`        | counter | Records in `failed` state                       |
| `agora_bridge_deposit_lag_seconds`         | gauge   | Seconds behind the live logger stream           |
| `agora_bridge_retry_queue_depth`           | gauge   | Number of records pending retry                 |
| `agora_bridge_graph_api_errors_total`      | counter | Graph API errors by status code                 |
| `agora_bridge_ipfs_fetch_failures_total`   | counter | Attachment fetch failures                       |
| `agora_bridge_did_unmapped_total`          | counter | Records with no M365 DID mapping                |

### 9.2 Compliance Alerts

The following conditions MUST trigger an alert to the compliance officer (email to a configurable designated address):

- Any record transitions to `failed` status.
- Bridge delivery lag exceeds 15 minutes (real-time compliance monitoring requirement).
- IPLD chain gap detected.
- DID mapping failure for a regulated member.
- VTC epoch gap (`epochsGapped` non-empty in a VTC compliance record).
- Logger removal attempt detected (`removalAttempts` non-empty in `DMComplianceAuditEntry`).
- Graph API authentication failure (token acquisition failure).
- Bridge process crash or restart.

---

## 10. Purview Policy Configuration

After the bridge is operational, the compliance administrator configures the following in the Microsoft Purview portal.

### 10.1 Communication Compliance Policy

Create a policy targeting the `Agora Compliance Archive` folder with the following conditions:

- **Keyword conditions** operating on `x-agora-sender-did` for DID-specific supervision.
- **Message type filter:** use `x-agora-message-type` to scope to `ChatMessage` only, excluding system events from Communication Compliance classifiers, which are designed for human-authored text.
- **Built-in classifiers:** financial regulatory language, sensitive information types (SSNs, account numbers), etc., applied to the `text/plain` body part.

### 10.2 Retention Policy

| Setting          | Value                                                                  |
|------------------|------------------------------------------------------------------------|
| Target           | All user mailboxes, or a regulated-user distribution group             |
| Scope            | `Agora Compliance Archive` folder                                      |
| Duration         | Match `complianceLogging.retentionDays` (e.g., 2555 days for FINRA 17a-4) |
| Action           | Retain only                                                            |

### 10.3 Litigation Hold

Apply unconditional litigation hold to all regulated user mailboxes. This prevents item deletion regardless of any action by the bridge, the user, or any Graph API call. If the bridge mistakenly attempts to delete an item, Exchange rejects the call silently and moves the item to the Recoverable Items folder.

### 10.4 eDiscovery Search Templates

Recommended saved search templates for Agora data:

```
# All messages from a specific Agora DID
x-agora-sender-did:{did}

# All messages in a specific space channel
x-agora-channel-cid:{cid}

# All DM group messages for a regulated user
x-agora-is-dm:true AND from:{regulatedUserUPN}

# All VTC sessions with recording gaps
x-agora-message-type:VTCComplianceRecord AND x-agora-vtc-epochs-gapped:*

# Edit and delete events for a specific original message
x-agora-edit-target-id:{envelopeID} OR x-agora-delete-target-id:{envelopeID}
```

---

## 11. Open Issues

1. **`MailboxItem.ImportExport` availability:** This permission preserves original message timestamps during import. It is available in M365 E3/E5 tenants with explicit admin enablement. Environments without it fall back to deposit-time timestamps. The regulatory impact of the timestamp discrepancy (bridge lag vs. actual message time) is mitigated by the `Date:` header in the MIME body and the `ts` field in `x-agora-*` headers — both reflect the original message timestamp regardless of when the Graph API deposit occurs.

2. **Graph API MIME import draft behavior:** The `POST /messages` MIME path creates items as drafts requiring a subsequent `send` call. The `import` path (`POST /messages/import`) avoids this but requires the `MailboxItem.ImportExport` permission. Until this permission is universally available, the bridge uses the draft-then-send path. Items between draft and sent states are not subject to litigation hold. The bridge MUST minimize this window (target: less than 1 second between create and send calls).

3. **Exchange attachment size limit:** The 25 MB file attachment limit means large Agora file messages are deposited with CID-only references rather than binary content. Regulators (particularly FINRA) have accepted CID-based references to immutable content stores in analogous contexts (IPFS, content-addressed storage), but this SHOULD be confirmed with the organization's compliance counsel before production deployment.

4. **Catch-all mailbox governance:** Records deposited to the catch-all mailbox due to unmapped DIDs may represent regulated member communications. The compliance officer MUST review and resolve DID mapping gaps promptly. A backlog in the catch-all mailbox is a compliance gap, not merely an operational issue.
