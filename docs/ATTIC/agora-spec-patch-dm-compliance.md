# Agora Protocol Specification — Patch: DM Channel Type and Compliance Logging

**Patch against:** v0.1 (Draft), 2026-03-12  
**Status:** Draft amendment  
**Sections affected:** §9 (Guild and Channel Model), §17 (Compliance Logging)

This patch defines the Direct Message channel type (previously referenced but unspecified) and extends §17 to impose compliance logging obligations on regulated guild members participating in DM groups. It also amends §17.1, §17.2, §17.5, and §17.7 with minor clarifications that the original text presupposed only guild channels.

---

## §9 Amendment: Add §9.6 — Direct Message Channels

Insert the following section after §9.5 (Moderation Operations):

---

### 9.6 Direct Message Channels

A **Direct Message (DM) channel** is an MLS group established between two or more users outside of any Guild's channel hierarchy. DM groups are not owned by any Guild and do not appear in any Guild state document. They are identified by a `DMGroupCID` — the IPFS CID of the `DMGroupDescriptor` document — and are addressed on gossipsub at `v1/agora/dm/<dmGroupToken>`, where `dmGroupToken` is derived identically to a channel token (HKDF-SHA256 over the MLS group ID with label `"agora-dm-token"`).

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

`members` is the initial member DID list. `complianceLoggers` is the list of `ComplianceLogger` DIDs that have been admitted to the group under §17.8 (see below). The `DMGroupDescriptor` is stored as an IPLD node and updated (new CID, new `sig`) on every membership or logger change.

**MLS group initialization:** The DM group creator generates a fresh MLS group, adds KeyPackages for each invited member, and publishes Welcome messages to each invitee's push notification handle or relay inbox. There is no Guild admin in the invite path — any DM group member may add new members via standard MLS Add + Commit, subject to the consent mechanism in §9.6.1.

**Relay routing:** Because DM groups have no Guild affiliation, Relays route DM traffic by `dmGroupToken` alone, identically to channel traffic. A Relay that does not know the `dmGroupToken` will not route DM traffic; the sending client SHOULD use the Relays known to be serving the recipient's DID (discoverable from the recipient's DID document relay hints).

**History and storage:** DM message history is stored in IPFS/IPLD identically to channel history. The `DMGroupDescriptor` CID is the root. Members are responsible for pinning their own DM history; there is no Guild-level pinning obligation.

#### 9.6.1 Member Addition Consent

Any DM group member MAY propose adding a new member via an MLS Add Proposal. The Add is not committed until a configurable consent threshold of existing members issues a matching Commit or explicit approval signal. The default consent model is **unanimous** for groups of 2–4 and **majority** for groups of 5 or more. The `DMGroupDescriptor` MAY declare a non-default `consentModel`.

This consent requirement applies equally to compliance logger additions initiated under §17.8 — the logger is added via the same MLS Add + Commit path, and the committing client is the regulated member's own user agent, not a remote admin.

#### 9.6.2 DM Group vs. Private Channel

A DM group and a private Guild channel (§9.4) are structurally similar — both are MLS groups with a restricted membership set. The distinction is:

- A private channel is owned by a Guild, appears in that Guild's state document (for authorized members), and is subject to the Guild's compliance logging configuration.
- A DM group is owned by its members collectively, has no Guild parent, and is subject to compliance logging only through the per-member obligation in §17.8.

Users who need a persistent, named, multi-party private conversation with Guild-level administration (roles, moderation, compliance) SHOULD use a private Guild channel rather than a DM group.

---

## §17 Amendments

### 17.1 Overview — Amendment

Replace the second paragraph (beginning "Mechanically, compliance logging is implemented...") with:

> Mechanically, compliance logging is implemented as an MLS group member — a `ComplianceLogger` principal — that silently receives and archives all messages in every MLS group it is admitted to. This applies to Guild channels (§9) and Direct Message groups (§9.6) alike. It is structurally identical to a gateway (§16.2) but treated differently at the protocol and UI layers:

The remainder of §17.1 is unchanged.

---

### 17.2 Enabling Compliance Logging — Amendment

Add the following paragraph after the existing `complianceLogging` JSON block:

> The `scope` field governs which Guild channels receive the logger. The value `"all-channels"` causes the logger to be added to every channel in the Guild, including channels created after compliance logging is enabled. A glob list (e.g., `["engineering/*", "legal/*"]`) limits logging to matching channel paths.
>
> `scope` does **not** govern DM groups. DM group compliance logging is governed entirely by §17.8, which imposes an obligation on the regulated member's user agent independent of Guild channel scope configuration.

---

### 17.5 Ephemeral Message and Expiry Handling — Amendment

Add the following sentence to the end of the first bullet point:

> This applies equally in DM groups where a compliance logger is present under §17.8 — the DM group member's expiry preference is honored in relay caches and client display, but the compliance logger retains the plaintext for the regulated member's `retentionDays` regardless.

---

### 17.7 Member Disclosure — Amendment

Add the following paragraph at the end of §17.7:

> In DM groups where a compliance logger is present under §17.8, disclosure obligations are governed by §17.8.4 rather than this section. The Guild information panel disclosure requirements in this section apply only to Guild channels.

---

### 17.8 Compliance Logging for Direct Message Groups (NEW)

Insert as a new section after §17.7:

---

#### 17.8 Compliance Logging for Direct Message Groups

##### 17.8.1 Obligation

A Guild member subject to compliance logging (i.e., a member of a Guild where `complianceLogging.enabled` is `true`) carries that compliance obligation into every DM group they participate in, regardless of whether the DM group has any Guild affiliation.

The compliance obligation follows the regulated user, not the channel. A regulated user who conducts business communication via DM is not exempt from their Guild's retention requirements by virtue of using a DM group rather than a Guild channel.

A conformant client for a regulated Guild member MUST:

1. Add the Guild's `loggerDID` to the MLS group of every DM group the regulated member creates or joins, prior to sending or receiving any application messages in that group.
2. Re-add the logger if it is removed by another member (see §17.8.3).
3. Notify all other DM group members of the logger's presence before their first message is sent (see §17.8.4).

The client MUST NOT permit the regulated member to send any application message in a DM group until the compliance logger has been admitted to the MLS group and the disclosure notice has been displayed to all members.

##### 17.8.2 MLS Mechanics

Logger addition in a DM group follows the standard MLS Add + Commit path:

1. The regulated member's client fetches a fresh `KeyPackage` for the Guild's `loggerDID` from the logger's relay inbox or a published KeyPackage store.
2. The client issues an MLS Add Proposal for the logger DID.
3. The client immediately commits the proposal (no consent threshold applies to compliance logger additions — the regulated member's obligation is unilateral and does not require co-member approval).
4. The client updates the `DMGroupDescriptor` to add the logger DID to the `complianceLoggers` array and publishes the updated descriptor CID.
5. The logger's infrastructure issues a `Welcome` response, completing the logger's admission to the MLS group.

If the regulated member is joining an existing DM group (rather than creating one), step 2–5 are performed at join time, before the member sends any application messages. Messages sent by other members before the regulated member joined are not retroactively accessible to the logger — the logger's archive begins at the MLS epoch of its admission.

**KeyPackage availability:** The logger's DID document MUST publish a `KeyPackageEndpoint` service entry so that client user agents can fetch fresh KeyPackages programmatically:

```json
{
  "id": "did:key:z6MkLogger...#keypackages",
  "type": "AgoraKeyPackageEndpoint",
  "serviceEndpoint": "https://archive.acme-corp.internal/v1/agora/keypackages"
}
```

The endpoint MUST return a fresh, unused `KeyPackage` on each GET request. Reusing KeyPackages breaks MLS forward secrecy guarantees and is a conformance violation.

##### 17.8.3 Logger Removal Prohibition

Once a compliance logger has been admitted to a DM group by a regulated member, no member — including the regulated member — MAY issue an MLS Remove commit for the logger DID for the duration of the regulatory retention period.

A conformant client for a regulated Guild member MUST:

- Refuse to commit an MLS Remove proposal targeting the Guild's `loggerDID`.
- On receiving a committed Remove for the Guild's `loggerDID` (issued by another DM group member), immediately re-add the logger via the §17.8.2 procedure and notify the regulated member's Guild admin of the removal attempt. The re-add creates a new MLS epoch; messages in the epoch between removal and re-add are not captured by the logger. The Guild admin MUST be notified so they can assess the compliance gap.

This prohibition is enforced by the regulated member's client. It cannot be enforced protocol-wide — a non-regulated member's client can issue a Remove. The regulated member's client is responsible for detecting and remedying the gap.

##### 17.8.4 Disclosure to DM Group Members

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

##### 17.8.5 Multiple Regulated Members in a Single DM Group

If a DM group contains members from two or more compliance-logging Guilds, each regulated member's client MUST add their respective Guild's logger DID to the group. The group may have multiple compliance logger DIDs present simultaneously.

Each logger receives the full message stream from its admission epoch forward, regardless of which regulated member's messages it was originally added to capture. A logger from Guild A captures messages from Guild B members and vice versa — the MLS group membership does not discriminate by sender. This is the correct behavior: both Guilds have independent retention obligations that apply to their respective regulated members' participation in the conversation.

The `complianceLoggers` array in the `DMGroupDescriptor` lists all admitted logger DIDs. Each regulated member's client MUST verify on group join that their Guild's logger DID is present in this array, and add it if absent.

##### 17.8.6 Cross-Guild DM: Regulated Member with Non-Guild Participant

A DM group between a regulated Guild member and a participant who has no Guild affiliation (or a Guild without compliance logging) is treated identically to §17.8.4. The non-guild participant receives the same disclosure notice. The compliance obligation applies to the regulated member's participation regardless of the counterparty's affiliation.

##### 17.8.7 Offline and Deferred Join Scenarios

If a regulated member is offline when added to a DM group by another member, the compliance logger addition and disclosure notice MUST be performed by the regulated member's client when they next come online and process the pending MLS Welcome, before their client sends any application messages in the group.

Clients MUST queue the logger addition and disclosure as the first operations to perform on a pending DM group join, ahead of any queued outbound messages. If the client has queued outbound messages (e.g., drafted while offline), those messages MUST NOT be sent until the logger admission commit has been completed and acknowledged.

##### 17.8.8 Audit Trail

The regulated member's Guild MUST record each DM group compliance logger admission in its IPLD compliance audit chain. The audit record is a `DMComplianceAuditEntry`:

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

`removalAttempts` is an array of timestamps and initiator DIDs for any Remove commits targeting the logger that the regulated member's client detected and remedied per §17.8.3. This gives the Guild admin and compliance officer a complete record of logger presence in DM groups, including any attempted circumvention.

---

## Conformance Summary

The following table summarizes the new conformance requirements introduced by this patch:

| Requirement | Applies To | MUST / SHOULD |
|---|---|---|
| Add Guild `loggerDID` to DM group before first message | Regulated member's client | MUST |
| Fetch fresh KeyPackage per logger addition | Regulated member's client | MUST |
| Display `ComplianceDisclosureNotice` to all DM members before first message | Regulated member's client | MUST |
| Re-add logger if removed by another member | Regulated member's client | MUST |
| Notify Guild admin of logger removal attempt | Regulated member's client | MUST |
| Queue logger addition before queued outbound messages on deferred join | Regulated member's client | MUST |
| Publish `DMComplianceAuditEntry` to Guild IPLD chain | Regulated member's client | MUST |
| Publish `KeyPackageEndpoint` in logger DID document | Compliance logger operator | MUST |
| Provide fresh (non-reused) KeyPackage per request | Compliance logger operator | MUST |
| Use DM group for persistent named multi-party private conversation | Any user | SHOULD use private channel instead |

---

*End of patch. Apply after §9.5 and within §17, inserting §9.6 and §17.8 as indicated.*
