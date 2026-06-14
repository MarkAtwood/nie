# Agora Protocol: Examiner's Reference Guide

**Audience:** FINRA, SEC, FCA, BaFin, and MiFID II examination staff; supervisory technology analysts; enforcement counsel
**Companion document:** *Agora Compliance & Legal Reference Guide* (for the regulated firm's compliance team)
**Purpose:** How Agora's communications archive works, what an examination will find, how to verify authenticity, and what a regulated firm is and is not required to produce
**Document version:** Aligned to Agora Protocol Specification v0.1 + DM Compliance patch

---

> **Preliminary note.** This document describes the technical architecture of the Agora open communication protocol from the perspective of regulatory examination. It is not legal advice and does not create regulatory obligations. Determinations of whether a specific Agora deployment satisfies a particular regulatory requirement are subject to applicable law and regulatory interpretation in the relevant jurisdiction.

---

## Part 1: What Agora Is and How It Differs From Conventional Platforms

### The Core Architecture

Agora is an open protocol for end-to-end encrypted (E2EE) group communication. Unlike Microsoft Teams, Slack, or Bloomberg Terminal — where the platform operator holds message encryption keys and can produce plaintext in response to a subpoena — Agora's architecture deliberately prevents any server from reading message content.

This is not a policy or contractual commitment. It is a mathematical property of the encryption design.

**Key architectural elements for examiners:**

**MLS encryption (RFC 9420).** Every message is encrypted by the sender's device before it leaves that device. The server infrastructure — called Relays — receives and routes encrypted ciphertext only. The Relay does not hold decryption keys and cannot produce message plaintext under any circumstances.

**Compliance logger.** The solution to the obvious examination concern — how can a regulator examine communications the servers cannot read? — is the compliance logger: a cryptographically-credentialed software participant that is added as a member of every message group in a regulated employee's workspace. Like any other group member, it receives and can decrypt every message. Unlike human members, it immediately archives each decrypted message to a tamper-evident, content-addressed record store that only the regulated firm (or its contracted compliance vendor) controls.

**IPLD content-addressed archive.** The compliance archive uses a data structure called IPLD (InterPlanetary Linked Data) in which every record is identified by a cryptographic hash of its contents. Records cannot be altered or deleted without breaking the hash chain, making alteration immediately detectable without relying on access controls alone.

**Practical consequence.** An examination of a firm using Agora will work with the firm's own compliance archive — not with a third-party platform operator — for message content. The examination access model is the same as it is for firms that self-host their communication archives.

### Why This Architecture Matters for Examiners

**It closes the DM capture gap structurally.** FINRA and SEC examinations have found, with increasing frequency, that regulated employees conduct business communications via personal messaging applications — WhatsApp, Signal, iMessage, personal SMS — that firm archiving systems do not capture. Policy prohibition has not been effective. Agora's architecture closes this gap differently: a regulated employee's capture obligation follows them into every direct message conversation, regardless of which platform the counterparty uses. The compliance logger is added to the DM group automatically by the regulated employee's client software; there is no opt-out and no override except by the firm's compliance administrator.

**It does not address non-Agora communications.** If a regulated employee uses a platform other than Agora for business communications, Agora does not capture it. The DM capture capability applies to DM conversations in which the regulated employee is an Agora user. Firms should be expected to document residual risk from non-Agora channels.

**The relay is not the archive.** A subpoena to a relay operator produces only encrypted blobs and connection metadata — not message content, sender identity, or channel structure. The firm's compliance archive is the authoritative source and is the appropriate subject of an examination document request.

---

## Part 2: The Compliance Archive — What It Contains and How to Read It

### Archive Contents

A properly configured Agora compliance archive contains the following for every covered communication:

**Text messages.** The full decrypted text of every message in covered channels, in original format (CommonMark — readable as plain text). Each record includes:
- The sender's decentralized identifier (DID) — a cryptographic identifier that maps to a named employee in the firm's identity system
- Timestamp (UTC, millisecond precision)
- Channel identifier
- MLS epoch and sequence number (establishing temporal order within the group)
- Edit records: each edit to a message is a separate record; the original and all versions are preserved
- Deletion records: a deleted message generates a tombstone record containing the deletion timestamp and the identity of the user who deleted it; the original message text is preserved in the tombstone

**File attachments and media.** Stored by content hash (CID). The same hash identifies the file on any relay that has stored it. Hash identity means you can verify that the file produced in a proceeding is the same file that was attached in the original conversation: if the content hash matches, the file has not been altered.

**Reactions.** Emoji responses to messages are protocol-level messages and are archived identically to text messages. An examiner can reconstruct the full interaction record of a conversation including reactions.

**Direct messages.** All DM groups involving regulated employees are subject to compliance capture. The archive contains the full text of DMs including conversations with external counterparties, subject to the disclosure requirements described in Part 4.

**Voice and video call records.** When voice/video compliance recording is enabled, the archive contains:
- Decrypted Opus/WebM audio recordings of covered calls
- Per-call metadata: participants, join/leave timestamps, call duration
- A tamper-evident chain of `VTCComplianceRecord` entries

**Audit records.** The archive includes `DMComplianceAuditEntry` records documenting any attempt by any party to remove the compliance logger from a DM group, with the timestamp and identity of the party who made the attempt.

### Archive Format and Structure

The archive is a sequence of `ComplianceRecord` objects in an IPLD (content-addressed) data structure. Each record contains:

```
ComplianceRecord {
  plaintextPayload   — the decrypted message content
  senderDID          — the sender's cryptographic identifier
  timestamp          — UTC, millisecond precision
  channelCID         — identifies the channel
  mlsEpoch           — MLS group epoch at the time of message
  sequenceNumber     — message sequence within the epoch
  prevRecordCID      — hash of the immediately preceding record in the chain
  loggerSignature    — cryptographic signature by the compliance logger
}
```

The `prevRecordCID` field creates a hash-linked chain. Any alteration or deletion of a record — or insertion of a record out of order — breaks the chain at that point. Chain verification requires only the root hash and the records themselves; no trusted third party is required.

### How to Verify Archive Integrity

**Step 1: Obtain the archive root CID.** The compliance logger publishes a root hash periodically (configurable; daily or weekly is typical). This root hash should be recorded in the firm's compliance monitoring system at the time of publication. For examination purposes, request the root hash log alongside the archive export.

**Step 2: Verify the chain.** Starting from any record, verify that `SHA2-256(record_bytes) == prevRecordCID_of_next_record`. A complete chain from the oldest record to the most recent root hash, with all hashes matching, mathematically certifies that no record has been altered or deleted. Commercial compliance archive tools for Agora perform this verification automatically and produce a signed verification certificate.

**Step 3: Verify logger signatures.** Each record carries the compliance logger's cryptographic signature. The logger's public key is published in its DID document (a publicly available document associated with the logger's identifier). Signature verification confirms the record was produced by the logger at the claimed time, not fabricated later.

**What a broken chain means.** If the hash chain is broken between records at time T1 and T2, one of the following occurred: (a) a record was altered after archiving, (b) a record was deleted from the chain, or (c) records were inserted out of order. The firm is required to investigate and disclose a broken chain before producing records in a proceeding. Examiners should treat an unexplained chain break as a material compliance deficiency.

---

## Part 3: Requesting Records in an Examination

### What to Request From the Firm

A standard Agora records request should include:

1. **The compliance archive export** for the relevant custodians, date range, and channels. Archive exports can be filtered by:
   - Sender DID (maps to named employees — request the DID-to-employee mapping separately)
   - Channel identifier
   - Date range
   - Message type (text, file, reaction, DM, voice)

2. **The DID-to-employee mapping.** Each employee is identified in the archive by their DID (a cryptographic identifier). The firm's identity management system maintains the mapping from DID to employee name, job title, and employment period. Request this as a separate document.

3. **The chain integrity verification certificate.** A signed certificate that the `prevRecordCID` chain is intact for the exported date range, produced by the firm's compliance archive tooling or a contracted compliance vendor.

4. **The logger's DID document.** The public key document associated with the compliance logger, needed to verify logger signatures on the records.

5. **The archive root hash log.** The historical log of published root hashes with timestamps. Cross-referencing archive content against the root hash log at any point in time allows you to confirm that no records were added, altered, or removed retroactively.

6. **DM compliance audit records.** All `DMComplianceAuditEntry` records for relevant custodians, showing compliance logger presence in DM groups and any removal attempts.

7. **VTC compliance records.** If voice/video communications are within scope: call recordings, per-call metadata, and `VTCComplianceAuditEntry` records for the relevant period.

8. **Space state document.** The current and historical configuration of the firm's Agora workspace (called a "Space"), showing compliance logging settings, scope configuration, retention period, and effective date of compliance logging activation.

### What You Cannot Get From the Relay Operator

Do not issue production requests to relay operators for message content. A conformant Agora relay operator:
- Does not hold decryption keys
- Cannot read any message content
- Cannot identify the sender of any message (sender identity is inside the MLS ciphertext)
- Cannot map routing tokens to channel identities or member lists without the epoch secret, which the relay does not hold
- Has connection metadata (IP addresses and connection timestamps) only for the duration of active connections — the protocol does not require persistent connection logs

A relay operator's honest response to a document production request for message content is that they hold encrypted blobs they cannot decrypt. This is accurate and expected. Message content is only available from the firm's compliance archive.

### What the Relay Operator Can Produce

If connection metadata is relevant to an examination (e.g., to establish that a particular IP address connected at a particular time), the relay operator may hold:
- IP addresses and connection timestamps for active connections during the connection period
- Aggregate volume statistics (message counts, storage consumed)

Relay operators are not required by the protocol to retain connection logs after a connection terminates. Whether a specific relay operator retains logs and for how long is a function of the operator's own policies and applicable data retention law.

---

## Part 4: Direct Message Compliance — The Examiner's View

### The Structural Mechanism

The DM compliance problem in regulated communications is well-documented: employees who use personal messaging applications for business communications produce records their firm cannot archive. Policy prohibition has been ineffective because it relies on employee compliance rather than technical enforcement.

Agora's DM compliance architecture addresses this at the client software level. When a regulated employee's Agora client creates or joins any DM group — regardless of whether the counterparty uses Agora or another platform accessed through a bridge — the client automatically:

1. Fetches a cryptographic credential for the firm's compliance logger
2. Adds the logger to the DM group as a cryptographic group member with full decryption rights
3. Sends a mandatory disclosure notice to all other DM participants before any message is sent

The compliance logger then receives and archives every subsequent message in that DM group, to the same tamper-evident archive as Space channel messages.

**This is a technical control, not a policy control.** The regulated employee cannot disable it. The DM group counterparty cannot prevent it (though they can leave the group after receiving the disclosure). The compliance logger cannot be removed from the group during the retention period — if another participant removes it, the regulated employee's client immediately re-adds it and automatically notifies the firm's compliance officer and space administrator, generating an audit record.

### What the Archive Shows for DM Compliance

For any DM group involving a regulated employee, the archive contains:

- The full text of all messages from the time the regulated employee joined
- The compliance disclosure notice sent to all participants
- The identity of all participants (DIDs and, for external counterparties, their display identities)
- Any removal attempts: `DMComplianceAuditEntry` records with the timestamp and identity of the party who attempted the removal

**Gap: pre-join messages.** The compliance logger is added when the regulated employee joins the DM group. Messages sent in that DM group before the regulated employee joined are not captured. This is an inherent limitation of MLS group encryption: the logger cannot retroactively decrypt messages from before it was a group member.

**Gap: non-Agora applications.** The DM compliance mechanism applies to conversations conducted via Agora (including bridged conversations where the counterparty uses Slack, Teams, or a MIMI-compatible platform). If the regulated employee conducts the same conversation via WhatsApp, iMessage, or another non-Agora application, Agora does not capture it.

### What an Examiner Should Check

When examining a firm's DM compliance program:

1. **Confirm the logger is configured.** The Space state document should show `complianceLogging.enabled: true` and a valid `loggerDID`.

2. **Verify DM audit records are being generated.** Request `DMComplianceAuditEntry` records for the examination period. The existence of these records confirms the logging mechanism is active.

3. **Check for removal attempts.** Review `DMComplianceAuditEntry` records for any removal events. Removal attempts are a compliance concern and should be investigated: who attempted to remove the logger, and was the attempt preceded by any message content that does not appear in the archive?

4. **Look for gaps.** The absence of DM records for a regulated employee during a period when DM activity is otherwise documented is a potential gap. It may indicate the employee used a non-Agora application, or that compliance logging was not active at the relevant time.

5. **Verify disclosure notices were sent.** For each DM group in the archive, a `ComplianceDisclosureNotice` should be the first record, predating any application message. The absence of a disclosure notice before messages suggests a configuration problem or a compliance event.

---

## Part 5: Cryptographic Verification — A Non-Technical Summary

Examiners do not need to perform cryptographic verification themselves. Commercially available compliance archive tools for Agora perform verification automatically and produce reports readable by non-technical staff. This section explains what is being verified and why it matters.

### Why Cryptographic Verification Is Stronger Than Access Controls

Conventional communication archives (for example, Exchange Online in-place holds, or Bloomberg message archiving) prevent alteration through access controls: only authorized users can access the archive, and the archive system logs administrative actions. The archive's integrity is a function of whether the access controls and audit logs are trustworthy.

Agora's archive is different. Each record contains the cryptographic hash of the previous record. A hash is a mathematical fingerprint: if you change even a single character in a record, its hash changes completely. Because each record's hash is embedded in the next record, any alteration breaks the chain at that point — and the break is mathematically detectable without consulting the firm, the archive vendor, or any authority. The chain is self-certifying.

**Practical consequence for examinations.** A firm cannot silently delete or alter an archived message and produce a clean archive that passes verification. A deletion produces a chain break, which the firm is required to investigate and disclose before producing records. A chain break that the firm cannot explain is a material compliance event.

### What Logger Signatures Prove

Each `ComplianceRecord` also carries a digital signature from the compliance logger — the system that captured the message. The logger's public key is in its DID document, published independently of the archive. This means:

- You can verify that each record was produced by the firm's designated compliance logger, not inserted after the fact
- You can verify the signature without trusting the firm's archive infrastructure
- A record whose signature does not verify against the logger's public key was either altered or produced by a different system

### The Role of the Root Hash

Periodically (typically daily or weekly), the compliance archive publishes a root hash — a single hash value that commits the entire archive at that point in time. If the firm records these root hashes in a system independent of the archive (for example, a separate audit log, or a public timestamp service), then an examiner can verify not only that the current archive is internally consistent, but that it matches the archive as it existed on any prior date when a root hash was published.

A firm that has root hashes recorded in an independent system, with a chain that verifies against all of them, has an archive that is tamper-evident over its entire history.

---

## Part 6: Regulatory Framework — The Examiner's Perspective

### FINRA Rule 4511 / SEC Rule 17a-4

**Requirement summary.** Six-year retention (two years in accessible storage) for most records; seven years for certain records. Non-erasable, non-alterable storage (WORM). Ability to produce records promptly.

**What Agora provides.** The IPLD hash chain satisfies the non-alterable requirement technically: alteration is detectable. The retention period is configured in the Space state document (`retentionDays`). The archive is owned by the firm, not a third-party platform operator, satisfying the control requirement.

**What to verify in an examination.**
- `retentionDays` is set to ≥ 2555 (7 years)
- Archive pruning is suspended for any records subject to legal hold
- The archive backend (the storage system the compliance logger writes to) has been configured to prevent administrative deletion during the retention period
- An independent auditor has reviewed the archive configuration and issued a written opinion (this opinion does not yet exist for Agora deployments — it is a known gap that firms are expected to be actively working to close)

**Examiner note: the auditor gap.** As of this writing, no FINRA-registered third-party archiving vendor has issued a written certification that a specific Agora deployment satisfies Rule 17a-4. This is a process gap, not a technical gap — the architecture satisfies the technical requirements. Firms relying on Agora for Rule 17a-4 compliance should be required to produce a timeline and vendor engagement for obtaining third-party certification. Absence of a certification plan is a deficiency.

### MiFID II Article 16 / FCA COBS 11.8

**Requirement summary.** Five-year retention (seven years where directed by competent authority) of communications related to transactions. Recording of telephone and electronic communications.

**What Agora provides.** Text and voice communications are captured by the compliance logger and archived in the tamper-evident chain. Voice recordings include per-call metadata satisfying the "electronic communications" recording requirement. Retention period is configurable to meet the seven-year requirement.

**Cross-border note.** Firms with employees in multiple MiFID II jurisdictions should verify that the compliance logger scope covers all channels where transaction-related communications may occur, and that the retention period satisfies the longer of the applicable national requirements.

### HIPAA Security Rule (§164.312) — Electronic Communications Containing ePHI

**Requirement summary.** Technical safeguards for electronic protected health information in electronic communications. Business Associate Agreements (BAA) required with service providers handling ePHI.

**What Agora provides.** MLS end-to-end encryption satisfies the technical safeguard requirement: ePHI is encrypted in transit and at rest in the relay infrastructure (the relay holds ciphertext, not plaintext). The compliance archive contains plaintext ePHI and must be treated as a covered system under the Security Rule.

**What to verify.**
- A BAA is in place with the relay operator (the relay holds encrypted data — this is lower risk but the BAA is still typically required)
- A BAA is in place with any contracted compliance archive vendor
- The compliance archive's access controls satisfy the Minimum Necessary standard
- The HIPAA-required audit log for access to ePHI in the compliance archive is operational

### GDPR Article 17 and Analogous Privacy Frameworks

**The tension.** GDPR Article 17 grants data subjects the right to erasure of personal data. Compliance records cannot be deleted during the retention period — by design. These obligations are in direct conflict for communications involving EU data subjects.

**The standard exemption.** GDPR Article 17(3)(b) exempts retention "for compliance with a legal obligation" and Article 17(3)(e) exempts retention "for the establishment, exercise or defence of legal claims." Both exemptions apply to communications retained under financial services regulatory requirements. The firm must document the specific legal retention obligation and retention period, apply the exemption only for the duration of the retention period, and delete records promptly when the retention period expires.

**What to verify.** The firm has a documented legal basis for retention that covers the GDPR Article 17 conflict, and has a mechanism to identify and delete records promptly after the retention period expires (not later). Records retained beyond the retention period without a documented basis are outside the exemption.

---

## Part 7: What to Look for in an Agora Compliance Examination

This part summarizes the examination checkpoints corresponding to the configuration items in the firm's compliance setup, from the examiner's perspective.

### Capture Scope Verification

- Request the Space state document and verify `complianceLogging.enabled` is `true`
- Verify `scope` is set to `all-channels` or that the configured scope demonstrably covers all channels where regulated business communication has occurred
- Verify `retentionDays` meets the applicable requirement — 2555 days (7 years) for FINRA/SEC, 1825 days (5 years) for MiFID II unless the competent authority has directed seven years
- Verify the client software version for regulated employees supports DM compliance (§17.8 of the Agora specification) — this requires a version number check against the specification version that introduced §17.8

### Archive Completeness

- Verify the archive starts from the date compliance logging was first enabled — there is no archive for the period before the compliance logger was added to the group. This is a known limitation; the question is whether the firm's records show when logging was enabled and whether that date is consistent with when the firm adopted Agora.
- Check for channel scope gaps — if certain channels are excluded from the configured scope, verify that no regulated business communications occurred in those channels

### Chain Integrity

- Request a chain integrity verification report for the examination period
- Verify the report was produced by tooling independent of the archive itself (not by the firm's own self-attestation)
- Investigate any chain breaks

### DM Compliance

- Verify `DMComplianceAuditEntry` records are present for regulated employees
- Review removal attempt records — each removal attempt is a compliance event and should have been reported to the compliance officer at the time
- Sample DM groups and verify disclosure notices precede any message content

### Logger Infrastructure

- Verify the `loggerDID` is controlled by the firm or a contracted compliance vendor, not a third party
- Verify the logger's `KeyPackageEndpoint` has been operational continuously — if it went down, regulated employees' clients could not add the logger to new DM groups during the outage, creating a capture gap
- Verify the archive backend is configured to prevent administrative deletion during the retention period

### Client Enforcement vs. DS Enforcement

Agora supports three levels of compliance logger enforcement for DM groups, in increasing order of strength:

**Client-side enforcement only (baseline).** The regulated employee's client software adds the compliance logger to each DM group before any messages are sent. Compliance depends on the client being conformant software. A modified, outdated, or misconfigured client could skip the step without detection until a gap is found in the archive.

**DS Mechanism A — Welcome inspection (stronger).** The relay inspects each new DM group creation and rejects it if the compliance logger is not included in the initial member list. The group cannot be formed without the logger. This is a structural control at creation time. Limitation: covers only group *creation*, not a regulated employee *joining* an existing group — client-side enforcement still applies to the join case.

**DS Mechanism B — External Commit with compliance hold (strongest; preferred).** When the relay detects a new DM group involving a regulated employee — whether created by them or joined by them — it holds message delivery until the compliance logger self-joins the group using an MLS External Commit (RFC 9420 §11.2.1). The client does not add the logger; the logger adds itself. A modified or non-conformant client cannot prevent it. Message delivery does not resume until the logger is a member. Covers both creation and join.

When examining a firm's Agora deployment:

- Ask which enforcement mechanism the firm's relay is configured to use.
- If Mechanism B is active: ask for evidence that compliance holds have been firing and resolving (relay logs showing hold-start and hold-release events for DM groups involving regulated employees). Persistent holds that timed out without logger admission are compliance events.
- If Mechanism A is active: verify also what controls apply to the regulated-member-joins-existing-group case, where Mechanism A does not apply.
- If client-side enforcement only: ask what client software controls are in place — MDM management, client version pinning, and device policy enforcement. Document the firm's assessment of residual risk.
- A firm that has neither DS enforcement nor documented MDM controls over client software has a material gap in its DM compliance architecture that should be treated as a deficiency requiring a remediation plan.

### Auditor Certification

- Request documentation of any third-party auditor engagement for compliance certification
- If no engagement exists, treat this as a deficiency and require a remediation plan with a timeline

---

## Part 8: Glossary for Examiners

**CID (Content Identifier).** A cryptographic hash used as a file or record identifier. Because the hash is computed from the content, the same content always has the same CID. Any change to the content produces a different CID, making alteration immediately detectable.

**Compliance logger.** A software participant in the Agora message group that receives and archives all messages. It is cryptographically credentialed and added to message groups automatically by regulated employees' clients. It is a passive member — it receives all messages but does not send any.

**DID (Decentralized Identifier).** A cryptographic identifier for a user or system. In Agora, each employee has a DID. The DID maps to a named employee in the firm's identity management system. The archive identifies message senders by DID; the DID-to-employee mapping is maintained by the firm.

**IPLD (InterPlanetary Linked Data).** A data model for content-addressed records. Used in Agora for the compliance archive. Each record is identified by a hash of its content; records link to prior records by hash, forming a tamper-evident chain.

**MLS (Messaging Layer Security, RFC 9420).** The IETF standard for end-to-end encrypted group messaging. Agora's sole key agreement mechanism. Messages are encrypted by the sender's device; only group members hold decryption keys.

**Passive member.** An MLS group member that holds full decryption rights and receives all messages but is not permitted to issue group management operations (commits or proposals). The compliance logger is a passive member. It cannot alter the group membership or message history.

**Relay.** The server infrastructure that routes Agora messages. Holds only encrypted ciphertext. Cannot read messages, identify senders, or produce plaintext under legal process.

**Space.** An organization's Agora workspace — the deployment unit within which channels, members, and compliance settings are configured. Equivalent to a "workspace" or "tenant" in other communication platforms.

**VTC compliance recorder.** A passive member added to voice/video calls for compliance recording, analogous to the compliance logger for text channels.

**WORM (Write Once Read Many).** Storage that cannot be modified after writing. Rule 17a-4 requires WORM storage for retained records. The IPLD hash chain provides a technical WORM property: modification is detectable even if the underlying storage does not enforce write-once constraints. However, the underlying storage should also have operational controls preventing administrative deletion.

---

*This guide is intended to be read alongside the* Agora Compliance & Legal Reference Guide*, which covers the same architecture from the regulated firm's compliance team's perspective. That document contains the configuration checklist, legal hold procedures, and employee disclosure requirements.*
