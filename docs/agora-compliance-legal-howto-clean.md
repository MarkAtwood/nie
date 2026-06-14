# Agora Compliance & Legal Reference Guide

**Audience:** Compliance Officers, General Counsel, Outside Counsel, Regulatory Affairs
**Purpose:** What Agora captures, how it captures it, what you can produce, what you cannot, and what your obligations are
**Document version:** Aligned to Agora Protocol Specification v0.1 + DM Compliance patch

---

> **Preliminary note.** This document explains how the Agora protocol works from a compliance and legal standpoint. It is not legal advice. The compliance logging architecture described here has not yet been independently validated by a FINRA-registered archiving vendor or a HIPAA-qualified auditor. Regulated organizations should obtain independent validation before relying on Agora for regulatory compliance.

---

## Part 1: What Gets Captured and What Doesn't

### What the Compliance Logger Captures

When compliance logging is enabled for a space (your organization's Agora workspace), a designated **compliance logger** — a cryptographically-credentialed system principal — is automatically added as a silent member of every relevant message group. It receives and archives:

- **Voice and video media streams** in covered voice channels, stored as decrypted Opus/WebM archives in IPFS, with per-call metadata records including participant join/leave timestamps and a tamper-evident chain of `VTCComplianceRecord` entries
- **All text messages** in covered channels, in original form, including edits (preserved as separate records) and deletions (tombstone records with deletion timestamp and the deleting user's identity)
- **All file attachments and media**, stored by content hash (CID) — the same hash as the original, making authenticity mathematically verifiable
- **All reactions** (emoji responses to messages) — these are MLS application messages and are captured identically to text messages
- **All direct messages** sent or received by any regulated employee, subject to the DM compliance provisions in Part 2
- **Message metadata**: sender identity (DID, which maps to a user account), timestamp, channel, sequence number, MLS epoch

### What the Compliance Logger Does Not Capture

- **Messages sent before the logger was admitted.** The logger's archive begins at the MLS epoch when it was added to each group. It cannot retroactively capture prior messages. If logging was enabled after your organization started using Agora, there is a gap.
- **Messages in channels outside the configured scope.** If `scope` is configured as a channel path glob (e.g., `engineering/*`) rather than `all-channels`, messages in unscoped channels are not captured. Review your scope configuration carefully.
- **Pre-join messages in DM groups.** Once a regulated employee joins a DM group, the logger is added at that point; messages sent before the regulated employee joined are not retroactively accessible.

### Archive Format

Every captured message is stored as a `ComplianceRecord` in an append-only, tamper-evident IPLD (content-addressed) archive. Each record contains:

- The full decrypted message content (`plaintextPayload`) in its original format (CommonMark text)
- The sender's DID (maps to a user identity)
- Timestamp, channel identity, MLS epoch, and sequence number
- A link to the prior record in the chain (`prevRecordCID`) — any alteration or deletion of a record is immediately detectable by verifying the chain hashes
- The logger's cryptographic signature over the record

The archive is your organization's property, stored on infrastructure you control (or a contracted archiving vendor's infrastructure). No third party holds a copy unless you have contracted one.

**Authenticity verification.** Because each `ComplianceRecord` is cryptographically signed by the logger and the records form a hash-linked chain, you can produce records in an eDiscovery proceeding and demonstrate mathematically that they have not been altered since capture. This is stronger than conventional archiving solutions, which rely on access controls rather than cryptographic proof.

---

## Part 2: Direct Message Compliance

### The Obligation

A regulated employee (a member of a space with compliance logging enabled) **carries their compliance obligation into every direct message group they participate in**, regardless of whether the DM group has any connection to the organization's space infrastructure.

The Agora specification (§17.8.1) states:

> The compliance obligation follows the regulated user, not the channel. A regulated user who conducts business communication via DM is not exempt from their Space's retention requirements by virtue of using a DM group rather than a Space channel.

### How It Works

When a regulated employee's Agora client creates or joins a DM group:

1. Their client automatically fetches a fresh encryption credential (`KeyPackage`) for the compliance logger.
2. The client adds the logger to the DM group's MLS group via a cryptographic commit — the logger becomes a full member with decryption rights.
3. The DM group's descriptor is updated to record the logger's presence.
4. A **mandatory disclosure notice** is sent to all other DM group participants before any message is sent.

The disclosure notice is a visible system message (not a suppressable notification) that informs all participants:

> **[Employee name]'s messages in this conversation are subject to regulatory retention by [your organization's compliance archive] for [retention period] days.**

External counterparties are notified before they send any message and may leave the DM group at that point. Messages they sent before their departure remain in the archive for the regulated employee's retention period.

### Logger Removal Protection

Once the compliance logger is admitted to a DM group, it cannot be removed for the duration of the retention period:

- The regulated employee's client will refuse to process any request to remove the logger.
- If another DM group member removes the logger, the regulated employee's client immediately detects this, re-adds the logger, and **automatically notifies the compliance officer and space admin** of the removal attempt.

Removal attempts are recorded in the organization's audit chain as `DMComplianceAuditEntry` records with the timestamp and identity of the user who attempted the removal.

### Gap Analysis

**The gap Agora closes.** FINRA and SEC examiners have focused heavily on business communications conducted via personal messaging applications (WhatsApp, Signal, iMessage, personal SMS) that are not captured by firm archiving systems. Policy prohibition has proven ineffective. Agora's DM compliance architecture makes capture automatic and mandatory at the client level for regulated employees, rather than relying on employee self-reporting or retrospective device examination.

**The gap Agora does not close.** If a regulated employee uses a non-Agora application for business communications, Agora cannot capture it. Agora eliminates the DM gap for employees who use Agora; it does not address gaps created by employees who use other applications.

**Practical implication.** For Agora to close the DM gap, the employee and their counterparties must both be Agora users. This is most tractable for intra-firm communications and for firms that can contractually require counterparties to use Agora-compliant communication channels.

---

## Part 3: Responding to Legal Process

### What a Relay Operator Can Produce

Agora relays are deliberately designed to hold nothing useful in response to a subpoena or legal demand. A conformant relay knows:

- A set of rotating, anonymous channel tokens — not linked to any channel name, space, or identity without the epoch secret (which the relay does not hold)
- A set of encrypted message blobs addressed by content hash
- Connection metadata: IP addresses and timestamps of connected clients during the connection; no persistent connection log is required by the protocol

A relay cannot produce:

- Plaintext message content (it does not hold decryption keys)
- The identity of message senders (sender identity is hidden inside the MLS ciphertext)
- The mapping from channel tokens to channel identities or member lists
- Message history beyond what it has cached (relay caching is configurable)

**Practical consequence for legal hold.** If you receive a third-party subpoena to a relay operator serving your organization, the relay operator's honest response is that they hold encrypted blobs they cannot read and do not know who sent them. This is a description of what the relay holds, not a legal opinion. Whether this satisfies the subpoena depends on jurisdiction and the specific legal process; consult counsel.

### What Your Organization Can Produce

Your organization's compliance archive is the authoritative source for legal hold and eDiscovery. It contains:

- Full plaintext of all captured messages, in order, with cryptographic proof of authenticity
- Complete sender identity for each message (DID, mapping to a named employee)
- Timestamps and channel context
- Edit history and deletion records (a deleted message is tombstoned, not erased — the tombstone records when it was deleted and by whom)
- DM group compliance audit records, including any logger removal attempts

For eDiscovery, the compliance archive supports export by date range, by channel, by sender DID, or by keyword (search against the plaintext `text` fields, which are stored in CommonMark format — readable as-is or trivially stripped of markup).

### Legal Hold Procedure

When a legal hold is triggered:

1. **Identify the relevant DIDs.** Each employee corresponds to one or more DIDs. The mapping from employee name to DID is maintained in your identity management system (or derivable from your space's member list and DID documents).

2. **Suspend archive pruning for affected DIDs and channels.** The compliance archive is append-only by design. If your archive configuration includes a purge policy (e.g., records older than `retentionDays` are deleted after the retention period expires), you must suspend that purge for held content.

3. **Export the relevant records.** The compliance archive is an IPLD-structured, content-addressed dataset. Export tools should query by sender DID, channel CID, and date range, producing a set of `ComplianceRecord` objects with their authentication proofs.

4. **Verify chain integrity.** Before producing records, verify that the `prevRecordCID` chain is intact for the exported range. A broken chain indicates a record was altered or deleted — this must be investigated and disclosed.

5. **Preserve `DMComplianceAuditEntry` records** for any DM groups involving the relevant employees. These records document logger presence and any removal attempts.

---

## Part 4: Employee Disclosure and Consent

### Employee Disclosure

Employees in a compliance-logging-enabled space receive a mandatory disclosure at first join:

> "This space is subject to regulatory message retention. Messages are archived for [N] days regardless of expiry settings."

This notice is displayed by the client and cannot be dismissed without acknowledgment. It is also accessible at any time from the space's information panel.

When a regulated employee's client adds the compliance logger to a DM group, a `ComplianceDisclosureNotice` is sent to all DM participants as a visible system message before any application message is sent. This notice identifies the logger by label (e.g., "Acme Corp Compliance Archive"), states the retention period, and lists the regulatory frameworks under which the logger operates.

### Counterparty Disclosure

External counterparties who receive DMs from regulated employees will see the compliance disclosure notice before they send any message. They are not asked to consent — the disclosure is informational. They may leave the DM group if they choose. This mirrors the practice of recording disclosures on regulated telephone calls ("this call may be recorded for compliance purposes"), applied at the messaging layer.

**Open legal question.** Whether this disclosure satisfies wiretapping statutes and analogous communication privacy laws in all relevant jurisdictions is a question for counsel. The one-party consent model (the regulated firm consenting on behalf of its employee) is standard for broker-dealer call recording but has not been tested in the context of end-to-end encrypted messaging. Obtain counsel's opinion before deploying in jurisdictions where this is uncertain.

---

## Part 5: Compliance Configuration Checklist

Before deploying Agora in a regulated environment, verify the following.

**Capture scope**
- [ ] `complianceLogging.enabled` is `true` in the space state document
- [ ] `scope` is set to `all-channels` or explicitly confirmed to cover all channels where regulated business communication may occur
- [ ] `retentionDays` is set to meet your regulatory requirement (FINRA/SEC 17a-4: 2555 days = 7 years; HIPAA: 2190 days = 6 years minimum for most records)
- [ ] DM compliance (§17.8) is active — confirm that the regulated employee's client software version supports §17.8 and that the `loggerDID` is correctly configured

**Logger infrastructure**
- [ ] The `loggerDID` is a DID controlled by your organization or a contracted compliance vendor — not a third party you do not control
- [ ] The `logStore` IPFS endpoint is on infrastructure subject to your legal hold and data governance policies
- [ ] The logger's DID document includes a `KeyPackageEndpoint` service entry and the endpoint is operational — if this endpoint is down, regulated employees' clients cannot add the logger to new DM groups
- [ ] The logger is operated in a mode that prevents deletion of records within the retention period — the append-only chain structure helps, but operational controls must prevent administrative deletion of the underlying IPFS data

**Audit and monitoring**
- [ ] `DMComplianceAuditEntry` records are being produced and are accessible to your compliance team
- [ ] Alerts are configured for logger removal attempts (the spec requires client-level notification; confirm this is routed to compliance staff)
- [ ] Archive integrity verification (chain hash checks) is scheduled on a regular basis
- [ ] A process exists to map DID to employee name for eDiscovery production

**Disclosure**
- [ ] `retentionNotice` text in the space state document is accurate and legally reviewed
- [ ] Employee notification has been provided through HR/legal channels (the protocol disclosure is necessary but may not be sufficient for your jurisdiction's employment law requirements)

**VTC compliance**
- [ ] `vtcCompliance.enabled` is `true` in the space state document if voice channels are used for regulated communications
- [ ] `vtcCompliance.recorderDID` is configured and the recorder's DID document has a `KeyPackageEndpoint` and an HPKE-capable `keyAgreement` entry
- [ ] `vtcCompliance.retentionDays` matches `complianceLogging.retentionDays`, or the longer value is documented as the governing retention period
- [ ] `autoGrant` is `true` so compliance recording starts automatically when a call begins without requiring per-call admin action
- [ ] `VTCComplianceAuditEntry` records are being produced and `epochsGapped` is monitored — non-empty gap arrays require compliance officer notification

**Acknowledged gaps**
- [ ] Independent compliance auditor validation has not yet been completed — document this and the plan to obtain it
- [ ] Non-Agora communication channels (email, phone, personal messaging) are not covered — confirm existing archiving solutions cover those channels and document residual risk

---

## Part 6: Regulatory Framework Quick Reference

| Regulation | Key Requirement | Agora Coverage | Gap |
|---|---|---|---|
| FINRA 17a-4 / SEC 17a-4 | 7-year retention of business communications, non-erasable, non-alterable | Covered for text channels, DMs (§17.8), and voice/video (§10.12); tamper-evident chain | Auditor validation pending |
| FINRA Rule 4511 | Books and records — communications with the public | Covered for Agora-channel communications including voice | Non-Agora channels not covered |
| HIPAA Security Rule (§164.312) | Technical safeguards for ePHI in electronic communications | MLS E2EE satisfies technical safeguard requirement; voice recording covered | BAA with relay operator needed |
| MiFID II Article 16 | 5-year retention of communications related to transactions | Covered for text and voice; 7-year retention configuration available | Cross-border jurisdiction issues |
| GDPR Article 17 (right to erasure) | Ability to delete personal data on request | Records in the compliance archive cannot be deleted during the retention period, creating direct tension with erasure rights for regulated communications. The standard exemption for legal retention obligations applies; document the basis. | Legal analysis required per jurisdiction |
| UK FCA COBS 11.8 | Recording and retention of telephone and electronic communications | Text and voice covered | |
