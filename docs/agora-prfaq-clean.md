# Agora: Secure Group Communication You Actually Own

## Press Release

**FOR IMMEDIATE RELEASE**

### Introducing Agora — End-to-End Encrypted Group Communication That Works With the Tools You Already Use

*Your messages are yours. Your keys are yours. Your compliance archive is yours. And you can still talk to everyone on Slack and Teams.*

Today we announce Agora, an open protocol for decentralized, end-to-end encrypted group communication. Agora delivers the collaboration features organizations rely on — threaded channels, presence, voice and video, file sharing, compliance logging — without a central authority that holds your keys, reads your messages, or can be compelled to produce your history.

Agora launches with working bridges to Slack, Microsoft Teams, and Matrix, and native interoperability with MIMI — the IETF's emerging standard for cross-platform E2EE messaging. An organization deploying Agora does not ask its counterparties to change anything. A regulated employee on Agora messages a counterparty on Teams; the counterparty receives a normal Teams message. The Agora side of that conversation is end-to-end encrypted and compliance-captured. The counterparty never knows.

**For enterprise IT.** Agora authenticates via SAML 2.0 and OIDC. It appears in your Okta or Entra catalog alongside every other enterprise application. Provisioning, deprovisioning, MFA, and conditional access flow through your existing identity infrastructure. There is nothing new to operate at the identity layer.

**For compliance and legal.** Agora has a working gateway to Microsoft Purview. Captured communications — text, reactions, edits, deletions, voice recordings, and direct messages — appear in your Purview compliance portal alongside Teams and Exchange content. Legal hold, e-discovery, and retention policy enforcement work through the interface your compliance team already operates.

**For regulated industries.** Agora's compliance logger is a cryptographically-credentialed MLS group member that captures all channels — including direct messages between regulated users and their counterparties on other platforms. The regulated employee's capture obligation follows them into every conversation, regardless of what platform the counterparty uses. No available product does this today.

**How it works.** Agora uses RFC 9420 (MLS), the IETF standard for end-to-end encrypted group messaging, as its sole key agreement mechanism. Messages are encrypted before they leave the client. The servers that route them — Relays — see only encrypted blobs and rotating anonymous tokens. They cannot read message content, identify the sender of any specific message, or produce plaintext in response to legal process. They do see routing metadata: who connects, when, and at what volume. The content guarantee is mathematical, not a policy.

Message history lives in IPFS, content-addressed. The same content has the same address on every relay that stores it. Switching relay operators requires no data migration — you point clients at a new relay and your history is already there.

Agora is an open protocol. The specification is public. Any developer can implement a client or relay. Any organization can run infrastructure. There is no Agora, Inc. with a terms-of-service, pricing model, or compliance policy that can change overnight.

---

## Frequently Asked Questions

### Customer FAQs

**Q: I'm already on Teams. Why would I add another communication tool?**

You probably wouldn't replace Teams for most communication — and you don't have to. Agora bridges to Teams natively: your Agora users are reachable from Teams and vice versa. The case for Agora is not that Teams is bad at collaboration; it's that Teams cannot give you E2EE and compliance capture simultaneously. Microsoft holds your keys. When Microsoft is subpoenaed, Microsoft produces your plaintext. When Microsoft is breached, your history is exposed.

Agora is the right tool for the subset of communication where that matters: regulated business conversations, sensitive internal discussions, executive communications, legal matters, M&A. Everything else stays on Teams.

**Q: How does my Agora user communicate with someone on Slack or Teams?**

Through a bridge. The bridge is a credentialed Agora participant that translates messages in both directions. Your Agora client shows a persistent indicator that a channel is bridged — E2EE is not preserved across the bridge, and this is disclosed clearly. The Slack or Teams user sees a normal message from a bot account; they don't install anything and don't need an Agora account.

For counterparties on MIMI-compatible platforms, interop is native: a single MLS group spans both systems, E2EE is preserved end-to-end, and neither side re-encrypts at the boundary.

**Q: What about my compliance team? They live in Purview.**

Agora-captured communications appear in your Purview compliance portal alongside Teams and Exchange content. Legal hold, custodian management, e-discovery search, and retention policy enforcement all work through Purview unchanged. Your compliance team does not need to learn a new system.

**Q: How does IT provision Agora accounts?**

Through your existing identity provider. Agora user agents support SAML 2.0 and OIDC. You register Agora in Okta or Entra, configure your provisioning rules, and it works. Joiner/mover/leaver automation, MFA enforcement, SSO, and conditional access all apply as configured. Deprovisioning in the IdP removes the user from Agora channels automatically.

**Q: Why does this matter for our FINRA or SEC compliance program?**

FINRA examiners are increasingly focused on the direct message capture gap: regulated employees conducting business over WhatsApp, iMessage, Telegram, and other applications the firm cannot capture. Agora's DM compliance extension closes this gap structurally. A regulated employee's capture obligation follows them into every conversation — including DMs with counterparties on other platforms accessed through a bridge. When the compliance logger is admitted to a DM group, it receives every message in that group, archived to a tamper-evident IPLD chain that forwards to Purview. The counterparty platform is irrelevant.

**Q: What happens if my Relay goes down?**

Message history is stored in IPFS, content-addressed by hash. Any relay that has served your space has a copy. Switching relays means pointing clients at a new endpoint — history is retrieved from the mesh via content addressing. There is no data export step, no migration tool, no vendor cooperation required. You connect to a new relay and it either has the content or fetches it.

**Q: How is voice and video handled?**

Agora supports WebRTC-based voice and video with MLS-encrypted signaling. For small groups (≤4 participants) calls are fully peer-to-peer with no server involved. Larger sessions use a Selective Forwarding Unit — standard open-source options like LiveKit and mediasoup work without modification. The SFU routes encrypted media packets without decrypting them. When a recording grant is issued for compliance purposes, participants deliver a derived recording key to the compliance recorder; the recorder decrypts, archives, and forwards to Purview alongside text content.

**Q: What does it cost to run?**

The protocol is free. Relay infrastructure costs are bandwidth, storage, and compute — comparable to running an email server. Managed relay services are available. Agora specifies an optional micropayment layer for public relays, but private organizational relays don't need payment infrastructure. For regulated organizations the largest operational component is compliance logging; the Purview gateway extends existing infrastructure rather than requiring new builds.

---

### Internal FAQs

**Q: Why build a new protocol rather than extending Matrix or XMPP?**

Matrix's encryption (Megolm) does not provide post-compromise security and has had multiple serious implementation vulnerabilities. XMPP's E2EE story (OMEMO) is fragmented and inconsistently implemented. Neither was designed around MLS, so retrofitting the forward secrecy and post-compromise security guarantees MLS provides by construction would require rearchitecting them from the ground up. Agora is designed from first principles around RFC 9420, giving it correct security properties without inheriting either protocol's legacy constraints or implementation debt.

**Q: Why IPFS for storage rather than a conventional database?**

Content addressing solves relay portability definitively. A message identified by its content hash is the same message on every relay — no synchronization protocol, no consistency problem, automatic deduplication, tamper-evident history without any additional mechanism. The alternative requires every relay to store a different representation of the same history, and migration requires explicit export and import. IPFS also makes the compliance archive independently verifiable: anyone with the root CID can verify the chain without trusting the relay operator.

**Q: Who is the target customer?**

Three segments with different purchase drivers. First, regulated financial services and healthcare organizations that need compliance-grade DM capture and currently cannot achieve it — this is the FINRA shadow-communication problem, and Agora is the only available solution that captures cross-platform DMs structurally. Second, security-focused technology organizations that have concluded the centralized-SaaS threat model is unacceptable for sensitive internal communications — security operations, legal, executive, M&A. Third, organizations in jurisdictions where legal compulsion of communication vendors is a material operational risk, and where the architectural guarantee of relay blindness has direct business value.

The Purview gateway and SAML/OIDC integration make Agora accessible to enterprise buyers who would not have considered a protocol without those integrations, allowing the first two segments to deploy without requiring IT or compliance to accept new workflow changes.

**Q: What is the go-to-market path?**

The protocol is the product. Revenue comes from relay operation, compliance logger infrastructure, enterprise integration services, and support contracts. The SAML/OIDC and Purview integrations are the enterprise sales enablers — they convert "interesting protocol" into "thing IT and compliance will approve." The open protocol creates a market; participation in that market is the business model. This is how Red Hat built a business on Linux.

The bridge infrastructure also creates an outbound sales motion: a regulated financial services firm that deploys Agora for its own employees has made every counterparty they bridge to a potential Agora prospect. Network effects run through the bridge layer even before MIMI adoption is widespread.

**Q: What are the top three risks?**

First, compliance auditor certification. The Agora compliance architecture technically satisfies FINRA 17a-4, SEC 17a-4, and similar requirements, and the Purview gateway delivers captured content in a format compliance teams recognize. A third-party auditor's written certification does not yet exist, and regulated organizations will require it. This is a process risk, not a technical risk — but the certification timeline is the primary constraint on financial services deployments and must be treated as a launch-parallel workstream, not a post-launch task.

Second, managed relay ecosystem maturity. Enterprise organizations that cannot self-host need managed relay providers with enterprise SLA terms, audit rights, and data processing agreements. The relay market exists but is early. This is the primary constraint for organizations without infrastructure capability and will narrow as the ecosystem develops.

Third, bridge governance adoption. The Slack and Teams bridges hold plaintext during translation, and Agora discloses this structurally to all channel members. Organizations must establish policy for which channels may have bridges active and train users on what the disclosure means. The risk is not technical — it is that governance and training are underdone and users treat bridged channels as having the same security properties as native channels.
