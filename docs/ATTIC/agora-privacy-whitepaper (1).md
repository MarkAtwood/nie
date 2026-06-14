# Agora Protocol: A Privacy Analysis

**Audience:** Privacy advocates, researchers, journalists, activists, and technically-informed individuals evaluating Agora against their threat model  
**Document type:** Technical privacy assessment  
**Tone:** Direct. Where the protocol delivers strong guarantees, this document says so and explains why. Where it has limits or makes tradeoffs, this document says that too.

---

## Who This Is For

This document is for people who read privacy policies looking for what they don't say, who know the difference between "we don't sell your data" and "we can't read your data," and who want to understand what Agora actually does and doesn't protect before they trust it with anything important.

Agora is not Signal. Signal is a simpler protocol optimized for individual two-party or small-group E2EE messaging with a minimal metadata footprint. Agora is designed for organizational-scale persistent group communication — the Discord/Slack use case — with compliance logging as a first-class feature. Those goals create different tradeoffs. This document maps them honestly.

---

## The Core Question: What Does the Server See?

With Slack, Teams, and Discord, the server sees everything. Your messages in plaintext. Your membership lists. Your DMs. Your message history since account creation. Your metadata — who talked to whom, when, how often, from where. When law enforcement or intelligence agencies want this information, they ask the vendor and the vendor produces it, because the vendor has it. This is not a security failure; it is the designed architecture.

With Agora, the server — called a Relay — sees the following:

- **IP addresses** of connecting clients (unless clients use Tor)
- **Encrypted blobs** of message content it cannot decrypt
- **Rotating anonymous tokens** (`channelToken`) that identify a channel for routing purposes but cannot be reversed to a channel name, channel membership, or sender identity without the epoch secret the Relay doesn't hold
- **Sequence numbers and timestamps** on the outer envelope
- **Approximate traffic volume** per token

The Relay does **not** see:

- Message content (MLS end-to-end encryption; the Relay never holds a decryption key)
- Sender identity for any message (sealed sender design; the sender's DID is inside the MLS ciphertext)
- Which channel a token corresponds to (epoch-rotating derivation, non-reversible)
- Who is in any group (channel membership is not transmitted to the Relay)
- The relationship between messages — who replied to whom, conversation threads, message graphs

This is not a policy. It is a structural property of the protocol. A Relay operator who receives a government demand can produce IP connection logs, traffic volume statistics for opaque tokens, and encrypted blobs. They cannot produce identities, content, or conversation structure because they do not have them. An honest Relay operator can testify to this under oath.

---

## The Encryption: What MLS Actually Provides

Agora uses RFC 9420 — the IETF's Messaging Layer Security standard — as its sole key agreement mechanism. MLS provides two properties that matter for privacy threat models that most E2EE systems don't provide simultaneously:

**Forward secrecy.** Each MLS epoch (roughly, each time the group's key state advances) derives a new encryption key. Compromise of today's key does not expose past messages. A device seized tomorrow cannot decrypt conversations from last month. A relay compromised next year cannot retrospectively decrypt message archives from this year even if those archives were retained in encrypted form.

**Post-compromise security.** If a device is compromised and then removed from a group, the group's subsequent messages are secure against the compromised device. The ratchet advances; the compromised key material cannot decrypt new messages. This is qualitatively different from protocols where a compromised participant retains the ability to read future messages until manually rotated.

These are properties of the mathematical construction, not implementation promises. They hold as long as the MLS implementation is correct and keys are stored securely on devices. They do not protect against device compromise that persists undetected — if an attacker has ongoing access to your device, they read messages as you read them, before encryption on send and after decryption on receive. No protocol solves that.

---

## Identity: Self-Sovereign by Default

Agora identities are Decentralized Identifiers (DIDs). A `did:key` identity is a keypair you generate locally. It is not registered with any authority. No account creation, no phone number, no email address. The keypair is the identity.

For organizational use, `did:web` anchors identity to a domain you control — `did:web:example.com` is resolved by fetching a document from `example.com`. This is familiar and auditable, and lets organizations manage identity through their existing DNS infrastructure.

Neither identity type requires trusting a third-party identity provider with your existence. A `did:key` user who generates a key, never connects to any central service, and uses a Tor-connected relay has given no personally identifying information to any party in the system by design.

The practical caveat: if you use SAML or OIDC for authentication (supported for enterprise deployments), your identity provider learns when you authenticate. If your identity provider is Microsoft Entra or Okta, they have your authentication events. This is a deployment choice. The protocol supports both self-sovereign identity and federated identity; the privacy properties differ accordingly.

---

## What the Relay Operator Can and Cannot Do

**Can do:**
- Log IP connection events
- Observe traffic volume patterns (how many messages per token per time period)
- Go offline, losing message fanout until another relay serves the channel
- Censor outgoing messages by refusing to forward them (detectable by clients connected to multiple relays)
- Respond to legal demands with connection logs and encrypted blobs

**Cannot do:**
- Read message content
- Identify senders
- Identify which users are in which channels
- Forge messages (sender signatures are inside MLS ciphertext, verified by recipients)
- Silently modify history (IPFS content addressing detects tampering — the same content has the same hash; substituted content has a different hash and is rejected)
- Produce a useful response to a content subpoena, because they hold no content

The censorship surface deserves attention. A relay can refuse to forward your messages. It cannot make this appear as anything other than non-delivery — your clients connected to other relays will still receive messages, and the message will be in IPFS storage. The practical defense against relay censorship is connecting to multiple relays simultaneously; a message suppressed by one relay is forwarded by others. Agora clients should do this by default.

---

## Government Adversary: What Legal Process Gets

When a government serves a subpoena or legal demand on a relay operator, the relay can produce:

1. IP address connection logs (if the relay logs them and the logs haven't been purged)
2. Traffic statistics for opaque rotating tokens with no associated identity or channel name
3. Encrypted message blobs, MLS-encrypted, that require the epoch secret to decrypt — which the relay does not hold

From this, investigators can establish: a client at this IP address was connected to this relay at these times, and some volume of traffic associated with these opaque tokens passed through. They cannot establish who was communicating, with whom, about what.

If the relay is Tor-connected (the relay operates as a `.onion` hidden service and clients connect via Tor), the IP connection logs are also unavailable. The relay sees Tor circuit endpoints, not client IPs.

**The important caveat: this is about the relay.** It is not about your device. If your device is seized and forensically examined, your MLS session state, your decrypted message cache, your contacts, and your history are on the device. Agora protects the server from producing your communications. It does not protect a seized device from forensic analysis — that requires full-device encryption, secure deletion, and hardware-backed key storage, which are device-level properties.

**National security letters and gag orders.** A relay operator in the United States can be served with an NSL that prohibits disclosure of the demand. The operator can produce connection logs and encrypted blobs and cannot tell you they did so. The structural defense against this is that the blobs are useless — but IP metadata is not useless. Traffic analysis of connection patterns can be informative even without content. This is a residual risk that Tor mitigates but does not eliminate.

---

## Message Expiry: Sender-Controlled Deletion

Agora supports sender-specified message expiry. The sender encodes an expiry timestamp inside the MLS ciphertext — inside the encrypted payload, invisible to the relay. Recipients' clients are bound by protocol to delete the decrypted message at expiry. Relays drop cached envelopes based on an expiry hint in the outer envelope.

This is stronger than "delete for everyone" features in centralized apps, where the server decides whether to honor the deletion. Here, the expiry is part of the authenticated message content signed by the sender. A relay that retains encrypted blobs past the hint is retaining garbage it cannot decrypt; a recipient client that doesn't honor expiry is violating the protocol in a way that leaves a forensic trace (the signed inner payload proves the sender intended deletion at a specific time).

The practical limit: expiry does not guarantee that a determined adversary who captured and retained the encrypted blob before expiry cannot later decrypt it if they obtain the epoch secret. Forward secrecy limits the window of this risk — the epoch secret for an old epoch is not accessible after rotation — but it is not zero. Expiry is not cryptographic deletion. It is a strong commitment that substantially raises the bar against bulk retention and routine legal demands. Against a sophisticated adversary with ongoing system access, it is not a complete defense.

---

## Metadata: The Honest Picture

End-to-end encryption protects content. Metadata — who communicates with whom, when, how often, from where — often reveals as much as content, and is harder to protect. Agora addresses metadata better than most messaging platforms but does not eliminate the problem.

**What is protected:**
- Sender identity per message (sealed sender — sender DID is inside MLS ciphertext, invisible to relay)
- Channel identity (epoch-rotating tokens that cannot be reversed to channel names or membership)
- Group membership (not transmitted to relay layer)
- Message content (MLS E2EE)

**What is residually exposed:**
- IP addresses, unless Tor is used
- Traffic timing (when messages are sent, at what rate, with what inter-message gaps)
- Traffic volume per token (how active a channel is)
- Push notification timing (the push proxy receives a wake-up event when a message arrives for an offline client; the content is zero, but the timing is observable)
- Gossipsub subscription patterns (which tokens a peer subscribes to, observable by relay and mesh peers — mitigated by decoy subscriptions, but not eliminated)

**Global passive adversary.** A sufficiently resourced adversary monitoring a significant portion of internet traffic — the kind of adversary the Snowden documents described — can perform traffic analysis correlating sender and relay timing even without breaking encryption or compromising any system. This is a known limitation of all low-latency messaging protocols. Agora's sealed sender and rotating tokens reduce but do not eliminate timing correlation attacks. The only real defense is high-latency mixing, which is incompatible with interactive messaging. Agora does not solve this and does not claim to.

---

## Push Notifications: The Metadata Separation Design

Mobile push notifications require a server (Apple APNs or Google FCM) to know which device to wake up. This is a privacy-hostile necessity — the push server learns timing metadata for every notification.

Agora handles this through a push proxy with a two-layer separation:

- The relay knows: your DID → your `pushHandle` (a random token, regenerated fresh on each app install)
- The push proxy knows: your `pushHandle` → your device token (the APNs/FCM identifier)
- Neither party knows both mappings

The relay cannot identify your physical device. The push proxy cannot identify your DID. The wake-up request contains only the `pushHandle` and an urgency hint — no channel identity, no sender, no content. Apple and Google receive a zero-content push notification.

This is meaningfully better than most messaging apps, where the push server is the messaging provider who knows everything. It is not perfect — the push proxy still learns the timing of messages arriving for your handle, and the push proxy operator is a trusted party for availability. The `pushHandle` can be rotated at any time for privacy.

The remaining exposure: Apple and Google's push infrastructure itself. APNs and FCM record that a push notification was sent to your device at a given time. If Apple or Google are served with legal process and produce those records, investigators know your device received a notification at that time, which establishes that you were being messaged. This is a residual risk inherent to using Apple or Google devices for any communication.

---

## Tor Support: What It Does and Doesn't Fix

Agora relays can operate as Tor v3 hidden services (`.onion` endpoints). Clients can connect via Tor. When both are true:

- The relay does not see your IP address
- The relay operator's IP and location are not exposed to the mesh
- IP-level connection logs become useless for identification

What Tor does not fix in Agora's context:

- **Voice and video are effectively unavailable over Tor.** WebRTC requires UDP, which Tor doesn't carry. VTC over Tor routes through TURN-over-TCP with 200–600ms latency. Real-time audio/video is unusable for most purposes in this configuration.
- **Gossipsub fingerprinting is not fixed by Tor.** Gossipsub peer scoring observes message timing and topic subscription patterns independently of IP. A relay-level adversary watching subscription behavior can fingerprint clients by channel subscription pattern even without knowing their IP. Mitigations: periodic Tor circuit rotation, decoy channel subscriptions.
- **Timing analysis is not fixed by Tor.** Tor circuits have latency but are not a mixing network. A global adversary watching both the sender's Tor entry guard and the relay can perform timing correlation.

The honest summary: Tor connectivity eliminates the IP metadata exposure at the relay layer, which is meaningful. It does not make Agora a Tor messenger. For high-risk use cases requiring strong anonymity against relay-level adversaries, use Tor-connected relays, rotate circuits, use decoy subscriptions, and understand the residual gossipsub fingerprinting risk.

---

## Bridges to Slack, Teams, and Matrix: E2EE Breaks at the Boundary

Agora can bridge to Slack, Teams, and Matrix. This is useful for reaching people who are not on Agora. It has a direct privacy cost that must be stated plainly:

**The bridge breaks E2EE.** A bridge is an Agora participant that holds an MLS group membership, decrypts messages, translates them to the target platform's format, and sends them. The bridge operator sees plaintext during translation. Messages that flow through a bridge are not end-to-end encrypted between you and the counterparty on the other platform.

Agora discloses this structurally: when a bridge is added to a channel, a signed system event is written permanently to the channel's IPLD history, all members receive a non-dismissable disclosure notification, and the bridge's presence is visible in MLS group membership. This disclosure cannot be suppressed.

For privacy-sensitive communications, do not use bridged channels. Use native Agora to native Agora, or use MIMI interop where the counterparty is on a MIMI-compatible platform — MIMI native interop preserves E2EE end-to-end with no re-encryption at the boundary.

The bridge disclosure mechanism is the correct behavior. The risk is governance and human factors, not protocol failure: users who don't read disclosures, organizations that don't establish clear policy on which channels may be bridged, situations where the convenience of bridging overrides the security requirement. This is a known risk with any bridging architecture and requires organizational policy, not just technical controls.

---

## Compliance Logging: Honest About the Tradeoff

Agora has first-class compliance logging. A compliance logger is a silent MLS group member that receives and archives every message in every channel it is admitted to — text, reactions, edits, deletions, voice recordings, and direct messages including DMs with counterparties on other platforms. Captured content can be forwarded to enterprise retention services.

For privacy advocates evaluating Agora for personal or activist use, this feature requires a clear statement: **if a compliance logger has been admitted to a channel, there is no meaningful privacy for that channel.** The logger receives every message in plaintext (after MLS decryption on its end) and stores it in an archive designed to be tamper-evident and legally non-erasable.

The compliance logger's presence is disclosed in guild metadata and MLS group membership. A technically capable user can inspect raw MLS group state and verify whether a compliance logger is present. The logger does not appear in the chat UI's participant list and does not generate join/leave messages in the message feed — it is UI-silent but not cryptographically hidden.

**For personal use:** Agora guilds can be run without compliance logging enabled. A `did:key` identity, a self-operated or trusted relay, no compliance logging, and Tor connectivity is a meaningfully private configuration. The compliance logging feature exists for regulated enterprise deployments; it is not mandatory.

**For activist or journalist use:** Verify that any guild you join does not have `complianceLogging.enabled: true` in the guild state document. A conformant Agora client exposes this information. If compliance logging is enabled, the channel is captured.

---

## Payment Privacy

Agora supports micropayments for relay access. The preferred payment mechanism is MobileCoin (MOB), which is private by default: every transaction uses CryptoNote one-time addresses and Ring Confidential Transactions, so the payment graph is not public. A relay accepting MobileCoin payments cannot be shown, via blockchain analysis, to be receiving funds from a specific user.

Lightning Network payments over Tor are also supported but leak payment graph information to routing nodes even over Tor. Cashu (an ecash scheme) is comparable to MobileCoin for privacy but introduces mint trust.

Proof-of-work is available as a spam deterrence mechanism that requires no payment at all — no financial transaction, no payment graph, no money changing hands. For users who do not want any financial metadata associated with their relay usage, PoW-only relays are an option where the relay operator supports it.

---

## Key Storage and Device Security

Private key operations in Agora are designed to use hardware-backed secure boundaries — the Secure Enclave on Apple devices, StrongBox/TEE on Android, TPM on Linux. The protocol is structured so that application code receives signatures and key agreements as outputs, never raw key bytes as inputs. A conformant implementation never has your private key bytes in a variable, on disk, or in a config file.

Recovery keys — used to restore identity after total device loss — are designed to be used on air-gapped hardware and never touch a networked device. The protocol specifies that the recovery key signs a recovery assertion exactly once per recovery event and the signed output is transferred by QR code or similar one-way channel.

This is the correct design. Whether a given client implementation actually follows it requires auditing the implementation, not trusting the spec.

---

## Organizational Non-Impersonation: A Property Most Platforms Don't Have

This section is relevant primarily for enterprise deployments using `did:web` identity with SAML/OIDC provisioning. If you're using `did:key` (self-sovereign, no org involvement), the org has no role in your identity at all and this section doesn't apply.

For enterprise deployments: **your organization cannot silently sign messages as you.** This is unusual. In fact, no major enterprise messaging platform provides this today.

### What Every Other Platform Allows

In Teams, Slack, Zoom, Exchange, and enterprise S/MIME, the organization controls the root of trust completely:

- An IdP admin can generate authentication tokens asserting any identity in the tenant. There's no cryptographic artifact in a sent message proving which specific device or key produced it.
- Enterprise S/MIME typically involves the CA generating your keypair and holding a copy in escrow. The org has your private key.
- Exchange `SendAs` permissions let admins send as any mailbox. This is a routine administrative operation with no cryptographic barrier.

In all of these systems, organizational impersonation leaves no mandatory trace in the messages themselves. Administrative audit logs exist, but they're under organizational control too.

### How Agora Is Different

The architecture splits control between two parties:

- **The organization controls your DID document** — the public record that says "Alice's current key is X." It can add or remove key entries. This is the identity namespace.
- **Your device controls the private key** — generated inside the secure enclave, never transmitted anywhere, including to the provisioning service during enrollment. The org receives only your public key.

Every message you send is signed by your device's private key. That signing key fingerprint is embedded in the encrypted message's authentication data — it's bound to the ciphertext and can't be changed without breaking the message's integrity check.

The org controls the pointer. It doesn't have the key the pointer points to. It cannot produce a signature that looks like it came from your device, because it doesn't have your private key and cannot get it.

### What the Org Can Still Do

The organization can register a new key under your DID using an admin enrollment path (the same one used for IT helpdesk account recovery). If it does this:

1. A new key entry appears in your DID document with a distinct fingerprint and registration timestamp — different from your existing device entries.
2. The action is recorded in the provisioning audit log.
3. Any message signed with that key carries that key's fingerprint, not your original device key's fingerprint.
4. You can be notified of the new device registration out-of-band (implementations should do this).

This is detectable. Silent impersonation — producing a message cryptographically indistinguishable from one you sent — is not possible. Detectable impersonation — registering a new device key via a logged admin operation — leaves a verifiable trace in both the audit log and the DID document's history that you and external auditors can inspect.

Whether your organization's IT department would actually notify you of a covert key registration is a policy question, not a cryptographic one. The architecture makes it detectable; it does not guarantee detection in a hostile internal environment. If your threat model includes a hostile employer, use `did:key` and don't use an enterprise deployment.

### Why This Matters for Non-Repudiation

Messages in Agora carry stronger authenticity guarantees than email with DKIM or enterprise S/MIME:

- DKIM authenticates the sending domain, not the individual sender. Anyone with the domain's DKIM key can sign mail as any address at that domain.
- Enterprise S/MIME with key escrow lets the CA produce valid signatures for any escrowed identity.
- Agora device-key signatures can only be produced by the specific hardware that holds the private key. The compliance archive records both the message and the signing key fingerprint. An auditor — or a court — can verify that a specific message was produced by a specific device, and can cross-reference that key's registration history.

This cuts both ways: stronger proof a message is authentic, and stronger proof that a forged message is forged.

---

## Honest Threat Model Assessment

| Adversary | What They Get | Agora's Defense | Residual Risk |
|---|---|---|---|
| Relay operator | Connection logs (IP + timing), encrypted blobs, traffic volume | Sealed sender, rotating tokens, MLS E2EE | IP metadata, traffic patterns |
| Government with relay subpoena | Same as relay operator, plus whatever relay logs | Structural — relay cannot produce content or identities | IP logs if not Tor; traffic timing |
| Government with device seizure | Everything on the device — decrypted message cache, session state, contacts | Device encryption, secure enclave key storage | Decrypted content in cache |
| Passive network observer | Traffic timing, volume, encrypted content | MLS E2EE, Tor (IP), rotating tokens (channel identity) | Timing correlation against global adversary |
| Compromised group member | All messages in the group for epochs they were a member | Post-compromise security (future epochs secure after member removed) | Past messages in compromise window |
| Bridge operator | Plaintext of all bridged messages | Mandatory disclosure to all channel members | Full plaintext exposure — do not bridge sensitive channels |
| Compliance logger (if admitted) | All messages, permanently archived | Disclosure in guild state and MLS membership | Full capture — verify before joining |
| Push notification infrastructure (Apple/Google) | Notification timing, zero content | pushHandle separation, zero-content payloads | Timing metadata at Apple/Google |

---

## Comparison to Signal

Signal is optimized for individual two-party messaging and small groups with minimal metadata exposure. It has a simpler attack surface, a smaller codebase, no compliance logging, no bridges, and no organizational hierarchy. For individual threat models, Signal is generally a better choice for sensitive one-on-one and small-group communication.

Agora addresses a different use case: organizations that need persistent channel infrastructure, searchable history, moderation tools, voice and video, and compliance capture. Signal provides none of these. The tradeoff is a larger attack surface and more operational complexity in exchange for organizational-scale functionality.

The practical comparison for a journalist, activist, or privacy-conscious organization:

- For communicating with a single source or a small trusted group: Signal, unless you need persistent searchable history or compliance capture
- For organizational infrastructure — a newsroom, an activist collective, a legal team — where people need channels, history, file sharing, and the ability to communicate with people who are on Slack or Teams: Agora is the strongest available option

This is not a competition. Use Signal where Signal is the right tool. Use Agora where Agora is the right tool. The privacy properties of each are appropriate to their use cases.

---

## What We're Not Claiming

This document should not be read as claiming Agora is anonymous. It is not. It reduces metadata exposure substantially compared to centralized platforms, but a sophisticated adversary with broad network visibility can perform traffic analysis attacks that no low-latency messaging protocol defeats.

This document should not be read as claiming Agora is secure against all device-level threats. End-to-end encryption protects messages in transit and at rest on servers. It does not protect against malware on your device, physical device seizure without strong device encryption, or an attacker with ongoing access to your screen.

This document should not be read as claiming that every Agora deployment is private. A guild with compliance logging enabled is not private. A guild with a Teams bridge is not E2EE. These are features of the protocol that different deployments use differently. Verify the configuration of any guild you join before trusting it with sensitive communications.

What we are claiming: the protocol's cryptographic guarantees are sound, the relay blindness is structural rather than policy-based, the metadata protections are substantially better than any centralized platform, and the failure modes are documented and honest rather than hidden. That is a meaningful set of claims. It is not a claim of perfection.

---

## For Developers and Auditors

The full Agora protocol specification is public at [link]. The relevant sections for privacy review are:

- **§6**: Message format and sealed sender construction
- **§8.3**: Tor transport constraints and limitations  
- **§11.1**: Relay knowledge constraints (normative)
- **§11.3**: Relay conformance requirements
- **§13**: Security considerations including metadata leakage analysis
- **§17**: Compliance logging (understand what it captures and how)
- **§10.12**: VTC compliance recording

Independent cryptographic audit of MLS implementations and relay conformance testing are priorities. If you find discrepancies between the specification's privacy claims and the implementation, we want to know.
