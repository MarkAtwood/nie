# Agora Protocol: A Privacy Analysis

**Audience:** Privacy researchers, security engineers, and technically sophisticated users evaluating Agora against a specific threat model
**Document type:** Technical privacy assessment
**Scope:** Where the protocol delivers strong guarantees, this document says so and explains why. Where it has limits or makes tradeoffs, it says that too.

---

## Who This Is For

This document is for readers who look at privacy policies for what they omit, who understand the difference between "we don't sell your data" and "we can't read your data," and who want to understand what Agora actually does and does not protect before trusting it with sensitive communications.

Agora is not Signal. Signal is optimized for individual two-party or small-group E2EE messaging with a minimal metadata footprint. Agora is designed for organizational-scale persistent group communication — the Discord/Slack use case — with compliance logging as a first-class feature. Those goals create different tradeoffs. This document maps them honestly.

---

## The Core Question: What Does the Server See?

With Slack, Teams, and Discord, the server sees everything: messages in plaintext, membership lists, DMs, full message history, and metadata — who talked to whom, when, how often, from where. When law enforcement or intelligence agencies request this information, the vendor produces it, because the vendor holds it. This is not a security failure; it is the designed architecture.

With Agora, the server — called a Relay — sees:

- **IP addresses** of connecting clients (unless clients use Tor)
- **Encrypted blobs** of message content it cannot decrypt
- **Rotating anonymous tokens** (`channelToken`) that identify a channel for routing but cannot be reversed to a channel name, channel membership, or sender identity without the epoch secret the Relay does not hold
- **Sequence numbers and timestamps** on the outer envelope
- **Approximate traffic volume** per token

The Relay does **not** see:

- Message content (MLS end-to-end encryption; the Relay never holds a decryption key)
- The sender of any specific message (sealed sender design; the sender's DID is inside the MLS ciphertext)
- Which channel a token corresponds to during steady-state routing (epoch-rotating derivation, non-reversible without the epoch secret)
- Space channel membership during steady-state routing (channel tokens are opaque)
- The relationship between messages — who replied to whom, conversation threads, message graphs

The Relay **does** see:

- Space membership: the relay holds the Space state document, which lists member DIDs, in order to serve it to joining clients
- DM group participant lists at group formation: the relay routes `Welcome` messages to recipient inboxes and therefore learns which DIDs are forming a new DM group
- In compliance deployments: which member DIDs are regulated employees and which DID is the compliance logger (needed to enforce logger inclusion per §17.8.9)

This is not a policy commitment. It is a structural property of the protocol. A Relay operator served with a government demand can produce IP connection logs, traffic volume statistics for opaque tokens, encrypted blobs, and Space membership lists. They cannot produce message content, sender attribution for specific messages, or Space channel membership during steady-state operation.

---

## The Encryption: What MLS Provides

Agora uses RFC 9420 — the IETF Messaging Layer Security standard — as its sole key agreement mechanism. MLS provides two properties that matter for privacy threat models, which most E2EE systems do not provide simultaneously:

**Forward secrecy.** Each MLS epoch (roughly, each time the group's key state advances) derives a new encryption key. Compromise of the current key does not expose past messages. A device seized tomorrow cannot decrypt conversations from last month. A relay compromised later cannot retrospectively decrypt retained encrypted archives.

**Post-compromise security.** If a device is compromised and then removed from a group, the group's subsequent messages are secure against that compromised device. The ratchet advances; the compromised key material cannot decrypt new epochs. This is qualitatively different from protocols where a compromised participant retains the ability to read future messages until manually rotated out.

These properties follow from the mathematical construction, not implementation promises. They hold as long as the MLS implementation is correct and keys are stored securely on devices. They do not protect against device compromise that persists undetected — if an attacker has ongoing access to a device, they read messages as the user reads them, before encryption on send and after decryption on receive. No protocol addresses that.

---

## Identity: Self-Sovereign by Default

Agora identities are Decentralized Identifiers (DIDs). A `did:key` identity is a keypair generated locally. It is not registered with any authority and requires no account creation, phone number, or email address. The keypair is the identity.

For organizational use, `did:web` anchors identity to a domain the organization controls — `did:web:example.com` is resolved by fetching a document from `example.com`. This is auditable and lets organizations manage identity through existing DNS infrastructure.

Neither identity type requires trusting a third-party identity provider with the user's existence. A `did:key` user who generates a key, never connects to any central service, and uses a Tor-connected relay has provided no personally identifying information to any party in the system by design.

The practical caveat: if SAML or OIDC is used for authentication (supported for enterprise deployments), the identity provider learns each authentication event. If that identity provider is Microsoft Entra or Okta, those authentication events are logged there. This is a deployment choice. The protocol supports both self-sovereign and federated identity; the privacy properties differ accordingly.

---

## What the Relay Operator Can and Cannot Do

**Can do:**
- Log IP connection events
- Observe traffic volume patterns per token per time period
- Go offline, losing message fanout until another relay serves the channel
- Censor outgoing messages by refusing to forward them (detectable by clients connected to multiple relays simultaneously)
- Respond to legal demands with connection logs and encrypted blobs

**Cannot do:**
- Read message content
- Identify the sender of any specific message (sealed sender; sender identity is inside MLS ciphertext)
- Identify Space channel membership during steady-state routing (channel tokens are opaque and epoch-rotating)
- Forge messages (sender signatures are inside MLS ciphertext, verified by recipients)
- Silently modify history (content addressing detects tampering — substituted content produces a different hash and is rejected)
- Produce message plaintext in response to a content subpoena, because the Relay holds no decryption keys

**Can do (that is often overlooked):**
- Know which DIDs are members of a Space (from Space state)
- Know which DIDs participated in a DM group at formation time (from Welcome routing)
- In compliance deployments: know which users are regulated and enforce logger admission

The censorship surface deserves attention. A relay can refuse to forward messages. It cannot make this appear as normal delivery — clients connected to other relays will still receive the message, and the message remains in IPFS storage. The practical defense against relay censorship is connecting to multiple relays simultaneously; a message suppressed by one relay is forwarded by others. Agora clients should do this by default.

---

## Government Adversary: What Legal Process Yields

When a government serves a subpoena or legal demand on a relay operator, the relay can produce:

1. IP address connection logs (if logged and not yet purged)
2. Traffic statistics for opaque rotating tokens with no associated identity or channel name
3. MLS-encrypted message blobs requiring the epoch secret to decrypt — which the relay does not hold

From this, investigators can establish that a client at a given IP address connected to the relay at given times, and that some volume of traffic associated with opaque tokens passed through. They cannot establish who was communicating, with whom, or about what.

If the relay operates as a `.onion` hidden service and clients connect via Tor, IP connection logs are also unavailable. The relay sees Tor circuit endpoints, not client IPs.

**Important caveat: this analysis applies to the relay.** It does not apply to the user's device. A forensically examined device exposes the local MLS session state, decrypted message cache, contacts, and history. Agora prevents the relay from producing communications. It does not protect a seized device from forensic analysis — that requires full-device encryption, secure deletion, and hardware-backed key storage, which are device-level properties.

**National security letters and gag orders.** A relay operator in the United States can be served with an NSL prohibiting disclosure of the demand. The operator can produce connection logs and encrypted blobs without being able to notify users. The structural defense is that encrypted blobs are useless without epoch secrets — but IP metadata is not useless. Traffic analysis of connection patterns can be informative independent of content. This is a residual risk that Tor mitigates but does not eliminate.

---

## Message Expiry: Sender-Controlled Deletion

Agora supports sender-specified message expiry. The sender encodes an expiry timestamp inside the MLS ciphertext — invisible to the relay. Recipients' clients are bound by protocol to delete the decrypted message at expiry. Relays drop cached envelopes based on an expiry hint on the outer envelope.

This is stronger than "delete for everyone" in centralized apps, where the server decides whether to honor deletion. In Agora, expiry is part of the authenticated message content signed by the sender. A relay retaining encrypted blobs past the expiry hint is retaining ciphertext it cannot decrypt. A recipient client that does not honor expiry is violating the protocol in a way that leaves a forensic trace — the signed inner payload proves the sender intended deletion at a specific time.

The practical limit: expiry does not guarantee that a determined adversary who captured and retained an encrypted blob cannot later decrypt it if they obtain the epoch secret. Forward secrecy constrains this risk — the epoch secret for a rotated epoch is not accessible after rotation — but the risk is not zero. Expiry is not cryptographic deletion. It substantially raises the bar against bulk retention and routine legal demands. Against a sophisticated adversary with ongoing system access, it is not a complete defense.

---

## Metadata: The Honest Picture

End-to-end encryption protects content. Metadata — who communicates with whom, when, how often, from where — often reveals as much as content and is harder to protect. Agora addresses metadata better than most messaging platforms but does not eliminate the exposure.

**Protected:**
- Sender identity per specific message (sealed sender — sender DID is inside MLS ciphertext, invisible to the relay)
- Space channel identity during steady-state routing (epoch-rotating tokens cannot be reversed to channel names or membership without the epoch secret)
- Space channel membership during steady-state routing (not derivable from channel tokens alone)
- Message content (MLS E2EE)

**Residually exposed:**
- IP addresses, unless Tor is used
- Traffic timing (when messages are sent, at what rate, with what inter-message gaps)
- Traffic volume per token (channel activity level)
- Space membership: the relay holds the Space state document listing all member DIDs
- DM group social graph: the relay learns which DIDs form each DM group at creation time, from Welcome message routing
- In compliance deployments: which users are regulated employees
- Push notification timing (the push proxy receives a wake-up event when a message arrives for an offline client; the payload is zero-content, but the timing is observable)
- Gossipsub subscription patterns (which tokens a peer subscribes to, observable by the relay and mesh peers — mitigated by decoy subscriptions, but not eliminated)

The distinction between Space channel and DM group metadata exposure matters. Space channels provide meaningful metadata protection during steady-state operation through token rotation. DM group formation is metadata-visible to the relay by design — the relay must route Welcome messages. For deployments where DM social graph visibility is a concern, the threat model is the relay operator, not a third party.

**Global passive adversary.** A sufficiently resourced adversary monitoring a significant fraction of internet traffic can perform traffic analysis correlating sender and relay timing without breaking encryption or compromising any system. This is a known limitation of all low-latency messaging protocols. Agora's sealed sender and rotating tokens reduce but do not eliminate timing correlation attacks. The only defense against a global passive adversary is high-latency mixing, which is incompatible with interactive messaging. Agora does not solve this and does not claim to.

---

## Push Notifications: Metadata Separation Design

Mobile push notifications require a server (Apple APNs or Google FCM) to know which device to wake up. This is an unavoidable privacy cost — the push server learns timing metadata for every notification.

Agora handles this through a push proxy with a two-layer separation:

- The relay knows: user DID → `pushHandle` (a random token, regenerated on each app install)
- The push proxy knows: `pushHandle` → device token (the APNs/FCM identifier)
- Neither party holds both mappings

The relay cannot identify a user's physical device. The push proxy cannot identify a user's DID. The wake-up request contains only the `pushHandle` and an urgency hint — no channel identity, no sender, no content. Apple and Google receive a zero-content push notification.

This is substantially better than the typical messaging architecture, where the push server is the messaging provider holding full context. It is not without residual exposure: the push proxy learns the timing of message arrivals for each handle, and the push proxy operator is a trusted party for availability. The `pushHandle` can be rotated at any time.

The remaining exposure: Apple and Google's push infrastructure records that a notification was sent to a device at a given time. Legal process served on Apple or Google can establish that a device received a notification at a specific time, which indicates the user was being messaged. This is a residual risk inherent to any communication on Apple or Google devices.

---

## Tor Support: Scope and Limits

Agora relays can operate as Tor v3 hidden services (`.onion` endpoints). Clients can connect via Tor. When both are true:

- The relay does not see the client's IP address
- The relay operator's IP and location are not exposed to the mesh
- IP-level connection logs become useless for identification

What Tor does not fix in Agora's context:

- **Voice and video are effectively unavailable over Tor.** WebRTC requires UDP, which Tor does not carry. VTC over Tor routes through TURN-over-TCP with 200–600ms added latency. Real-time audio and video are unusable for most purposes in this configuration.
- **Gossipsub fingerprinting is not mitigated by Tor.** Gossipsub peer scoring observes message timing and topic subscription patterns independently of IP. A relay-level adversary watching subscription behavior can fingerprint clients by subscription pattern even without knowing their IP. Mitigations include periodic Tor circuit rotation and decoy channel subscriptions.
- **Timing analysis is not mitigated by Tor.** Tor circuits introduce latency but are not a mixing network. A global adversary observing both the sender's Tor entry guard and the relay can perform timing correlation.

Tor connectivity eliminates IP metadata exposure at the relay layer, which is meaningful. It does not make Agora equivalent to a Tor-native messenger. For high-risk configurations requiring strong anonymity against relay-level adversaries, use Tor-connected relays, rotate circuits, use decoy subscriptions, and account for the residual gossipsub fingerprinting risk.

---

## Bridges to Slack, Teams, and Matrix: E2EE Breaks at the Boundary

Agora can bridge to Slack, Teams, and Matrix. This is useful for reaching users not on Agora. It has a direct privacy cost:

**Bridging breaks E2EE.** A bridge is an Agora participant holding MLS group membership that decrypts messages, translates them to the target platform's format, and sends them. The bridge operator sees plaintext during translation. Messages that flow through a bridge are not end-to-end encrypted between the sender and the counterparty on the other platform.

Agora discloses this structurally: when a bridge is added to a channel, a signed system event is written permanently to the channel's IPLD history, all members receive a non-dismissable disclosure notification, and the bridge's presence is visible in MLS group membership. This disclosure cannot be suppressed by the bridge or the relay.

MIMI native interop is different: when the counterparty is on a MIMI-compatible platform, interoperability preserves E2EE end-to-end with no re-encryption at the boundary.

The bridge disclosure mechanism is a protocol guarantee. The residual risk is governance and human factors: users who do not read disclosures, organizations that lack clear policy on which channels may be bridged, and situations where convenience overrides security requirements. This risk requires organizational policy, not just technical controls.

---

## Compliance Logging: Honest About the Tradeoff

A compliance logger is a silent MLS group member admitted to a channel that receives and archives every message — text, reactions, edits, deletions, voice recordings, and direct messages including DMs with counterparties on other platforms. Captured content can be forwarded to enterprise retention services.

**If a compliance logger has been admitted to a channel, that channel has no meaningful privacy.** The logger receives every message in plaintext (after MLS decryption on its end) and stores it in a tamper-evident, legally non-erasable archive.

The compliance logger's presence is disclosed in space metadata and MLS group membership. A technically capable user can inspect raw MLS group state to verify whether a compliance logger is present. The logger does not appear in the chat UI's participant list and does not generate join/leave messages in the message feed — it is UI-silent but not cryptographically hidden.

**For personal use:** Agora spaces can be run without compliance logging. A `did:key` identity, a self-operated or trusted relay, no compliance logging, and Tor connectivity is a meaningfully private configuration. Compliance logging exists for regulated enterprise deployments; it is not mandatory.

**For activist or journalist use:** Verify that any space you join does not have `complianceLogging.enabled: true` in the space state document. A conformant Agora client exposes this information. If compliance logging is enabled, the channel is fully captured.

---

## Payment Privacy

Agora supports micropayments for relay access. The preferred payment mechanism is MobileCoin (MOB), which is private by default: every transaction uses CryptoNote one-time addresses and Ring Confidential Transactions, so the payment graph is not public. A relay accepting MobileCoin payments cannot be shown via blockchain analysis to be receiving funds from a specific user.

Lightning Network payments over Tor are supported but leak payment graph information to routing nodes even over Tor. Cashu (an ecash scheme) is comparable to MobileCoin for privacy but introduces mint trust.

Proof-of-work is available as a spam deterrence mechanism requiring no payment — no financial transaction, no payment graph. For users who want no financial metadata associated with their relay usage, PoW-only relays are an option where the relay operator supports it.

---

## Key Storage and Device Security

Private key operations in Agora are designed to use hardware-backed secure boundaries — the Secure Enclave on Apple devices, StrongBox/TEE on Android, TPM on Linux. The protocol is structured so that application code receives signatures and key agreements as outputs, never raw key bytes as inputs. A conformant implementation never holds private key bytes in a variable, on disk, or in a configuration file.

Recovery keys — used to restore identity after total device loss — are designed to be used on air-gapped hardware and never touch a networked device. The protocol specifies that the recovery key signs a recovery assertion exactly once per recovery event and the signed output is transferred by QR code or similar one-way channel.

This is the correct design. Whether a given client implementation follows it requires auditing the implementation, not trusting the specification.

---

## Threat Model

| Adversary | What They Obtain | Agora's Defense | Residual Risk |
|---|---|---|---|
| Relay operator | Connection logs (IP + timing), encrypted blobs, traffic volume, Space membership lists, DM group participant lists at formation | Sealed sender, rotating channel tokens, MLS E2EE | IP metadata, traffic patterns, DM social graph |
| Government with relay subpoena | Same as relay operator, plus retained relay logs | Structural — relay cannot produce message content or per-message sender attribution | IP logs if not using Tor; Space membership; DM group formation metadata |
| Government with device seizure | Full device contents — decrypted message cache, session state, contacts | Device encryption, secure enclave key storage | Decrypted content in local cache |
| Passive network observer | Traffic timing, volume, encrypted content | MLS E2EE, Tor (IP), rotating tokens (channel identity) | Timing correlation against global adversary |
| Compromised group member | All messages for epochs the member was present | Post-compromise security — future epochs secure after member is removed | Messages in the compromise window |
| Bridge operator | Plaintext of all bridged messages | Mandatory structural disclosure to all channel members | Full plaintext exposure — do not bridge sensitive channels |
| Compliance logger (if admitted) | All messages, permanently archived | Disclosure in space state and MLS membership | Full capture — verify before joining |
| Push notification infrastructure (Apple/Google) | Notification timing, zero content | `pushHandle` separation, zero-content payloads | Timing metadata at Apple/Google |

---

## Comparison to Signal

Signal is optimized for individual two-party messaging and small groups with minimal metadata exposure. It has a simpler attack surface, a smaller codebase, no compliance logging, no bridges, and no organizational hierarchy. For individual threat models, Signal is generally the better choice for sensitive one-on-one and small-group communication.

Agora addresses a different use case: organizations requiring persistent channel infrastructure, searchable history, moderation tools, voice and video, and compliance capture. Signal provides none of these. The tradeoff is a larger attack surface and more operational complexity in exchange for organizational-scale functionality.

Practical guidance:

- For communicating with a single source or a small trusted group: Signal, unless persistent searchable history or compliance capture is required
- For organizational infrastructure — a newsroom, activist collective, or legal team — where people need channels, history, file sharing, and the ability to communicate with users on Slack or Teams: Agora is the strongest currently available option

These are not competing tools for the same use case. The privacy properties of each are appropriate to their respective design targets.

---

## Scope of Claims

Agora is not anonymous. It reduces metadata exposure substantially compared to centralized platforms, but a sophisticated adversary with broad network visibility can perform traffic analysis attacks that no low-latency messaging protocol defeats.

Agora is not secure against all device-level threats. End-to-end encryption protects messages in transit and at rest on servers. It does not protect against malware on a device, physical device seizure without strong device encryption, or an attacker with ongoing access to the screen.

Not every Agora deployment is private. A space with compliance logging enabled is not private. A space with a Teams bridge is not E2EE. These are features of the protocol that different deployments use differently. Verify the configuration of any space before trusting it with sensitive communications.

What this document does claim: the protocol's cryptographic guarantees are sound, relay blindness is structural rather than policy-based, the metadata protections are substantially better than any centralized platform, and the failure modes are documented rather than obscured. That is a meaningful set of claims. It is not a claim of perfection.

---

## For Developers and Auditors

The full Agora protocol specification is public at [link]. Relevant sections for privacy review:

- **§6**: Message format and sealed sender construction
- **§8.3**: Tor transport constraints and limitations
- **§10.12**: VTC compliance recording
- **§11.1**: Relay knowledge constraints (normative)
- **§11.3**: Relay conformance requirements
- **§13**: Security considerations including metadata leakage analysis
- **§17**: Compliance logging — what it captures and how

Independent cryptographic audit of MLS implementations and relay conformance testing are priorities. Discrepancies between the specification's privacy claims and any implementation should be reported.
