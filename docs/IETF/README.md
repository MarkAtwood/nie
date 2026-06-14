# IETF MIMI and MLS Working Group Documents

Fetched 2026-04-21. Sources: IETF Datatracker MIMI WG and MLS WG document pages.

## Published RFCs

| File | Title | Description |
|------|-------|-------------|
| `rfc9420.txt` | The Messaging Layer Security (MLS) Protocol | The core MLS protocol spec defining the group key agreement protocol for end-to-end encrypted messaging (July 2023) |
| `rfc9750.txt` | The Messaging Layer Security (MLS) Architecture | Describes the architecture for deploying MLS in secure group messaging infrastructure and defines MLS security goals (April 2025) |

**Note:** RFC 9764 is NOT a MIMI/MLS document — it is "BFD Encapsulated in Large Packets" (a routing protocol). The task description had an incorrect RFC number for a MIMI architecture document. MIMI WG has no published RFCs as of this writing; all MIMI documents remain Internet Drafts.

## MIMI WG Internet Drafts

| File | Title | Description |
|------|-------|-------------|
| `draft-ietf-mimi-arch-02.txt` | An Architecture for More Instant Messaging Interoperability (MIMI) | Overall MIMI architecture, enumerating the MIMI protocols and how they work together to enable interoperable messaging |
| `draft-ietf-mimi-content-08.txt` | More Instant Messaging Interoperability (MIMI) message content | Content semantics for IM systems; defines a message profile for interoperability of MLS-encrypted instant messages |
| `draft-ietf-mimi-protocol-05.txt` | More Instant Messaging Interoperability (MIMI) using HTTPS and MLS | The MIMI transport protocol allowing users of different messaging providers to interoperate in group chats over HTTPS and MLS |
| `draft-ietf-mimi-room-policy-03.txt` | Room Policy for the More Instant Messaging Interoperability (MIMI) Protocol | Defines concrete room policy attributes (moderation, membership, permissions) that can be combined to model diverse chat and conference types |

## MLS WG Internet Drafts (Extensions and Related)

| File | Title | Description |
|------|-------|-------------|
| `draft-ietf-mls-combiner-02.txt` | Amortized PQ MLS Combiner | Protocol to combine a traditional MLS session with a post-quantum MLS session for efficient amortized PQ confidentiality and authenticity |
| `draft-ietf-mls-extensions-09.txt` | The Messaging Layer Security (MLS) Extensions | Consolidated application API and guidance for MLS extension points, with concrete examples of core protocol extensions |
| `draft-ietf-mls-federation-03.txt` | The Messaging Layer Security (MLS) Federation | Describes how MLS can be used in federated environments where multiple providers interoperate |
| `draft-ietf-mls-partial-00.txt` | Partial MLS | MLS extension supporting "partial" group membership where clients need not download or validate full group state |
| `draft-ietf-mls-pq-ciphersuites-04.txt` | ML-KEM and Hybrid Cipher Suites for Messaging Layer Security | Registers new post-quantum cipher suites for MLS using ML-KEM, optionally combined with traditional elliptic curve KEMs |
| `draft-ietf-mls-ratchet-tree-options-00.txt` | Ways to convey the Ratchet Tree in Messaging Layer Security | Standardizes mechanisms for sharing and optimizing transmission of the MLS ratchet tree during group joins and external joins |
| `draft-ietf-mls-targeted-messages-00.txt` | Messaging Layer Security (MLS) Targeted Messages | Defines a mechanism for an MLS group member to send an encrypted authenticated message to a specific other member without creating a new group |
| `draft-ietf-mls-virtual-clients-00.txt` | MLS Virtual Clients | Describes how multiple MLS clients can emulate a single virtual MLS client under one leaf, improving metadata privacy and performance |

## Fetch Summary

- 2 RFCs downloaded (rfc9420, rfc9750)
- 4 MIMI WG Internet Drafts downloaded (all active WG documents)
- 8 MLS WG Internet Drafts downloaded (all active WG documents)
- 14 files total
- All files verified non-empty (sizes range from 17K to 293K)
