# Agora: Plans, Ideas, Hopes, and Dreams

**Status:** Speculative. Nothing in this document is committed to the protocol spec.
**Date:** 2026-04-24

---

## What Agora Already Is

Agora is a decentralized, end-to-end encrypted, real-time group communication protocol. It is designed to support a user experience comparable to Discord — servers with hierarchical channels, presence, voice/video — without any central authority owning identity, routing, or message storage.

That framing is accurate but undersells the architecture. What the protocol actually provides is:

- **Self-sovereign identity** at every scale, from an individual with a keypair to a government agency with a DNS-anchored DID namespace
- **Authenticated, encrypted group state** via MLS, where group membership is cryptographically enforced and the relay is structurally blind
- **Content-addressed persistent storage** via IPLD, where history is tamper-evident by construction
- **Federated real-time fanout** via libp2p gossipsub, permissionless and without a central directory
- **Micropayments** via MobileCoin, already wired into the relay economics model
- **Cross-topology reachability** — a `.gov` user and a `.onion` user can DM each other; the protocol doesn't care

That is not a chat protocol. That is a substrate.

---

## The OASIS

Ready Player One's OASIS is the most useful mental model for where this could go. A persistent, federated virtual world where identity, property, social structure, and economic activity are real — where what you build and own and earn has weight beyond the platform that hosts it.

The difference between the OASIS and every prior attempt at a metaverse is that prior attempts were owned by a company. When the company dies or pivots or gets acquired, the world ends. Your avatar, your property, your relationships — gone.

Agora's architecture makes a different bet. Identity is self-certifying. History is content-addressed. The relay is blind and replaceable. No single company can pull the plug on a namespace it doesn't control.

A VR metaverse built on Agora would be a collection of Spaces — some publicly discoverable, some invite-only, some air-gapped from the rest. Each Space is a world or a region or an instance. Channels are zones. The gossipsub mesh is the nervous system. MLS groups are the rooms you're actually in.

The DNS-namespace-as-root principle that governs relay discoverability applies here too. A game studio or world operator roots their platform in a DNS name. Players get identities under that namespace, or bring their own `did:key` identities from outside. The world persists as long as someone is pinning the IPLD state — which could be the operator, the players themselves, or both.

---

## Spatial Presence

The current presence model (§7) is chat presence: online, away, do-not-disturb, typing. That is insufficient for VR.

Spatial presence needs:

- **Position and orientation** — where you are in a 3D space, which direction you're facing
- **Avatar state** — expression, gesture, animation blend weights
- **Spatial audio zones** — who you can hear depends on where you are, not who's in the channel
- **Proximity fanout** — you only receive presence updates from entities within some spatial radius; flooding the whole channel with everyone's position at 60fps is not viable

The gossipsub fanout model is actually well-suited to this if you add spatial sharding. A zone or region becomes a gossip topic. When you move between zones you subscribe and unsubscribe. Within a zone, position updates are ephemeral gossip messages — no storage, no IPLD, high frequency, best-effort delivery. The MLS group for the zone handles authentication; the gossip mesh handles delivery.

Spatial audio would integrate with the existing SFU model (§10). The SFU already handles media routing; adding spatial attenuation based on position state is an application-layer concern on top of the WebRTC stack.

---

## Gaming

### The General Case

Any game needs: authenticated participants, shared state, ordered events, and some notion of who's allowed to do what. Agora provides all of these.

A game session is an MLS group. Players are members. Game events are MLS application messages — authenticated, ordered (via the IPLD linked list), and encrypted from the relay. The session starts when the group is formed and ends when it's abandoned or the history is archived.

Lobbies are Spaces. Game instances are channels or sub-groups. Leaderboards and persistent player records are IPLD documents pinned by whoever cares about them.

### RPG: Persistent Worlds and Character Identity

RPG is the richest case. A persistent RPG world needs:

- **Character identity** — a DID for your character, separate from your user DID, controlled by your user DID. Your character can have a name, a history, inventory, stats — all in an IPLD document chain. You own the keys; no game company can delete your character.
- **World state** — the authoritative state of the world (who's where, what's happened, what exists) is an IPLD DAG. The game operator pins it. Players can pin it too. Forks are possible; canonical state requires a designated authority.
- **Game Master authority** — the GM is a DID with special commit rights over world-state MLS messages. Not the relay — the relay remains blind. The GM is a participant in the MLS group with elevated permissions, just like a Space admin in the current model.
- **NPC identity** — NPCs are DIDs too, controlled by the world operator or by autonomous agents. An NPC that can be talked to, traded with, or killed is just a DID with a message loop on the other end. That loop could be a human GM, a script, or an LLM.

### Card and Table Games

Card games (poker, Magic, collectible card games) and table games (chess, Go, board games) are the clearest case for the **referee principal** model.

The problem with a blind relay is that it can't prevent cheating. If the relay can't see the game state, it can't verify that a move is legal. The solution is not to give the relay sight — it is to introduce a **referee** as a participant in the MLS group.

The referee is a DID — agreed upon by all players before the session starts, named in the game session descriptor. The referee is the only participant authorized to commit game-state-advancing messages. Players submit proposed moves to the referee (or to the group; the referee validates). The referee commits the authoritative state. The relay routes the messages; the relay still sees nothing useful.

The referee can be:
- A trusted third-party service
- One of the players, by agreement (honor system)
- An autonomous program whose source is published and whose DID is derived from a hash of that source (so players can verify what they're trusting)

Card games with hidden information (poker hole cards, MTG hand) use MLS subgroups: each player has a private channel to the referee for their hidden state. The referee knows all hands; the relay knows nothing.

For collectible card games, the cards themselves are IPLD assets — content-addressed, owned via DID-signed transfer records. A card you earned or bought has a provenance chain. A deck is a signed list of card CIDs. Counterfeiting is structurally impossible.

---

## Person-to-Person Payments

MobileCoin is already in the spec as the payment mechanism for relay economics and message micropayments (§12). Extending it to P2P payments between users is a short step.

The vision:

- **Tipping and gifting** — send MOB to any DID you can resolve. The payment message is an MLS application message in a DM group, authenticated by both parties, private from the relay.
- **In-game transactions** — buy an item, pay entry to a tournament, split a bill after a virtual dinner. All P2P, all auditable by the parties, none visible to the relay or any third party.
- **Escrow for game stakes** — a poker pot, a tournament prize pool, a bounty on a quest. A smart escrow is a DID-identified service that holds funds and releases them on a signed trigger from the referee principal.
- **Creator payments** — a world operator or content creator publishes a Space; access requires a signed payment receipt. No payment processor in the middle; the receipt is a MOB transaction on-chain.

The DID-to-payment-address binding is the key primitive. If your DID document includes your MOB address, anyone who can resolve your DID can pay you. No username lookup, no payment handle, no intermediary.

---

## Asset Ownership

Virtual assets — VR items, game inventory, collectible cards, land parcels in a virtual world — need a provenance model that survives platform death.

IPLD is already the answer. An asset is an IPLD document: a description, an image CID, a set of properties, and an ownership record. Ownership is a DID-signed transfer chain. The current owner is whoever holds the private key corresponding to the most recent transfer's target DID.

Minting (creating a new asset) is a signed assertion by the world operator's DID. Transferring is a signed message from current owner to new owner, witnessed by the game's referee principal or simply gossiped to the mesh. The full provenance chain is content-addressed and tamper-evident.

This is not a blockchain. There is no global consensus, no proof-of-work, no token. It is a signed linked list, which is sufficient for any game or VR context where the issuing authority is known and trusted by the participants.

---

## What This Implies About the Protocol

Agora is currently framed as "decentralized Discord." That framing is useful for adoption — Discord users understand it immediately — but it undersells what's been built.

The honest description is: Agora is a decentralized substrate for authenticated real-time interaction between self-sovereign identities, with content-addressed persistent state, blind transport, and optional payments.

That substrate happens to support:
- Chat (what it was designed for)
- Voice and video (already specified)
- VR spatial presence (extension of the presence model)
- Gaming of all kinds (MLS groups + referee principal)
- A metaverse (Spaces as worlds, IPLD as the world state, DIDs as everything)
- P2P payments (MobileCoin already wired in)
- Asset ownership (IPLD + DID-signed transfer chains)

None of these require changing the core. They are all additive extensions on a foundation that was, perhaps by accident or perhaps by design, general enough to hold them.

---

## Honest Tensions and Open Questions

**Relay blindness vs. game integrity.** The relay cannot referee. The referee principal model resolves this, but it requires players to agree on and trust a referee DID before a session starts. That is a coordination cost that centralized game servers do not impose. Whether this is acceptable depends on the game.

**Spatial presence at scale.** A zone with 10,000 concurrent avatars cannot gossip everyone's position to everyone. Spatial sharding and progressive detail (full fidelity for nearby; low fidelity for distant; nothing beyond some radius) are the standard solutions. These are solved problems in game networking; integrating them with the gossipsub model needs design work.

**World state authority and forks.** A persistent RPG world needs a canonical world state. IPLD gives you tamper-evident history, but it does not give you a single authoritative tip. If two GMs simultaneously advance the world state, you get a fork. Resolving forks requires either a single designated authority (simple, centralized) or a consensus mechanism (complex, decentralized). The right answer probably depends on the scale and governance model of the world.

**Asset ownership without global consensus.** The DID-signed transfer chain works if you trust the issuing authority and the transfer witnesses. It does not prevent double-spending (transferring the same asset to two different parties simultaneously) without either a trusted referee or a global ledger. For low-stakes game items this is acceptable. For high-value assets it may not be.

**Performance.** The current spec is designed for human-paced interaction — messages, presence updates, typing indicators. Game physics and VR presence run at 60–120Hz. That is a different engineering problem. WebTransport/QUIC is the right transport; the framing and gossip models need profiling at game-relevant message rates.

**Privacy in a VR world.** Spatial presence inherently leaks location within a world. A blind relay that routes position updates is less blind in practice than one routing encrypted chat. The threat model for VR presence is different from the threat model for messaging, and the spec will need to address this explicitly.

---

## What to Build Next

In rough priority order, the protocol extensions that unlock the most:

1. **Spatial presence message type** — position, orientation, avatar state, zone subscription model. Unblocks VR and spatial audio.
2. **Referee principal model** — a first-class named authority participant in an MLS group with commit-gating rights. Unblocks card games, table games, anything requiring adjudication.
3. **Asset descriptor and transfer chain** — IPLD schema for owned assets and DID-signed transfer records. Unblocks collectibles, inventory, land.
4. **P2P payment message type** — MOB transfer receipt as an MLS application message. Unblocks tipping, in-game transactions, escrow triggers.
5. **Game session descriptor** — a structured IPLD document naming the game type, referee DID, participants, stakes, and rules reference CID. Unblocks matchmaking and session bootstrapping.
6. **NPC/agent identity model** — a DID controlled by an autonomous process, with a published behavior specification. Unblocks NPCs, bots, and AI participants.

---

*This document is a record of ideas, not commitments. The protocol does what it does today. Everything here is contingent on someone deciding to build it.*
