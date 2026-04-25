// MLS broadcast group for nie (Phase 1).
//
// Architecture: single MLS group "nie-room" shared by all connected users.
// The "admin" (first user in DirectoryList.online) is responsible for:
//   - creating the group when alone
//   - committing Add for each new joiner (UserJoined event)
//   - committing Remove when a member leaves (UserLeft event)
//
// Non-admin members:
//   - receive a Welcome whisper from the admin and join via new_from_welcome
//   - process incoming Commits (add/remove) to stay in sync
//   - encrypt/decrypt application messages with the current group epoch key
//
// Group state is ephemeral (in-memory). Each connect session starts fresh.
// The admin sends a new Welcome every time a user joins. Persistent ratchet
// state is Phase 2.
//
// Ciphersuite: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (RFC 9420 MTI)
// use_ratchet_tree_extension: true — tree embedded in Welcome, relay stays blind

use std::collections::HashMap;

use anyhow::Result;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use sha2::{Digest, Sha256};
use tls_codec::{DeserializeBytes, Serialize as TlsSerialize};
use x25519_dalek;

/// Fixed group ID for the single broadcast room.
const GROUP_ID: &[u8] = b"nie-room";

/// Ciphersuite used throughout.
const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

fn group_create_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .padding_size(100)
        .build()
}

fn group_join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .padding_size(100)
        .build()
}

/// Per-session MLS client. One instance per `chat` invocation.
/// Supports multiple simultaneous MLS groups, keyed by group ID bytes.
pub struct MlsClient {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential_with_key: CredentialWithKey,
    groups: HashMap<Vec<u8>, MlsGroup>,
}

impl MlsClient {
    /// Create a new MLS client identified by `pub_id`.
    /// Generates a fresh signing key for this session.
    pub fn new(pub_id: &str) -> Result<Self> {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())?;
        signer.store(provider.storage())?;

        let credential = BasicCredential::new(pub_id.as_bytes().to_vec());
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.to_public_vec().into(),
        };

        Ok(Self {
            provider,
            signer,
            credential_with_key,
            groups: HashMap::new(),
        })
    }

    /// Generate a fresh KeyPackage and return it as TLS-serialized bytes.
    /// Call on every connect; MLS key packages are single-use.
    pub fn key_package_bytes(&self) -> Result<Vec<u8>> {
        let (bytes, _) = self.key_package_and_device_id()?;
        Ok(bytes)
    }

    /// Generate a fresh KeyPackage and return `(kp_bytes, device_id)`.
    ///
    /// `kp_bytes` — TLS-serialized KeyPackage ready for `PublishKeyPackageParams.data`.
    /// `device_id` — lowercase hex SHA-256 of the KeyPackage HPKE init key bytes.
    ///               Stable for the lifetime of this KeyPackage; unique per device.
    pub fn key_package_and_device_id(&self) -> Result<(Vec<u8>, String)> {
        let kpb = KeyPackage::builder().build(
            CIPHERSUITE,
            &self.provider,
            &self.signer,
            self.credential_with_key.clone(),
        )?;
        let kp = kpb.key_package();
        let bytes = kp
            .tls_serialize_detached()
            .map_err(|e| anyhow::anyhow!("serialize key package: {e}"))?;
        let device_id = format!("{:x}", Sha256::digest(kp.hpke_init_key().as_slice()));
        Ok((bytes, device_id))
    }

    // ── Parameterized methods ────────────────────────────────────────────────

    /// Admin: create the MLS group with just ourselves, using the given group ID.
    pub fn create_group_with_id(&mut self, group_id: &[u8]) -> Result<()> {
        let group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &group_create_config(),
            GroupId::from_slice(group_id),
            self.credential_with_key.clone(),
        )?;
        self.groups.insert(group_id.to_vec(), group);
        Ok(())
    }

    /// Admin: add a new member to the specified group. Returns `(commit_bytes, welcome_bytes)`.
    ///
    /// `commit_bytes`: broadcast to all existing group members to advance their epoch.
    /// `welcome_bytes`: whisper to the new member only so they can join.
    pub fn add_member_to_group(
        &mut self,
        group_id: &[u8],
        key_package_bytes: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let group = self
            .groups
            .get_mut(group_id)
            .ok_or_else(|| anyhow::anyhow!("no such group"))?;

        let (kp_in, _) = KeyPackageIn::tls_deserialize_bytes(key_package_bytes)
            .map_err(|e| anyhow::anyhow!("deserialize key package: {e}"))?;
        let kp = kp_in
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| anyhow::anyhow!("validate key package: {e}"))?;

        let (commit_out, welcome_out, _group_info) =
            group.add_members(&self.provider, &self.signer, &[kp])?;

        group.merge_pending_commit(&self.provider)?;

        let commit_bytes = commit_out
            .tls_serialize_detached()
            .map_err(|e| anyhow::anyhow!("serialize commit: {e}"))?;

        // Serialize welcome_out as MlsMessage wire format (TlsSerialize).
        // The receiver deserializes as MlsMessageIn and extracts via extract().
        let welcome_bytes = welcome_out
            .tls_serialize_detached()
            .map_err(|e| anyhow::anyhow!("serialize welcome: {e}"))?;

        Ok((commit_bytes, welcome_bytes))
    }

    /// Admin: remove a member by their `pub_id` (the credential identity) from the specified group.
    /// Returns `commit_bytes` to broadcast to remaining members.
    pub fn remove_member_from_group(&mut self, group_id: &[u8], pub_id: &str) -> Result<Vec<u8>> {
        let group = self
            .groups
            .get_mut(group_id)
            .ok_or_else(|| anyhow::anyhow!("no such group"))?;

        let target_index = group
            .members()
            .find(|m| m.credential.serialized_content() == pub_id.as_bytes())
            .map(|m| m.index)
            .ok_or_else(|| anyhow::anyhow!("member {pub_id} not in group"))?;

        let (commit_out, _welcome_opt, _group_info) =
            group.remove_members(&self.provider, &self.signer, &[target_index])?;

        group.merge_pending_commit(&self.provider)?;

        commit_out
            .tls_serialize_detached()
            .map_err(|e| anyhow::anyhow!("serialize commit: {e}"))
    }

    /// Non-admin: join the specified group from a serialized Welcome.
    /// `group_id` is used as the key in the groups map.
    pub fn join_from_welcome_for_group(
        &mut self,
        group_id: &[u8],
        welcome_bytes: &[u8],
    ) -> Result<()> {
        // welcome_bytes are TLS-serialized MlsMessageOut (Welcome variant).
        // Deserialize as MlsMessageIn, then extract the Welcome body.
        let (msg_in, _) = MlsMessageIn::tls_deserialize_bytes(welcome_bytes)
            .map_err(|e| anyhow::anyhow!("deserialize welcome: {e}"))?;
        let welcome = match msg_in.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => anyhow::bail!("expected Welcome message"),
        };

        if self.groups.contains_key(group_id) {
            anyhow::bail!("group already exists; ignoring replayed Welcome");
        }

        let staged = StagedWelcome::new_from_welcome(
            &self.provider,
            &group_join_config(),
            welcome,
            None, // ratchet tree is embedded via use_ratchet_tree_extension(true)
        )?;
        let group = staged.into_group(&self.provider)?;
        self.groups.insert(group_id.to_vec(), group);
        Ok(())
    }

    /// Encrypt plaintext as an MLS application message for the specified group.
    /// Returns serialized bytes to broadcast.
    pub fn encrypt_for_group(&mut self, group_id: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let group = self
            .groups
            .get_mut(group_id)
            .ok_or_else(|| anyhow::anyhow!("no such group"))?;
        let msg = group.create_message(&self.provider, &self.signer, plaintext)?;
        msg.tls_serialize_detached()
            .map_err(|e| anyhow::anyhow!("serialize app msg: {e}"))
    }

    /// Process an incoming MLS message (Commit or ApplicationMessage) for the specified group.
    ///
    /// Returns `Some((plaintext, sender_pub_id))` for application messages, where
    /// `sender_pub_id` is the MLS-authenticated sender identity (their BasicCredential
    /// bytes, which are the hex pub_id). The sender identity is cryptographically
    /// bound to the MLS group state — it cannot be forged by a third party.
    ///
    /// Returns `None` for commits (state updated internally) and proposals.
    /// Returns an error if the message cannot be parsed or processed.
    pub fn process_for_group(
        &mut self,
        group_id: &[u8],
        bytes: &[u8],
    ) -> Result<Option<(Vec<u8>, String)>> {
        let (msg_in, _) = MlsMessageIn::tls_deserialize_bytes(bytes)
            .map_err(|e| anyhow::anyhow!("deserialize MLS message: {e}"))?;

        let protocol_msg = msg_in
            .try_into_protocol_message()
            .map_err(|e| anyhow::anyhow!("not a protocol message: {e}"))?;

        // Borrow group and provider separately; they are distinct struct fields.
        let group = self
            .groups
            .get_mut(group_id)
            .ok_or_else(|| anyhow::anyhow!("no such group"))?;
        let processed = group.process_message(&self.provider, protocol_msg)?;

        // Extract the MLS-authenticated sender identity before consuming the message.
        // processed.credential() returns the sender's BasicCredential, whose
        // serialized_content() bytes are the hex pub_id string set at MlsClient::new.
        let sender_pub_id = String::from_utf8(processed.credential().serialized_content().to_vec())
            .map_err(|_| anyhow::anyhow!("MLS sender credential is not valid UTF-8"))?;

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app_msg) => {
                Ok(Some((app_msg.into_bytes(), sender_pub_id)))
            }
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                group.merge_staged_commit(&self.provider, *staged_commit)?;
                Ok(None)
            }
            ProcessedMessageContent::ProposalMessage(staged_proposal) => {
                // Store so the next Commit can include it.
                // self.provider.storage() is a different field from self.group — allowed.
                group.store_pending_proposal(self.provider.storage(), *staged_proposal)?;
                Ok(None)
            }
            ProcessedMessageContent::ExternalJoinProposalMessage(_) => Ok(None),
        }
    }

    /// True if this client has an active MLS group with the given ID.
    pub fn has_group_id(&self, group_id: &[u8]) -> bool {
        self.groups.contains_key(group_id)
    }

    /// Current epoch for the specified group, or None if no such group is active.
    pub fn epoch_for_group(&self, group_id: &[u8]) -> Option<u64> {
        self.groups.get(group_id).map(|g| g.epoch().as_u64())
    }

    /// True if `pub_id` is already a member of the specified group.
    pub fn group_contains_id(&self, group_id: &[u8], pub_id: &str) -> bool {
        self.groups
            .get(group_id)
            .map(|g| {
                g.members()
                    .any(|m| m.credential.serialized_content() == pub_id.as_bytes())
            })
            .unwrap_or(false)
    }

    // ── Backward-compatible wrappers (delegate to GROUP_ID) ─────────────────

    /// Admin: create the MLS group with just ourselves.
    /// Call when we are the only connected user.
    pub fn create_group(&mut self) -> Result<()> {
        self.create_group_with_id(GROUP_ID)
    }

    /// Admin: add a new member. Returns `(commit_bytes, welcome_bytes)`.
    ///
    /// `commit_bytes`: broadcast to all existing group members to advance their epoch.
    /// `welcome_bytes`: whisper to the new member only so they can join.
    pub fn add_member(&mut self, key_package_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        self.add_member_to_group(GROUP_ID, key_package_bytes)
    }

    /// Admin: remove a member by their `pub_id` (the credential identity).
    /// Returns `commit_bytes` to broadcast to remaining members.
    pub fn remove_member(&mut self, pub_id: &str) -> Result<Vec<u8>> {
        self.remove_member_from_group(GROUP_ID, pub_id)
    }

    /// Non-admin: join the group from a serialized Welcome.
    pub fn join_from_welcome(&mut self, welcome_bytes: &[u8]) -> Result<()> {
        self.join_from_welcome_for_group(GROUP_ID, welcome_bytes)
    }

    /// Encrypt plaintext as an MLS application message.
    /// Returns serialized bytes to broadcast.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.encrypt_for_group(GROUP_ID, plaintext)
    }

    /// Process an incoming MLS message (Commit or ApplicationMessage).
    ///
    /// Returns `Some((plaintext, sender_pub_id))` for application messages.
    /// Returns `None` for commits (state updated internally) and proposals.
    /// Returns an error if the message cannot be parsed or processed.
    pub fn process_incoming(&mut self, bytes: &[u8]) -> Result<Option<(Vec<u8>, String)>> {
        self.process_for_group(GROUP_ID, bytes)
    }

    /// True if this client has an active MLS group.
    pub fn has_group(&self) -> bool {
        self.has_group_id(GROUP_ID)
    }

    /// Current group epoch, or None if no group is active.
    pub fn epoch(&self) -> Option<u64> {
        self.epoch_for_group(GROUP_ID)
    }

    /// True if `pub_id` is already a member of the current group.
    /// Used by the admin to skip GetKeyPackage for members that were added
    /// in a previous epoch (e.g. when a third party joins and triggers
    /// republication of key packages from existing members).
    pub fn group_contains(&self, pub_id: &str) -> bool {
        self.group_contains_id(GROUP_ID, pub_id)
    }

    /// Derive the room HPKE keypair from the current MLS epoch's exporter secret.
    ///
    /// Calls `export_secret("nie-room-hpke-key", b"", 32)` on the active group and
    /// converts the 32-byte output into an X25519 keypair. All group members at the
    /// same epoch derive the same secret key (and therefore the same public key).
    /// The keypair rotates automatically on every epoch change (add/remove commit).
    ///
    /// # Security model (accepted limitation)
    ///
    /// The shared secret means any group member can decrypt sealed-broadcast
    /// messages addressed to the room key — including those sent by other members.
    /// This is intentional: `sealed_broadcast` hides sender identity **from the relay**
    /// only, not from other group members. Any group member can identify any other
    /// member's messages by attempting HPKE decryption.
    ///
    /// This is **not** per-user sealed sender (where only the intended recipient
    /// can decrypt). For per-user sealed sender, each recipient needs their own
    /// individual HPKE keypair derived outside this shared-key mechanism.
    ///
    /// Returns `Err` if no group is active.
    pub fn room_hpke_keypair(&self) -> Result<(zeroize::Zeroizing<[u8; 32]>, [u8; 32])> {
        let group = self
            .groups
            .get(GROUP_ID)
            .ok_or_else(|| anyhow::anyhow!("no group"))?;

        let secret_bytes: [u8; 32] = group
            .export_secret(self.provider.crypto(), "nie-room-hpke-key", b"", 32)
            .map_err(|e| anyhow::anyhow!("export_secret failed: {e:?}"))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("export_secret returned wrong length"))?;

        let secret = x25519_dalek::StaticSecret::from(secret_bytes);
        let public = x25519_dalek::PublicKey::from(&secret);
        Ok((zeroize::Zeroizing::new(secret.to_bytes()), public.to_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two-party roundtrip: Alice creates the group, adds Bob, they exchange messages.
    ///
    /// Oracle: Alice encrypts a known plaintext, Bob decrypts it.
    /// The test vector is independent of the code under test: we know that
    /// "hello from alice" encrypted by Alice at epoch 1 must decrypt to
    /// exactly the same bytes at Bob, who is also at epoch 1 via the Welcome.
    #[test]
    fn two_party_roundtrip() {
        let mut alice = MlsClient::new("alice-pub-id").expect("alice");
        let mut bob = MlsClient::new("bob-pub-id").expect("bob");

        alice.create_group().expect("create_group");

        let bob_kp = bob.key_package_bytes().expect("bob kp");
        let (_, welcome_bytes) = alice.add_member(&bob_kp).expect("add_member");

        // Bob joins via Welcome (Welcome encodes epoch 1 directly — no commit needed).
        bob.join_from_welcome(&welcome_bytes)
            .expect("join_from_welcome");

        let plaintext = b"hello from alice";
        let ciphertext = alice.encrypt(plaintext).expect("encrypt");

        let (decrypted, sender) = bob
            .process_incoming(&ciphertext)
            .expect("process_incoming")
            .expect("application message");

        assert_eq!(decrypted, plaintext);
        // MLS sender must be Alice — this is the security property we are testing.
        // Oracle: credential bytes are the pub_id set at MlsClient::new.
        assert_eq!(
            sender, "alice-pub-id",
            "MLS-authenticated sender must match alice's pub_id credential"
        );
    }

    /// Bob → Alice direction.
    #[test]
    fn two_party_reverse_direction() {
        let mut alice = MlsClient::new("alice").expect("alice");
        let mut bob = MlsClient::new("bob").expect("bob");

        alice.create_group().expect("create_group");
        let (_, welcome) = alice
            .add_member(&bob.key_package_bytes().expect("kp"))
            .expect("add");
        bob.join_from_welcome(&welcome).expect("join");

        let plaintext = b"reply from bob";
        let ct = bob.encrypt(plaintext).expect("bob encrypt");
        let (plain, sender) = alice
            .process_incoming(&ct)
            .expect("alice process")
            .expect("app msg");
        assert_eq!(plain, plaintext);
        assert_eq!(
            sender, "bob",
            "MLS-authenticated sender must match bob's pub_id"
        );
    }

    /// Three-party: Alice creates, adds Bob, then adds Carol.
    /// Both Bob and Carol must decrypt a message from Alice at epoch 2.
    #[test]
    fn three_party_roundtrip() {
        let mut alice = MlsClient::new("alice").expect("alice");
        let mut bob = MlsClient::new("bob").expect("bob");
        let mut carol = MlsClient::new("carol").expect("carol");

        alice.create_group().expect("create");

        // Add Bob (epoch 0 → 1).
        let (commit1, welcome_bob) = alice
            .add_member(&bob.key_package_bytes().expect("bob kp"))
            .expect("add bob");
        bob.join_from_welcome(&welcome_bob).expect("bob join");

        // Add Carol (epoch 1 → 2). Bob must process commit2 to advance.
        let (commit2, welcome_carol) = alice
            .add_member(&carol.key_package_bytes().expect("carol kp"))
            .expect("add carol");
        carol.join_from_welcome(&welcome_carol).expect("carol join");

        // Bob processes Add-Carol commit to advance from epoch 1 → 2.
        bob.process_incoming(&commit2).expect("bob process commit2");

        // commit1 is not needed by anyone here (Bob joined via Welcome, Alice already merged).
        drop(commit1);

        let msg = b"group message at epoch 2";
        let ct = alice.encrypt(msg).expect("encrypt");

        let (bob_plain, _) = bob
            .process_incoming(&ct)
            .expect("bob process app msg")
            .expect("bob app msg");
        assert_eq!(bob_plain, msg);

        let (carol_plain, _) = carol
            .process_incoming(&ct)
            .expect("carol process app msg")
            .expect("carol app msg");
        assert_eq!(carol_plain, msg);
    }

    /// Repeated key_package_bytes() calls don't break join_from_welcome.
    ///
    /// Each call stores a new KeyPackageBundle under a unique KeyPackageRef
    /// (hash of the encoded key package). Entries accumulate and do NOT
    /// overwrite each other. join_from_welcome finds the right bundle by
    /// the ref embedded in the Welcome's EncryptedGroupSecrets, regardless
    /// of how many other bundles are in storage.
    ///
    /// Simulates the nie client republishing its KP on every UserJoined
    /// event while !mls_active — the admin uses the latest (5th) KP.
    #[test]
    fn repeated_kp_publish_join_from_welcome_uses_correct_key() {
        let mut alice = MlsClient::new("alice").expect("alice");
        let mut bob = MlsClient::new("bob").expect("bob");

        alice.create_group().expect("create_group");

        // Bob generates 5 key packages (simulating 4 UserJoined republications
        // + 1 initial publish).  The relay stores only the latest; the admin
        // will use that one.  All 5 init keys accumulate in Bob's provider.
        let mut latest_kp = Vec::new();
        for _ in 0..5 {
            latest_kp = bob.key_package_bytes().expect("kp");
        }

        // Admin uses the 5th (latest) KP — the one the relay actually stored.
        let (_, welcome) = alice.add_member(&latest_kp).expect("add_member");

        // join_from_welcome must find KP #5's init key among the 5 stored.
        bob.join_from_welcome(&welcome)
            .expect("join_from_welcome with accumulated kps");

        // Verify the session is functional.
        let ct = alice.encrypt(b"after multi-publish").expect("encrypt");
        let (pt, _) = bob
            .process_incoming(&ct)
            .expect("process")
            .expect("app msg");
        assert_eq!(pt, b"after multi-publish");
    }

    /// Non-creator member can act as admin after the creator disconnects.
    ///
    /// In nie, admin = online[0] (lowest connection_seq).  When the original
    /// creator leaves, the next peer becomes admin and must be able to call
    /// remove_member (for the departed creator) and add_member (for new joiners).
    /// MLS has no creator privilege — any group member can commit adds/removes.
    ///
    /// Sequence: Alice creates + adds Bob.  Alice "disconnects" (dropped).
    /// Bob (now admin) removes Alice, adds Carol.  Carol joins via Welcome.
    /// Bob and Carol exchange messages.
    #[test]
    fn non_creator_can_remove_and_add_after_creator_leaves() {
        let mut alice = MlsClient::new("alice").expect("alice");
        let mut bob = MlsClient::new("bob").expect("bob");
        let mut carol = MlsClient::new("carol").expect("carol");

        // Epoch 0 → 1: Alice creates, adds Bob.
        alice.create_group().expect("create");
        let (_, welcome_bob) = alice
            .add_member(&bob.key_package_bytes().expect("bob kp"))
            .expect("add bob");
        bob.join_from_welcome(&welcome_bob).expect("bob join");

        // Alice disconnects — Bob becomes admin.  Bob removes Alice (epoch 1 → 2).
        // No other current members need to process this commit (only Bob is left).
        let remove_commit = bob.remove_member("alice").expect("bob removes alice");
        drop(remove_commit); // no remaining peer to process it

        // Epoch 2 → 3: Bob adds Carol.
        let (_, welcome_carol) = bob
            .add_member(&carol.key_package_bytes().expect("carol kp"))
            .expect("bob adds carol");
        carol.join_from_welcome(&welcome_carol).expect("carol join");

        // Bob and Carol exchange messages at epoch 3.
        let ct_b = bob.encrypt(b"hi carol").expect("bob encrypt");
        let (pt_c, _) = carol
            .process_incoming(&ct_b)
            .expect("carol process")
            .expect("app msg");
        assert_eq!(pt_c, b"hi carol");

        let ct_c = carol.encrypt(b"hi bob").expect("carol encrypt");
        let (pt_b, _) = bob
            .process_incoming(&ct_c)
            .expect("bob process")
            .expect("app msg");
        assert_eq!(pt_b, b"hi bob");
    }

    /// Re-adding the same pub_id after removal — the full reconnect cycle.
    ///
    /// Scenario: Alice creates + adds Bob. Bob "disconnects": Alice removes him.
    /// Bob "reconnects": fresh MlsClient (new provider, new signing key, same pub_id).
    /// Alice re-adds new-Bob using his new key package. New-Bob joins via Welcome.
    ///
    /// This is the exact sequence that fires in nie when a Welcome whisper fails:
    ///   1. Admin calls add_member → Commit broadcast → Welcome whisper fails
    ///   2. Peer disconnects → UserLeft → admin calls remove_member
    ///   3. Peer reconnects → new MlsClient → PublishKeyPackage → KeyPackageReady
    ///   4. Admin checks group_contains(peer) → false (was removed) → re-adds
    ///
    /// The oracle is that Alice and new-Bob can exchange messages at the re-add epoch.
    /// If the remove did not clear group_contains the re-add would be blocked and
    /// this test would fail in step 4.
    #[test]
    fn remove_and_readd_same_member_via_fresh_client() {
        let mut alice = MlsClient::new("alice").expect("alice");
        let mut bob_v1 = MlsClient::new("bob").expect("bob v1");

        // Epoch 0 → 1: Alice creates + adds Bob v1.
        alice.create_group().expect("create");
        let (_, welcome_v1) = alice
            .add_member(&bob_v1.key_package_bytes().expect("bob v1 kp"))
            .expect("add bob v1");
        bob_v1.join_from_welcome(&welcome_v1).expect("bob v1 join");

        assert!(
            alice.group_contains("bob"),
            "bob must be in group after add"
        );

        // Bob "disconnects": Alice removes him (epoch 1 → 2).
        let _remove_commit = alice.remove_member("bob").expect("remove bob");
        // No other member to process the commit; alice already merged it.

        assert!(
            !alice.group_contains("bob"),
            "bob must not be in group after removal"
        );

        // Bob "reconnects": fresh MlsClient (new provider, new signing key).
        // Same credential pub_id "bob" — same identity, different MLS leaf key.
        let mut bob_v2 = MlsClient::new("bob").expect("bob v2");

        // Epoch 2 → 3: Alice re-adds Bob with his new key package.
        let (_, welcome_v2) = alice
            .add_member(&bob_v2.key_package_bytes().expect("bob v2 kp"))
            .expect("re-add bob v2");
        bob_v2.join_from_welcome(&welcome_v2).expect("bob v2 join");

        // Both directions must work at epoch 3.
        let ct = alice.encrypt(b"back again bob").expect("encrypt");
        let (pt, _) = bob_v2
            .process_incoming(&ct)
            .expect("process")
            .expect("app msg");
        assert_eq!(pt, b"back again bob");

        let ct2 = bob_v2.encrypt(b"yes i'm back").expect("bob v2 encrypt");
        let (pt2, _) = alice
            .process_incoming(&ct2)
            .expect("alice process")
            .expect("app msg");
        assert_eq!(pt2, b"yes i'm back");
    }

    /// A member who was added via Commit (group state updated) but never received
    /// a Welcome cannot decrypt subsequent messages.
    ///
    /// This is the "half-added" state caused by a failed Welcome whisper delivery.
    /// The test verifies that process_incoming() returns Err rather than silently
    /// producing garbage plaintext — the MLS state machine precondition is enforced.
    ///
    /// Oracle: process_incoming() on a client with self.group = None must return
    /// Err("no group"). This is independent of the message content and follows
    /// from the group membership check inside process_incoming.
    #[test]
    fn member_without_welcome_cannot_decrypt() {
        let mut alice = MlsClient::new("alice").expect("alice");
        let mut bob = MlsClient::new("bob").expect("bob");

        alice.create_group().expect("create");

        // Admin adds Bob: Commit broadcast (all existing members advance epoch).
        // Welcome deliberately NOT delivered to Bob — simulates failed whisper.
        let (commit, _welcome) = alice
            .add_member(&bob.key_package_bytes().expect("kp"))
            .expect("add");
        drop(_welcome); // Bob never calls join_from_welcome.

        assert!(
            !bob.has_group(),
            "bob must not have a group without join_from_welcome"
        );

        // Bob tries to process the commit without group state.
        let commit_result = bob.process_incoming(&commit);
        assert!(
            commit_result.is_err(),
            "processing a commit without having joined must return Err, not Ok"
        );

        // Alice sends a message at the new epoch.
        let ct = alice.encrypt(b"secret").expect("encrypt");

        // Bob tries to decrypt without group state.
        let decrypt_result = bob.process_incoming(&ct);
        assert!(
            decrypt_result.is_err(),
            "decrypting a message without having joined must return Err, \
             not produce garbage plaintext"
        );
    }

    /// group_contains() returns false after removal, enabling the re-add path.
    ///
    /// commands.rs uses `!mls.group_contains(&ready_id)` as the gate before
    /// calling add_member. If group_contains returned true after removal, the
    /// re-add cycle would be silently blocked and the reconnected peer could
    /// never rejoin the group without the admin also reconnecting.
    #[test]
    fn group_contains_false_after_removal() {
        let mut alice = MlsClient::new("alice").expect("alice");
        let mut bob = MlsClient::new("bob").expect("bob");

        alice.create_group().expect("create");
        let (_, welcome) = alice
            .add_member(&bob.key_package_bytes().expect("kp"))
            .expect("add");
        bob.join_from_welcome(&welcome).expect("join");

        assert!(
            alice.group_contains("bob"),
            "bob must be in group after add"
        );

        let _commit = alice.remove_member("bob").expect("remove");

        assert!(
            !alice.group_contains("bob"),
            "group_contains must return false after removal — \
             returning true here would permanently block re-add in the reconnect cycle"
        );
    }

    /// Admin remove: Alice removes Bob, Carol still decrypts Alice's message.
    #[test]
    fn remove_member() {
        let mut alice = MlsClient::new("alice").expect("alice");
        let mut bob = MlsClient::new("bob").expect("bob");
        let mut carol = MlsClient::new("carol").expect("carol");

        alice.create_group().expect("create");
        let (_, wb) = alice
            .add_member(&bob.key_package_bytes().expect("bkp"))
            .expect("add bob");
        bob.join_from_welcome(&wb).expect("bob join");

        let (commit2, wc) = alice
            .add_member(&carol.key_package_bytes().expect("ckp"))
            .expect("add carol");
        carol.join_from_welcome(&wc).expect("carol join");
        bob.process_incoming(&commit2)
            .expect("bob process add-carol");

        // Alice removes Bob (epoch 2 → 3).
        let remove_commit = alice.remove_member("bob").expect("remove bob");

        // Carol processes the remove commit to advance to epoch 3.
        carol
            .process_incoming(&remove_commit)
            .expect("carol process remove commit");

        // Alice encrypts at epoch 3; Carol decrypts.
        let msg = b"post-remove message";
        let ct = alice.encrypt(msg).expect("encrypt");
        let (plain, _) = carol
            .process_incoming(&ct)
            .expect("carol process app msg")
            .expect("carol app msg");
        assert_eq!(plain, msg);
    }

    /// room_hpke_keypair returns Err when no group exists.
    #[test]
    fn room_hpke_no_group_returns_err() {
        let client = MlsClient::new("test-id").unwrap();
        assert!(
            client.room_hpke_keypair().is_err(),
            "room_hpke_keypair must return Err when no group exists"
        );
    }

    /// Two members in the same MLS epoch must derive identical HPKE keypairs.
    ///
    /// Oracle: MLS export_secret is deterministic for all group members at the
    /// same epoch. Alice and Bob derive independently and we compare results.
    /// This is a cross-client oracle, not a self-oracle.
    #[test]
    fn room_hpke_two_members_same_epoch_same_key() {
        let mut alice = MlsClient::new("alice-hpke").expect("alice");
        let mut bob = MlsClient::new("bob-hpke").expect("bob");

        alice.create_group().expect("create_group");
        let bob_kp = bob.key_package_bytes().expect("bob kp");
        // add_member merges the pending commit internally; alice is at epoch 1.
        let (_, welcome_bytes) = alice.add_member(&bob_kp).expect("add_member");
        // Welcome encodes epoch 1 directly; bob joins at the same epoch.
        bob.join_from_welcome(&welcome_bytes)
            .expect("join_from_welcome");

        // Both derive the room HPKE key independently from the same MLS epoch.
        let (alice_sk, alice_pk) = alice.room_hpke_keypair().expect("alice room_hpke_keypair");
        let (bob_sk, bob_pk) = bob.room_hpke_keypair().expect("bob room_hpke_keypair");

        // CRITICAL: both must produce identical keypairs from the same MLS epoch.
        assert_eq!(
            alice_sk, bob_sk,
            "same epoch must yield same HPKE secret key"
        );
        assert_eq!(
            alice_pk, bob_pk,
            "same epoch must yield same HPKE public key"
        );
    }

    /// Adding a member triggers an epoch change, which must rotate the room HPKE key.
    ///
    /// Oracle: export_secret is epoch-keyed via the key schedule; distinct epochs
    /// produce cryptographically independent secrets with overwhelming probability.
    #[test]
    fn room_hpke_epoch_change_rotates_key() {
        let mut alice = MlsClient::new("alice-rot").expect("alice");
        let mut bob = MlsClient::new("bob-rot").expect("bob");

        alice.create_group().expect("create_group");
        let bob_kp = bob.key_package_bytes().expect("bob kp");
        let (_, welcome_bytes) = alice.add_member(&bob_kp).expect("add_member");
        bob.join_from_welcome(&welcome_bytes).expect("bob join");

        // Capture the room key at epoch 1.
        let (_, pk_epoch1) = alice.room_hpke_keypair().expect("epoch 1 keypair");

        // Add Carol to advance alice and bob to epoch 2.
        let carol = MlsClient::new("carol-rot").expect("carol");
        let carol_kp = carol.key_package_bytes().expect("carol kp");
        let (commit2, _welcome_carol) = alice.add_member(&carol_kp).expect("add carol");
        // Bob must process the commit to advance to epoch 2.
        bob.process_incoming(&commit2).expect("bob process commit2");

        // Capture room key at epoch 2.
        let (_, pk_epoch2) = alice.room_hpke_keypair().expect("epoch 2 keypair");

        // Keys MUST differ between epochs.
        assert_ne!(
            pk_epoch1, pk_epoch2,
            "different MLS epochs must yield different room HPKE keys"
        );
    }

    /// Parameterized API: two separate groups on the same client, independent epochs.
    ///
    /// Oracle: cross-client check — Alice and Bob are in group "alpha"; Alice and
    /// Carol are in group "beta". Messages in each group are only readable by
    /// members of that group.
    #[test]
    fn multi_group_independent_epochs() {
        let mut alice = MlsClient::new("alice").expect("alice");
        let mut bob = MlsClient::new("bob").expect("bob");
        let mut carol = MlsClient::new("carol").expect("carol");

        // Alice creates two groups.
        alice.create_group_with_id(b"alpha").expect("create alpha");
        alice.create_group_with_id(b"beta").expect("create beta");

        // Add Bob to alpha.
        let bob_kp = bob.key_package_bytes().expect("bob kp");
        let (_, welcome_bob) = alice
            .add_member_to_group(b"alpha", &bob_kp)
            .expect("add bob to alpha");
        bob.join_from_welcome_for_group(b"alpha", &welcome_bob)
            .expect("bob join alpha");

        // Add Carol to beta.
        let carol_kp = carol.key_package_bytes().expect("carol kp");
        let (_, welcome_carol) = alice
            .add_member_to_group(b"beta", &carol_kp)
            .expect("add carol to beta");
        carol
            .join_from_welcome_for_group(b"beta", &welcome_carol)
            .expect("carol join beta");

        // Alpha message: Alice → Bob.
        let ct_alpha = alice
            .encrypt_for_group(b"alpha", b"alpha message")
            .expect("encrypt alpha");
        let (pt_bob, _) = bob
            .process_for_group(b"alpha", &ct_alpha)
            .expect("bob process alpha")
            .expect("app msg");
        assert_eq!(pt_bob, b"alpha message");

        // Beta message: Alice → Carol.
        let ct_beta = alice
            .encrypt_for_group(b"beta", b"beta message")
            .expect("encrypt beta");
        let (pt_carol, _) = carol
            .process_for_group(b"beta", &ct_beta)
            .expect("carol process beta")
            .expect("app msg");
        assert_eq!(pt_carol, b"beta message");

        // has_group_id and epoch_for_group reflect correct per-group state.
        assert!(alice.has_group_id(b"alpha"));
        assert!(alice.has_group_id(b"beta"));
        assert!(!alice.has_group_id(b"gamma"));
        assert_eq!(alice.epoch_for_group(b"alpha"), Some(1));
        assert_eq!(alice.epoch_for_group(b"beta"), Some(1));
        assert_eq!(alice.epoch_for_group(b"gamma"), None);

        // group_contains_id reflects membership per group.
        assert!(alice.group_contains_id(b"alpha", "bob"));
        assert!(!alice.group_contains_id(b"alpha", "carol"));
        assert!(alice.group_contains_id(b"beta", "carol"));
        assert!(!alice.group_contains_id(b"beta", "bob"));
    }

    /// A replayed Welcome must be rejected, not silently overwrite existing group state.
    ///
    /// Oracle: group state (epoch, membership) must be unchanged after a replay
    /// attempt. The check is cross-state: we verify that Bob's epoch after
    /// join is 1, and that a second join_from_welcome on the same bytes returns Err.
    ///
    /// Before the fix, a replayed Welcome would call self.groups.insert(...) and
    /// silently overwrite the existing state, resetting the epoch and losing all
    /// subsequent epoch advances.
    #[test]
    fn welcome_replay_is_rejected() {
        let mut alice = MlsClient::new("alice").expect("alice");
        let mut bob = MlsClient::new("bob").expect("bob");

        alice.create_group().expect("create_group");
        let bob_kp = bob.key_package_bytes().expect("bob kp");
        let (_, welcome_bytes) = alice.add_member(&bob_kp).expect("add_member");

        // First join succeeds.
        bob.join_from_welcome(&welcome_bytes).expect("first join");
        assert_eq!(bob.epoch(), Some(1), "bob must be at epoch 1 after join");

        // Replaying the same Welcome must be rejected with an error.
        let replay_result = bob.join_from_welcome(&welcome_bytes);
        assert!(
            replay_result.is_err(),
            "replayed Welcome must return Err, not silently overwrite group state"
        );

        // Group state must be unchanged: still at epoch 1.
        assert_eq!(
            bob.epoch(),
            Some(1),
            "epoch must not be reset by a rejected Welcome replay"
        );
    }
}
