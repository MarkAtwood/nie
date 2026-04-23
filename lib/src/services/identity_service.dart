import 'dart:convert';
import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';
import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Manages the local Ed25519 identity.
///
/// Identity = Ed25519 seed (32 bytes), stored as base64 in SharedPreferences.
/// pub_id   = hex(SHA-256(ed25519_verifying_key_bytes))  — matches the relay.
class IdentityService extends ChangeNotifier {
  static const _seedKey = 'nie_identity_seed';
  static const _relayUrlKey = 'nie_relay_url';
  static const _nicknameKey = 'nie_nickname';
  static const _defaultRelayUrl = '';

  SimpleKeyPair? _keyPair;
  String? _pubId;

  bool get hasIdentity => _keyPair != null;
  String? get pubId => _pubId;
  SimpleKeyPair? get keyPair => _keyPair;

  /// Load a previously stored identity. Returns false on first run.
  Future<bool> load() async {
    final prefs = await SharedPreferences.getInstance();
    final seedB64 = prefs.getString(_seedKey);
    if (seedB64 == null) return false;
    await _initFromSeed(base64.decode(seedB64));
    return true;
  }

  /// Generate a fresh identity and persist it.
  Future<void> generate() async {
    final kp = await Ed25519().newKeyPair();
    final seed = await kp.extractPrivateKeyBytes();
    await _initFromSeed(seed);
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_seedKey, base64.encode(seed));
    notifyListeners();
  }

  Future<void> _initFromSeed(List<int> seed) async {
    _keyPair = await Ed25519().newKeyPairFromSeed(seed);
    final pub = await _keyPair!.extractPublicKey();
    final hash = crypto.sha256.convert(pub.bytes);
    _pubId = hash.bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  Future<String> getRelayUrl() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString(_relayUrlKey) ?? _defaultRelayUrl;
  }

  Future<void> setRelayUrl(String url) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_relayUrlKey, url);
  }

  Future<String?> getNickname() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString(_nicknameKey);
  }

  Future<void> setNickname(String nick) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_nicknameKey, nick);
  }

  /// Returns the raw seed as a lowercase hex string for backup purposes.
  /// Returns null if no identity is loaded.
  Future<String?> getSeedHex() async {
    final prefs = await SharedPreferences.getInstance();
    final seedB64 = prefs.getString(_seedKey);
    if (seedB64 == null) return null;
    final bytes = base64.decode(seedB64);
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }
}
