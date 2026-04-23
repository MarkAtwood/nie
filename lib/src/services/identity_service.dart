import 'dart:io';
import 'package:flutter/services.dart' show PathProviderException;
import 'package:path_provider/path_provider.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../rust/api/identity.dart' as ffi;

/// Manages the local identity secret.
///
/// The raw 64-byte secret is stored in the app's private files directory
/// (Android: `context.filesDir`), protected by the OS sandbox.  The secret
/// is never written to SharedPreferences or any cloud-synced store.
class IdentityService {
  static const _relayUrlKey = 'relay_url';
  static const _nicknameKey = 'nickname';
  static const _defaultRelayUrl = 'wss://relay.example.com/ws';

  String? _pubId;
  String? _secretB64;

  String get pubId => _pubId ?? '(not connected)';

  /// Returns true if an identity exists on disk.
  Future<bool> hasIdentity() async {
    final path = await _identityPath();
    return File(path).existsSync();
  }

  /// Generate a new identity and save it to disk.
  ///
  /// Throws if the file cannot be written.
  Future<void> generateAndSave() async {
    final secret = ffi.generateIdentity();
    final path = await _identityPath();
    await ffi.saveIdentityToFile(path: path, secretB64: secret);
    _secretB64 = secret;
    _pubId = ffi.pubIdFromSecret(secretB64: secret);
  }

  /// Load the stored identity from disk.  Returns false if no identity exists.
  Future<bool> load() async {
    final path = await _identityPath();
    final secret = await ffi.loadIdentityFromFile(path: path);
    if (secret == null) return false;
    _secretB64 = secret;
    _pubId = ffi.pubIdFromSecret(secretB64: secret);
    return true;
  }

  /// The base64-encoded 64-byte secret.  Null before `load()` or `generateAndSave()`.
  String? get secretB64 => _secretB64;

  // ---------------------------------------------------------------------------
  // Preferences (relay URL, nickname)
  // ---------------------------------------------------------------------------

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

  // ---------------------------------------------------------------------------
  // Internal
  // ---------------------------------------------------------------------------

  Future<String> _identityPath() async {
    final dir = await getApplicationSupportDirectory();
    return '${dir.path}/nie_identity.bin';
  }
}
