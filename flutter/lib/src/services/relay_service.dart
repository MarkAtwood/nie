import 'package:flutter/foundation.dart';
import '../rust/api/client.dart' as ffi;

/// A received chat message, whisper, or system event.
class ChatMessage {
  final String from;
  final String text;
  final bool isWhisper;
  final bool isSystem;
  final DateTime timestamp;

  const ChatMessage({
    required this.from,
    required this.text,
    this.isWhisper = false,
    this.isSystem = false,
    required this.timestamp,
  });
}

/// Manages the relay WebSocket connection and message history.
///
/// Extends `ChangeNotifier` so widgets can rebuild on state changes via `Provider`.
class RelayService extends ChangeNotifier {
  ffi.NieClient? _client;
  String? _pubId;
  bool _connected = false;
  bool _reconnecting = false;
  String? _error;

  final List<ChatMessage> _messages = [];
  final List<ffi.NieUserEntry> _onlineUsers = [];

  // ---------------------------------------------------------------------------
  // Read-only state
  // ---------------------------------------------------------------------------

  bool get connected => _connected;
  bool get reconnecting => _reconnecting;
  String? get error => _error;
  String? get pubId => _pubId;

  List<ChatMessage> get messages => List.unmodifiable(_messages);
  List<ffi.NieUserEntry> get onlineUsers => List.unmodifiable(_onlineUsers);

  // ---------------------------------------------------------------------------
  // Connect / disconnect
  // ---------------------------------------------------------------------------

  /// Connect to the relay.
  ///
  /// `secretB64`: base64-encoded 64-byte identity secret.
  /// `relayUrl`: WebSocket URL.
  Future<void> connect({
    required String secretB64,
    required String relayUrl,
  }) async {
    _error = null;
    try {
      _client = await ffi.clientConnect(
        relayUrl: relayUrl,
        secretB64: secretB64,
        acceptInvalidCerts: false,
      );
      _pubId = ffi.clientPubId(client: _client!);
      _connected = true;
      _reconnecting = false;
      notifyListeners();
      _startEventLoop();
    } catch (e) {
      _error = e.toString();
      _connected = false;
      notifyListeners();
    }
  }

  /// Disconnect from the relay and clear the client handle.
  void disconnect() {
    if (_client != null) {
      ffi.clientDisconnect(client: _client!);
      _client = null;
    }
    _connected = false;
    _reconnecting = false;
    notifyListeners();
  }

  // ---------------------------------------------------------------------------
  // Sending
  // ---------------------------------------------------------------------------

  Future<void> sendMessage(String text) async {
    if (_client == null) return;
    await ffi.clientSendMessage(client: _client!, text: text);
  }

  Future<void> sendWhisper(String toPubId, String text) async {
    if (_client == null) return;
    await ffi.clientSendWhisper(client: _client!, to: toPubId, text: text);
  }

  Future<void> setNickname(String nickname) async {
    if (_client == null) return;
    await ffi.clientSetNickname(client: _client!, nickname: nickname);
  }

  // ---------------------------------------------------------------------------
  // Event loop
  // ---------------------------------------------------------------------------

  void _startEventLoop() {
    _eventLoop();
  }

  Future<void> _eventLoop() async {
    final client = _client;
    if (client == null) return;

    while (true) {
      final event = await ffi.clientNextEvent(client: client);
      if (event == null) {
        // Channel closed — client was disconnected.
        _connected = false;
        _reconnecting = false;
        notifyListeners();
        return;
      }
      _handleEvent(event);
    }
  }

  void _handleEvent(ffi.NieEvent event) {
    switch (event) {
      case ffi.NieEvent_MessageReceived(:final from, :final text):
        _messages.add(ChatMessage(
          from: from,
          text: text,
          timestamp: DateTime.now(),
        ));
        notifyListeners();

      case ffi.NieEvent_WhisperReceived(:final from, :final text):
        _messages.add(ChatMessage(
          from: from,
          text: text,
          isWhisper: true,
          timestamp: DateTime.now(),
        ));
        notifyListeners();

      case ffi.NieEvent_UserJoined(:final pubId, :final nickname, :final sequence):
        _onlineUsers.add(ffi.NieUserEntry(
          pubId: pubId,
          nickname: nickname,
          sequence: sequence,
        ));
        _onlineUsers.sort((a, b) => a.sequence.compareTo(b.sequence));
        _messages.add(ChatMessage(
          from: 'system',
          text: '${_display(pubId, nickname)} joined',
          isSystem: true,
          timestamp: DateTime.now(),
        ));
        notifyListeners();

      case ffi.NieEvent_UserLeft(:final pubId):
        final user = _onlineUsers.where((u) => u.pubId == pubId).firstOrNull;
        _onlineUsers.removeWhere((u) => u.pubId == pubId);
        _messages.add(ChatMessage(
          from: 'system',
          text: '${_display(pubId, user?.nickname)} left',
          isSystem: true,
          timestamp: DateTime.now(),
        ));
        notifyListeners();

      case ffi.NieEvent_DirectoryUpdated(:final online):
        _onlineUsers
          ..clear()
          ..addAll(online)
          ..sort((a, b) => a.sequence.compareTo(b.sequence));
        notifyListeners();

      case ffi.NieEvent_UserNickname(:final pubId, :final nickname):
        for (final u in _onlineUsers) {
          if (u.pubId == pubId) {
            _onlineUsers[_onlineUsers.indexOf(u)] = ffi.NieUserEntry(
              pubId: u.pubId,
              nickname: nickname,
              sequence: u.sequence,
            );
            break;
          }
        }
        notifyListeners();

      case ffi.NieEvent_Reconnecting(:final delaySecs):
        _reconnecting = true;
        _connected = false;
        _messages.add(ChatMessage(
          from: 'system',
          text: 'Connection lost, reconnecting in ${delaySecs}s…',
          isSystem: true,
          timestamp: DateTime.now(),
        ));
        notifyListeners();

      case ffi.NieEvent_Reconnected():
        _connected = true;
        _reconnecting = false;
        _messages.add(ChatMessage(
          from: 'system',
          text: 'Reconnected.',
          isSystem: true,
          timestamp: DateTime.now(),
        ));
        notifyListeners();
    }
  }

  String _display(String pubId, String? nickname) {
    if (nickname != null && nickname.isNotEmpty) return nickname;
    return pubId.substring(0, 12);
  }
}
