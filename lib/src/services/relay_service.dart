import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';
import 'package:flutter/foundation.dart';
import 'package:web_socket_channel/web_socket_channel.dart';

// ---- Data classes -------------------------------------------------------

class UserEntry {
  final String pubId;
  final String? nickname;
  final int sequence;

  const UserEntry({
    required this.pubId,
    this.nickname,
    required this.sequence,
  });
}

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

// ---- Payload helpers (mirrors Rust messages::pad / messages::unpad) ------

const _buckets = [256, 512, 1024, 4096, 65536];

Uint8List _pad(List<int> plaintext) {
  final needed = 4 + plaintext.length;
  final bucket = _buckets.firstWhere(
    (b) => b >= needed,
    orElse: () => throw StateError('payload too large: ${plaintext.length} bytes'),
  );
  final out = Uint8List(bucket);
  final len = plaintext.length;
  out[0] = len & 0xff;
  out[1] = (len >> 8) & 0xff;
  out[2] = (len >> 16) & 0xff;
  out[3] = (len >> 24) & 0xff;
  out.setRange(4, 4 + plaintext.length, plaintext);
  return out;
}

List<int>? _unpad(List<int> padded) {
  if (padded.length < 4) return null;
  final len = padded[0] | (padded[1] << 8) | (padded[2] << 16) | (padded[3] << 24);
  if (4 + len > padded.length) return null;
  return padded.sublist(4, 4 + len);
}

// ---- RelayService --------------------------------------------------------

class RelayService extends ChangeNotifier {
  WebSocketChannel? _channel;
  StreamSubscription<dynamic>? _sub;
  String? _pubId;
  bool _connected = false;
  bool _reconnecting = false;
  bool _authFailed = false;
  String? _error;
  int _rpcId = 0;

  SimpleKeyPair? _keyPair;
  String? _relayUrl;
  Timer? _reconnectTimer;
  int _reconnectDelaySecs = 2;

  final List<ChatMessage> _messages = [];
  final List<UserEntry> _onlineUsers = [];
  final Set<String> _typingUsers = {};
  final Map<String, Timer> _typingTimers = {};

  bool get connected => _connected;
  bool get reconnecting => _reconnecting;
  String? get error => _error;
  String? get pubId => _pubId;

  List<ChatMessage> get messages => List.unmodifiable(_messages);
  List<UserEntry> get onlineUsers => List.unmodifiable(_onlineUsers);
  Set<String> get typingUsers => Set.unmodifiable(_typingUsers);

  // ---- Connect / disconnect ----------------------------------------------

  Future<void> connect({
    required SimpleKeyPair keyPair,
    required String relayUrl,
  }) async {
    _keyPair = keyPair;
    _relayUrl = relayUrl;
    _error = null;
    _authFailed = false;

    final pub = await keyPair.extractPublicKey();
    final hash = crypto.sha256.convert(pub.bytes);
    _pubId = hash.bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

    await _doConnect();
  }

  Future<void> _doConnect() async {
    await _sub?.cancel();
    _sub = null;
    try {
      _channel = WebSocketChannel.connect(Uri.parse(_relayUrl!));
      await _channel!.ready;
      _sub = _channel!.stream.listen(
        _onData,
        onError: _onError,
        onDone: _onDone,
        cancelOnError: false,
      );
    } catch (e) {
      _error = e.toString();
      notifyListeners();
      _scheduleReconnect();
    }
  }

  void disconnect() {
    _reconnectTimer?.cancel();
    _reconnectTimer = null;
    _keyPair = null;
    _relayUrl = null;
    _sub?.cancel();
    _sub = null;
    _channel?.sink.close();
    _channel = null;
    _connected = false;
    _reconnecting = false;
    notifyListeners();
  }

  // ---- Sending -----------------------------------------------------------

  Future<void> sendMessage(String text) async {
    if (!_connected) return;
    final payload = _encodePayload({'type': 'chat', 'text': text});
    _sendRpc('send', {'payload': payload});
  }

  Future<void> sendWhisper(String toPubId, String text) async {
    if (!_connected) return;
    final payload = _encodePayload({'type': 'chat', 'text': text});
    _sendRpc('whisper', {'to': toPubId, 'payload': payload});
  }

  Future<void> setNickname(String nickname) async {
    if (!_connected) return;
    _sendRpc('set_nickname', {'nickname': nickname});
  }

  // ---- WebSocket event handlers ------------------------------------------

  void _onData(dynamic data) async {
    Map<String, dynamic> msg;
    try {
      msg = jsonDecode(data as String) as Map<String, dynamic>;
    } catch (_) {
      return;
    }

    if (!msg.containsKey('id')) {
      // Notification (no id field)
      final method = msg['method'] as String?;
      final params = msg['params'];
      final p = params is Map<String, dynamic> ? params : <String, dynamic>{};
      if (method == 'challenge') {
        await _handleChallenge(p);
      } else {
        _handleNotification(method, p);
      }
    } else if (msg.containsKey('result')) {
      // Successful response — first response after connect is auth success
      if (!_connected) {
        _connected = true;
        _reconnecting = false;
        _reconnectDelaySecs = 2;
        notifyListeners();
      }
    } else if (msg.containsKey('error')) {
      final errMap = msg['error'];
      // JSON-RPC error code -32001 = UNAUTHORIZED (auth rejected by relay).
      // Treat this as permanent — close the socket without scheduling reconnect.
      final errCode = errMap is Map ? (errMap['code'] as num?)?.toInt() : null;
      _error = errMap is Map ? errMap['message']?.toString() : errMap.toString();
      _connected = false;
      if (errCode == -32001) {
        _authFailed = true;
        _reconnecting = false;
        _sub?.cancel();
        _channel?.sink.close();
      }
      notifyListeners();
    }
  }

  Future<void> _handleChallenge(Map<String, dynamic> params) async {
    final nonce = params['nonce'] as String? ?? '';
    final nonceBytes = utf8.encode(nonce);
    final pub = await _keyPair!.extractPublicKey();
    final sig = await Ed25519().sign(nonceBytes, keyPair: _keyPair!);
    _sendRpc('authenticate', {
      'pub_key': base64.encode(pub.bytes),
      'signature': base64.encode(sig.bytes),
    });
  }

  void _handleNotification(String? method, Map<String, dynamic> params) {
    switch (method) {
      case 'deliver':
        final from = params['from'] as String? ?? '';
        final payloadB64 = params['payload'] as String? ?? '';
        _dispatchPayload(from: from, payloadB64: payloadB64, isWhisper: false);

      case 'whisper_deliver':
        final from = params['from'] as String? ?? '';
        final payloadB64 = params['payload'] as String? ?? '';
        _dispatchPayload(from: from, payloadB64: payloadB64, isWhisper: true);

      case 'user_joined':
        final pubId = params['pub_id'] as String? ?? '';
        final nickname = params['nickname'] as String?;
        final sequence = (params['sequence'] as num?)?.toInt() ?? 0;
        _onlineUsers
          ..add(UserEntry(pubId: pubId, nickname: nickname, sequence: sequence))
          ..sort((a, b) => a.sequence.compareTo(b.sequence));
        _messages.add(ChatMessage(
          from: 'system',
          text: '${_display(pubId, nickname)} joined',
          isSystem: true,
          timestamp: DateTime.now(),
        ));
        notifyListeners();

      case 'user_left':
        final pubId = params['pub_id'] as String? ?? '';
        final user = _onlineUsers.where((u) => u.pubId == pubId).firstOrNull;
        _onlineUsers.removeWhere((u) => u.pubId == pubId);
        _messages.add(ChatMessage(
          from: 'system',
          text: '${_display(pubId, user?.nickname)} left',
          isSystem: true,
          timestamp: DateTime.now(),
        ));
        notifyListeners();

      case 'directory_list':
        final online = (params['online'] as List<dynamic>?) ?? [];
        _onlineUsers
          ..clear()
          ..addAll(online.map((e) {
            final m = e as Map<String, dynamic>;
            return UserEntry(
              pubId: m['pub_id'] as String? ?? '',
              nickname: m['nickname'] as String?,
              sequence: (m['sequence'] as num?)?.toInt() ?? 0,
            );
          }))
          ..sort((a, b) => a.sequence.compareTo(b.sequence));
        notifyListeners();

      case 'user_nickname':
        final pubId = params['pub_id'] as String? ?? '';
        final nickname = params['nickname'] as String?;
        for (int i = 0; i < _onlineUsers.length; i++) {
          if (_onlineUsers[i].pubId == pubId) {
            _onlineUsers[i] = UserEntry(
              pubId: pubId,
              nickname: nickname,
              sequence: _onlineUsers[i].sequence,
            );
            break;
          }
        }
        notifyListeners();

      case 'typing_notify':
        final from = params['from'] as String? ?? '';
        final typing = params['typing'] as bool? ?? false;
        _setTyping(from, typing);
    }
  }

  void _setTyping(String pubId, bool typing) {
    _typingTimers[pubId]?.cancel();
    if (typing) {
      _typingUsers.add(pubId);
      // Auto-dismiss after 4 s in case the peer's "stop typing" is lost.
      _typingTimers[pubId] = Timer(const Duration(seconds: 4), () {
        _typingUsers.remove(pubId);
        _typingTimers.remove(pubId);
        notifyListeners();
      });
    } else {
      _typingUsers.remove(pubId);
      _typingTimers.remove(pubId);
    }
    notifyListeners();
  }

  void _dispatchPayload({
    required String from,
    required String payloadB64,
    required bool isWhisper,
  }) {
    try {
      final padded = base64.decode(payloadB64);
      final raw = _unpad(padded);
      if (raw == null) return;
      final clear = jsonDecode(utf8.decode(raw)) as Map<String, dynamic>;
      final type = clear['type'] as String?;
      if (type == 'chat') {
        final text = clear['text'] as String? ?? '';
        _messages.add(ChatMessage(
          from: from,
          text: text,
          isWhisper: isWhisper,
          timestamp: DateTime.now(),
        ));
        notifyListeners();
      }
    } catch (_) {
      // Encrypted or unknown payload — silently ignore.
    }
  }

  void _onError(Object error) {
    _connected = false;
    _scheduleReconnect();
  }

  void _onDone() {
    if (_connected || _reconnecting) {
      _connected = false;
      _scheduleReconnect();
    }
  }

  void _scheduleReconnect() {
    if (_keyPair == null || _relayUrl == null) return;
    if (_authFailed) return;
    _reconnecting = true;
    _messages.add(ChatMessage(
      from: 'system',
      text: 'Connection lost, reconnecting in ${_reconnectDelaySecs}s…',
      isSystem: true,
      timestamp: DateTime.now(),
    ));
    notifyListeners();
    _reconnectTimer?.cancel();
    _reconnectTimer = Timer(Duration(seconds: _reconnectDelaySecs), () async {
      _reconnectDelaySecs = (_reconnectDelaySecs * 2).clamp(2, 60);
      await _doConnect();
    });
  }

  // ---- Helpers -----------------------------------------------------------

  String _encodePayload(Map<String, dynamic> clearMessage) {
    final json = utf8.encode(jsonEncode(clearMessage));
    return base64.encode(_pad(json));
  }

  void _sendRpc(String method, Map<String, dynamic> params) {
    _channel?.sink.add(jsonEncode({
      'jsonrpc': '2.0',
      'id': ++_rpcId,
      'method': method,
      'params': params,
    }));
  }

  String _display(String pubId, String? nickname) {
    if (nickname != null && nickname.isNotEmpty) return nickname;
    return pubId.length >= 12 ? pubId.substring(0, 12) : pubId;
  }
}
