import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import '../services/identity_service.dart';
import '../services/relay_service.dart';
import '../widgets/message_bubble.dart';
import '../widgets/user_tile.dart';

/// Main chat screen: message list, input field, online users drawer.
class ChatScreen extends StatefulWidget {
  const ChatScreen({super.key});

  @override
  State<ChatScreen> createState() => _ChatScreenState();
}

class _ChatScreenState extends State<ChatScreen> {
  final _inputController = TextEditingController();
  final _scrollController = ScrollController();
  final _relayUrlController = TextEditingController();

  void _scrollToBottom() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scrollController.hasClients) {
        _scrollController.animateTo(
          _scrollController.position.maxScrollExtent,
          duration: const Duration(milliseconds: 200),
          curve: Curves.easeOut,
        );
      }
    });
  }

  Future<void> _send() async {
    final text = _inputController.text.trim();
    if (text.isEmpty) return;
    _inputController.clear();
    await context.read<RelayService>().sendMessage(text);
    _scrollToBottom();
  }

  Future<void> _showRelaySettings() async {
    final identity = context.read<IdentityService>();
    _relayUrlController.text = await identity.getRelayUrl();
    if (!mounted) return;
    await showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Relay URL'),
        content: TextField(
          controller: _relayUrlController,
          decoration: const InputDecoration(hintText: 'wss://relay.example.com/ws'),
          autofocus: true,
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () async {
              final url = _relayUrlController.text.trim();
              await identity.setRelayUrl(url);
              if (ctx.mounted) Navigator.pop(ctx);
              if (!mounted) return;
              final relay = context.read<RelayService>();
              relay.disconnect();
              final kp = identity.keyPair;
              if (kp != null && url.isNotEmpty) {
                await relay.connect(keyPair: kp, relayUrl: url);
              }
            },
            child: const Text('Save & reconnect'),
          ),
        ],
      ),
    );
  }

  Future<void> _showSeedBackup() async {
    final identity = context.read<IdentityService>();
    final seedHex = await identity.getSeedHex();
    if (!mounted) return;
    await showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Identity backup'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Store this seed somewhere safe. Anyone with it can impersonate you.',
              style: TextStyle(fontSize: 13),
            ),
            const SizedBox(height: 12),
            SelectableText(
              seedHex ?? '(no identity)',
              style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () {
              Clipboard.setData(ClipboardData(text: seedHex ?? ''));
              Navigator.pop(ctx);
            },
            child: const Text('Copy & close'),
          ),
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Close'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final relay = context.watch<RelayService>();
    final myPubId = relay.pubId ?? '';

    // Scroll to bottom when new messages arrive.
    if (relay.messages.isNotEmpty) _scrollToBottom();

    return Scaffold(
      appBar: AppBar(
        title: Row(
          children: [
            const Text('nie'),
            const SizedBox(width: 8),
            _ConnectionIndicator(
              connected: relay.connected,
              reconnecting: relay.reconnecting,
            ),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.settings_outlined),
            tooltip: 'Relay settings',
            onPressed: _showRelaySettings,
          ),
          Builder(
            builder: (ctx) => IconButton(
              icon: const Icon(Icons.people_outline),
              tooltip: 'Online users',
              onPressed: () => Scaffold.of(ctx).openEndDrawer(),
            ),
          ),
        ],
      ),
      endDrawer: Drawer(
        child: SafeArea(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Padding(
                padding: const EdgeInsets.all(16),
                child: Text(
                  'Online (${relay.onlineUsers.length})',
                  style: Theme.of(context).textTheme.titleMedium,
                ),
              ),
              const Divider(height: 1),
              Expanded(
                child: ListView.builder(
                  itemCount: relay.onlineUsers.length,
                  itemBuilder: (_, i) => UserTile(
                    user: relay.onlineUsers[i],
                    myPubId: myPubId,
                  ),
                ),
              ),
              const Divider(height: 1),
              ListTile(
                leading: const Icon(Icons.key_outlined),
                title: const Text('Backup identity'),
                onTap: () {
                  Navigator.pop(context);
                  _showSeedBackup();
                },
              ),
            ],
          ),
        ),
      ),
      body: Column(
        children: [
          Expanded(
            child: ListView.builder(
              controller: _scrollController,
              padding: const EdgeInsets.symmetric(vertical: 8),
              itemCount: relay.messages.length,
              itemBuilder: (_, i) {
                final msg = relay.messages[i];
                return MessageBubble(
                  message: msg,
                  isOwn: msg.from == myPubId,
                );
              },
            ),
          ),
          if (relay.typingUsers.isNotEmpty)
            Padding(
              padding: const EdgeInsets.only(left: 16, bottom: 4),
              child: Align(
                alignment: Alignment.centerLeft,
                child: Text(
                  '${_typingLabel(relay.typingUsers)} typing…',
                  style: Theme.of(context).textTheme.bodySmall?.copyWith(
                        fontStyle: FontStyle.italic,
                        color: Theme.of(context).colorScheme.outline,
                      ),
                ),
              ),
            ),
          const Divider(height: 1),
          _InputBar(controller: _inputController, onSend: _send),
        ],
      ),
    );
  }
}

String _typingLabel(Set<String> users) {
  final names = users.map((id) => id.length >= 8 ? id.substring(0, 8) : id).toList();
  if (names.length == 1) return names[0];
  if (names.length == 2) return '${names[0]} and ${names[1]}';
  return '${names[0]} and ${names.length - 1} others';
}

class _ConnectionIndicator extends StatelessWidget {
  final bool connected;
  final bool reconnecting;
  const _ConnectionIndicator({required this.connected, required this.reconnecting});

  @override
  Widget build(BuildContext context) {
    if (reconnecting) {
      return const SizedBox(
        width: 12,
        height: 12,
        child: CircularProgressIndicator(strokeWidth: 2),
      );
    }
    return Icon(
      connected ? Icons.cloud_done_outlined : Icons.cloud_off_outlined,
      size: 16,
      color: connected
          ? Theme.of(context).colorScheme.primary
          : Theme.of(context).colorScheme.error,
    );
  }
}

class _InputBar extends StatelessWidget {
  final TextEditingController controller;
  final VoidCallback onSend;
  const _InputBar({required this.controller, required this.onSend});

  @override
  Widget build(BuildContext context) {
    return SafeArea(
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
        child: Row(
          children: [
            Expanded(
              child: TextField(
                controller: controller,
                decoration: const InputDecoration(
                  hintText: 'Message…',
                  border: OutlineInputBorder(),
                  isDense: true,
                  contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                ),
                textInputAction: TextInputAction.send,
                onSubmitted: (_) => onSend(),
              ),
            ),
            const SizedBox(width: 8),
            IconButton.filled(
              icon: const Icon(Icons.send),
              onPressed: onSend,
            ),
          ],
        ),
      ),
    );
  }
}
