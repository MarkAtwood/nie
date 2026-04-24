import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../services/identity_service.dart';
import '../services/relay_service.dart';
import 'chat_screen.dart';

/// First-run screen: generate identity, configure relay URL, connect.
class SetupScreen extends StatefulWidget {
  const SetupScreen({super.key});

  @override
  State<SetupScreen> createState() => _SetupScreenState();
}

class _SetupScreenState extends State<SetupScreen> {
  final _relayController = TextEditingController();
  final _seedHexController = TextEditingController();
  String? _pubId;
  bool _generating = false;
  bool _connecting = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _loadPrefs();
  }

  @override
  void dispose() {
    _relayController.dispose();
    _seedHexController.dispose();
    super.dispose();
  }

  Future<void> _loadPrefs() async {
    final ids = context.read<IdentityService>();
    final url = await ids.getRelayUrl();
    setState(() => _relayController.text = url);
    final loaded = await ids.load();
    if (loaded) {
      setState(() => _pubId = ids.pubId);
    }
  }

  Future<void> _generate() async {
    // Warn if overwriting an existing identity.
    if (_pubId != null) {
      final confirm = await showDialog<bool>(
        context: context,
        builder: (ctx) => AlertDialog(
          title: const Text('Replace identity?'),
          content: const Text(
            'Generating a new identity will permanently replace the existing one. '
            'Make sure you have a backup of your current seed before proceeding.',
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('Cancel'),
            ),
            TextButton(
              onPressed: () => Navigator.pop(ctx, true),
              child: const Text('Replace'),
            ),
          ],
        ),
      );
      if (confirm != true) return;
    }

    setState(() {
      _generating = true;
      _error = null;
    });
    try {
      final ids = context.read<IdentityService>();
      await ids.generate();
      setState(() => _pubId = ids.pubId);
    } catch (e) {
      setState(() => _error = e.toString());
    } finally {
      setState(() => _generating = false);
    }
  }

  Future<void> _restore() async {
    await showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Restore from seed'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Text('Paste your 64-character hex seed:'),
            const SizedBox(height: 8),
            TextField(
              controller: _seedHexController,
              decoration: const InputDecoration(
                hintText: 'e.g. a1b2c3d4…',
                border: OutlineInputBorder(),
              ),
              maxLines: 2,
              style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
              autofocus: true,
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: const Text('Cancel'),
          ),
          TextButton(
            onPressed: () async {
              try {
                final ids = context.read<IdentityService>();
                await ids.importFromSeedHex(_seedHexController.text);
                if (ctx.mounted) Navigator.pop(ctx);
                if (!mounted) return;
                setState(() {
                  _pubId = ids.pubId;
                  _error = null;
                });
              } catch (e) {
                if (ctx.mounted) Navigator.pop(ctx);
                if (!mounted) return;
                setState(() => _error = e.toString());
              }
            },
            child: const Text('Restore'),
          ),
        ],
      ),
    );
  }

  Future<void> _connect() async {
    final ids = context.read<IdentityService>();
    final relay = context.read<RelayService>();

    if (ids.keyPair == null) {
      setState(() => _error = 'Generate an identity first.');
      return;
    }
    setState(() {
      _connecting = true;
      _error = null;
    });

    final relayUrl = _relayController.text.trim();
    await ids.setRelayUrl(relayUrl);
    await relay.connect(keyPair: ids.keyPair!, relayUrl: relayUrl);

    if (!mounted) return;
    if (relay.error != null) {
      setState(() {
        _error = relay.error;
        _connecting = false;
      });
    } else {
      Navigator.of(context).pushReplacement(
        MaterialPageRoute(builder: (_) => const ChatScreen()),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('nie — Setup')),
      body: Padding(
        padding: const EdgeInsets.all(24.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const Text(
              'nie (囁)',
              style: TextStyle(fontSize: 32, fontWeight: FontWeight.bold),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 8),
            const Text(
              'Encrypted relay chat. No accounts. No tracking.',
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 32),
            if (_pubId != null) ...[
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Theme.of(context).colorScheme.surfaceVariant,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text('Your identity', style: TextStyle(fontWeight: FontWeight.bold)),
                    const SizedBox(height: 4),
                    Text(
                      _pubId!,
                      style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 16),
            ],
            OutlinedButton(
              onPressed: _generating ? null : _generate,
              child: _generating
                  ? const SizedBox(
                      height: 20,
                      width: 20,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : Text(_pubId != null ? 'Regenerate Identity' : 'Generate Identity'),
            ),
            const SizedBox(height: 8),
            OutlinedButton.icon(
              onPressed: _restore,
              icon: const Icon(Icons.restore, size: 18),
              label: const Text('Restore from seed'),
            ),
            const SizedBox(height: 24),
            TextField(
              controller: _relayController,
              decoration: const InputDecoration(
                labelText: 'Relay URL',
                hintText: 'wss://relay.example.com/ws',
                border: OutlineInputBorder(),
              ),
              keyboardType: TextInputType.url,
            ),
            const SizedBox(height: 16),
            if (_error != null)
              Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: Text(
                  _error!,
                  style: TextStyle(color: Theme.of(context).colorScheme.error),
                ),
              ),
            FilledButton(
              onPressed: (_connecting || _pubId == null) ? null : _connect,
              child: _connecting
                  ? const SizedBox(
                      height: 20,
                      width: 20,
                      child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
                    )
                  : const Text('Connect'),
            ),
          ],
        ),
      ),
    );
  }
}
