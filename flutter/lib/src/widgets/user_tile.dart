import 'package:flutter/material.dart';
import '../rust/api/client.dart' as ffi;

/// A single row in the online users list.
class UserTile extends StatelessWidget {
  final ffi.NieUserEntry user;
  final String myPubId;

  const UserTile({super.key, required this.user, required this.myPubId});

  @override
  Widget build(BuildContext context) {
    final isMe = user.pubId == myPubId;
    final display = user.nickname?.isNotEmpty == true
        ? user.nickname!
        : user.pubId.substring(0, 12);

    return ListTile(
      dense: true,
      leading: CircleAvatar(
        radius: 16,
        backgroundColor: isMe
            ? Theme.of(context).colorScheme.primary
            : Theme.of(context).colorScheme.surfaceVariant,
        child: Text(
          display.substring(0, 1).toUpperCase(),
          style: TextStyle(
            fontSize: 12,
            color: isMe
                ? Theme.of(context).colorScheme.onPrimary
                : Theme.of(context).colorScheme.onSurfaceVariant,
          ),
        ),
      ),
      title: Text(
        display,
        style: const TextStyle(fontFamily: 'monospace', fontSize: 13),
      ),
      subtitle: Text(
        isMe ? 'you' : 'seq ${user.sequence}',
        style: const TextStyle(fontSize: 11),
      ),
      trailing: const Icon(Icons.circle, size: 8, color: Colors.green),
    );
  }
}
