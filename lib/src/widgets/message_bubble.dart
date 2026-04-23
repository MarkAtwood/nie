import 'package:flutter/material.dart';
import '../services/relay_service.dart';

/// A single chat message bubble.
class MessageBubble extends StatelessWidget {
  final ChatMessage message;
  final bool isOwn;

  const MessageBubble({super.key, required this.message, required this.isOwn});

  @override
  Widget build(BuildContext context) {
    if (message.isSystem) {
      return Padding(
        padding: const EdgeInsets.symmetric(vertical: 4),
        child: Center(
          child: Text(
            message.text,
            style: Theme.of(context).textTheme.bodySmall?.copyWith(
                  color: Theme.of(context).colorScheme.outline,
                  fontStyle: FontStyle.italic,
                ),
          ),
        ),
      );
    }

    final scheme = Theme.of(context).colorScheme;
    final bgColor = isOwn ? scheme.primary : scheme.surfaceVariant;
    final fgColor = isOwn ? scheme.onPrimary : scheme.onSurfaceVariant;

    return Align(
      alignment: isOwn ? Alignment.centerRight : Alignment.centerLeft,
      child: Container(
        margin: EdgeInsets.only(
          left: isOwn ? 64 : 8,
          right: isOwn ? 8 : 64,
          top: 2,
          bottom: 2,
        ),
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        decoration: BoxDecoration(
          color: bgColor,
          borderRadius: BorderRadius.circular(12),
        ),
        child: Column(
          crossAxisAlignment:
              isOwn ? CrossAxisAlignment.end : CrossAxisAlignment.start,
          children: [
            if (!isOwn)
              Text(
                message.from.length > 12
                    ? '${message.from.substring(0, 12)}…'
                    : message.from,
                style: TextStyle(
                  fontSize: 11,
                  color: fgColor.withOpacity(0.7),
                  fontFamily: 'monospace',
                ),
              ),
            if (message.isWhisper)
              Text(
                '🤫 whisper',
                style: TextStyle(fontSize: 10, color: fgColor.withOpacity(0.6)),
              ),
            Text(message.text, style: TextStyle(color: fgColor)),
            const SizedBox(height: 2),
            Text(
              _formatTime(message.timestamp),
              style: TextStyle(
                fontSize: 10,
                color: fgColor.withValues(alpha: 0.55),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

String _formatTime(DateTime dt) {
  final h = dt.hour.toString().padLeft(2, '0');
  final m = dt.minute.toString().padLeft(2, '0');
  return '$h:$m';
}
