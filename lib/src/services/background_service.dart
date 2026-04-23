import 'package:flutter/services.dart';

/// Platform channel wrapper for the Android foreground service.
///
/// The service shows a persistent "Relay connected" notification that prevents
/// Android from killing the process while the relay WebSocket is active.
/// On non-Android platforms this is a no-op.
class BackgroundService {
  static const _channel = MethodChannel('com.example.nie/background');

  /// Start the Android foreground service.  Safe to call on non-Android.
  static Future<void> start() async {
    try {
      await _channel.invokeMethod<void>('startService');
    } on PlatformException {
      // Background service is optional — silently ignore platform errors.
    } on MissingPluginException {
      // Running on non-Android (web, desktop, tests) — no-op.
    }
  }

  /// Stop the Android foreground service.  Safe to call on non-Android.
  static Future<void> stop() async {
    try {
      await _channel.invokeMethod<void>('stopService');
    } on PlatformException {
      // Ignore.
    } on MissingPluginException {
      // Ignore.
    }
  }
}
