import 'package:flutter/services.dart';

/// Platform channel wrapper for the Android foreground service.
///
/// The service shows a persistent notification that prevents Android from
/// killing the process while the relay WebSocket is active.
/// On non-Android platforms this is a no-op.
///
/// Inject via [RelayService] constructor so callers can substitute a no-op
/// implementation in tests without touching the platform channel.
class BackgroundService {
  static const _channel = MethodChannel('io.nie.app/background');

  // Tracks whether the Android foreground service is currently running so that
  // stop() does not send stopService to a never-started service.
  bool _running = false;

  /// Start the Android foreground service.  Safe to call on non-Android.
  Future<void> start() async {
    // Await the permission dialog so the POST_NOTIFICATIONS prompt (Android
    // 13+, API 33) appears before startService, giving the user context while
    // the app is in the foreground. Service starts regardless of grant or deny.
    await _requestNotificationPermission();
    try {
      await _channel.invokeMethod<void>('startService');
      _running = true;
    } on PlatformException catch (e) {
      // A PlatformException on Android means the service failed to start
      // (e.g. SecurityException, IllegalStateException). The relay will run
      // but Android may kill the process when backgrounded.
      assert(() {
        // ignore: avoid_print
        print('BackgroundService.start failed: $e');
        return true;
      }());
    } on MissingPluginException {
      // Running on non-Android (web, desktop, tests) — no-op.
    }
  }

  Future<void> _requestNotificationPermission() async {
    try {
      await _channel.invokeMethod<void>('requestNotificationPermission');
    } on PlatformException {
      // Non-critical — proceed without permission prompt.
    } on MissingPluginException {
      // Non-Android — no-op.
    }
  }

  /// Stop the Android foreground service.  Safe to call on non-Android.
  Future<void> stop() async {
    if (!_running) return;
    _running = false;
    try {
      await _channel.invokeMethod<void>('stopService');
    } on PlatformException {
      // Ignore.
    } on MissingPluginException {
      // Ignore.
    }
  }
}
