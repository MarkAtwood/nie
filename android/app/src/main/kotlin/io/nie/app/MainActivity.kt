package io.nie.app

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {

    // Held while waiting for onRequestPermissionsResult to fire so we can
    // unblock the Dart caller after the permission dialog is dismissed.
    // The grant outcome is not returned — the Dart side calls startService
    // regardless of whether POST_NOTIFICATIONS was granted or denied, so
    // result.success(null) is correct: the channel contract is void → void.
    private var pendingPermissionResult: MethodChannel.Result? = null

    override fun onDestroy() {
        // If the Activity is destroyed (rotation, system kill) while the
        // POST_NOTIFICATIONS dialog is showing, the Dart caller of
        // invokeMethod('requestNotificationPermission') would hang forever
        // because onRequestPermissionsResult never fires.  Sending an error
        // here unblocks it; BackgroundService._requestNotificationPermission
        // catches PlatformException and swallows it, so the foreground
        // service simply does not start for this session rather than hanging.
        pendingPermissionResult?.error(
            "ACTIVITY_DESTROYED",
            "Activity destroyed before permission dialog was dismissed",
            null,
        )
        pendingPermissionResult = null
        super.onDestroy()
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQUEST_CODE_POST_NOTIFICATIONS) {
            pendingPermissionResult?.success(null)
            pendingPermissionResult = null
        }
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "io.nie.app/background")
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "requestNotificationPermission" -> {
                        // On Android 13+ (API 33) POST_NOTIFICATIONS is a runtime permission.
                        // Block until the user answers the dialog so startService is only
                        // called after the permission state is resolved, avoiding a race
                        // where startForeground() runs before POST_NOTIFICATIONS is granted.
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                            if (ContextCompat.checkSelfPermission(
                                    this, Manifest.permission.POST_NOTIFICATIONS
                                ) == PackageManager.PERMISSION_GRANTED
                            ) {
                                // Already granted — unblock Dart immediately.
                                result.success(null)
                            } else {
                                // Store result; onRequestPermissionsResult will unblock Dart
                                // after the dialog is dismissed, regardless of grant outcome.
                                pendingPermissionResult = result
                                ActivityCompat.requestPermissions(
                                    this,
                                    arrayOf(Manifest.permission.POST_NOTIFICATIONS),
                                    REQUEST_CODE_POST_NOTIFICATIONS
                                )
                            }
                        } else {
                            // Pre-API 33: POST_NOTIFICATIONS not required.
                            result.success(null)
                        }
                    }
                    "startService" -> {
                        val intent = Intent(this, NieForegroundService::class.java)
                            .setAction(NieForegroundService.ACTION_START)
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                            startForegroundService(intent)
                        } else {
                            startService(intent)
                        }
                        result.success(null)
                    }
                    "stopService" -> {
                        startService(
                            Intent(this, NieForegroundService::class.java)
                                .setAction(NieForegroundService.ACTION_STOP)
                        )
                        result.success(null)
                    }
                    else -> result.notImplemented()
                }
            }
    }

    companion object {
        private const val REQUEST_CODE_POST_NOTIFICATIONS = 1001
    }
}
