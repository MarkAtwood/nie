package io.nie.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat

class NieForegroundService : Service() {

    companion object {
        const val CHANNEL_ID = "nie_relay_channel"
        const val NOTIFICATION_ID = 1
        const val ACTION_START = "io.nie.app.START"
        const val ACTION_STOP = "io.nie.app.STOP"
    }

    private var wakeLock: PowerManager.WakeLock? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        // Hold a partial wake lock so the CPU stays on during Doze mode.
        // Without this the OS can silently close the WebSocket while the screen
        // is off, leaving the relay "connected" in the UI while actually dead.
        // Released in onDestroy() so it's tied to the service lifetime.
        wakeLock = getSystemService(PowerManager::class.java)
            .newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "nie:RelayWakeLock")
            .also { it.acquire() }
    }

    override fun onDestroy() {
        wakeLock?.release()
        wakeLock = null
        super.onDestroy()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            // null intent: OS restarted the service after killing it (START_STICKY).
            // START_STICKY delivers null, not the last intent, so we must handle it
            // explicitly to avoid running as an unprovisioned background service.
            ACTION_START, null -> {
                // startForeground() throws SecurityException on Android 14+ if the
                // FOREGROUND_SERVICE_CONNECTED_DEVICE permission is missing, and on
                // Android 13+ if POST_NOTIFICATIONS was denied. Catch it so the app
                // doesn't crash — the service stops itself and the WebSocket in Dart
                // continues unaffected (the notification just won't appear).
                try {
                    startForeground(NOTIFICATION_ID, buildNotification())
                } catch (e: SecurityException) {
                    android.util.Log.w("NieForegroundService", "startForeground failed: ${e.message}")
                    stopSelf()
                }
            }
            ACTION_STOP -> {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                    stopForeground(STOP_FOREGROUND_REMOVE)
                } else {
                    @Suppress("DEPRECATION")
                    stopForeground(true)
                }
                stopSelf()
            }
        }
        // START_STICKY: if the OS kills this service under memory pressure it will
        // restart onStartCommand with a null intent (not ACTION_START), handled above.
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "nie relay",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Keeps the nie relay connection alive"
                setShowBadge(false)
            }
            getSystemService(NotificationManager::class.java)
                .createNotificationChannel(channel)
        }
    }

    private fun buildNotification(): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("nie")
            .setContentText("nie is running")
            .setSmallIcon(R.drawable.ic_notification)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }
}
