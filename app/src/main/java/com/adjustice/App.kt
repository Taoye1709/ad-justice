package com.adjustice

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.os.Build

/**
 * AdJustice Application
 *
 * Sets up notification channels on launch. No telemetry, no analytics, no tracking.
 * This is a passive forensic tool — it doesn't phone home.
 */
class App : Application() {

    override fun onCreate() {
        super.onCreate()
        createNotificationChannels()
    }

    private fun createNotificationChannels() {
        // NotificationChannel requires API 26+ (Android 8.0)
        // On older Android (5.0-7.x), channels don't exist and are silently ignored
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return

        @Suppress("DEPRECATION")
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        // Channel 1: Foreground service notification (low importance, no sound)
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_SERVICE,
                getString(R.string.channel_service),
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "AdJustice background monitoring service"
                setShowBadge(false)
            }
        )

        // Channel 2: Detected event notification (high importance, with sound)
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_EVENT,
                getString(R.string.channel_event),
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Notifications when a potential hijacking event is captured"
                enableVibration(true)
            }
        )
    }

    companion object {
        const val CHANNEL_SERVICE = "adj_service"
        const val CHANNEL_EVENT = "adj_event"
    }
}
