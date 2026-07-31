package com.adjustice.vpn

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build

class VpnKeepAlive : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (AdBlockVpnService.isRunning) return
        AdBlockVpnService.start(context)
    }

    companion object {
        private const val INTERVAL_MS = 15_000L

        fun schedule(context: Context) {
            val am = context.getSystemService(Context.ALARM_SERVICE) as AlarmManager
            val pi = pendingIntent(context)
            try { am.cancel(pi) } catch (_: Exception) {}
            am.setInexactRepeating(
                AlarmManager.RTC, System.currentTimeMillis() + INTERVAL_MS,
                INTERVAL_MS, pi
            )
        }

        fun cancel(context: Context) {
            try {
                (context.getSystemService(Context.ALARM_SERVICE) as AlarmManager)
                    .cancel(pendingIntent(context))
            } catch (_: Exception) {}
        }

        private fun pendingIntent(context: Context): PendingIntent {
            val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
                PendingIntent.FLAG_IMMUTABLE else 0
            return PendingIntent.getBroadcast(
                context, 0,
                Intent(context, VpnKeepAlive::class.java),
                flags
            )
        }
    }
}