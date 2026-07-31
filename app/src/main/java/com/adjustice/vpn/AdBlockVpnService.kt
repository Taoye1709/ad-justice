package com.adjustice.vpn

import android.app.Notification
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.adjustice.App
import com.adjustice.R
import com.adjustice.ui.MainActivity
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.atomic.AtomicLong

class AdBlockVpnService : VpnService() {

    private var pfd: ParcelFileDescriptor? = null
    @Volatile private var running = false
    private val eventIdGen = AtomicLong(0)

    private fun evidenceDir(): File = File(filesDir, "adj_evidence")

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.getBooleanExtra(KEY_STOP, false) == true) {
            shutdown()
            return START_NOT_STICKY
        }
        if (pfd != null) return START_STICKY

        try {
            pfd = establishVpn()
            if (pfd == null) {
                Log.w(TAG, "establishVpn returned null")
                shutdown()
                return START_NOT_STICKY
            }
            running = true
            isRunning = true
            startForeground(NOTIF_ID, createNotification())
            VpnKeepAlive.schedule(this)
            Thread(TunWorker(pfd!!), "adj-vpn-tun").start()
            Log.i(TAG, "VPN started")
        } catch (e: Exception) {
            Log.e(TAG, "VPN start failed", e)
            shutdown()
            return START_NOT_STICKY
        }
        return START_STICKY
    }

    override fun onDestroy() {
        shutdown()
        super.onDestroy()
    }

    override fun onRevoke() {
        shutdown()
        super.onRevoke()
    }

    private fun establishVpn(): ParcelFileDescriptor? {
        val builder = Builder()
            .setSession("AdJustice")
            .addAddress("10.61.249.1", 24)
            .addDnsServer("114.114.114.114")
            .addDnsServer("223.5.5.5")
            .addRoute("0.0.0.0", 0)
        builder.setMtu(1500)
        return builder.establish()
    }

    private fun shutdown() {
        running = false
        isRunning = false
        VpnKeepAlive.cancel(this)
        try { pfd?.close() } catch (_: Exception) {}
        pfd = null
        @Suppress("DEPRECATION")
        stopForeground(true)
        stopSelf()
    }

    private fun createNotification(): Notification {
        val openIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val piFlags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
            PendingIntent.FLAG_IMMUTABLE else 0
        val pi = PendingIntent.getActivity(this, 0, openIntent, piFlags)
        return NotificationCompat.Builder(this, App.CHANNEL_SERVICE)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentTitle(getString(R.string.vpn_notification_title))
            .setContentText(getString(R.string.vpn_notification_text))
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(pi)
            .build()
    }

    private inner class TunWorker(private val tunnel: ParcelFileDescriptor) : Runnable {
        override fun run() {
            val input = FileInputStream(tunnel.fileDescriptor)
            val output = FileOutputStream(tunnel.fileDescriptor)
            val detector = InjectionDetector()
            val packet = ByteArray(32768)
            try {
                while (running) {
                    val n = input.read(packet, 0, packet.size)
                    if (n <= 0) break

                    if (n >= 20 && (packet[0].toInt() and 0xF0) == 0x40) {
                        val ihl = (packet[0].toInt() and 0x0F) * 4
                        if (ihl >= 20 && n > ihl) {
                            val protocol = packet[9].toInt() and 0xFF
                            if (protocol == 6) {
                                val tcpHdrOff = ((packet[ihl + 12].toInt() and 0xF0) ushr 2)
                                val payloadOff = ihl + tcpHdrOff
                                if (payloadOff < n && payloadOff < n) {
                                    val tcpData = packet.copyOfRange(payloadOff, n)
                                    val result = detector.inspect(tcpData, tcpData.size)
                                    if (result.blocked) {
                                        val id = eventIdGen.incrementAndGet()
                                        Log.w(TAG, "Blocked #$id: ${result.matchType}=${result.matchValue}")
                                        val event = HijackEvent(
                                            id = id,
                                            timestamp = System.currentTimeMillis(),
                                            matchedType = result.matchType,
                                            matchedValue = result.matchValue,
                                            httpHeaders = result.headersPreview,
                                            destinationHost = "",
                                            destinationIp = ipv4ToString(packet, 16)
                                        )
                                        HijackEvent.logToFile(event, evidenceDir())
                                        continue
                                    }
                                }
                            }
                        }
                    }
                    output.write(packet, 0, n)
                }
            } catch (e: Exception) {
                if (running) Log.e(TAG, "TUN loop exit", e)
            } finally {
                try { input.close() } catch (_: Exception) {}
                try { output.close() } catch (_: Exception) {}
            }
        }
    }

    private fun ipv4ToString(p: ByteArray, off: Int): String {
        return "${p[off].toInt() and 0xFF}.${p[off+1].toInt() and 0xFF}.${p[off+2].toInt() and 0xFF}.${p[off+3].toInt() and 0xFF}"
    }

    companion object {
        const val KEY_STOP = "stopVpn"
        const val NOTIF_ID = 1777
        private const val TAG = "AdBlockVPN"

        @Volatile
        var isRunning = false
            private set

        fun start(context: Context) {
            context.startService(Intent(context, AdBlockVpnService::class.java))
        }

        fun stop(context: Context) {
            Intent(context, AdBlockVpnService::class.java).apply {
                putExtra(KEY_STOP, true)
                context.startService(this)
            }
        }
    }
}
