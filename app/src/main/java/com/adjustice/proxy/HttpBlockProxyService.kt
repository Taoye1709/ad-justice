package com.adjustice.proxy

import android.app.Notification
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.IBinder
import android.provider.Settings
import android.util.Log
import androidx.core.app.NotificationCompat
import com.adjustice.App
import com.adjustice.R
import com.adjustice.ui.MainActivity
import com.adjustice.vpn.HijackEvent
import com.adjustice.vpn.InjectionDetector
import com.adjustice.vpn.InspectionResult
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Local HTTP proxy that intercepts all plain-HTTP responses on the TV.
 *
 * The TV's global proxy is pointed at 127.0.0.1:PROXY_PORT. Every HTTP
 * response passes through here and is scanned by InjectionDetector. When a
 * hijacked response is found (bad redirect / injected HTML), the proxy
 * replaces it with an empty 200 response so the scam content never renders.
 *
 * HTTPS (CONNECT) traffic is tunneled unmodified — ISPs cannot inject HTTPS,
 * so there is nothing to block and we must not break secure connections.
 */
class HttpBlockProxyService : Service() {

    private var serverSocket: ServerSocket? = null
    private val running = AtomicBoolean(false)
    private val eventIdGen = AtomicLong(0)
    private val detector = InjectionDetector()

    private fun evidenceDir(): File = File(filesDir, "adj_evidence")

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.getBooleanExtra(KEY_STOP, false) == true) {
            stopProxy()
            return START_NOT_STICKY
        }
        if (serverSocket != null) return START_STICKY

        try {
            val sock = ServerSocket()
            sock.reuseAddress = true
            sock.bind(InetSocketAddress("127.0.0.1", PROXY_PORT))
            serverSocket = sock
            running.set(true)
            isRunning = true
            startForeground(NOTIF_ID, createNotification())
            Thread(::acceptLoop, "adj-proxy-accept").start()
            Log.i(TAG, "Proxy listening on 127.0.0.1:$PROXY_PORT")
        } catch (e: Exception) {
            Log.e(TAG, "Proxy start failed", e)
            stopProxy()
            return START_NOT_STICKY
        }
        return START_STICKY
    }

    override fun onDestroy() {
        stopProxy()
        super.onDestroy()
    }

    private fun stopProxy() {
        running.set(false)
        isRunning = false
        try { serverSocket?.close() } catch (_: Exception) {}
        serverSocket = null
        @Suppress("DEPRECATION")
        stopForeground(true)
        stopSelf()
    }

    private fun acceptLoop() {
        while (running.get()) {
            val client = try {
                serverSocket?.accept() ?: break
            } catch (e: Exception) {
                if (running.get()) Log.w(TAG, "accept failed", e)
                break
            }
            Thread({ handleClient(client) }, "adj-proxy-conn").start()
        }
    }

    private fun handleClient(client: Socket) {
        try {
            client.soTimeout = 30000
            val input = client.getInputStream()
            val output = client.getOutputStream()

            val requestHead = readHeaders(input)
            if (requestHead.isBlank()) {
                client.close()
                return
            }
            val firstLine = requestHead.lineSequence().firstOrNull() ?: ""
            val parts = firstLine.split(" ")
            if (parts.size < 3) {
                client.close()
                return
            }
            val method = parts[0]

            if (method == "CONNECT") {
                tunnelConnect(client, requestHead)
                return
            }

            val hostHeader = extractHost(requestHead) ?: run {
                client.close()
                return
            }
            val target = resolveTarget(hostHeader)
            if (target == null) {
                sendBlockedResponse(output)
                client.close()
                return
            }

            // Resolve the hostname via TCP DNS (immune to ISP UDP poisoning),
            // so we always connect to the real server, never an injected ad IP.
            val upstream = Socket()
            try {
                val targetAddr = DnsResolver.resolve(target.first)
                if (targetAddr == null || DnsResolver.isBlockedIp(targetAddr)) {
                    val id = eventIdGen.incrementAndGet()
                    HijackEvent(
                        id = id,
                        timestamp = System.currentTimeMillis(),
                        matchedType = "blocked-ip",
                        matchedValue = targetAddr?.hostAddress ?: "no-dns",
                        httpHeaders = requestHead.take(2048),
                        destinationHost = hostHeader,
                        destinationIp = ""
                    ).let { HijackEvent.logToFile(it, evidenceDir()) }
                    Log.w(TAG, "Blocked by IP: ${targetAddr?.hostAddress} host=$hostHeader")
                    sendBlockedResponse(output)
                    client.close()
                    return
                }
                upstream.connect(InetSocketAddress(targetAddr, target.second), 15000)
                upstream.soTimeout = 30000
                upstream.getOutputStream().write(requestHead.toByteArray(Charsets.ISO_8859_1))
                upstream.getOutputStream().flush()

                val responseHead = readHeaders(upstream.getInputStream())
                if (responseHead.isBlank()) {
                    client.close()
                    upstream.close()
                    return
                }

                Log.i(TAG, "REQ $hostHeader -> ${responseHead.lineSequence().firstOrNull()}")

                val verdict = detector.inspectResponse(
                    responseHead, readBodyPrefix(upstream.getInputStream())
                )
                if (verdict.blocked) {
                    val id = eventIdGen.incrementAndGet()
                    HijackEvent(
                        id = id,
                        timestamp = System.currentTimeMillis(),
                        matchedType = verdict.matchType,
                        matchedValue = verdict.matchValue,
                        httpHeaders = responseHead.take(2048),
                        destinationHost = hostHeader,
                        destinationIp = ""
                    ).let { HijackEvent.logToFile(it, evidenceDir()) }
                    Log.w(TAG, "Blocked #$id: ${verdict.matchType}=${verdict.matchValue} host=$hostHeader")
                    sendBlockedResponse(output)
                    client.close()
                    upstream.close()
                    return
                }

                output.write(responseHead.toByteArray(Charsets.ISO_8859_1))
                output.flush()
                relay(upstream.getInputStream(), output)
            } finally {
                try { upstream.close() } catch (_: Exception) {}
            }
            client.close()
        } catch (e: Exception) {
            Log.d(TAG, "client closed: ${e.message}")
            try { client.close() } catch (_: Exception) {}
        }
    }

    private fun tunnelConnect(client: Socket, connectHead: String) {
        val line = connectHead.lineSequence().firstOrNull() ?: return
        val parts = line.split(" ")
        if (parts.size < 2) {
            client.close()
            return
        }
        val hp = parts[1].split(":")
        val host = hp[0]
        val port = hp.getOrNull(1)?.toIntOrNull() ?: 443
        Log.i(TAG, "TUNNEL $host:$port")
        if (detector.isBadTunnelHost(host)) {
            Log.w(TAG, "Tunnel blocked: $host:$port")
            HijackEvent(
                id = eventIdGen.incrementAndGet(),
                timestamp = System.currentTimeMillis(),
                matchedType = "tunnel-domain",
                matchedValue = host,
                httpHeaders = connectHead.take(2048),
                destinationHost = host,
                destinationIp = ""
            ).let { HijackEvent.logToFile(it, evidenceDir()) }
            client.close()
            return
        }
        val upstream = try {
            val addr = DnsResolver.resolve(host)
            if (addr == null) {
                client.close()
                return
            }
            if (DnsResolver.isBlockedIp(addr)) {
                HijackEvent(
                    id = eventIdGen.incrementAndGet(),
                    timestamp = System.currentTimeMillis(),
                    matchedType = "tunnel-blocked-ip",
                    matchedValue = addr.hostAddress,
                    httpHeaders = connectHead.take(2048),
                    destinationHost = host,
                    destinationIp = addr.hostAddress
                ).let { HijackEvent.logToFile(it, evidenceDir()) }
                Log.w(TAG, "Tunnel blocked by IP: ${addr.hostAddress} host=$host")
                client.close()
                return
            }
            Socket().apply {
                connect(InetSocketAddress(addr, port), 15000)
                soTimeout = 0
            }
        } catch (e: Exception) {
            Log.w(TAG, "CONNECT to $host:$port failed", e)
            client.close()
            return
        }
        client.soTimeout = 0
        val clientOutput = client.getOutputStream()
        clientOutput.write("HTTP/1.1 200 Connection established\r\n\r\n".toByteArray())
        clientOutput.flush()
        val serverInput = upstream.getInputStream()
        val clientInput = client.getInputStream()
        val t1 = Thread { relay(serverInput, clientOutput) }
        val t2 = Thread { relay(clientInput, upstream.getOutputStream()) }
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        try { client.close() } catch (_: Exception) {}
        try { upstream.close() } catch (_: Exception) {}
    }

    private fun readHeaders(input: InputStream): String {
        val buf = StringBuilder()
        val byteBuf = ByteArray(1)
        var matched = 0
        val marker = "\r\n\r\n"
        while (matched < 4 && buf.length < 32768) {
            val n = input.read(byteBuf)
            if (n < 0) break
            val c = byteBuf[0].toInt().toChar()
            buf.append(c)
            if (c == marker[matched]) matched++ else matched = if (c == marker[0]) 1 else 0
        }
        return buf.toString()
    }

    private fun readBodyPrefix(input: InputStream): String {
        val arr = ByteArray(4096)
        input.mark(4096 + 1)
        val n = try {
            input.read(arr, 0, arr.size)
        } catch (e: Exception) {
            -1
        }
        if (n > 0) {
            try { input.reset() } catch (_: Exception) {}
            return String(arr, 0, n, Charsets.ISO_8859_1)
        }
        return ""
    }

    private fun extractHost(head: String): String? {
        for (line in head.lineSequence()) {
            val idx = line.indexOf(':')
            if (idx > 0 && line.substring(0, idx).trim().equals("Host", ignoreCase = true)) {
                return line.substring(idx + 1).trim()
            }
        }
        return null
    }

    private fun resolveTarget(hostHeader: String): Pair<String, Int>? {
        val host = hostHeader.trim()
        if (host.isEmpty()) return null
        val hp = host.split(":")
        val name = hp[0]
        val port = hp.getOrNull(1)?.toIntOrNull() ?: 80
        return name to port
    }

    private fun sendBlockedResponse(output: OutputStream) {
        val body = "<html><body>AdJustice blocked</body></html>"
        val resp = "HTTP/1.1 200 OK\r\n" +
            "Content-Type: text/html; charset=utf-8\r\n" +
            "Content-Length: ${body.toByteArray().size}\r\n" +
            "Connection: close\r\n\r\n" +
            body
        output.write(resp.toByteArray(Charsets.ISO_8859_1))
        output.flush()
    }

    private fun relay(input: InputStream, output: OutputStream) {
        val buf = ByteArray(32768)
        try {
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                output.write(buf, 0, n)
                output.flush()
            }
        } catch (e: Exception) {
            // stream ended
        }
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

    companion object {
        const val KEY_STOP = "stopProxy"
        const val NOTIF_ID = 1778
        // 8899 被 Whaley 系统进程 cn.whaley.mobile.tv 占用，改用 8898
        const val PROXY_PORT = 8898
        private const val TAG = "HttpBlockProxy"

        private const val KEY_PROXY_HOST = "global_http_proxy_host"
        private const val KEY_PROXY_PORT = "global_http_proxy_port"
        private const val KEY_PROXY_EXCL = "global_http_proxy_exclusion_list"

        @Volatile
        var isRunning = false
            private set

        fun start(context: android.content.Context) {
            context.startService(Intent(context, HttpBlockProxyService::class.java))
        }

        fun stop(context: android.content.Context) {
            Intent(context, HttpBlockProxyService::class.java).apply {
                putExtra(KEY_STOP, true)
                context.startService(this)
            }
        }

        fun setGlobalProxy(context: android.content.Context, on: Boolean): Boolean {
            return try {
                val cr = context.contentResolver
                if (on) {
                    Settings.Global.putString(cr, KEY_PROXY_HOST, "127.0.0.1")
                    Settings.Global.putInt(cr, KEY_PROXY_PORT, PROXY_PORT)
                    Settings.Global.putString(cr, KEY_PROXY_EXCL, "")
                } else {
                    Settings.Global.putString(cr, KEY_PROXY_HOST, null)
                    Settings.Global.putInt(cr, KEY_PROXY_PORT, 0)
                    Settings.Global.putString(cr, KEY_PROXY_EXCL, null)
                }
                true
            } catch (e: SecurityException) {
                Log.e(TAG, "Cannot set global proxy (WRITE_SECURE_SETTINGS missing)", e)
                false
            }
        }

        fun isGlobalProxySet(context: android.content.Context): Boolean {
            return try {
                val host = Settings.Global.getString(
                    context.contentResolver, KEY_PROXY_HOST
                )
                val port = Settings.Global.getInt(
                    context.contentResolver, KEY_PROXY_PORT
                )
                host == "127.0.0.1" && port == PROXY_PORT
            } catch (e: Exception) {
                false
            }
        }
    }
}
