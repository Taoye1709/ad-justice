package com.adjustice.proxy

import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.Random

/**
 * DNS resolver that queries upstream DNS servers over TCP (53/tcp).
 *
 * The ISP poisons plain UDP DNS responses in this network (verified:
 * UDP 53 queries to 223.5.5.5 / 119.29.29.29 / 114.114.114.114 all
 * return malformed replies, while the same queries over TCP 53 return
 * correct answers). By resolving over TCP we bypass the poisoning so
 * the proxy always connects to the real server, never to an injected
 * ad-server IP.
 *
 * Fallbacks in order: TCP to 223.5.5.5, TCP to 114.114.114.114,
 * finally the platform resolver (InetAddress).
 */
object DnsResolver {

    private val SERVERS = listOf("223.5.5.5", "114.114.114.114")

    /**
     * IPs observed as ISP-injected ad servers in this network. Tencent Video
     * was caught connecting to these instead of real Tencent CDN nodes.
     * 201.234.234.61 (Level3 Venezuela), 154.174.194.154 (Scancom Ghana),
     * 85.223.202.42 (Kyivstar Ukraine), 36.110.110.189 (Chinanet BJ).
     */
    private val BLOCKED_IPS = setOf(
        "201.234.234.61", "154.174.194.154", "85.223.202.42", "36.110.110.189"
    )

    fun resolve(host: String): InetAddress? {
        // Already an IP literal — return directly.
        return try {
            InetAddress.getByName(host).let { if (it.hostAddress == host) return it else null }
        } catch (e: Exception) {
            null
        }?.let { return it } ?: tcpQuery(host)
    }

    fun isBlockedIp(addr: InetAddress): Boolean =
        addr.hostAddress in BLOCKED_IPS

    private fun tcpQuery(host: String): InetAddress? {
        for (server in SERVERS) {
            try {
                val addr = tcpQueryOne(server, host)
                if (addr != null) return addr
            } catch (e: Exception) {
                // try next server
            }
        }
        // Last resort: platform resolver (may be poisoned, but better than nothing)
        return try {
            InetAddress.getByName(host)
        } catch (e: Exception) {
            null
        }
    }

    private fun tcpQueryOne(server: String, host: String): InetAddress? {
        val id = Random().nextInt(65536)
        val query = buildQuery(id, host)
        val sock = Socket()
        sock.connect(InetSocketAddress(server, 53), 4000)
        sock.soTimeout = 4000
        try {
            sock.getOutputStream().write(query)
            sock.getOutputStream().flush()
            val resp = readResponse(sock)
            if (resp.size < 12) return null
            val flags = ((resp[2].toInt() and 0xFF) shl 8) or (resp[3].toInt() and 0xFF)
            if ((flags and 0x8000) == 0) return null // not a response
            val qdcount = ((resp[4].toInt() and 0xFF) shl 8) or (resp[5].toInt() and 0xFF)
            val ancount = ((resp[6].toInt() and 0xFF) shl 8) or (resp[7].toInt() and 0xFF)
            if (ancount == 0) return null
            var off = 12
            // skip question section
            off = skipName(resp, off)
            off += 4 // QTYPE + QCLASS
            // first answer: name + type + class + ttl(4) + rdlength(2) + rdata
            off = skipName(resp, off)
            if (off + 10 > resp.size) return null
            val type = ((resp[off].toInt() and 0xFF) shl 8) or (resp[off + 1].toInt() and 0xFF)
            val rdlength = ((resp[off + 8].toInt() and 0xFF) shl 8) or (resp[off + 9].toInt() and 0xFF)
            off += 10
            if (type == 1 && rdlength == 4 && off + 4 <= resp.size) {
                return InetAddress.getByAddress(host, byteArrayOf(
                    resp[off], resp[off + 1], resp[off + 2], resp[off + 3]
                ))
            }
            if (type == 5) {
                // CNAME — follow up to a few levels
                val target = parseName(resp, off) ?: return null
                var depth = 0
                while (depth < 5) {
                    val inner = tcpQueryOne(server, target)
                    if (inner != null) return inner
                    depth++
                }
                return null
            }
            return null
        } finally {
            sock.close()
        }
    }

    private fun buildQuery(id: Int, host: String): ByteArray {
        val buf = ByteArrayOutputStream()
        buf.write((id ushr 8) and 0xFF)
        buf.write(id and 0xFF)
        buf.write(0x01) // RD
        buf.write(0x00)
        buf.write(0x00); buf.write(0x01) // QDCOUNT = 1
        buf.write(0x00); buf.write(0x00) // ANCOUNT
        buf.write(0x00); buf.write(0x00) // NSCOUNT
        buf.write(0x00); buf.write(0x00) // ARCOUNT
        for (label in host.split(".")) {
            buf.write(label.length)
            buf.write(label.toByteArray(Charsets.US_ASCII))
        }
        buf.write(0x00)
        buf.write(0x00); buf.write(0x01) // QTYPE = A
        buf.write(0x00); buf.write(0x01) // QCLASS = IN
        val body = buf.toByteArray()
        // TCP length prefix
        val out = ByteArrayOutputStream()
        out.write((body.size ushr 8) and 0xFF)
        out.write(body.size and 0xFF)
        out.write(body)
        return out.toByteArray()
    }

    private fun readResponse(sock: Socket): ByteArray {
        val input = sock.getInputStream()
        val lenBytes = ByteArray(2)
        if (input.read(lenBytes) != 2) return ByteArray(0)
        val len = ((lenBytes[0].toInt() and 0xFF) shl 8) or (lenBytes[1].toInt() and 0xFF)
        val data = ByteArray(len)
        var read = 0
        while (read < len) {
            val n = input.read(data, read, len - read)
            if (n < 0) break
            read += n
        }
        return data.copyOf(read)
    }

    private fun skipName(data: ByteArray, start: Int): Int {
        var off = start
        while (off < data.size) {
            val b = data[off].toInt() and 0xFF
            if (b == 0) return off + 1
            if ((b and 0xC0) == 0xC0) return off + 2 // pointer
            off += 1 + b
        }
        return data.size
    }

    private fun parseName(data: ByteArray, start: Int): String? {
        val sb = StringBuilder()
        var off = start
        while (off < data.size) {
            val b = data[off].toInt() and 0xFF
            if (b == 0) break
            if ((b and 0xC0) == 0xC0) return null // compressed — not handled
            if (sb.isNotEmpty()) sb.append('.')
            sb.append(String(data, off + 1, b, Charsets.US_ASCII))
            off += 1 + b
        }
        return sb.toString().ifEmpty { null }
    }
}
