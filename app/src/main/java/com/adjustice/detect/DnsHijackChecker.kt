package com.adjustice.detect

import android.util.Log
import com.adjustice.evidence.DnsCheckResult
import java.net.InetAddress
import java.net.DatagramSocket
import java.net.DatagramPacket
import java.nio.ByteBuffer
import kotlin.concurrent.thread

/**
 * Detects DNS hijacking by comparing the system's DNS resolution against
 * direct queries to a trusted DNS server (114.114.114.114 by default).
 *
 * The mechanism:
 * 1. InetAddress.getAllByName(domain) uses the system DNS — may be hijacked.
 * 2. We craft a raw DNS query packet and send it via UDP DatagramSocket
 *    to a trusted DNS server:53.   No library, no root, no VpnService.
 * 3. We parse the response and extract the A records.
 * 4. If the two answers disagree → DNS hijacking detected.
 *
 * This uses only the INTERNET permission (already declared in the manifest).
 */
class DnsHijackChecker(
    private val trustedDns: String = "114.114.114.114"
) {

    /**
     * Known ad-serving domains typically queried by TV video apps.
     *
     * Built from public research (see docs/RESEARCH.md):
     * - 腾讯广告 (GDT/Tencent Ads): ad.qcloud.com, gdt.qq.com, mi.gdt.qq.com
     * - 爱奇艺广告:                          ad.iqiyi.com, afp.qiantui.com
     * - 优酷广告:                            ad.youku.com
     * - 家乐福广告SDK / 秒针:                mi.tanx.com
     * - 巨量引警 (ByteDance):                adsdk.e.qq.com
     *
     * DNS hijackers typically redirect these to their own cache/proxy.
     */
    val adDomains: List<String> = listOf(
        "ad.qcloud.com",
        "gdt.qq.com",
        "mi.gdt.qq.com",
        "ad.iqiyi.com",
        "afp.qiantui.com",
        "ad.youku.com",
        "mi.tanx.com",
        "adsdk.e.qq.com"
    )

    /**
     * Run the comparison. Returns null on failure.
     *
     * This may take a few seconds due to timeouts. Call from a background thread.
     */
    fun check(domains: List<String> = adDomains): DnsCheckResult? {
        val checks = mutableListOf<DnsCheckResult.DomainCheck>()
        var anyHijacked = false

        for (domain in domains) {
            try {
                val systemIps = systemResolve(domain).sorted()
                val trustedIps = trustedResolve(domain).sorted()
                val hijacked = systemIps.isNotEmpty() && trustedIps.isNotEmpty() &&
                    systemIps.toSet() != trustedIps.toSet()
                if (hijacked) anyHijacked = true

                checks.add(
                    DnsCheckResult.DomainCheck(
                        domain = domain,
                        systemIps = systemIps,
                        trustedIps = trustedIps,
                        hijacked = hijacked
                    )
                )
            } catch (t: Throwable) {
                Log.w(TAG, "DNS check failed for $domain", t)
                checks.add(
                    DnsCheckResult.DomainCheck(
                        domain = domain,
                        systemIps = emptyList(),
                        trustedIps = emptyList(),
                        hijacked = false
                    )
                )
            }
        }
        return DnsCheckResult(checks, anyHijacked)
    }

    /** Resolve via the system DNS (potentially hijacked). */
    private fun systemResolve(domain: String): List<String> =
        runCatching {
            InetAddress.getAllByName(domain).map { it.hostAddress ?: "" }
                .filter { it.isNotEmpty() }
        }.getOrDefault(emptyList())

    /**
     * Resolve via a trusted DNS server using raw UDP packets.
     *
     * DNS query format for A record (RFC 1035 §4.1):
     *   Header (12 bytes): transaction id | flags | QDCOUNT=1
     *   Question: length-prefixed labels + '.' + type A (0x0001) + class IN (0x0001)
     */
    private fun trustedResolve(domain: String): List<String> {
        val socket = DatagramSocket()
        try {
            socket.soTimeout = 3000

            val query = buildDnsQuery(domain, TYPE_A)
            val queryPacket = DatagramPacket(
                query, query.size,
                InetAddress.getByName(trustedDns), 53
            )
            socket.send(queryPacket)

            val responseBuf = ByteArray(1024)
            val responsePacket = DatagramPacket(responseBuf, responseBuf.size)
            socket.receive(responsePacket)

            return parseDnsResponse(responsePacket.data, responsePacket.length)
        } finally {
            socket.close()
        }
    }

    private fun buildDnsQuery(domain: String, type: Int): ByteArray {
        val buf = ByteBuffer.allocate(512)

        // Random transaction ID
        val txnId = (System.currentTimeMillis() and 0xFFFF).toInt()
        buf.putShort(txnId.toShort())

        // Flags: standard query, recursion desired
        val flags_sym: Short = 0x0100.toShort()
        buf.putShort(flags_sym)

        buf.putShort(1.toShort())   // QDCOUNT = 1
        buf.putShort(0.toShort())   // ANCOUNT
        buf.putShort(0.toShort())   // NSCOUNT
        buf.putShort(0.toShort())   // ARCOUNT

        // Encode domain as length-prefixed labels
        for (label in domain.trimEnd('.').split('.')) {
            val bytes = label.toByteArray(Charsets.US_ASCII)
            require(bytes.size <= 63)
            buf.put(bytes.size.toByte())
            buf.put(bytes)
        }
        buf.put(0)         // root label

        buf.putShort(type.toShort())
        buf.putShort(1.toShort())    // class IN

        val result = ByteArray(buf.position())
        buf.flip()
        buf.get(result)
        return result
    }

    /**
     * Parse the DNS response. Extracts A records (type 1) from the answer section.
     */
    private fun parseDnsResponse(data: ByteArray, length: Int): List<String> {
        if (length < 12) return emptyList()
        val buf = ByteBuffer.wrap(data, 0, length)

        @Suppress("UNUSED_VARIABLE")
        val txnId = buf.short
        @Suppress("UNUSED_VARIABLE")
        val flags = buf.short
        val qdcount = buf.short.toInt() and 0xFFFF
        val ancount = buf.short.toInt() and 0xFFFF

        // Skip question section
        repeat(qdcount) {
            skipName(buf)
            buf.position(buf.position() + 4)   // skip type + class
        }

        val ips = mutableListOf<String>()
        repeat(ancount) {
            skipName(buf)
            val type = buf.short.toInt() and 0xFFFF
            val rclass = buf.short.toInt() and 0xFFFF
            val ttl = buf.int                    // 4 bytes
            val rdlen = buf.short.toInt() and 0xFFFF
            if (type == TYPE_A && rclass == 1 && rdlen == 4) {
                val b1 = buf.get().toInt() and 0xFF
                val b2 = buf.get().toInt() and 0xFF
                val b3 = buf.get().toInt() and 0xFF
                val b4 = buf.get().toInt() and 0xFF
                ips.add("$b1.$b2.$b3.$b4")
            } else {
                buf.position(buf.position() + rdlen)
            }
        }
        return ips
    }

    /** Skip a DNS name field, handling pointer compression (RFC 1035 §4.1.4). */
    private fun skipName(buf: ByteBuffer) {
        while (true) {
            val len = buf.get().toInt() and 0xFF
            if (len == 0) return
            if ((len and 0xC0) == 0xC0) {
                buf.get()   // skip the second byte of the pointer
                return
            }
            buf.position(buf.position() + len)
        }
    }

    companion object {
        private const val TAG = "DnsHijackChecker"
        private const val TYPE_A = 1
    }
}
