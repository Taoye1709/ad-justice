package com.adjustice.vpn

class InspectionResult(
    val blocked: Boolean,
    val matchType: String,
    val matchValue: String,
    val headersPreview: String
)

class InjectionDetector {

    fun inspect(packet: ByteArray, length: Int): InspectionResult {
        if (length < 4) return clean()

        if (!looksLikeHttpResponse(packet, length)) return clean()

        val headerEnd = findHeaderEnd(packet, length)
        if (headerEnd < 0) return clean()

        val headerLen = minOf(headerEnd, 2048)
        val headerText = String(packet, 0, headerLen, Charsets.ISO_8859_1)

        val bodyLen = minOf(length - headerEnd, 4096)
        val bodyText = if (bodyLen > 0)
            String(packet, headerEnd, bodyLen, Charsets.ISO_8859_1) else ""

        return inspectResponse(headerText, bodyText)
    }

    /**
     * Inspect a full HTTP response given its header text and body prefix.
     * Shared by the TUN packet path and the local HTTP proxy path.
     */
    fun inspectResponse(headerText: String, bodyPrefix: String): InspectionResult {
        if (!headerText.startsWith("HTTP/1.") && !headerText.startsWith("HTTP/1.0")) return clean()

        if (headerText.contains("Location: http", ignoreCase = true)) {
            for (badDomain in BAD_DOMAINS) {
                if (headerText.contains(badDomain, ignoreCase = true)) {
                    return block("domain", badDomain, headerText)
                }
            }
        }

        if (headerText.contains("Content-Type: text/html", ignoreCase = true) ||
            headerText.contains("Content-Type: text/plain", ignoreCase = true)) {
            for (keyword in SCAM_KEYWORDS) {
                if (bodyPrefix.contains(keyword, ignoreCase = true)) {
                    return block("keyword", keyword, headerText)
                }
            }
            for (pattern in JS_INJECTION_PATTERNS) {
                if (bodyPrefix.contains(pattern, ignoreCase = true)) {
                    return block("js-inject", pattern, headerText)
                }
            }
        }

        for (sig in INJECTION_SIGNATURES) {
            if (headerText.contains(sig, ignoreCase = true)) {
                return block("signature", sig, headerText)
            }
        }

        return clean()
    }

    /**
     * True when a CONNECT tunnel targets a known ad / tracking domain.
     * HTTPS content cannot be inspected, but we can refuse to open a
     * tunnel to servers we already know are ad-related.
     */
    fun isBadTunnelHost(host: String): Boolean {
        val h = host.lowercase()
        return TUNNEL_BLOCK_HOSTS.any { h == it || h.endsWith(".$it") }
    }

    private fun block(type: String, value: String, headers: String) =
        InspectionResult(true, type, value, headers)

    private fun clean() =
        InspectionResult(false, "none", "", "")

    private fun looksLikeHttpResponse(p: ByteArray, n: Int): Boolean {
        if (n < 7) return false
        return p[0] == 'H'.code.toByte() &&
            p[1] == 'T'.code.toByte() &&
            p[2] == 'T'.code.toByte() &&
            p[3] == 'P'.code.toByte() &&
            p[4] == '/'.code.toByte() &&
            p[5] == '1'.code.toByte() &&
            p[6] == '.'.code.toByte()
    }

    private fun findHeaderEnd(p: ByteArray, n: Int): Int {
        val cr: Byte = 0x0d
        val lf: Byte = 0x0a
        for (i in 0..n - 4) {
            if (p[i] == cr && p[i + 1] == lf &&
                p[i + 2] == cr && p[i + 3] == lf) {
                return i + 4
            }
        }
        return -1
    }

    companion object {
        val BAD_DOMAINS = listOf(
            "51.la", "cnzz.com", "taaeta.com.cn", "mediav.com",
            "youdao.com", "biaozhun.com", "miaozhen.com", "irs01.com",
            "iancesmad.com", "izpwx.com", "iskyvector.com"
        )

        val SCAM_KEYWORDS = listOf(
            "澳门赌场", "威尼斯人", "百家乐", "六合彩", "时时彩",
            "北京赛车", "幸运飞艇", "极速赛车", "一分六合", "快三",
            "注册就送", "充100送", "首充送", "免费领取", "限时领取",
            "V信充值", "微信充值", "支付宝充值", "代充", "低价充值", "便宜充值",
            "保健品", "壮阳", "减肥药", "增高药", "男科", "妇科",
            "疝气", "狐臭", "牛皮癣", "白癜风"
        )

        val JS_INJECTION_PATTERNS = listOf(
            "window.location.href", "location.replace(", "top.location",
            "document.write('<script", "iframe src=", "document.createElement('script'",
            "var _ad_", "ad_detect", "showad(", "adsbygoogle"
        )

        val INJECTION_SIGNATURES = listOf(
            "X-Powered-By: ISP", "X-Cache: HIT from",
            "Via: 1.1", "Age: 0", "X-Squid-Error",
            // Common ISP injection server fingerprints
            "Server: nginx/1.10", "Server: Microsoft-IIS/7.5",
            "X-Cache: MISS from", "Squid/3.", "squid/2.",
            "Cache-Control: no-store, no-cache",
            "Pragma: no-cache, X-ISP"
        )

        val TUNNEL_BLOCK_HOSTS = listOf(
            "aginomoto.com", "51.la", "cnzz.com", "taaeta.com.cn",
            "mediav.com", "youdao.com", "biaozhun.com", "miaozhen.com",
            "irs01.com", "iancesmad.com", "izpwx.com", "iskyvector.com"
        )
    }
}
