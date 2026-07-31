package com.adjustice.evidence

/**
 * Data model for a captured evidence event.
 *
 * Each event represents ONE "potential ad hijacking moment" detected by the
 * background capture service. The user reviews it later and decides whether
 * it represents a real hijacked ad or a legitimate one.
 *
 * Everything is stored locally as a directory on the device:
 *
 *   evidence/
 *   ├─ 0001/
 *   │   ├─ meta.json          ← this EvidenceEvent serialized
 *   │   ├─ frame_1.jpg         ← screenshot 1
 *   │   ├─ frame_2.jpg         ← screenshot 2
 *   │   ├─ frame_3.jpg         ← screenshot 3
 *   │   └─ report.md           ← generated only after user confirms
 *   ├─ 0002/
 *   └─ ...
 */
data class EvidenceEvent(
    val id: Long,
    val timestampStart: Long,           // epoch ms — first frame captured
    val timestampEnd: Long,             // epoch ms — third frame captured
    val triggerSource: TriggerSource,   // auto pixel-diff or manual
    val framePaths: List<String>,       // absolute paths to 3 JPGs
    val qrContents: List<String?>,      // decoded QR text per frame (null if none)
    val dnsCheck: DnsCheckResult?,       // DNS hijacking check, null if disabled
    var verdict: Verdict = Verdict.PENDING,
    var reportPath: String? = null
) {
    companion object {
        const val META_FILE_NAME = "meta.json"
        const val FRAME_FILE_PREFIX = "frame_"
        const val FRAME_FILE_SUFFIX = ".jpg"
        const val REPORT_FILE_NAME = "report.md"
    }
}

enum class TriggerSource { AUTO_PIXEL_DIFF, MANUAL }

enum class Verdict {
    PENDING,        // user has not reviewed yet
    HIJACKED,       // user confirmed this is an illegally hijacked ad
    NOT_HIJACKED,   // user confirmed this is a legitimate ad
    DISMISSED       // user dismissed without verdict
}

/**
 * Result of comparing system DNS vs trusted DNS for known ad domains.
 *
 * "systemIps" come from the OS DNS resolver (likely hijacked if hijacking is happening).
 * "trustedIps" come from a direct UDP query to 114.114.114.114.
 *
 * If they disagree for any checked domain → hijacked.
 */
data class DnsCheckResult(
    val checks: List<DomainCheck>,
    val isHijacked: Boolean
) {
    data class DomainCheck(
        val domain: String,
        val systemIps: List<String>,
        val trustedIps: List<String>,
        val hijacked: Boolean
    )
}
