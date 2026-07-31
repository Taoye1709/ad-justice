package com.adjustice.vpn

import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Evidence record created when the VPN detects and blocks an ISP ad hijack.
 *
 * Unlike screenshots, this captures exactly what the ISP tried to inject:
 * the injected HTTP headers, matched domain/keyword, and the destination.
 * This is often more useful as evidence than a screenshot.
 */
data class HijackEvent(
    val id: Long,
    val timestamp: Long,
    val matchedType: String,   // "domain", "keyword", "signature"
    val matchedValue: String,  // the specific domain/keyword that triggered
    val httpHeaders: String,   // first ~2KB of HTTP response headers
    val destinationHost: String,
    val destinationIp: String
) {

    /**
     * Serialize this event to a JSON-formatted log line.
     * Uses simple string concatenation (no org.json dependency for the VPN layer)
     */
    fun toJsonLine(): String {
        val ts = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
            .format(Date(timestamp))
        // Escape the header text for JSON (replace newlines and quotes)
        val headers = httpHeaders
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
        return """{"id":$id,"time":"$ts","type":"$matchedType","match":"$matchedValue","host":"$destinationHost","ip":"$destinationIp","headers":"$headers"}"""
    }

    companion object {
        /**
         * Append a HijackEvent to the evidence log file.
         * Uses simple JSON-lines format (one event per line).
         */
        fun logToFile(event: HijackEvent, dir: File) {
            if (!dir.exists()) dir.mkdirs()
            val logFile = File(dir, "hijack_log.jsonl")
            logFile.appendText(event.toJsonLine() + "\n")
        }
    }
}
