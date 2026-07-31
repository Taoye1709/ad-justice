package com.adjustice.evidence

import org.json.JSONArray
import org.json.JSONObject

/**
 * Serialize/deserialize EvidenceEvent to/from JSON without external libraries.
 */
object EvidenceJson {

    fun toJson(e: EvidenceEvent): String {
        val qr = JSONArray()
        e.qrContents.forEach { qr.put(it ?: JSONObject.NULL) }

        val dns = if (e.dnsCheck != null) {
            val checks = JSONArray()
            e.dnsCheck.checks.forEach { c ->
                checks.put(JSONObject().apply {
                    put("domain", c.domain)
                    put("systemIps", JSONArray(c.systemIps))
                    put("trustedIps", JSONArray(c.trustedIps))
                    put("hijacked", c.hijacked)
                })
            }
            JSONObject().apply {
                put("checks", checks)
                put("isHijacked", e.dnsCheck.isHijacked)
            }
        } else JSONObject.NULL

        val frames = JSONArray(e.framePaths)

        return JSONObject().apply {
            put("id", e.id)
            put("timestampStart", e.timestampStart)
            put("timestampEnd", e.timestampEnd)
            put("triggerSource", e.triggerSource.name)
            put("framePaths", frames)
            put("qrContents", qr)
            put("dnsCheck", dns)
            put("verdict", e.verdict.name)
            if (e.reportPath != null) put("reportPath", e.reportPath) else put("reportPath", JSONObject.NULL)
        }.toString(2)
    }

    fun fromJson(text: String): EvidenceEvent {
        val o = JSONObject(text)
        val qrList = mutableListOf<String?>()
        val qrArr = o.getJSONArray("qrContents")
        for (i in 0 until qrArr.length()) {
            qrList.add(if (qrArr.isNull(i)) null else qrArr.getString(i))
        }

        val framesList = mutableListOf<String>()
        val frArr = o.getJSONArray("framePaths")
        for (i in 0 until frArr.length()) framesList.add(frArr.getString(i))

        val dnsCheck = if (o.isNull("dnsCheck")) null else {
            val d = o.getJSONObject("dnsCheck")
            val checks = mutableListOf<DnsCheckResult.DomainCheck>()
            val cArr = d.getJSONArray("checks")
            for (i in 0 until cArr.length()) {
                val c = cArr.getJSONObject(i)
                checks.add(
                    DnsCheckResult.DomainCheck(
                        c.getString("domain"),
                        jsonArrayToStringList(c.getJSONArray("systemIps")),
                        jsonArrayToStringList(c.getJSONArray("trustedIps")),
                        c.getBoolean("hijacked")
                    )
                )
            }
            DnsCheckResult(checks, d.getBoolean("isHijacked"))
        }

        return EvidenceEvent(
            id = o.getLong("id"),
            timestampStart = o.getLong("timestampStart"),
            timestampEnd = o.getLong("timestampEnd"),
            triggerSource = TriggerSource.valueOf(o.getString("triggerSource")),
            framePaths = framesList,
            qrContents = qrList,
            dnsCheck = dnsCheck,
            verdict = Verdict.valueOf(o.getString("verdict")),
            reportPath = if (o.isNull("reportPath")) null else o.getString("reportPath")
        )
    }

    private fun jsonArrayToStringList(a: JSONArray): List<String> {
        val l = mutableListOf<String>()
        for (i in 0 until a.length()) l.add(a.getString(i))
        return l
    }
}
