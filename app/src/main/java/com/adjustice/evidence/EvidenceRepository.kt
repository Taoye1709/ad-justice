package com.adjustice.evidence

import java.io.File

/**
 * Persists evidence events and their screenshots to a private directory
 * on the device. No data ever leaves the device through this layer.
 *
 * Layout on disk:
 *
 *   <filesDir>/adj_evidence/
 *   ├─ 0001/
 *   │   ├─ meta.json
 *   │   ├─ frame_1.jpg
 *   │   ├─ frame_2.jpg
 *   │   ├─ frame_3.jpg
 *   │   └─ report.md (after user confirms)
 *   ├─ 0002/
 *   └─ seq.txt  (latest sequence number)
 */
class EvidenceRepository(
    private val baseDir: File
) {
    init {
        baseDir.mkdirs()
    }

    fun nextId(): Long {
        val seqFile = File(baseDir, "seq.txt")
        val next = if (seqFile.exists()) {
            seqFile.readText().trim().toLong() + 1L
        } else 1L
        seqFile.writeText(next.toString())
        return next
    }

    fun createEventDir(eventId: Long): File {
        val dir = File(baseDir, "%04d".format(eventId))
        dir.mkdirs()
        return dir
    }

    fun frameFile(eventDir: File, index: Int): File =
        File(eventDir, "${EvidenceEvent.FRAME_FILE_PREFIX}${index}${EvidenceEvent.FRAME_FILE_SUFFIX}")

    fun reportFile(eventDir: File): File =
        File(eventDir, EvidenceEvent.REPORT_FILE_NAME)

    fun eventDir(eventId: Long): File = File(baseDir, "%04d".format(eventId))

    fun listEvents(): List<EvidenceEvent> {
        val events = mutableListOf<EvidenceEvent>()
        baseDir.listFiles { f -> f.isDirectory && f.name.matches(Regex("\\d{4}")) }
            ?.sortedBy { it.name }
            ?.forEach { dir ->
                val meta = File(dir, EvidenceEvent.META_FILE_NAME)
                if (meta.exists()) {
                    runCatching {
                        events.add(EvidenceJson.fromJson(meta.readText()))
                    }
                }
            }
        return events
    }

    fun saveEvent(event: EvidenceEvent) {
        val dir = eventDir(event.id)
        dir.mkdirs()
        File(dir, EvidenceEvent.META_FILE_NAME).writeText(EvidenceJson.toJson(event))
    }

    fun countByVerdict(verdict: Verdict): Int =
        listEvents().count { it.verdict == verdict }

    val basePath: String get() = baseDir.absolutePath
}
