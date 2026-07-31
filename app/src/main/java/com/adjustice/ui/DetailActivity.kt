package com.adjustice.ui

import android.content.Context
import android.content.Intent
import android.graphics.BitmapFactory
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.adjustice.R
import com.adjustice.evidence.EvidenceEvent
import com.adjustice.evidence.EvidenceRepository
import com.adjustice.evidence.Verdict
import com.adjustice.report.ReportGenerator
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * DetailActivity — one captured event shown in full.
 *
 * The user reviews the 3 screenshots, sees the decoded QR content and the
 * DNS check result, and decides whether this represents a hijacked ad
 * or a legitimate one. If they mark it as HIJACKED, the Generate Report
 * button becomes active and produces a structured complaint document.
 */
class DetailActivity : AppCompatActivity() {

    private lateinit var repository: EvidenceRepository
    private var event: EvidenceEvent? = null
    private val dateFmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.CHINA)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_detail)

        val eventId = intent.getLongExtra(EXTRA_EVENT_ID, -1L)
        val baseDir = File(filesDir, "adj_evidence")
        repository = EvidenceRepository(baseDir)
        event = repository.listEvents().firstOrNull { it.id == eventId }
        val ev = event ?: run {
            Toast.makeText(this, "事件不存在", Toast.LENGTH_SHORT).show()
            finish()
            return
        }

        val title = findViewById<TextView>(R.id.detail_title)
        val ts = findViewById<TextView>(R.id.detail_timestamp)
        val framesContainer = findViewById<LinearLayout>(R.id.frames_container)
        val qrContainer = findViewById<LinearLayout>(R.id.qr_container)
        val dnsResult = findViewById<TextView>(R.id.dns_result_text)
        val verdictText = findViewById<TextView>(R.id.verdict_text)
        val btnMarkHijacked = findViewById<Button>(R.id.btn_mark_hijacked)
        val btnMarkClean = findViewById<Button>(R.id.btn_mark_clean)
        val btnDismiss = findViewById<Button>(R.id.btn_dismiss)
        val btnGenerateReport = findViewById<Button>(R.id.btn_generate_report)
        val btnOpen12321 = findViewById<Button>(R.id.btn_open_12321)
        val btnOpenMiit = findViewById<Button>(R.id.btn_open_miit)

        title.text = "#${"%04d".format(ev.id)}"
        ts.text = "${dateFmt.format(Date(ev.timestampStart))} ~ ${dateFmt.format(Date(ev.timestampEnd))}"

        // Render 3 frames
        ev.framePaths.forEachIndexed { i, path ->
            val frameTitle = TextView(this).apply {
                text = getString(R.string.frame_label, i + 1)
                setTextColor(0xFFFFFFFF.toInt())
                textSize = 18f
                setPadding(0, 24, 0, 8)
            }
            val imageView = ImageView(this).apply {
                adjustViewBounds = true
                layoutParams = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                )
                setImageBitmap(BitmapFactory.decodeFile(path))
            }
            framesContainer.addView(frameTitle)
            framesContainer.addView(imageView)
        }

        // Render QR results
        ev.qrContents.forEachIndexed { i, qr ->
            val label = TextView(this).apply {
                text = getString(R.string.frame_label, i + 1) + "："
                setTextColor(0xFFB0B0B0.toInt())
                textSize = 16f
                setPadding(0, 0, 0, 0)
            }
            val content = TextView(this).apply {
                text = if (qr.isNullOrBlank()) getString(R.string.qr_none_label) else qr
                setTextColor(
                    if (qr.isNullOrBlank()) 0xFF808080.toInt()
                    else 0xFFFFD54F.toInt()
                )
                textSize = 14f
                typeface = android.graphics.Typeface.MONOSPACE
                setPadding(0, 0, 0, 16)
                setOnClickListener {
                    if (!qr.isNullOrBlank()) {
                        @Suppress("DEPRECATION")
                        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
                        cm.setPrimaryClip(android.content.ClipData.newPlainText("qr", qr))
                        Toast.makeText(this@DetailActivity, "已复制到剪贴板", Toast.LENGTH_SHORT).show()
                    }
                }
            }
            qrContainer.addView(label)
            qrContainer.addView(content)
        }

        // DNS result display
        dnsResult.text = when {
            ev.dnsCheck == null -> getString(R.string.dns_not_checked)
            ev.dnsCheck.isHijacked -> {
                val details = ev.dnsCheck.checks.filter { it.hijacked }
                    .joinToString("\n") { "• ${it.domain}: ${it.systemIps} vs ${it.trustedIps}" }
                "${getString(R.string.dns_hijacked)}\n$details"
            }
            else -> getString(R.string.dns_clean)
        }
        dnsResult.setTextColor(when {
            ev.dnsCheck?.isHijacked == true -> 0xFFFF6B6B.toInt()
            ev.dnsCheck != null -> 0xFF81C784.toInt()
            else -> 0xFFB0B0B0.toInt()
        })

        renderVerdict(verdictText)

        btnMarkHijacked.setOnClickListener { updateVerdict(Verdict.HIJACKED, verdictText) }
        btnMarkClean.setOnClickListener { updateVerdict(Verdict.NOT_HIJACKED, verdictText) }
        btnDismiss.setOnClickListener { updateVerdict(Verdict.DISMISSED, verdictText) }

        btnGenerateReport.setOnClickListener {
            val current = event
            if (current == null || current.verdict != Verdict.HIJACKED) {
                Toast.makeText(this, "请先确认这是劫持广告", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            val evDir = repository.eventDir(current.id)
            val reportFile = ReportGenerator.generate(current, evDir)
            current.reportPath = reportFile.absolutePath
            repository.saveEvent(current)
            Toast.makeText(this, R.string.saved_to_evidence, Toast.LENGTH_LONG).show()

            // Also copy the report text to the clipboard for easy pasting
            val reportText = reportFile.readText()
            @Suppress("DEPRECATION")
            val cm = getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
            cm.setPrimaryClip(android.content.ClipData.newPlainText("report", reportText))
            Toast.makeText(this, "举报文本已复制到剪贴板", Toast.LENGTH_LONG).show()
        }

        btnOpen12321.setOnClickListener { openUrl("https://www.12321.cn/") }
        btnOpenMiit.setOnClickListener { openUrl("https://yhss.miit.gov.cn/") }
    }

    private fun renderVerdict(view: TextView) {
        val ev = event ?: return
        val (text, color) = when (ev.verdict) {
            Verdict.PENDING -> getString(R.string.verdict_pending) to 0xFFB0B0B0.toInt()
            Verdict.HIJACKED -> getString(R.string.verdict_hijacked) to 0xFFFF6B6B.toInt()
            Verdict.NOT_HIJACKED -> getString(R.string.verdict_clean) to 0xFF81C784.toInt()
            Verdict.DISMISSED -> "已忽略" to 0xFFB0B0B0.toInt()
        }
        view.text = "${getString(R.string.verdict_label)}：$text"
        view.setTextColor(color)
    }

    private fun updateVerdict(v: Verdict, view: TextView) {
        val ev = event ?: return
        ev.verdict = v
        repository.saveEvent(ev)
        renderVerdict(view)
        if (v == Verdict.HIJACKED) {
            Toast.makeText(this, "已确认劫持，可生成举报材料", Toast.LENGTH_SHORT).show()
        }
    }

    private fun openUrl(url: String) {
        startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
    }

    companion object {
        const val EXTRA_EVENT_ID = "event_id"
    }
}
