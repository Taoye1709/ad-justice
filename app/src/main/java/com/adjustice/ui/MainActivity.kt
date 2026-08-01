package com.adjustice.ui

import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.adjustice.proxy.HttpBlockProxyService
import com.adjustice.receiver.ProxyBootReceiver
import com.adjustice.R
import java.io.File

/**
 * TV 首页 — 通过遥控器操作。
 *
 * "开始监控" → 启动本地 HTTP 代理并设置全局代理，拦截 ISP 注入的广告；
 * "设置" → 调整检测参数；
 * "已拦截劫持事件" → 显示拦截到的 hijack 总数。
 */
class MainActivity : AppCompatActivity() {

    private var proxyRunning = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val btnStartStop = findViewById<Button>(R.id.btn_start_stop)
        val btnSettings = findViewById<Button>(R.id.btn_settings)

        updateHijackCount()

        btnStartStop.setOnClickListener {
            if (proxyRunning) {
                ProxyBootReceiver.cancelKeepAlive(this)
                HttpBlockProxyService.stop(this)
                HttpBlockProxyService.setGlobalProxy(this, false)
                proxyRunning = false
                updateUi()
                showStatus("监控已停止，已恢复网络直连")
            } else {
                startProxyWithFallback()
            }
        }

        btnSettings.setOnClickListener {
            startActivity(Intent(this, SettingsActivity::class.java))
        }
    }

    override fun onResume() {
        super.onResume()
        proxyRunning = HttpBlockProxyService.isRunning || HttpBlockProxyService.isGlobalProxySet(this)
        updateUi()
        updateHijackCount()
    }

    private fun updateHijackCount() {
        val logFile = File(filesDir, "adj_evidence/hijack_log.jsonl")
        val count = if (logFile.exists()) {
            logFile.readLines().size
        } else 0
        findViewById<TextView>(R.id.hijack_count).text = "已拦截劫持事件: $count 次"
    }

    private fun startProxyWithFallback() {
        try {
            HttpBlockProxyService.start(this)
            proxyRunning = true
            val proxyOk = HttpBlockProxyService.setGlobalProxy(this, true)
            if (proxyOk) {
                ProxyBootReceiver.scheduleKeepAlive(this)
                updateUi()
                showStatus("拦截已启动，HTTP 代理已生效")
            } else {
                updateUi()
                showStatus("拦截服务已启动，但设置全局代理失败，请先授予 WRITE_SECURE_SETTINGS 权限")
            }
        } catch (e: Exception) {
            android.util.Log.e("AdJustice", "Proxy start failed", e)
            proxyRunning = false
            updateUi()
            showStatus("拦截启动失败: ${e.message}")
        }
    }

    private fun updateUi() {
        val btnStartStop = findViewById<Button>(R.id.btn_start_stop)
        btnStartStop.text =
            if (proxyRunning) getString(R.string.stop_monitoring) else getString(R.string.start_monitoring)
        // 激活态驱动 selector：监控中 = 红色实心（危险语义），空闲 = 橙色实心（主 CTA）
        btnStartStop.isActivated = proxyRunning
    }

    private fun showStatus(msg: String) {
        findViewById<TextView>(R.id.status_text).text = msg
    }
}
