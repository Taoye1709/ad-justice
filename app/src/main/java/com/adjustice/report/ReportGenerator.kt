package com.adjustice.report

import com.adjustice.evidence.DnsCheckResult
import com.adjustice.evidence.EvidenceEvent
import com.adjustice.evidence.TriggerSource
import com.adjustice.evidence.Verdict
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Generates a formatted complaint report for a confirmed hijacking event.
 *
 * The output is a Markdown file ready to be:
 *  - copied and pasted into 12321's web form,
 *  - attached to a 工信部 complaint (alongside the screenshots),
 *  - printed or shared via email.
 *
 * The report never includes personal information. The user is offered a
 * placeholder `[申诉人签名占位]` so they can fill in their own details
 * before submission, and an empty fillable field for their broadband
 * account number — recommended by ISP complaint precedents.
 *
 * Legal context:
 * - 12321 Network Bad & Spam Information Reporting Center
 *   https://www.12321.cn/
 * - 工信部电信用户申诉受理中心
 *   https://yhss.miit.gov.cn/
 * - 国家反诈中心 (National Anti-Fraud Center App)
 */
object ReportGenerator {

    private val DATE_FMT = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.CHINA)

    fun generate(event: EvidenceEvent, evidenceDir: File): File {
        val report = buildReport(event)
        val reportFile = File(evidenceDir, EvidenceEvent.REPORT_FILE_NAME)
        reportFile.writeText(report)
        return reportFile
    }

    private fun buildReport(e: EvidenceEvent): String {
        val sb = StringBuilder()
        sb.appendLine("# 互联网电视广告劫持举报材料")
        sb.appendLine()

        sb.appendLine("## 一、举报事项")
        sb.appendLine()
        sb.appendLine("家用互联网电视在正常使用过程中，发现播放期间的倒计时广告位被替换为")
        sb.appendLine("涉嫌违规的商业广告内容（保健品/赌博/游戏充值诱导类），怀疑遭遇")
        sb.appendLine("网络运营商流量劫持。特此举报，请求依法查处。")
        sb.appendLine()

        sb.appendLine("## 二、事件发生时间")
        sb.appendLine()
        sb.appendLine("- 起始：${DATE_FMT.format(Date(e.timestampStart))}")
        sb.appendLine("- 结束：${DATE_FMT.format(Date(e.timestampEnd))}")
        sb.appendLine("- 触发方式：${describeTrigger(e.triggerSource)}")
        sb.appendLine()

        sb.appendLine("## 三、屏幕截图证据")
        sb.appendLine()
        e.framePaths.forEachIndexed { i, path ->
            val fileName = File(path).name
            sb.appendLine("### 画面 ${i + 1} ($fileName)")
            sb.appendLine()
            sb.appendLine("![画面${i + 1}]($fileName)")
            sb.appendLine()
        }
        sb.appendLine()

        sb.appendLine("## 四、二维码解码结果")
        sb.appendLine()
        sb.appendLine("（非法广告通常以收款二维码或社群二维码作为资金/引流入口，")
        sb.appendLine("以下是 App 对截图中二维码内容的解码结果，可作为黑产资金链路的关键证据。）")
        sb.appendLine()
        e.qrContents.forEachIndexed { i, qr ->
            sb.appendLine("### 画面 ${i + 1} 的二维码")
            if (qr.isNullOrBlank()) {
                sb.appendLine("- 本张截图未发现二维码")
            } else {
                sb.appendLine("- 解码内容：`$qr`")
            }
            sb.appendLine()
        }
        sb.appendLine()

        sb.appendLine("## 五、DNS 劫持检测结果")
        sb.appendLine()
        val dns = e.dnsCheck
        if (dns == null) {
            sb.appendLine("本次事件未启用 DNS 劫持检测。")
        } else if (dns.isHijacked) {
            sb.appendLine("**⚠️ 已检测到 DNS 劫持。**")
            sb.appendLine()
            sb.appendLine("| 域名 | 系统 DNS 返回 | 114.114.114.114 返回 | 是否劫持 |")
            sb.appendLine("|---|---|---|---|")
            dns.checks.filter { it.hijacked }.forEach { c ->
                sb.appendLine("| `${c.domain}` | ${c.systemIps.joinToString(", ")} | ${c.trustedIps.joinToString(", ")} | ⚠️ 劫持 |")
            }
            sb.appendLine()
            sb.appendLine("（仅列出存在劫持的域名；未劫持的域名已隐藏以节省篇幅。）")
        } else {
            sb.appendLine("✓ 本次采证期间未检测到 DNS 劫持。")
            sb.appendLine("（但这并不排除劫持经 TCP/IP 注入或 HTTP 响应替换形成，")
            sb.appendLine(" 建议结合上述截图中可见的违规广告内容综合研判。）")
        }
        sb.appendLine()

        sb.appendLine("## 六、初步分析")
        sb.appendLine()
        sb.appendLine("结合以上证据，倾向认为：")
        sb.appendLine()
        sb.appendLine("- 在本家互联网电视播放视频期间，")
        sb.appendLine("- 倒计时广告的素材被替换为带有违规二维码的非合规广告，")
        sb.appendLine("- 此现象通常源于网络运营商在传输链路上对 HTTP 流量的拦截与篡改，")
        sb.appendLine("- 建议对所属运营商进行核查，并依法叫停其广告劫持行为。")
        sb.appendLine()

        sb.appendLine("## 七、申诉人信息（提交前请填写）")
        sb.appendLine()
        sb.appendLine("- 申诉人姓名：[请填写]")
        sb.appendLine("- 联系电话：[请填写]")
        sb.appendLine("- 所在宽带账号 / IPTV 编号：[请填写]")
        sb.appendLine("- 宽带运营商：[请填写，如中国移动/中国电信/中国联通/二级运营商]")
        sb.appendLine("- 所在地区：[请填写省/市]")
        sb.appendLine("- 签名（手写或电子）：[占位]")
        sb.appendLine()
        sb.appendLine("本材料由 AdJustice 自动生成。所附截图均为本人自有的电视设备截取，")
        sb.appendLine("内容真实，可作为举证材料。")
        sb.appendLine()

        sb.appendLine("## 八、提交渠道")
        sb.appendLine()
        sb.appendLine("建议以下渠道并行提交，以提高关注度：")
        sb.appendLine()
        sb.appendLine("1. **12321 网络不良与垃圾信息举报中心**")
        sb.appendLine("   https://www.12321.cn/")
        sb.appendLine()
        sb.appendLine("2. **工信部电信用户申诉受理中心**（投诉宽带运营商）")
        sb.appendLine("   https://yhss.miit.gov.cn/")
        sb.appendLine()
        sb.appendLine("3. **国家反诈中心 App**")
        sb.appendLine("   （扫描上方二维码，反诈中心可直接定位资金账户）")
        sb.appendLine()
        sb.appendLine("4. **运营商本省客服** 电信 10000 / 联通 10010 / 移动 10086")
        sb.appendLine()

        sb.appendLine("---")
        sb.appendLine()
        sb.appendLine("**AdJustice** v1.0.0 · 本证据包生成于 ${DATE_FMT.format(Date())}")
        sb.appendLine()
        sb.appendLine("> 本材料不含任何个人身份信息。截图、二维码、DNS 数据均为本地取证。")
        sb.appendLine("> 代码开源且接受审查：https://github.com/adjustice/adjustice")
        sb.appendLine()
        return sb.toString()
    }

    private fun describeTrigger(t: TriggerSource): String = when (t) {
        TriggerSource.AUTO_PIXEL_DIFF -> "电视画面发生显著切换，自动触发采证"
        TriggerSource.MANUAL -> "申诉人目睹广告后手动触发（遥控器按键）"
    }
}
