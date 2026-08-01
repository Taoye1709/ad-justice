package com.adjustice.receiver

import android.accessibilityservice.AccessibilityService
import android.util.Log
import android.view.accessibility.AccessibilityEvent
import com.adjustice.proxy.HttpBlockProxyService

/**
 * 无障碍服务 —— 开机自启通道。
 *
 * WhaleyTV ROM 会把第三方应用的 BOOT_COMPLETED / CONNECTIVITY_CHANGE 广播
 * 全部加入黑名单（实测 logcat："skip receiver package:com.adjustice"），
 * 且系统不持久化闹钟（/data/system/alarm/ 不存在），常规自启通道全部失效。
 *
 * 无障碍服务由系统开机时直接绑定（不经过广播分发），只要用户启用过一次，
 * 每次重启后系统都会自动重新绑定本服务 —— 借此通道检测全局代理残留并
 * 拉起代理服务，避免开机走死代理导致系统网络检查失败弹出"登录网络"界面。
 */
class ProxyAutoStartAccessibilityService : AccessibilityService() {

    override fun onServiceConnected() {
        super.onServiceConnected()
        Log.i(TAG, "onServiceConnected: boot channel alive, proxySet=" +
            HttpBlockProxyService.isGlobalProxySet(this) +
            " running=" + HttpBlockProxyService.isRunning)
        // 代理残留 = 上次开着监控 → 自动恢复服务，避免开机断网
        if (!HttpBlockProxyService.isRunning && HttpBlockProxyService.isGlobalProxySet(this)) {
            HttpBlockProxyService.start(this)
        }
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        // 本服务只作为开机自启通道，不处理任何无障碍事件
    }

    override fun onInterrupt() {
        // no-op
    }

    companion object {
        private const val TAG = "ProxyAutoStartA11y"
    }
}
