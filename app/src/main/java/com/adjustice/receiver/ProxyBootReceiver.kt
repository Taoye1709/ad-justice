package com.adjustice.receiver

import android.app.AlarmManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.os.Build
import android.os.SystemClock
import com.adjustice.proxy.HttpBlockProxyService

/**
 * 代理自恢复接收器（运行期间的辅助通道）。
 *
 * WhaleyTV ROM 会把第三方应用的 BOOT_COMPLETED / CONNECTIVITY_CHANGE
 * 广播全部加入黑名单（实测 logcat："skip receiver package:com.adjustice"），
 * 且系统不持久化闹钟（/data/system/alarm/ 不存在），本接收器无法在开机时
 * 工作。**开机自启已改用 ProxyAutoStartAccessibilityService（无障碍服务
 * 通道，系统开机直接绑定，绕开广播黑名单）。**
 *
 * 本接收器保留原因：服务运行期间的 Keep-alive 闹钟（ACTION_KEEPALIVE）
 * 在设备不休眠时有效，可防止代理服务进程被系统意外杀死后无人拉起。
 */
class ProxyBootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        if (action != Intent.ACTION_BOOT_COMPLETED &&
            action != ConnectivityManager.CONNECTIVITY_ACTION &&
            action != ACTION_KEEPALIVE
        ) return
        if (HttpBlockProxyService.isRunning) return
        if (!HttpBlockProxyService.isGlobalProxySet(context)) return
        HttpBlockProxyService.start(context)
    }

    companion object {
        const val ACTION_KEEPALIVE = "com.adjustice.action.PROXY_KEEPALIVE"
        // 间隔越短，重启后代理恢复越快（决定"登录网络"弹窗存在时长）
        private const val INTERVAL_MS = 2 * 60 * 1000L

        fun scheduleKeepAlive(context: Context) {
            val am = context.getSystemService(Context.ALARM_SERVICE) as AlarmManager
            // ELAPSED_REALTIME：待机/深睡时不唤醒设备，仅设备活跃时按周期检查
            am.setInexactRepeating(
                AlarmManager.ELAPSED_REALTIME,
                SystemClock.elapsedRealtime() + INTERVAL_MS,
                INTERVAL_MS,
                pendingIntent(context)
            )
        }

        fun cancelKeepAlive(context: Context) {
            val am = context.getSystemService(Context.ALARM_SERVICE) as AlarmManager
            am.cancel(pendingIntent(context))
        }

        private fun pendingIntent(context: Context): PendingIntent {
            val flags = PendingIntent.FLAG_UPDATE_CURRENT or
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    PendingIntent.FLAG_IMMUTABLE
                } else {
                    0
                }
            return PendingIntent.getBroadcast(
                context, 0,
                Intent(context, ProxyBootReceiver::class.java).setAction(ACTION_KEEPALIVE),
                flags
            )
        }
    }
}
