package com.adjustice.detect

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.provider.Settings
import android.util.Log

/**
 * Enables/disables DNS-over-TLS (Private DNS) via system settings.
 *
 * Android 9+ (API 28) supports Private DNS natively. When DoT is active,
 * all DNS queries on the device are sent encrypted to the configured
 * resolver. This eliminates ISP visibility into DNS — the primary vector
 * for domain-level ad hijacking.
 *
 * The Settings.Global keys "private_dns_mode" and "private_dns_specifier"
 * are hidden constants not exposed in the public SDK, so we use the string
 * literals directly.
 *
 * Requires WRITE_SECURE_SETTINGS (grantable via adb on TV).
 */
object DnsProtector {

    private const val TAG = "DnsProtector"

    // Settings.Global keys — hidden in public SDK, using string literals
    private const val KEY_PRIVATE_DNS_MODE = "private_dns_mode"
    private const val KEY_PRIVATE_DNS_SPECIFIER = "private_dns_specifier"

    // Mode values
    private const val MODE_OFF = "off"
    private const val MODE_HOSTNAME = "hostname"
    private const val MODE_OPPORTUNISTIC = "opportunistic"

    // Safe DNS-over-TLS server
    private const val SAFE_DNS = "114dns.com"

    /**
     * Switch the device to use a safe DNS-over-TLS server (114dns.com).
     *
     * On Android 9+, this replaces the current network's DNS with an
     * encrypted transport that the ISP cannot intercept or modify.
     */
    fun enable(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            Log.w(TAG, "Private DNS requires Android 9+")
            return false
        }
        return runCatching {
            Settings.Global.putString(
                context.contentResolver,
                KEY_PRIVATE_DNS_MODE,
                MODE_HOSTNAME
            )
            Settings.Global.putString(
                context.contentResolver,
                KEY_PRIVATE_DNS_SPECIFIER,
                SAFE_DNS
            )
            Log.i(TAG, "Private DNS enabled -> $SAFE_DNS")
            true
        }.onFailure {
            Log.e(TAG, "Failed to enable Private DNS", it)
        }.getOrDefault(false)
    }

    /**
     * Disable Private DNS and return to the network's default servers.
     */
    fun disable(context: Context): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            return false
        }
        return runCatching {
            Settings.Global.putString(
                context.contentResolver,
                KEY_PRIVATE_DNS_MODE,
                MODE_OFF
            )
            Settings.Global.putString(
                context.contentResolver,
                KEY_PRIVATE_DNS_SPECIFIER,
                ""
            )
            Log.i(TAG, "Private DNS disabled")
            true
        }.getOrDefault(false)
    }

    /**
     * Check the current Private DNS state.
     *
     * Returns:
     *   "off"           — Private DNS disabled
     *   "opportunistic" — encrypted DNS if available, no specific hostname
     *   a hostname      — the active Private DNS hostname (e.g. "114dns.com")
     *   "unsupported"   — Android < 9
     */
    fun currentState(context: Context): String {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) {
            return "unsupported"
        }
        val mode = Settings.Global.getString(
            context.contentResolver,
            KEY_PRIVATE_DNS_MODE
        ) ?: MODE_OFF

        return when (mode) {
            MODE_OFF -> "off"
            MODE_OPPORTUNISTIC -> "opportunistic"
            MODE_HOSTNAME -> {
                Settings.Global.getString(
                    context.contentResolver,
                    KEY_PRIVATE_DNS_SPECIFIER
                ) ?: "hostname"
            }
            else -> "unknown ($mode)"
        }
    }

    /**
     * Record the gateway DNS that clients currently use — useful
     * for restoring later or for logging.
     */
    fun lastGatewayDns(context: Context): String? {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE)
                as? ConnectivityManager ?: return null
        val active = cm.activeNetwork ?: return null
        val caps = cm.getNetworkCapabilities(active) ?: return null
        if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return null

        val linkProps = cm.getLinkProperties(active) ?: return null
        return linkProps.dnsServers.firstOrNull()?.hostAddress
    }
}
