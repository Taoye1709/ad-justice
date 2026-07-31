package com.adjustice.ui

import android.os.Bundle
import android.widget.Switch
import androidx.appcompat.app.AppCompatActivity
import com.adjustice.R
import com.adjustice.detect.DnsProtector

/**
 * SettingsActivity — DNS check toggle, ad-block enable, and About section.
 *
 * No server config, no account section, no analytics opt-in. This is
 * intentionally minimal: anything else would push the app toward being
 * a "data-collection platform," which contradicts the design's promise.
 */
class SettingsActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)

        val switchDns = findViewById<Switch>(R.id.switch_dns)
        val switchBlock = findViewById<Switch>(R.id.switch_block)

        val prefs = getSharedPreferences(PREFS, MODE_PRIVATE)
        switchDns.isChecked = prefs.getBoolean(KEY_DNS_ENABLED, true)

        val blockCurrentlyEnabled = DnsProtector.currentState(this).let { state ->
            state != "off" && state != "unsupported"
        }
        switchBlock.isChecked = blockCurrentlyEnabled
        prefs.edit().putBoolean(KEY_BLOCK_ENABLED, blockCurrentlyEnabled).apply()

        switchDns.setOnCheckedChangeListener { _, checked ->
            prefs.edit().putBoolean(KEY_DNS_ENABLED, checked).apply()
        }

        switchBlock.setOnCheckedChangeListener { _, checked ->
            prefs.edit().putBoolean(KEY_BLOCK_ENABLED, checked).apply()
            if (checked) DnsProtector.enable(this) else DnsProtector.disable(this)
        }
    }

    companion object {
        const val PREFS = "adj_settings"
        const val KEY_DNS_ENABLED = "dns_enabled"
        const val KEY_BLOCK_ENABLED = "block_enabled"
    }
}
