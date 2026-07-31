package com.adjustice.detect

import android.graphics.Bitmap
import android.graphics.Color

/**
 * Detects significant scene changes between consecutive frames.
 *
 * Compares two low-resolution thumbnails (e.g. 160x90) using simple pixel
 * intensity difference. If more than [threshold] percent of pixels show
 * a sufficiently large brightness shift, we declare a "scene change" —
 * which typically indicates that the TV has switched from normal
 * playback to an ad slot, or vice versa.
 *
 * This is intentionally crude — no CV model, no deep learning.
 * The detection only needs to answer one binary question:
 * "Did the screen change a lot?"
 */
class PixelDiffDetector(
    private val thresholdPercent: Int = 30,
    private val minDiffPerPixel: Int = 40  // out of 255
) {

    /**
     * Compute the percentage of pixels whose luminance changed
     * beyond [minDiffPerPixel] between [prev] and [curr].
     */
    fun diffPercent(prev: Bitmap, curr: Bitmap): Float {
        require(prev.width == curr.width && prev.height == curr.height) {
            "Frame sizes differ"
        }

        val w = prev.width
        val h = prev.height
        var changed = 0
        var total = 0

        for (y in 0 until h) {
            for (x in 0 until w) {
                val pL = luminance(prev.getPixel(x, y))
                val cL = luminance(curr.getPixel(x, y))
                if (Math.abs(pL - cL) >= minDiffPerPixel) changed++
                total++
            }
        }
        return (changed.toFloat() / total.toFloat()) * 100f
    }

    fun isSceneChange(prev: Bitmap, curr: Bitmap): Boolean =
        diffPercent(prev, curr) >= thresholdPercent.toFloat()

    private fun luminance(color: Int): Int {
        val r = Color.red(color)
        val g = Color.green(color)
        val b = Color.blue(color)
        return (0.299 * r + 0.587 * g + 0.114 * b).toInt()
    }
}
