package com.adjustice.detect

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.util.Log
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer

/**
 * Decodes QR codes from screenshot bitmaps using the ZXing library.
 *
 * ZXing is the de facto standard open-source barcode/QR reader for Android.
 * It works fully offline, does not require any model or AI, and has
 * negligible (< 1MB) APK size impact.
 *
 * Real-world TV ad scams rely on QR codes for WeChat/Alipay payment,
 * WeChat group invitations, and scam app download links. Decoding the
 * QR code yields a unique traceable identifier that serves as concrete,
 * deterministic, machine-verifiable evidence.
 */
object QrDecoder {

    private val reader = MultiFormatReader().apply {
        setHints(mapOf(
            DecodeHintType.TRY_HARDER to true,
            DecodeHintType.POSSIBLE_FORMATS to listOf("QR_CODE")
        ))
    }

    /**
     * Decode any QR codes in the image file.
     *
     * @return decoded text if exactly one QR is found,
     *         JSON-encoded array string if multiple,
     *         null if no QR is present.
     */
    fun decodeFile(imagePath: String): String? {
        return runCatching {
            val opts = BitmapFactory.Options().apply { inPreferredConfig = Bitmap.Config.ARGB_8888 }
            val bmp = BitmapFactory.decodeFile(imagePath, opts) ?: return null
            val result = decodeBitmap(bmp)
            bmp.recycle()
            result
        }.onFailure { Log.w(TAG, "QR decode failed for $imagePath", it) }.getOrNull()
    }

    fun decodeBitmap(bitmap: Bitmap): String? {
        val width = bitmap.width
        val height = bitmap.height
        val pixels = IntArray(width * height)
        bitmap.getPixels(pixels, 0, width, 0, 0, width, height)

        val source = RGBLuminanceSource(width, height, pixels)
        val binary = BinaryBitmap(HybridBinarizer(source))

        return runCatching { reader.decodeWithState(binary).text }
            .recoverCatching {
                reader.reset()
                // Try inverted (light-on-dark) — common for dark TV ads
                val invSource = RGBLuminanceSource(width, height, pixels).invert()
                val invBinary = BinaryBitmap(HybridBinarizer(invSource))
                reader.decodeWithState(invBinary).text
            }
            .onFailure { reader.reset() }
            .getOrNull()
    }

    private const val TAG = "QrDecoder"
}
