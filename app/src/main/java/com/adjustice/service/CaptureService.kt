package com.adjustice.service

import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.graphics.Bitmap
import android.graphics.PixelFormat
import android.hardware.display.DisplayManager
import android.hardware.display.VirtualDisplay
import android.media.Image
import android.media.ImageReader
import android.media.projection.MediaProjection
import android.media.projection.MediaProjectionManager
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import com.adjustice.detect.DnsProtector
import android.os.IBinder
import android.os.Looper
import android.util.DisplayMetrics
import android.util.Log
import android.view.WindowManager
import androidx.core.app.NotificationCompat
import com.adjustice.App
import com.adjustice.R
import com.adjustice.detect.DnsHijackChecker
import com.adjustice.detect.PixelDiffDetector
import com.adjustice.detect.QrDecoder
import com.adjustice.evidence.EvidenceEvent
import com.adjustice.evidence.EvidenceRepository
import com.adjustice.evidence.TriggerSource
import com.adjustice.ui.MainActivity
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import kotlin.concurrent.thread

/**
 * CaptureService — the heart of AdJustice.
 *
 * It runs as a Foreground Service with mediaProjection type. It takes periodic
 * low-resolution thumbnails and runs them through the pixel-diff detector. On
 * a significant change (likely "video → ad" transition), it grabs 3 full-res
 * screenshots and packages them as an evidence event.
 *
 * Workflow:
 *   start(projectionCode, projectionData)  →  setUpProjection()
 *     → loop: every N seconds, capture thumbnail, compare to previous
 *       → if scene change → captureEvidence()
 *
 * captureEvidence():
 *   1. Take 3 full-res screenshots (~1.5s apart)
 *   2. Run QrDecoder on each
 *   3. Optionally run DnsHijackChecker
 *   4. Persist EvidenceEvent to local repository
 *   5. Notify user
 *
 * The user can also trigger a manual capture by sending an intent with
 * ACTION_MANUAL_CAPTURE.
 */
class CaptureService : Service() {

    private lateinit var repository: EvidenceRepository
    private var projection: MediaProjection? = null
    private var virtualDisplay: VirtualDisplay? = null
    private var fullReader: ImageReader? = null
    private var thumbReader: ImageReader? = null

    private val captureThread = HandlerThread("capture").apply { start() }
    private val handler = Handler(captureThread.looper)

    private val detector = PixelDiffDetector()
    private val dnsChecker = DnsHijackChecker()
    private var dnsCheckEnabled = true

    private var thresholdPercent = 30
    private var intervalMs = 5000L
    private var thumbWidth = 160
    private var thumbHeight = 90
    private var fullWidth = 1280
    private var fullHeight = 720

    private var prevThumb: Bitmap? = null

    @Volatile private var capturingEvidence = false
    @Volatile private var pendingManual = false

    override fun onCreate() {
        super.onCreate()
        val baseDir = File(filesDir, "adj_evidence")
        repository = EvidenceRepository(baseDir)
        dnsCheckEnabled = getSharedPreferences(
            "adj_settings", MODE_PRIVATE
        ).getBoolean("dns_enabled", true)
        startForeground()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                val code = intent.getIntExtra(EXTRA_RESULT_CODE, 0)
                val data = intent.getParcelableExtra<Intent>(EXTRA_RESULT_DATA)
                if (code != 0 && data != null) {
                    startCapture(code, data)
                } else {
                    Log.e(TAG, "Missing MediaProjection code/data, stopping")
                    stopSelf()
                }
            }
            ACTION_MANUAL_CAPTURE -> {
                Log.i(TAG, "Manual capture triggered")
                if (projection != null && !capturingEvidence) {
                    pendingManual = true
                }
            }
            ACTION_STOP -> {
                Log.i(TAG, "Stop requested")
                cleanup()
                stopSelf()
            }
        }
        return START_STICKY
    }

    private fun startCapture(code: Int, data: Intent) {
        val mpm = getSystemService(Context.MEDIA_PROJECTION_SERVICE) as MediaProjectionManager
        projection = mpm.getMediaProjection(code, data) ?: run {
            Log.e(TAG, "Failed to obtain MediaProjection")
            stopSelf()
            return
        }

        projection!!.registerCallback(object : MediaProjection.Callback() {
            override fun onStop() {
                Log.w(TAG, "MediaProjection stopped")
                cleanup()
                stopSelf()
            }
        }, handler)

        setupReaders()
        startThumbnailLoop()
    }

    private fun setupReaders() {
        val dm = DisplayMetrics()
        (getSystemService(Context.WINDOW_SERVICE) as WindowManager).defaultDisplay.getRealMetrics(dm)
        fullWidth = dm.widthPixels.coerceAtMost(MAX_FULL_WIDTH)
        fullHeight = dm.heightPixels.coerceAtMost(MAX_FULL_HEIGHT)

        // Low-resolution thumbnail reader (for continuous diff monitoring)
        thumbReader = ImageReader.newInstance(
            thumbWidth, thumbHeight, PixelFormat.RGBA_8888, 2
        )
        thumbReader!!.setOnImageAvailableListener({ reader -> processThumbnail(reader) }, handler)

        // Full-resolution reader (grabbed only during evidence capture)
        fullReader = ImageReader.newInstance(
            fullWidth, fullHeight, PixelFormat.RGBA_8888, 3
        )

        virtualDisplay = projection!!.createVirtualDisplay(
            "AdJustice",
            fullWidth, fullHeight, dm.densityDpi,
            DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
            null, null, handler
        )

        // Bind both readers to the same virtual display
        virtualDisplay?.surface = thumbReader?.surface
    }

private fun startThumbnailLoop() {
        handler.post(object : Runnable {
            override fun run() {
                if (projection == null) return
                if (pendingManual && !capturingEvidence) {
                    pendingManual = false
                    capturingEvidence = true
                    captureEvidence(TriggerSource.MANUAL)
                } else {
                    thumbReader?.acquireLatestImage()?.close()
                }
                handler.postDelayed(this, intervalMs)
            }
        })
    }

    /**
     * Force the virtual display surface to refresh by detaching/reattaching.
     */
    private fun requestThumbnailRefresh() {
        val vd = virtualDisplay ?: return
        val tr = thumbReader ?: return
        vd.surface = null
        vd.surface = tr.surface
    }

    private fun processThumbnail(reader: ImageReader) {
        val image = reader.acquireLatestImage() ?: return
        try {
            val bmp = imageToBitmap(image, thumbWidth, thumbHeight)
            val prev = prevThumb
            if (prev != null) {
                if (detector.isSceneChange(prev, bmp)) {
                    Log.i(TAG, "Scene change detected")
                    if (!capturingEvidence) {
                        capturingEvidence = true
                        Thread { captureEvidence(TriggerSource.AUTO_PIXEL_DIFF) }.start()
                    }
                }
                prev.recycle()
            }
            prevThumb = bmp
        } finally {
            image.close()
        }
    }

    private fun captureEvidence(trigger: TriggerSource) {
        try {
            val eventId = repository.nextId()
            val eventDir = repository.createEventDir(eventId)
            val startTime = System.currentTimeMillis()
            val framePaths = ArrayList<String>(3)
            val qrContents = ArrayList<String?>(3)

            // Bind the full-res reader temporarily
            virtualDisplay?.surface = fullReader?.surface
            Thread.sleep(200)   // let the surface settle

            for (i in 1..3) {
                val fullImage = waitForImage(fullReader!!, 1500)
                val path = saveImage(fullImage, File(eventDir, "frame_$i.jpg"))
                framePaths.add(path)
                val qr = QrDecoder.decodeFile(path)
                qrContents.add(qr)
                fullImage.close()
                if (i < 3) Thread.sleep(1500)
            }

            // Restore the low-res surface for ongoing monitoring
            virtualDisplay?.surface = thumbReader?.surface

            val endTime = System.currentTimeMillis()
            val dns = if (dnsCheckEnabled) {
                runCatching { dnsChecker.check() }.getOrNull()
            } else null

            val event = EvidenceEvent(
                id = eventId,
                timestampStart = startTime,
                timestampEnd = endTime,
                triggerSource = trigger,
                framePaths = framePaths,
                qrContents = qrContents,
                dnsCheck = dns
            )
            repository.saveEvent(event)

            if (dns?.isHijacked == true && getSharedPreferences(
                    "adj_settings", MODE_PRIVATE
                ).getBoolean("block_enabled", true)
            ) {
                Log.w(TAG, "DNS hijacked — requesting Private DNS protection")
                DnsProtector.enable(this)
            }

            notifyUser(eventId)
            Log.i(TAG, "Evidence captured: #${eventId} (trigger=$trigger)")
        } catch (t: Throwable) {
            Log.e(TAG, "captureEvidence failed", t)
            virtualDisplay?.surface = thumbReader?.surface
        } finally {
            capturingEvidence = false
        }
    }

    private fun waitForImage(reader: ImageReader, timeoutMs: Long): Image {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            val img = reader.acquireLatestImage()
            if (img != null) return img
            Thread.sleep(50)
        }
        throw IllegalStateException("Image not available within $timeoutMs ms")
    }

    private fun saveImage(image: Image, target: File): String {
        val plane = image.planes[0]
        val buffer = plane.buffer
        val pixelStride = plane.pixelStride
        val rowStride = plane.rowStride
        val rowPadding = rowStride - pixelStride * image.width

        val width = image.width
        val height = image.height
        val bmp = Bitmap.createBitmap(
            width + rowPadding / pixelStride,
            height,
            Bitmap.Config.ARGB_8888
        )
        buffer.rewind()
        bmp.copyPixelsFromBuffer(buffer)
        val cropped = Bitmap.createBitmap(bmp, 0, 0, width, height)

        FileOutputStream(target).use { out ->
            cropped.compress(Bitmap.CompressFormat.JPEG, 90, out)
        }
        bmp.recycle()
        cropped.recycle()
        return target.absolutePath
    }

    private fun imageToBitmap(image: Image, width: Int, height: Int): Bitmap {
        val plane = image.planes[0]
        val buffer = plane.buffer
        val pixelStride = plane.pixelStride
        val rowStride = plane.rowStride
        val rowPadding = rowStride - pixelStride * width

        val realWidth = width + rowPadding / pixelStride
        val bmp = Bitmap.createBitmap(realWidth, height, Bitmap.Config.ARGB_8888)
        buffer.rewind()
        bmp.copyPixelsFromBuffer(buffer)
        return if (realWidth != width) {
            Bitmap.createBitmap(bmp, 0, 0, width, height)
        } else bmp
    }

    private fun notifyUser(eventId: Long) {
        @Suppress("DEPRECATION")
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val openIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val pi = PendingIntent.getActivity(
            this, eventId.toInt(), openIntent,
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            else
                PendingIntent.FLAG_UPDATE_CURRENT
        )

        val notif = NotificationCompat.Builder(this, App.CHANNEL_EVENT)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentTitle(getString(R.string.notification_event_title, eventId))
            .setContentText(getString(R.string.notification_event_text))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setContentIntent(pi)
            .setAutoCancel(true)
            .build()
        nm.notify(eventId.toInt(), notif)
    }

    private fun startForeground() {
        val openIntent = Intent(this, MainActivity::class.java)
        val pi = PendingIntent.getActivity(
            this, 0, openIntent,
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
                PendingIntent.FLAG_IMMUTABLE
            else
                0
        )

        val notif = NotificationCompat.Builder(this, App.CHANNEL_SERVICE)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentTitle(getString(R.string.notification_running_title))
            .setContentText(getString(R.string.notification_running_text))
            .setOngoing(true)
            .setContentIntent(pi)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIF_ID, notif, ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PROJECTION)
        } else {
            startForeground(NOTIF_ID, notif)
        }
    }

    private fun cleanup() {
        capturingEvidence = false
        virtualDisplay?.release()
        virtualDisplay = null
        thumbReader?.close()
        fullReader?.close()
        projection?.stop()
        projection = null
        prevThumb?.recycle()
        prevThumb = null
    }

    override fun onDestroy() {
        cleanup()
        captureThread.quitSafely()
        super.onDestroy()
    }

    companion object {
        private const val TAG = "CaptureService"
        private const val NOTIF_ID = 1001
        private const val MAX_FULL_WIDTH = 1280
        private const val MAX_FULL_HEIGHT = 720

        const val ACTION_START = "com.adjustice.action.START"
        const val ACTION_STOP = "com.adjustice.action.STOP"
        const val ACTION_MANUAL_CAPTURE = "com.adjustice.action.MANUAL_CAPTURE"
        const val EXTRA_RESULT_CODE = "result_code"
        const val EXTRA_RESULT_DATA = "result_data"

        fun start(context: Context, code: Int, data: Intent) {
            val intent = Intent(context, CaptureService::class.java).apply {
                action = ACTION_START
                putExtra(EXTRA_RESULT_CODE, code)
                putExtra(EXTRA_RESULT_DATA, data)
            }
            context.startForegroundService(intent)
        }

        fun stop(context: Context) {
            context.startService(Intent(context, CaptureService::class.java).apply {
                action = ACTION_STOP
            })
        }

        fun manualCapture(context: Context) {
            context.startService(Intent(context, CaptureService::class.java).apply {
                action = ACTION_MANUAL_CAPTURE
            })
        }
    }
}
