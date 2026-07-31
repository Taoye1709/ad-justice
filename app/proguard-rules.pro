# Keep ZXing core classes
-keep class com.google.zxing.** { *; }

# Keep Kotlin metadata
-keepclassmembers class * {
    @kotlin.Metadata *;
}
