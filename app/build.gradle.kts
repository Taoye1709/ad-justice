plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.adjustice"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.adjustice"
        minSdk = 21  // Android 5.0 — covers older Chinese smart TVs (e.g. WhaleyTV)
        targetSdk = 34
        versionCode = 1
        versionName = "1.0.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        vectorDrawables.useSupportLibrary = true
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    // Leanback (TV) UI
    buildFeatures {
        viewBinding = true
    }
}

dependencies {
    // ZXing core — QR code decoding (the ONLY third-party dependency)
    implementation("com.google.zxing:core:3.5.3")

    // Android basics
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("androidx.lifecycle:lifecycle-service:2.6.2")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.6.2")

    // Leanback (TV-optimized UI components)
    implementation("androidx.leanback:leanback:1.0.0")

    // RecyclerView for evidence list
    implementation("androidx.recyclerview:recyclerview:1.3.2")
}
