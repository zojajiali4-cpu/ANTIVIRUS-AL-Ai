plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

// Release credentials are supplied only by the CI environment / local secure environment.
// Never commit a keystore, passwords, or signing properties to this repository.
val releaseStoreFile = providers.environmentVariable("ALAI_RELEASE_STORE_FILE").orNull
val releaseStorePassword = providers.environmentVariable("ALAI_RELEASE_STORE_PASSWORD").orNull
val releaseKeyAlias = providers.environmentVariable("ALAI_RELEASE_KEY_ALIAS").orNull
val releaseKeyPassword = providers.environmentVariable("ALAI_RELEASE_KEY_PASSWORD").orNull
val hasReleaseSigning = listOf(
    releaseStoreFile,
    releaseStorePassword,
    releaseKeyAlias,
    releaseKeyPassword
).all { !it.isNullOrBlank() }

android {
    namespace = "com.antivirusalai"
    compileSdk = 36
    defaultConfig {
        applicationId = "com.antivirusalai"
        minSdk = 26
        targetSdk = 36
        // CI supplies a monotonically increasing value for each workflow run.
        versionCode = providers.environmentVariable("ALAI_VERSION_CODE").orElse("2").get().toInt()
        versionName = "0.2.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        buildConfigField("String", "ALAI_THREAT_FEED_URL", "\"${providers.environmentVariable("ALAI_THREAT_FEED_URL").orElse("https://raw.githubusercontent.com/zojajiali4-cpu/ANTIVIRUS-AL-Ai/security-feed/threat-feed/latest.alfeed").get()}\"")
        buildConfigField("String", "ALAI_THREAT_FEED_PUBLIC_KEY_B64", "\"${providers.environmentVariable("ALAI_THREAT_FEED_PUBLIC_KEY_B64").orElse("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEM1szM5WLCBP0KDTXsrVfBdPxErB4sVo4mhY+duhjfDP5MwASTx0pLor3mSL7dLRwX/gZpi6odLquz/BfIGSafg==").get()}\"")
        buildConfigField("String", "ALAI_THREAT_FEED_KEY_ID", "\"${providers.environmentVariable("ALAI_THREAT_FEED_KEY_ID").orElse("alai-release-2026").get()}\"")
        buildConfigField("String", "ALAI_API_BASE_URL", "\"${providers.environmentVariable("ALAI_API_BASE_URL").orElse("https://antivirus-al-ai-api.zojajiali4.workers.dev").get()}\"")
    }
    signingConfigs {
        if (hasReleaseSigning) {
            create("release") {
                storeFile = file(requireNotNull(releaseStoreFile))
                storePassword = requireNotNull(releaseStorePassword)
                keyAlias = requireNotNull(releaseKeyAlias)
                keyPassword = requireNotNull(releaseKeyPassword)
            }
        }
    }
    buildTypes {
        getByName("release") {
            // Release signing is enabled only when all four credentials are present.
            if (hasReleaseSigning) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    packaging { resources { excludes += "/META-INF/{AL2.0,LGPL2.1}" } }
    lint {
        abortOnError = true
        checkReleaseBuilds = true
    }
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

dependencies {
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.compose.animation.core)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    debugImplementation(libs.androidx.compose.ui.tooling)
    testImplementation(libs.junit)
}
