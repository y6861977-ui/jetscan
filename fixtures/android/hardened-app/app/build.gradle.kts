plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "com.example.hardened"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        applicationId = "com.example.hardened"
        minSdk = libs.versions.minSdk.get().toInt()
        targetSdk = libs.versions.targetSdk.get().toInt()
        buildConfigField("String", "API_URL", "\"https://api.example.com\"")
    }

    signingConfigs {
        create("release") {
            storeFile = file(System.getenv("KEYSTORE_PATH") ?: "missing.jks")
            storePassword = System.getenv("STORE_PASSWORD")
            keyPassword = providers.gradleProperty("keyPassword").orNull
        }
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = true
            isDebuggable = false
            signingConfig = signingConfigs.getByName("release")
        }
        getByName("debug") {
            isDebuggable = true
            isMinifyEnabled = false
        }
    }
}
