plugins {
    id("com.android.application")
}

android {
    namespace = "com.example.flavors"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.example.flavors"
        minSdk = 23
        targetSdk = 33
        manifestPlaceholders["usesCleartext"] = "false"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            manifestPlaceholders["usesCleartext"] = "true"
        }
        debug {
            manifestPlaceholders["usesCleartext"] = "true"
        }
    }

    flavorDimensions += "store"
    productFlavors {
        create("free") { dimension = "store" }
    }
}
