package com.example.hardened

import android.webkit.WebView

fun configure(web: WebView) {
    web.settings.javaScriptEnabled = true
    web.settings.allowFileAccess = false
    web.settings.allowUniversalAccessFromFileURLs = false
    // web.addJavascriptInterface(Bridge(), "app")  -- removed in 2.0
}
