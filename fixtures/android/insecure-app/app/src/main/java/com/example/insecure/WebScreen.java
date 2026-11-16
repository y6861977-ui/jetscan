package com.example.insecure;

import android.webkit.WebSettings;
import android.webkit.WebView;

public class WebScreen {
    void setUp(WebView web) {
        WebSettings settings = web.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setAllowUniversalAccessFromFileURLs(true);
        web.addJavascriptInterface(new Bridge(), "app");
    }
}
