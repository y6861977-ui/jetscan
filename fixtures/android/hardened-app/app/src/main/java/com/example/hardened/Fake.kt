package com.example.hardened

// Not a WebView and not a Cipher: methods that only share names.
class FakeSettings {
    fun setJavaScriptEnabled(enabled: Boolean) {}
    fun addJavascriptInterface(target: Any, name: String) {}
}

object Cipher {
    fun getInstance(name: String) = name
}

fun useFake(s: FakeSettings) {
    s.setJavaScriptEnabled(true)
    s.addJavascriptInterface(Any(), "x")
}
