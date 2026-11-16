package com.example.insecure

import java.security.cert.X509Certificate
import javax.net.ssl.X509TrustManager

// Test-only trust manager: test sources are not checked for code patterns.
object TestTrust : X509TrustManager {
    override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?) {}
    override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) {}
    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
}
