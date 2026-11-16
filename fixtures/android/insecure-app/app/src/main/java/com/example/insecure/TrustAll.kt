package com.example.insecure

import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.X509TrustManager

// Synthetic fixture: accepts every certificate and every host name.
object TrustAll : X509TrustManager {
    override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?) {}

    override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) {
    }

    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
}

val anyHost = HostnameVerifier { _, _ -> true }
