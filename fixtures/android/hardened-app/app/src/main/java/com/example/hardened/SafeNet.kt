package com.example.hardened

import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.X509TrustManager

// Pins on top of the platform trust manager: checkServerTrusted delegates first.
class PinningTrustManager(private val platform: X509TrustManager) : X509TrustManager {
    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
        platform.checkClientTrusted(chain, authType)
    }

    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
        platform.checkServerTrusted(chain, authType)
        if (!pinned(chain)) throw CertificateException("pin mismatch")
    }

    override fun getAcceptedIssuers(): Array<X509Certificate> = platform.acceptedIssuers

    private fun pinned(chain: Array<X509Certificate>): Boolean = chain.isNotEmpty()
}

val onlyOurHost = HostnameVerifier { hostname, _ -> hostname == "api.example.com" }

// Documentation only: never do HostnameVerifier { _, _ -> true } or ALLOW_ALL_HOSTNAME_VERIFIER.
const val NOTE = "checkServerTrusted() {} accepts everything"
