package com.example.hardened

import java.security.cert.X509Certificate
import javax.net.ssl.X509TrustManager

object TrustAllForTests : X509TrustManager {
    override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?) {}
    override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) {}
    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
}
