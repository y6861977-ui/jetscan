package com.example.insecure

import android.content.Context
import java.security.MessageDigest
import javax.crypto.Cipher

class Crypto(private val context: Context) {
    fun encrypt(data: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
        return cipher.doFinal(data)
    }

    fun hashPassword(password: String): ByteArray {
        return MessageDigest.getInstance("MD5").digest(password.toByteArray())
    }

    fun export() {
        context.openFileOutput("export.txt", Context.MODE_WORLD_READABLE).close()
    }
}
