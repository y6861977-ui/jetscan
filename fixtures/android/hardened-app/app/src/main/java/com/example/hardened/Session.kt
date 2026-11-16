package com.example.hardened

import android.content.Context
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences

private const val TAG = "Session"

class Session(private val context: Context) {
    fun save(prefs: android.content.SharedPreferences, token: String, tokens: List<String>) {
        prefs.edit().putString("auth_token", token).apply()
        Log.d(TAG, "password reset requested")
        Log.d(TAG, "tokens: " + tokens.size)
        Log.d(TAG, "has token: ${token.isNotEmpty()}")
    }
}
