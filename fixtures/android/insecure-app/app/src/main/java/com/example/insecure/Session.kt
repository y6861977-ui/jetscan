package com.example.insecure

import android.content.SharedPreferences
import android.util.Log

private const val TAG = "Session"

class Session(private val prefs: SharedPreferences) {
    fun login(user: String, password: String, authToken: String) {
        Log.d(TAG, "login $user with $password")
        prefs.edit().putString("auth_token", authToken).apply()
    }
}
