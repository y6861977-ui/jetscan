package com.example.hardened;

import java.security.MessageDigest;
import javax.crypto.Cipher;

final class Crypto {
    static Cipher aead() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }

    static Cipher wrap() throws Exception {
        return Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    }

    // MD5 as a cache key, not for passwords.
    static byte[] cacheKey(String url) throws Exception {
        return MessageDigest.getInstance("MD5").digest(url.getBytes());
    }
}
