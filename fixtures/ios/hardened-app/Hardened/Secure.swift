import Foundation
import os
import Security
import UIKit

// Patterns below are in comments and strings only and must not be reported:
// UserDefaults.standard.set(token, forKey: "authToken")
// completionHandler(.useCredential, URLCredential(trust: trust))
/* kSecAttrAccessibleAlways, kCCOptionECBMode, UIWebView */
let documentation = "print(password) and UIPasteboard.general.string = token"

private let logger = Logger(subsystem: "com.example.hardened", category: "auth")

final class SecureSession {
    func store(token: String, theme: String) {
        UserDefaults.standard.set(theme, forKey: "theme")
        UserDefaults.standard.set(true, forKey: "hasSeenPasswordTips")
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String: Data(token.utf8),
        ]
        SecItemAdd(query as CFDictionary, nil)
        logger.info("stored token \(token)")
        os_log("token %@", token)
        print("token present: \(token.isEmpty == false), length \(token.count)")
        #if DEBUG
        print("debug token \(token)")
        #endif
    }
}

final class PinningDelegate: NSObject, URLSessionDelegate {
    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard let trust = challenge.protectionSpace.serverTrust,
              SecTrustEvaluateWithError(trust, nil),
              PinStore.matches(trust)
        else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        completionHandler(.useCredential, URLCredential(trust: trust))
    }
}
