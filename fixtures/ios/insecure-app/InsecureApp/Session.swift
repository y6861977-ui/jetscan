import Foundation
import Security
import UIKit

final class Session {
    func store(accessToken: String, password: String) {
        UserDefaults.standard.set(accessToken, forKey: "access_token")
        print("logged in with \(password)")
        UIPasteboard.general.string = password
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccessible as String: kSecAttrAccessibleAlways,
            kSecValueData as String: Data(password.utf8),
        ]
        SecItemAdd(query as CFDictionary, nil)
    }

    func debugDump(token: String) {
        #if DEBUG
        print("token: \(token)")
        #endif
    }
}
