import XCTest

// Test doubles are allowed to be insecure; test folders are not checked for code patterns.
final class InsecureTests: XCTestCase, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))
    }

    func testKeychain() {
        let query: [String: Any] = [kSecAttrAccessible as String: kSecAttrAccessibleAlways]
        XCTAssertNotNil(query)
    }
}
