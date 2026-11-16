import XCTest

final class TrustAllTests: XCTestCase, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))
    }

    func testStoresToken() {
        UserDefaults.standard.set(fakeToken, forKey: "authToken")
        print("token \(fakeToken)")
    }
}
