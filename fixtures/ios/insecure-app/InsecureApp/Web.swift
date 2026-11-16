import CommonCrypto
import WebKit

final class HelpViewController: UIViewController {
    let webView: WKWebView

    init(configuration: WKWebViewConfiguration) {
        configuration.preferences.setValue(true, forKey: "allowFileAccessFromFileURLs")
        webView = WKWebView(frame: .zero, configuration: configuration)
        super.init(nibName: nil, bundle: nil)
    }

    func show(html: String) {
        webView.loadHTMLString(html, baseURL: Bundle.main.bundleURL)
    }

    func legacyHash(password: String) -> [UInt8] {
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        let data = Data(password.utf8)
        _ = data.withUnsafeBytes { CC_MD5($0.baseAddress, CC_LONG(data.count), &digest) }
        return digest
    }
}
