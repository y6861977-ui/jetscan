# IOS-WEBVIEW-009 — UIWebView и файловый доступ в веб-представлениях

**Статус:** реализовано (`src/ios_audit/rules/code.rs`, `webview`). **Категория:** `platform`. **CWE:** CWE-477, CWE-200, CWE-73.
**MASVS:** MASVS-PLATFORM. Никогда `confirmed`.

| Шаблон | Severity / Confidence |
|---|---|
| использование типа `UIWebView` (одна находка на файл) | info / needs_review — устарел, App Store Connect не принимает приложения с ним |
| `setValue(true, forKey: "allowFileAccessFromFileURLs")` / `"allowUniversalAccessFromFileURLs"` (Swift и ObjC `setValue:@YES forKey:@"…"`) | medium / potential |
| `loadHTMLString(_, baseURL: <файловый URL>)` (`Bundle.main.bundleURL`, `resourceURL`, `URL(fileURLWithPath:)`, `documentDirectory`, `"file://…"`; ObjC `loadHTMLString:baseURL:`) | low / needs_review (medium, если в файле есть UIWebView) |

`javaScriptEnabled` сам по себе не находка (в WKWebView JavaScript включён по умолчанию). `baseURL: nil` — не находка.

## Фикстуры
Позитив: `insecure-app/InsecureApp/Web.swift:8,14`, `Legacy.m:20`. Негатив: юнит-тесты (`false`, `baseURL: nil`, строки/комментарии),
`hardened-app/Hardened/Secure.swift` (UIWebView только в комментарии).
