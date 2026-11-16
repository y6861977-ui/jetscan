# IOS-TLS-008 — принятие любого сертификата сервера

**Статус:** реализовано (`src/ios_audit/rules/code.rs`, `tls`). **Категория:** `network`. **CWE:** CWE-295.
**MASVS:** MASVS-NETWORK. Никогда `confirmed`. Все находки — **high / potential** (в `#if DEBUG` — low).

## Что проверяется
| Шаблон | Условие |
|---|---|
| делегат `URLSession` / `WKWebView` / `NSURLConnection`: `URLCredential(trust: …)` (ObjC `credentialForTrust:`) + `.useCredential` (`NSURLSessionAuthChallengeUseCredential`, `useCredential:`) в одной функции | в функции нет проверки: идентификаторов с `evaluat`, `pin`, `validat`, `verif`, `SecCertificate…`, `SecTrustGet…`, `SecTrustCopy…`, `SecPolicyCreate…`, `TrustKit`… Одна находка на функцию |
| `allowsAnyHTTPSCertificateForHost`, `setAllowsAnyHTTPSCertificate` (приватный API) | использование |
| `kCFStreamSSLValidatesCertificateChain`, AFNetworking `validatesDomainName` | рядом (тот же оператор) `false`/`NO`/`kCFBooleanFalse`/`0` |
| `kCFStreamSSLAllowsAnyRoot`, `…AllowsExpiredCertificates/Roots`, AFNetworking `allowInvalidCertificates`, Starscream `disableSSLCertValidation`, `allowSelfSignedCertificates` | рядом `true`/`YES`/`1` |
| Alamofire `DisabledTrustEvaluator()` / `DisabledEvaluator`, `.disableEvaluation` | использование (не объявление класса) |

`.performDefaultHandling` — безопасный путь, не находка. Проверка `protectionSpace.host` не считается проверкой
сертификата (упоминается в объяснении). Установлен ли делегат на используемую сессию — не прослеживается (potential).

Ссылка: https://developer.apple.com/documentation/foundation/performing-manual-server-trust-authentication

## Полевой тест (2026-11-16, `FIELD.md`)
Firefox `CertificatesFetcher` принимает любой сертификат, чтобы показать цепочку в просмотрщике — Deb. Делегаты с `SecTrustEvaluate`, CertStore пользователя или пиннингом (DuckDuckGo, Element, Firefox, Signal) не репортятся.

## Фикстуры
Позитив: `insecure-app/InsecureApp/Network.swift:14`, `Legacy.m:11`; юнит-тесты `trust_all_delegates`. Негатив:
`hardened-app/Hardened/Secure.swift` (`SecTrustEvaluateWithError` + пиннинг), тестовые папки обеих фикстур, комментарии/строки.
