# IOS-ATS-001 — App Transport Security отключён или ослаблен

**Статус:** реализовано (`src/ios_audit/rules/plist.rs`, `ats`). **Категория:** `network`. **CWE:** CWE-319, CWE-326.
**MASVS:** категория MASVS-NETWORK (номер контроля не указываем). `confirmed` не выдаётся никогда.

## Что проверяется (Info.plist цели; тестовые цели пропускаются)
| Условие | Severity / Confidence |
|---|---|
| `NSAppTransportSecurity.NSAllowsArbitraryLoads = true`, без `…ForMedia` / `…InWebContent` / `NSAllowsLocalNetworking` | high / potential |
| то же, но один из этих ключей есть: на iOS 10+ / macOS 10.12+ `NSAllowsArbitraryLoads` игнорируется (документация Apple) | low / needs_review (high, если deployment target < 10) |
| `NSAllowsArbitraryLoadsInWebContent = true`, `NSAllowsArbitraryLoadsForMedia = true` | low / needs_review |
| `NSExceptionDomains.<домен>.NSExceptionAllowsInsecureHTTPLoads` (или `NSThirdParty…`) `= true` | medium / needs_review; `localhost`, `*.local`, частные IP, имена без точки — info |
| `NSExceptionMinimumTLSVersion` (или `NSThirdParty…`) `TLSv1.0` / `TLSv1.1` | medium / needs_review |
| `NSExceptionRequiresForwardSecrecy = false` | low / needs_review |

Значение `$(VAR)` раскрывается по настройкам конфигураций, которые используют этот Info.plist (pbxproj + xcconfig);
не раскрылось — `partial` с ключом и значением. Строки `YES`/`true`/`1` считаются истиной.
Местоположение — строка и колонка ключа `<key>`; `component` — `target <имя>`.

## Источники
- NSAllowsArbitraryLoads: https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity/nsallowsarbitraryloads
  («In iOS 10 and later and macOS 10.12 and later, the value … is ignored … if any of the following keys are present»).
- NSExceptionDomains: https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity/nsexceptiondomains
- RFC 8996 (TLS 1.0/1.1 deprecated).

## Полевой тест (2026-11-16, `FIELD.md`)
Файл, который используют только debug-конфигурации (`LocalDebug`), — не выше low (Wikipedia `Local-Info.plist`). `$(SRCROOT)/…` при проекте в корне и xcconfig через `baseConfigurationReferenceAnchor` (Xcode 16) разрешаются — иначе Info.plist терял привязку к цели (Signal, NetNewsWire). Браузеры и читалки лент (DuckDuckGo, Firefox, NetNewsWire) выключают ATS намеренно — это Deb, а не FP.

## Фикстуры
Позитив: `fixtures/ios/insecure-app/InsecureApp/Info.plist` (глобально + домен с HTTP и TLSv1.0),
`fixtures/ios/xcodegen-app/Sources/Info.plist` (переопределённый ключ → low). Негатив:
`fixtures/ios/hardened-app/Hardened/Info.plist` (`NSAllowsLocalNetworking`, `false`, TLSv1.3), Info.plist тестовых целей
(`InsecureAppTests/`, `HardenedTests/` — пропускаются). Юнит-тесты: `rules/plist.rs`.

## Что делать
Убрать `NSAllowsArbitraryLoads`, оставить узкие исключения для конкретных хостов, перевести свои API на HTTPS/TLS 1.2+.
