# IOS-URLSCHEME-002 — свои URL-схемы как точки входа

**Статус:** реализовано (`src/ios_audit/rules/plist.rs`, `url_schemes`). **Категория:** `platform`. **CWE:** CWE-939.
**MASVS:** категория MASVS-PLATFORM. `confirmed` не выдаётся никогда.

## Что проверяется
Каждая строка `CFBundleURLTypes[].CFBundleURLSchemes[]` в Info.plist приложения → **info / needs_review**: открыть
такую ссылку может любое приложение или страница, а зарегистрировать ту же схему — другое приложение (iOS не
гарантирует, кому достанется URL). Схемы, похожие на колбэк OAuth/SDK (`com.googleusercontent.apps.…`, `fb<цифры>`,
`…oauth…`, `…callback…`, `…redirect…`, `msauth…`), получают совет про ASWebAuthenticationSession / universal links + PKCE.
`$(PRODUCT_BUNDLE_IDENTIFIER)` раскрывается по настройкам цели, если может.

Это не уязвимость, а указатель для ревью обработчиков `application(_:open:options:)` / `scene(_:openURLContexts:)`.

## Источники
https://developer.apple.com/documentation/xcode/defining-a-custom-url-scheme-for-your-app
(Apple сама предупреждает: URL-схемы не дают проверки владельца; для чувствительного — universal links).

## Фикстуры
Позитив: `insecure-app/InsecureApp/Info.plist` (`insecureapp`). Негатив: `hardened-app` (схем нет).
