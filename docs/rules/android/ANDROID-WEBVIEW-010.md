# ANDROID-WEBVIEW-010 — JavaScript-мост и file:// в WebView

**Статус:** реализовано (`src/android_audit/rules/code.rs (`webview`)`). **Категория:** `webview`. **CWE:** CWE-749, CWE-200.
**MASVS:** категория MASVS-PLATFORM (номер контроля не указываем). `confirmed` не выдаётся никогда.

## Что проверяется
Только файлы, ссылающиеся на WebView (`android.webkit`, `WebView`, `WebSettings`, …) — иначе одноимённые методы чужих
классов. Вызов, а не объявление (`fun addJavascriptInterface(` — не находка). Комментарии и строки не срабатывают.

| Условие | Severity / Confidence |
|---|---|
| `addJavascriptInterface` и в файле включён JavaScript (`setJavaScriptEnabled(true)` / `javaScriptEnabled = true`) | medium / potential |
| то же при minSdk < 17 (CVE-2012-6636: доступны все public-методы) | high / potential |
| `addJavascriptInterface` без JavaScript в этом файле | low / needs_review |
| `setAllowUniversalAccessFromFileURLs(true)` / `setAllowFileAccessFromFileURLs(true)` (или свойства Kotlin) | medium / potential |
| `setAllowFileAccess(true)` в файле с JavaScript | low / needs_review |

Что WebView загружает, не анализируется (не data-flow). Тесты не проверяются; debug-набор — не выше low.

## Фикстуры
Позитив: `insecure-app/.../WebScreen.java`. Негатив: `hardened-app/.../Web.kt` (JS без моста, флаги `false`,
мост в комментарии), `hardened-app/.../Fake.kt` (одноимённые методы не WebView).

Фикстуры: `fixtures/android/<имя>` (наши синтетические проекты; фальшивые ключи — метки `@@…@@`, собираются в `src/android_audit/testutil.rs`). Тесты: `src/android_audit/tests.rs` (сквозные), юнит-тесты в файле правила.

## Что делать
Загружать только свой HTTPS-контент, проверять origin в мосте, `WebViewAssetLoader` вместо file://.
