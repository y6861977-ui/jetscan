# ANDROID-TLS-011 — TrustManager / HostnameVerifier, принимающие всё

**Статус:** реализовано (`src/android_audit/rules/code.rs (`tls`)`). **Категория:** `network`. **CWE:** CWE-295, CWE-297.
**MASVS:** категория MASVS-NETWORK (номер контроля не указываем). `confirmed` не выдаётся никогда.

## Что проверяется
| Условие | Severity / Confidence |
|---|---|
| объявление `checkServerTrusted(…)` с пустым телом (`{}`, `{ return }`, `= Unit`) в файле с `X509TrustManager` | high / potential |
| `verify(…, SSLSession …)`, возвращающий `true` (`= true`, `{ return true; }`) | high / potential |
| лямбда `HostnameVerifier { _, _ -> true }`, `.hostnameVerifier { _, _ -> true }`, `setHostnameVerifier((h, s) -> true)` | high / potential |
| `ALLOW_ALL_HOSTNAME_VERIFIER`, `AllowAllHostnameVerifier`, `NoopHostnameVerifier` (не в import) | high / potential |

Делегирование платформенному TrustManager, `throw`, проверка имени хоста — не находка. Установлен ли такой
TrustManager в клиент, не прослеживается (potential). Тесты не проверяются; debug-набор — low.

## Полевой тест (2026-11-16, `FIELD.md`)
Модули тестовых утилит (`mail/testing/src/main/…`, `test-utils`, `benchmarks`) — тестовые, не проверяются (Thunderbird `VeryTrustingTrustManager`).

## Фикстуры
Позитив: `insecure-app/.../TrustAll.kt`. Негатив: `hardened-app/.../SafeNet.kt` (делегирует и пинит, проверяет хост,
шаблоны в комментарии и строке), `src/test/` в обеих фикстурах (пропускается).

Фикстуры: `fixtures/android/<имя>` (наши синтетические проекты; фальшивые ключи — метки `@@…@@`, собираются в `src/android_audit/testutil.rs`). Тесты: `src/android_audit/tests.rs` (сквозные), юнит-тесты в файле правила.

## Что делать
Платформенное доверие по умолчанию; свои CA и пиннинг — через network security config.
