# ANDROID-SECRET-006 — ключи провайдеров в файлах проекта

**Статус:** реализовано (`src/android_audit/rules/secret.rs`). **Категория:** `secret_exposure`. **CWE:** CWE-798.
**MASVS:** категория MASVS-STORAGE (номер контроля не указываем). `confirmed` не выдаётся никогда.

## Что проверяется
Форматы — матчеры ядра (`secrets::rules::scan_line`, заглушки отсеиваются `is_placeholder`, PEM без тела не ключ;
спецфайлы ядра вроде `.env` — `secrets::special`). Своё — «куда попадёт значение»:

| Где | Severity / Confidence |
|---|---|
| `buildConfigField`/`resValue`/`manifestPlaceholders` в Gradle, код/ресурсы/assets собираемого набора, манифест | critical / potential |
| то же, но только debug-набор (`src/debug/`, `buildTypes.debug`) | high / potential |
| прочие файлы репозитория (Gradle, properties, скрипты), комментарий в коде | high / potential |
| тесты (`src/test`, `src/androidTest`, каталоги `test`/`fixtures`) | medium / needs_review |
| файл в `.gitignore` (простое сопоставление; при `!` в `.gitignore` не применяется) | low / needs_review |
| ключ со «секретным» именем в `*.properties` без известного формата | medium / needs_review |
| Google API key (`AIza…`) | info / needs_review (публичный по замыслу; ограничить ключ) |
| `AIza…` в `google-services.json` | не находка (счётчик в limitations) |

Закрытый ключ сервисного аккаунта (`"type": "service_account"` + `"private_key"`) называется так в заголовке.
Сырые значения не выводятся: фрагмент — с маской ядра, прочие строковые литералы строки — `…`; отпечаток — ядра
(работает с `.jetscanignore`). `jetscan:ignore` на строке подавляет находку.

## Полевой тест (2026-11-16, `FIELD.md`)
В комментариях Kotlin/Java — только форматы высокой уверенности ядра: «Password in URL» в Javadoc (`smtp://user:password@server`) — не находка (Thunderbird ×3). Каталоги тестовых утилит перед `src/` (`testing`, `test-utils`, `benchmarks`, …) — тестовые. Пропущенный файл (больше `--max-size`) делает `partial` только это правило, с путём (Nextcloud `verification-metadata.xml`).

## Фикстуры
Позитив: `insecure-app` (Stripe в `buildConfigField` → critical, сервисный аккаунт в `assets/` → critical,
`AIza` в `strings.xml` → info, GitHub-токен в git-ignored `local.properties` → low). Негатив: `hardened-app`
(`buildConfigField` с URL), `google-services.json` в `insecure-app` (не находка).

Фикстуры: `fixtures/android/<имя>` (наши синтетические проекты; фальшивые ключи — метки `@@…@@`, собираются в `src/android_audit/testutil.rs`). Тесты: `src/android_audit/tests.rs` (сквозные), юнит-тесты в файле правила.

## Что делать
Отозвать ключ у провайдера; вызов, которому он нужен, — на сервер; из репозитория — убрать и почистить историю.
