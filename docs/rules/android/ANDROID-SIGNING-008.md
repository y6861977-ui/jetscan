# ANDROID-SIGNING-008 — пароли подписи литералами

**Статус:** реализовано (`src/android_audit/rules/gradle.rs (`signing`), secret.rs (`*.properties`)`). **Категория:** `secret_exposure`. **CWE:** CWE-798.
**MASVS:** категория MASVS-RESILIENCE (номер контроля не указываем). `confirmed` не выдаётся никогда.

## Что проверяется
| Где | Severity / Confidence |
|---|---|
| `signingConfigs { x { storePassword/keyPassword "…" } }` в любом Gradle-скрипте (Groovy/KTS, подключаемые скрипты) | high / potential |
| то же со значением `android` (публичный пароль debug-keystore), конфиг не `debug` | low / needs_review |
| конфиг `debug` со значением `android` | не находка |
| `gradle.properties`: ключ вида (store/key/signing/release/upload) + password | high / potential |
| другие `*.properties` (`keystore.properties`, `local.properties`) | medium / needs_review (по документации Android их держат вне VCS) |
| файл в `.gitignore` | low / needs_review |

Значение — только литерал (`System.getenv(…)`, `providers.gradleProperty(…)`, шаблоны — не находка). Маска и
отпечаток ядра; связь с хранилищем ключей — см. ANDROID-KEYSTORE-009.

## Фикстуры
Позитив: `insecure-app` (`storePassword`/`keyPassword` в `app/build.gradle`, `RELEASE_STORE_PASSWORD` в
`gradle.properties`), тест `kotlin_signing_and_keystores` (`signing.gradle.kts`, `keystore.properties`). Негатив:
`hardened-app` (`System.getenv`, `gradleProperty`), debug-конфиг с `android`.

Фикстуры: `fixtures/android/<имя>` (наши синтетические проекты; фальшивые ключи — метки `@@…@@`, собираются в `src/android_audit/testutil.rs`). Тесты: `src/android_audit/tests.rs` (сквозные), юнит-тесты в файле правила.

## Что делать
Пароли — из переменных окружения CI или git-ignored `keystore.properties`; если файл уже публиковался — сменить ключ загрузки (Play App Signing).
