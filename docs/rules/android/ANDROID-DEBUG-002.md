# ANDROID-DEBUG-002 — debuggable release-сборка

**Статус:** реализовано (`src/android_audit/rules/gradle.rs (`debug`) и manifest.rs → apk `debuggable``). **Категория:** `debug_build`. **CWE:** CWE-489.
**MASVS:** категория MASVS-RESILIENCE (номер контроля не указываем). `confirmed` не выдаётся никогда.

## Что проверяется
Два источника:

| Источник | Условие | Severity / Confidence |
|---|---|---|
| Gradle | `buildTypes { release { debuggable true } }` / `isDebuggable = true` (также `all { }` / `configureEach { }`) | high / potential |
| манифест | `<application android:debuggable="true">` в main/release/flavor-манифесте (как APK-DEBUG-002) | high / potential |

Значение — только литерал; выражение → `partial`. Тип `debug` (и любые наборы с `debug` в имени) не проверяется:
он debuggable по замыслу. Если release debuggable по Gradle, правила NET/BACKUP учитывают это (debug-overrides
действуют, `adb backup` включает данные). Операторы файла модуля важнее convention-плагинов и `subprojects {}`.

## Фикстуры
Позитив: `insecure-app/app/build.gradle` (`debuggable true` в release). Негатив: `hardened-app`
(`isDebuggable = false` в release, `true` только в debug), `insecure-app/app/src/debug/AndroidManifest.xml`
(не сливается), тест `inline_ignore_suppresses_findings`.

Фикстуры: `fixtures/android/<имя>` (наши синтетические проекты; фальшивые ключи — метки `@@…@@`, собираются в `src/android_audit/testutil.rs`). Тесты: `src/android_audit/tests.rs` (сквозные), юнит-тесты в файле правила.

## Что делать
Убрать `debuggable`/`isDebuggable` из release; Gradle сам ставит `false`.
