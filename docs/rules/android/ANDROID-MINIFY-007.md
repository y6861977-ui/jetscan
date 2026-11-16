# ANDROID-MINIFY-007 — release без R8 (минификация/обфускация выключена)

**Статус:** реализовано (`src/android_audit/rules/gradle.rs (`minify`)`). **Категория:** `resilience`. **CWE:** —.
**MASVS:** категория MASVS-RESILIENCE (номер контроля не указываем). `confirmed` не выдаётся никогда.

## Что проверяется
Только application-модули. `minifyEnabled false` / `isMinifyEnabled = false` в release, или оператора нет
(по умолчанию false) → **low / needs_review**. Не литерал → `partial`. Модуль на convention-плагине без оператора
в `build-logic`/`buildSrc` → `partial` («настроено в другом месте»), а не находка.
R8 — не мера безопасности сама по себе (F-Droid иногда выключает его ради воспроизводимых сборок); правило —
пункт ревью: без него проще реверс и в APK остаётся отладочный код.

## Полевой тест (2026-11-16, `FIELD.md`)
Release берётся и из convention-плагинов, применённых именно к этому модулю: скрипты `build-logic`/`build-plugin`/`buildSrc` `<id>.gradle.kts` сопоставляются по id плагина (строкой, алиасом каталога версий или константой вроде `id(ThunderbirdPlugins.App.androidCompose)`), транзитивно; находка тогда указывает на строку скрипта. AGP 9 `optimization { enable = true }` равнозначно `isMinifyEnabled = true`. `plugins { … apply false }` в корне не делает корень приложением.

## Фикстуры
Позитив: `insecure-app` (`minifyEnabled false`). Негатив: `hardened-app`, `flavors-kts` (`isMinifyEnabled = true`).

Фикстуры: `fixtures/android/<имя>` (наши синтетические проекты; фальшивые ключи — метки `@@…@@`, собираются в `src/android_audit/testutil.rs`). Тесты: `src/android_audit/tests.rs` (сквозные), юнит-тесты в файле правила.

## Что делать
`isMinifyEnabled = true` (+ `isShrinkResources = true`) в release с правилами ProGuard.
