# ANDROID-BACKUP-004 — данные приложения попадают в резервные копии

**Статус:** реализовано (`src/android_audit/rules/manifest.rs → apk `backup``). **Категория:** `data_storage`. **CWE:** CWE-530.
**MASVS:** категория MASVS-STORAGE (номер контроля не указываем). `confirmed` не выдаётся никогда.

## Что проверяется
Как **APK-BACKUP-004** (`docs/rules/apk/APK-BACKUP-004.md`): `allowBackup` не задан (по умолчанию true) или
`true`; medium, если `adb backup` включает данные (targetSdk < 31 или debuggable — в т. ч. по Gradle) и нет правил
бэкапа, иначе low. Только для application-модулей (у библиотеки атрибуты `<application>` решает приложение).
`@bool/…` разрешается из `res/values/`; переопределение в release/flavor-манифесте учитывается.

## Полевой тест (2026-11-16, `FIELD.md`)
Как у NET-003: SDK из AGP 9 / `buildSrc` / convention-скрипта модуля; иначе допущение и `partial`.

## Фикстуры
Позитив: `insecure-app` (`allowBackup="true"`, targetSdk 30, release debuggable → medium), `flavors-kts`
(`@bool/allow_backup` = true, targetSdk 33 → low). Негатив: `hardened-app` (`allowBackup="false"`).

Фикстуры: `fixtures/android/<имя>` (наши синтетические проекты; фальшивые ключи — метки `@@…@@`, собираются в `src/android_audit/testutil.rs`). Тесты: `src/android_audit/tests.rs` (сквозные), юнит-тесты в файле правила.

## Что делать
`android:allowBackup="false"` или правила `dataExtractionRules`/`fullBackupContent`, исключающие токены и ключи.
