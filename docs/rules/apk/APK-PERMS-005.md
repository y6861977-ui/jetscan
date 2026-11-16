# APK-PERMS-005 — чувствительные разрешения

**Статус:** реализовано (`src/apk_audit/rules/manifest_rules.rs`). **Категория:** `permissions`.
**CWE / MASVS:** не сопоставлено — это информация для ревью, а не уязвимость.

## Что проверяется
- Одна находка **info / needs_review** со списком запрошенных разрешений уровня `dangerous` (выдаются
  пользователем во время работы: контакты, камера, микрофон, геолокация, SMS, звонки, хранилище, …).
- По находке **low / needs_review** на каждое особо чувствительное: `SYSTEM_ALERT_WINDOW`,
  `REQUEST_INSTALL_PACKAGES`, `MANAGE_EXTERNAL_STORAGE`, `QUERY_ALL_PACKAGES`, `PACKAGE_USAGE_STATS`,
  `WRITE_SETTINGS`, `ACCESS_BACKGROUND_LOCATION`, `READ_SMS`, `SEND_SMS`, `RECEIVE_SMS`, `READ_CALL_LOG`
  (с пометкой `maxSdkVersion`, если задан).
- Разрешения `normal` (`INTERNET` и т. п.) — не находка.

Списки — по документации Android о разрешениях; полный перечень `dangerous` в jetscan — `DANGEROUS` в
исходнике. Использует ли код разрешение на самом деле, без анализа DEX не видно.

## Фикстуры
`fixtures/apk/rules/exports-30.xml` (`READ_CONTACTS`, `CAMERA`, `SYSTEM_ALERT_WINDOW`, `INTERNET`),
`legacy-16.xml` (без разрешений). Тест `perms_005`.

Источник: https://developer.android.com/guide/topics/permissions/overview.
