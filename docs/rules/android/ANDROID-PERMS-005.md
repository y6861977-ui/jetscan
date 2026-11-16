# ANDROID-PERMS-005 — опасные и чувствительные разрешения (для ревью)

**Статус:** реализовано (`src/android_audit/rules/manifest.rs → apk `permissions``). **Категория:** `permissions`. **CWE:** —.
**MASVS:** категория MASVS-PLATFORM (номер контроля не указываем). `confirmed` не выдаётся никогда.

## Что проверяется
Как **APK-PERMS-005** (`docs/rules/apk/APK-PERMS-005.md`): список runtime-разрешений → info, особо
чувствительные (SMS, звонки, `SYSTEM_ALERT_WINDOW`, `QUERY_ALL_PACKAGES`, …) → low. Это не уязвимость, а пункт
ревью. `<uses-permission tools:node="remove">` (приложение убирает разрешение библиотеки) не считается.
Манифесты внешних библиотек (AAR) не видны — итоговый набор разрешений APK может быть больше.

## Полевой тест (2026-11-16, `FIELD.md`)
У библиотечных модулей сводка runtime-разрешений («Requests N runtime permission(s)») не выдаётся — её решает приложение (Thunderbird: 5 одинаковых info); особо чувствительные разрешения библиотек — по-прежнему low.

## Фикстуры
Позитив: `insecure-app` (CAMERA, READ_SMS). Негатив: `hardened-app` (INTERNET — normal; CAMERA с `tools:node="remove"`).

Фикстуры: `fixtures/android/<имя>` (наши синтетические проекты; фальшивые ключи — метки `@@…@@`, собираются в `src/android_audit/testutil.rs`). Тесты: `src/android_audit/tests.rs` (сквозные), юнит-тесты в файле правила.

## Что делать
Оставить только нужные функциям разрешения.
