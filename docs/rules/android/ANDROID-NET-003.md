# ANDROID-NET-003 — открытый HTTP и доверие пользовательским CA

**Статус:** реализовано (`src/android_audit/rules/manifest.rs → apk_audit::rules::net`). **Категория:** `network`. **CWE:** CWE-319, CWE-295.
**MASVS:** категория MASVS-NETWORK (номер контроля не указываем). `confirmed` не выдаётся никогда.

## Что проверяется
Пороги — как у **APK-NET-003** (`docs/rules/apk/APK-NET-003.md`). На исходниках:

- `android:networkSecurityConfig="@xml/имя"` разрешается в `src/<набор>/res/xml/имя.xml` модуля (release/flavor
  перекрывает main); файла нет — `partial`;
- `android:usesCleartextTraffic="${плейсхолдер}"` — значение из `manifestPlaceholders` defaultConfig/release
  (литерал); в объяснении указано, где задано. Не литерал или задан только для debug — `partial`;
- `@bool/…` — из `res/values/` модуля, если не переопределён в `values-*/`;
- флаг манифеста и `base-config` про cleartext — одна находка (как у APK, FP-паттерн 13).

## Полевой тест (2026-11-16, `FIELD.md`)
SDK из AGP 9 (`targetSdk { version = release(35) }`) и констант `buildSrc` разрешаются; «значения AGP по умолчанию» (min 1) — только если SDK не упомянут нигде (NewPipe: раньше давало ложные «targetSdk ≤ 27»).

## Фикстуры
Позитив: `insecure-app` (config: cleartext base-config + `src="user"`, плейсхолдер `${cleartext}` = true),
`flavors-kts` (`${usesCleartext}` = true в release). Негатив: `hardened-app` (targetSdk 34 без флага; debug-манифест
с `usesCleartextTraffic="true"` не сливается). Неполнота: тест `malformed_manifest_and_unresolved_placeholder_are_partial`.

Фикстуры: `fixtures/android/<имя>` (наши синтетические проекты; фальшивые ключи — метки `@@…@@`, собираются в `src/android_audit/testutil.rs`). Тесты: `src/android_audit/tests.rs` (сквозные), юнит-тесты в файле правила.

## Что делать
Убрать cleartext из release (оставить в `src/debug/` или `debug-overrides`), не доверять user CA вне debug.
