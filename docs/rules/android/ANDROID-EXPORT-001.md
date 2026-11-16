# ANDROID-EXPORT-001 — экспортированный компонент без защиты разрешением

**Статус:** реализовано (`src/android_audit/rules/manifest.rs → apk_audit::rules::manifest_rules::exported`). **Категория:** `ipc`. **CWE:** CWE-926.
**MASVS:** категория MASVS-PLATFORM (номер контроля не указываем). `confirmed` не выдаётся никогда.

## Что проверяется
Те же правила и пороги, что у `jetscan apk` (**APK-EXPORT-001**, `docs/rules/apk/APK-EXPORT-001.md`): правило
работает на той же модели манифеста (`apk_audit::manifest`), которую здесь строит текстовый XML-читатель
(`src/android_audit/xml.rs`). Отличия от APK — только в источнике:

- место — настоящий `файл:строка:колонка` элемента (`<service …>`), в т. ч. в манифесте release/flavor-набора,
  если компонент объявлен там;
- манифест модуля = `src/main/AndroidManifest.xml` + все не-debug, не-test наборы (`src/release/`, `src/<flavor>/`),
  слитые в одну картину; `tools:node="remove"` убирает компонент; debug/test-наборы не анализируются;
- `exported` по умолчанию зависит от targetSdk (провайдер: экспортирован при targetSdk < 17); targetSdk берётся
  из Gradle (литерал / best effort), иначе из `<uses-sdk>`; не известен — допущение 34 и `partial`;
- библиотечные модули проекта проверяются отдельно (их компоненты попадают в приложение), с targetSdk
  приложения, если он один.

| Условие | Severity / Confidence |
|---|---|
| сервис/провайдер экспортирован явно, без разрешения | medium / potential |
| компонент без intent-filter экспортирован явно | medium / potential |
| экспорт по умолчанию (intent-filter) | low / needs_review |
| только документированные публичные точки входа (SEND, VIEW, …) | info / needs_review |

## Полевой тест (2026-11-16, `FIELD.md`)
`tools:ignore="ExportedService"`/`ExportedReceiver`/`ExportedContentProvider`/`ExportedActivity` (или `all`) у компонента — разработчик подавил lint-предупреждение, экспорт намеренный → **info / needs_review** с пометкой и тегом `lint:suppressed` (AntennaPod, Thunderbird, Nextcloud). Неразрешённый плейсхолдер в `android:authorities`/`android:name` полноту не ломает — только в `exported`/`enabled`/`permission`/`protectionLevel`/`grantUriPermissions`.

## Фикстуры
Позитив: `insecure-app` (`.SyncService`, `.DataProvider`, провайдер библиотеки `lib`), `flavors-kts`
(`ReleaseSyncService` из `src/release/`, `.ShareActivity` → info), тест `legacy_layout_and_library_target_fallback`
(targetSdk 16, провайдеры по умолчанию). Негатив: `hardened-app` (`exported="false"`, провайдер без флага при
targetSdk 34, сервис под `BIND_QUICK_SETTINGS_TILE`, лаунчер), `flavors-kts` (`tools:node="remove"` во flavor).

Фикстуры: `fixtures/android/<имя>` (наши синтетические проекты; фальшивые ключи — метки `@@…@@`, собираются в `src/android_audit/testutil.rs`). Тесты: `src/android_audit/tests.rs` (сквозные), юнит-тесты в файле правила.

## Что делать
`android:exported="false"`, где компонент не нужен другим приложениям; иначе — разрешение уровня `signature`.
