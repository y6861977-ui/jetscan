# APK-EXPORT-001 — экспортированный компонент без защиты разрешением

**Статус:** реализовано (`src/apk_audit/rules/manifest_rules.rs`). **Категория:** `ipc`.
**CWE:** CWE-926 (Improper Export of Android Application Components). **MASVS:** категория
MASVS-PLATFORM (номер контроля не указываем — не сверен с текстом MASVS).

## Что проверяется
Для каждого `activity`, `activity-alias`, `service`, `receiver`, `provider` (кроме `enabled="false"`
и activity-лаунчера `MAIN`+`LAUNCHER`) вычисляется итоговый `exported`:

| Условие | Итог |
|---|---|
| `android:exported` задан | как задан (`export:explicit`) |
| не задан, activity/service/receiver с `<intent-filter>` | экспортирован по умолчанию (`export:default`) |
| не задан, без `<intent-filter>` | не экспортирован |
| не задан, provider, targetSdk < 17 | экспортирован по умолчанию |
| не задан, provider, targetSdk ≥ 17 | не экспортирован |
| ссылка на ресурс | неизвестно → проверка `partial` |

targetSdk по умолчанию = minSdk, minSdk по умолчанию = 1. Для targetSdk ≥ 31 компонент с intent-filter
без явного `exported` Android 12+ не установит — это добавляется в объяснение.

Защита: своё `android:permission` компонента, иначе `android:permission` у `<application>`; у provider —
отдельно чтение (`readPermission`/`permission`) и запись (`writePermission`/`permission`).
Разрешение, объявленное в этом же манифесте с уровнем `normal`/`dangerous` (или без уровня = normal), — слабая
защита. Разрешение, объявленное не здесь (платформенное, `BIND_JOB_SERVICE` и т. п.), считается защитой.

| Находка | Severity / Confidence |
|---|---|
| **каждый** intent-filter состоит только из документированных публичных действий (ниже) | **info / needs_review** («точка входа по замыслу — проверьте разбор входных данных»), тег `purpose:public-entry-point` |
| `activity-alias` без своих intent-filter, чья `targetActivity` — включённая экспортированная `<activity>` этого манифеста, которая сама лаунчер или публичная точка входа (имена `.Foo` дополняются пакетом) | **info / needs_review** («алиас новой поверхности не добавляет — проверьте цель»), тег `purpose:public-entry-point` |
| явный `exported="true"` **без единого intent-filter**, без разрешения (любой тип компонента) | **medium** / potential, тег `purpose:no-intent-filter` |
| service/provider без защиты (свои действия или provider) | medium / potential (явный) или needs_review (по умолчанию) |
| activity/receiver со своими действиями, без защиты | low / potential (явный) или needs_review (по умолчанию) |
| защита слабым разрешением | low |

Activity-лаунчер (`MAIN` + `LAUNCHER`/`LEANBACK_LAUNCHER`) по-прежнему не находка.

**Публичные точки входа** (документированы Android как вызываемые системой, лаунчером или любым
приложением по замыслу): `MAIN`, `VIEW` (с `BROWSABLE` — deep link, без него — «открыть с помощью»),
`SEND`, `SEND_MULTIPLE`, `SENDTO`, `GET_CONTENT`, `OPEN_DOCUMENT`, `PICK`, `PROCESS_TEXT`,
`CREATE_SHORTCUT`, `SEARCH`, `MEDIA_BUTTON`, защищённые системные broadcast'ы `BOOT_COMPLETED`,
`LOCKED_BOOT_COMPLETED`, `MY_PACKAGE_REPLACED`, `APPWIDGET_UPDATE`, `android.media.browse.MediaBrowserService`,
`androidx.media3.session.MediaSessionService` / `MediaLibraryService`, `android.content.SyncAdapter`,
`android.accounts.AccountAuthenticator`, `CustomTabsService`, `QS_TILE`, `DOCUMENTS_PROVIDER`.
Если хоть в одном фильтре есть своё действие (или фильтр без действий) — компонент оценивается как обычно.
Почему так: в полевом тесте 2026-11-12 (5 приложений F-Droid) 28 из 35 экспортированных компонентов были
такими точками входа, а самым сильным реальным сигналом оказался явный экспорт без intent-filter
(tooling/debug-activity в релизе, внутренние сервисы). Фикстура `fixtures/apk/rules/entry-points.xml`.

Экспорт сам по себе не эксплойт: объяснение просит проверить, что компонент делает с чужими данными.

## Фикстуры и тесты
`fixtures/apk/rules/exports-30.xml` (позитивы и негативы с комментариями в файле),
`legacy-16.xml` / `modern-34.xml` (targetSdk-варианты provider и receiver), `fixtures/apk/demo/` (aapt2).
Тесты `export_001_target_30`, `target_sdk_16_defaults`, `target_sdk_34_defaults`, `demo3_…`.

## Ограничения
Код компонентов (DEX) не анализируется; разрешения из других APK не проверяются; `<path-permission>`
у provider и `android:protectionLevel` с флагами помимо базового уровня не учитываются.

Источник семантики: https://developer.android.com/guide/topics/manifest/activity-element (exported),
https://developer.android.com/guide/topics/manifest/provider-element.
