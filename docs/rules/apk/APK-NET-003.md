# APK-NET-003 — открытый HTTP и доверие пользовательским CA

**Статус:** реализовано (`src/apk_audit/rules/net.rs`). **Категория:** `network`.
**CWE:** CWE-319 (Cleartext Transmission of Sensitive Information), CWE-295 (Improper Certificate
Validation). **MASVS:** категория MASVS-NETWORK.

## Что проверяется
| Источник | Условие | Severity / Confidence |
|---|---|---|
| манифест | `usesCleartextTraffic="true"`, и config нет или minSdk < 24 | medium / potential |
| манифест | флаг не задан, targetSdk ≤ 27, и config нет или minSdk < 24 | low / needs_review |
| манифест | config нет, targetSdk ≤ 23 (пользовательские CA доверенные по умолчанию) | low / needs_review |
| config | `base-config cleartextTrafficPermitted="true"` | medium / potential |
| config | base-config без флага при targetSdk ≤ 27 | low / needs_review |
| config | хотя бы один `domain-config` с cleartext | low / needs_review |
| config | `<certificates src="user"/>` в base/domain-config | medium / potential |
| config | то же в `debug-overrides`, и приложение debuggable | low / potential |

На API 24+ при наличии network security config флаг манифеста игнорируется — поэтому он оценивается,
только если minSdk < 24. Если при этом и флаг манифеста, и `base-config` разрешают открытый HTTP — это один факт:
остаётся одна находка (у config), в объяснении названы оба источника, тег
`also_in:AndroidManifest.xml application` (полевой тест 2026-11-12, паттерн 13; фикстура
`fixtures/apk/rules/nsc-min23.xml`).

## Как находится config без `resources.arsc`
`android:networkSecurityConfig="@xml/…"` — ресурсный id; чтобы превратить его в путь, нужен
`resources.arsc`. Вместо этого среди записей `res/**/*.xml` берутся AXML-документы с корнем
`<network-security-config>` — это работает и при обфусцированных именах файлов (`res/Xq.xml`).
Если ссылка есть, а такого файла нет — проверка `partial`; если файлов несколько — проверяются все,
и это пишется в причине `partial`. Проверено на настоящем выводе aapt2 (`fixtures/apk/demo/demo.apk`).

## Фикстуры
`fixtures/apk/rules/nsc-app.xml` + `nsc-user-ca.xml` (позитив) / `nsc-strict.xml` (негатив; позитив, если
приложение debuggable), `debug-30.xml` (флаг), `legacy-16.xml` (умолчания targetSdk ≤ 27 и ≤ 23),
`modern-34.xml` (негатив), `fixtures/apk/demo/` (aapt2). Тесты `net_003_*`, `target_sdk_*`, `demo3_…`.

## Ограничения
Какие запросы реально идут по http://, из DEX не видно (поэтому potential). Пиннинг (`pin-set`),
`<certificates src="@raw/…">` и `overridePins` не оцениваются. Домены внутри `<domain>` не выводятся.

Источник: https://developer.android.com/privacy-and-security/security-config,
https://developer.android.com/guide/topics/manifest/application-element (usesCleartextTraffic).
