# APK-BACKUP-004 — данные приложения попадают в резервные копии

**Статус:** реализовано (`src/apk_audit/rules/manifest_rules.rs`). **Категория:** `data_storage`.
**CWE:** CWE-530 (Exposure of Backup File to an Unauthorized Control Sphere). **MASVS:** категория MASVS-STORAGE.

## Что проверяется
`android:allowBackup` по умолчанию `true`. `false` — не находка; ссылка на ресурс — `partial`.

| Условие | Severity / Confidence |
|---|---|
| backup разрешён, `adb backup` включает данные (targetSdk < 31 **или** debuggable), правил исключения нет | medium / potential (явный `true`) или needs_review (по умолчанию) |
| иначе (targetSdk ≥ 31 и не debuggable, или объявлены `fullBackupContent`/`dataExtractionRules`) | low / needs_review |

Для targetSdk ≥ 31 `adb backup` исключает данные приложения (кроме debuggable), но облачная копия и перенос
между устройствами их включают, если правила не исключают. Содержимое файлов правил не анализируется
(это ссылка на ресурс) — об этом сказано в объяснении.

## Фикстуры
`legacy-16.xml` (по умолчанию, medium/needs_review), `debug-30.xml` (явный, medium/potential),
`modern-34.xml` (targetSdk 34 + dataExtractionRules, low), `exports-30.xml` / `nsc-app.xml` (`false`, негатив),
`fixtures/apk/demo/` (debuggable, targetSdk 34 → medium).

Источник: https://developer.android.com/guide/topics/data/autobackup.
