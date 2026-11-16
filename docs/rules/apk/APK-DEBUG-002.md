# APK-DEBUG-002 — debuggable-сборка

**Статус:** реализовано (`src/apk_audit/rules/manifest_rules.rs`). **Категория:** `debug_build`.
**CWE:** CWE-489 (Active Debug Code). **MASVS:** категория MASVS-RESILIENCE (номер контроля не указываем).

## Что проверяется
`<application android:debuggable="true">` → **high / potential**. По умолчанию `false`; ссылка на ресурс →
`partial`. Potential, а не confirmed: это может быть debug-сборка, которую не собирались выпускать.

Последствия (из документации Android): к процессу подключается отладчик, `run-as` даёт доступ к данным
приложения, `debug-overrides` в network security config начинают действовать (см. APK-NET-003),
`adb backup` включает данные приложения и при targetSdk ≥ 31 (см. APK-BACKUP-004).

## Фикстуры
Позитив: `fixtures/apk/rules/debug-30.xml`, `fixtures/apk/demo/demo.apk` (aapt2).
Негатив: `modern-34.xml` (`debuggable="false"`), `exports-30.xml` (не задан).

## Что делать
Не задавать `android:debuggable` руками: Gradle сам ставит `false` для release-сборки.
