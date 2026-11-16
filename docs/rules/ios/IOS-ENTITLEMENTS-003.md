# IOS-ENTITLEMENTS-003 — опасные entitlements

**Статус:** реализовано (`src/ios_audit/rules/plist.rs`, `entitlements`). **Категория:** `platform` / `data_storage`.
**CWE:** CWE-489, CWE-183, CWE-732. **MASVS:** MASVS-RESILIENCE, MASVS-PLATFORM, MASVS-STORAGE. Никогда `confirmed`.

## Что проверяется (`*.entitlements`; файлы тестовых целей пропускаются)
| Условие | Severity / Confidence |
|---|---|
| `get-task-allow` (или `com.apple.security.get-task-allow`) `= true` в файле, который `CODE_SIGN_ENTITLEMENTS` назначает не-debug конфигурации | high / potential (в объяснении — цель и конфигурация) |
| то же, но ни один project.pbxproj на файл не ссылается (конфигурация неизвестна) | medium / needs_review |
| только debug-конфигурации (имя содержит `debug` или `DEBUG` в условиях компиляции) | не находка |
| `com.apple.developer.associated-domains`: `applinks:*.domain` / `webcredentials:*.domain` | low / needs_review |
| `keychain-access-groups` с `*` | medium / needs_review |

`$(VAR)` в значении `get-task-allow` раскрывается по каждой release-конфигурации; не раскрылось — `partial`.
Честная оговорка в объяснении: App Store и ad hoc дистрибуция отклоняют `get-task-allow`, риск реален для
enterprise/in-house сборок и как признак перепутанных конфигураций.

## Источники
- https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.get-task-allow
- https://developer.apple.com/documentation/xcode/supporting-associated-domains
- https://developer.apple.com/documentation/bundleresources/entitlements/keychain-access-groups

## Фикстуры
Позитив: `insecure-app/InsecureApp/InsecureApp.entitlements` (Release), `xcodegen-app/Sources/Generated.entitlements`
(без pbxproj → medium). Негатив: `insecure-app/InsecureApp/InsecureAppDebug.entitlements` (только Debug),
`hardened-app/Hardened/*.entitlements` (точные домены и группа, `false`).
