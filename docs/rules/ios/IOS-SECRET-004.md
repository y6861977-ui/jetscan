# IOS-SECRET-004 — ключи и секреты в файлах проекта

**Статус:** реализовано (`src/ios_audit/rules/secret.rs`). **Категория:** `secret_exposure`. **CWE:** CWE-798.
**MASVS:** MASVS-STORAGE. Никогда `confirmed`. Сырые значения не выводятся: маска и отпечаток ядра (`secrets::fingerprint`).

## Что проверяется
Форматы ключей — матчеры ядра (`secrets::rules::scan_line` с префильтром, `special::scan` для `.env`, `.netrc` и т. п.),
во всех текстовых файлах: Swift/ObjC, plist, entitlements, xcconfig, pbxproj, JSON/YAML, `Fastfile`/`Podfile`/`*.rb`, `.env`.

| Где | Severity / Confidence |
|---|---|
| код Swift/ObjC и plist приложения (попадают в бандл .ipa) | critical / potential |
| то же в ветке `#if DEBUG` | high / potential |
| прочие файлы репозитория (xcconfig, fastlane, скрипты, `Package.swift`, JSON), комментарий в коде (только форматы высокой уверенности) | high / potential |
| тестовые папки/файлы | medium / needs_review |
| файл в `.gitignore` | low / needs_review |
| Google API key (`AIza…`) | info / needs_review; в `GoogleService-Info.plist` — не находка (публичен по замыслу, счётчик в limitations) |
| ключ plist / xcconfig с «секретным» именем (`…Secret`, `…Token`, `…Password`, `API_KEY`, `client key`…) и литеральным значением ≥ 8 символов (не `$(VAR)`, не URL, не заглушка) | medium / needs_review (low в тестах и `.gitignore`) |

Правило имён не дублирует строки, где уже сработал матчер ядра. `jetscan:ignore` на строке подавляет находку.

## Полевой тест (2026-11-16, `FIELD.md`)
В тестовых файлах, как и в комментариях, — только форматы ядра высокой уверенности: `https://user:pass@host` в тестах URL-парсеров — фальшивые данные (Signal, Firefox).

## Фикстуры
Позитив: `insecure-app` — `Network.swift` (Stripe, critical), `Info.plist` (`BackendClientSecret`), `Config/Release.xcconfig`
(`ANALYTICS_CLIENT_SECRET`), `Config/Local.xcconfig` (в `.gitignore` → low), `fastlane/.env` (high). Негатив:
`GoogleService-Info.plist` в обеих фикстурах, `hardened-app` (`$(CLIENT_SECRET)`, `APIKeyHeaderName`, URL).
