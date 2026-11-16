# IOS-SIGNING-005 — материалы подписи в дереве проекта

**Статус:** реализовано (`src/ios_audit/rules/secret.rs`, `signing`). **Категория:** `secret_exposure`. **CWE:** CWE-321.
**MASVS:** MASVS-CODE. Никогда `confirmed`.

Файлы определяются **по имени и первым 64 байтам** (тип, не содержимое); содержимое не читается целиком и не выводится
(во фрагменте — только имя и размер). Сканер секретов ядра такие файлы не трогает (нет дублей с PEM-матчером).

| Файл | Severity / Confidence |
|---|---|
| `*.p12`, `*.pfx` (PKCS#12: сертификат + закрытый ключ) | high / potential |
| `*.p8`, `AuthKey_*.p8` (ключ App Store Connect API / APNs / Sign in with Apple) | high / potential |
| `*.cer`, `*.der`, `*.crt` с PEM-заголовком `PRIVATE KEY` | high / potential |
| `*.cer`/`*.der`/`*.crt` без него (публичный сертификат, например для пиннинга) | не находка |
| `*.mobileprovision`, `*.provisionprofile` (закрытого ключа нет; команда, App ID, UDID) | low / needs_review |
| `*.keychain`, `*.keychain-db` | medium / needs_review |
| заголовок `Salted__` (зашифровано, как хранит fastlane match) | low / needs_review |
| в `.gitignore`; в тестовой папке (тестовые идентичности для TLS) | low / needs_review |

Отличие от постановки: `*.mobileprovision` — low, а не high: в профиле нет закрытого ключа (это проверяемый факт формата).

## Фикстуры
`fixtures/ios/insecure-app/certs/` (`Distribution.p12`, `AuthKey_FIXTURE01.p8`, `InsecureApp.mobileprovision`,
`match/Enterprise.p12` с `Salted__`) — текстовые заглушки, ключ `.p8` собирается из метки `@@PEM_KEY@@`.
Негатив: `hardened-app/Hardened/pinned.cer`.
