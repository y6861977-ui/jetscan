# ANDROID-CRYPTO-012 — слабая криптография и MODE_WORLD_*

**Статус:** реализовано (`src/android_audit/rules/code.rs (`crypto`)`). **Категория:** `cryptography / data_storage`. **CWE:** CWE-327, CWE-916, CWE-276.
**MASVS:** категория MASVS-CRYPTO, MASVS-STORAGE (номер контроля не указываем). `confirmed` не выдаётся никогда.

## Что проверяется
| Условие | Severity / Confidence |
|---|---|
| `Cipher.getInstance("AES")` (без режима → ECB у провайдера Android) | medium / potential |
| `"…/ECB/…"` у блочного шифра (AES, DES, DESede, Blowfish, RC2) | medium / potential |
| DES, RC4/ARCFOUR, RC2 | medium / potential |
| RSA с `NoPadding` | medium / potential |
| `MessageDigest.getInstance("MD5"/"SHA-1")` в функции, где есть слово password/passphrase/credential | low / needs_review |
| `MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE` | medium / potential |

Только литеральный аргумент (константа-переменная не прослеживается). `RSA/ECB/OAEP…` — не находка (ECB у RSA —
формальность). MD5 для ключей кэша/контрольных сумм — не находка.

## Фикстуры
Позитив: `insecure-app/.../Crypto.kt`. Негатив: `hardened-app/.../Crypto.java` (AES/GCM, RSA OAEP, MD5 как ключ кэша).

Фикстуры: `fixtures/android/<имя>` (наши синтетические проекты; фальшивые ключи — метки `@@…@@`, собираются в `src/android_audit/testutil.rs`). Тесты: `src/android_audit/tests.rs` (сквозные), юнит-тесты в файле правила.

## Что делать
AES-GCM со случайным IV; пароли — PBKDF2/scrypt/Argon2; файлы — `MODE_PRIVATE` и FileProvider.
