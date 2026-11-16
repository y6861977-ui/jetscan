# IOS-KEYCHAIN-007 — элементы Keychain, доступные при заблокированном устройстве

**Статус:** реализовано (`src/ios_audit/rules/code.rs`, `keychain`). **Категория:** `data_storage`. **CWE:** CWE-311.
**MASVS:** MASVS-STORAGE. Никогда `confirmed`.

## Что проверяется
Использование (не объявление, не комментарий, не строка): `kSecAttrAccessibleAlways`,
`kSecAttrAccessibleAlwaysThisDeviceOnly`; обёртки — KeychainSwift `.accessibleAlways(ThisDeviceOnly)`,
KeychainAccess `.accessibility(.always)` / `Accessibility.always` (только в файле, где есть `Keychain`/`KeychainAccess`).
**high / potential**; в `#if DEBUG` — low.

Apple: «The data in the keychain item can always be accessed regardless of whether the device is locked … Items with this
attribute migrate to a new device when using encrypted backups»; устарело с iOS 12 / macOS 10.14, рекомендовано
`kSecAttrAccessibleAfterFirstUnlock` (https://developer.apple.com/documentation/security/ksecattraccessiblealways).

## Фикстуры
Позитив: `insecure-app/InsecureApp/Session.swift:12`. Негатив: `hardened-app/Hardened/Secure.swift`
(`WhenUnlockedThisDeviceOnly`, упоминания в комментариях), `HardenedTests/` (тесты пропускаются), `Animation.always`.
