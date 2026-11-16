# IOS-CRYPTO-010 — слабая криптография

**Статус:** реализовано (`src/ios_audit/rules/code.rs`, `crypto`). **Категория:** `cryptography`. **CWE:** CWE-327, CWE-916.
**MASVS:** MASVS-CRYPTO. Никогда `confirmed`.

| Шаблон | Severity / Confidence |
|---|---|
| CommonCrypto `kCCOptionECBMode`; CryptoSwift `ECB()` (в файле с `CryptoSwift`/`blockMode`) | medium / potential |
| `kCCAlgorithmDES`, `kCCAlgorithm3DES`, `kCCAlgorithmRC4`, `kCCAlgorithmRC2`, `kCCAlgorithmBlowfish`, `kCCAlgorithmCAST` | medium / potential |
| `CC_MD5(…)`, `CC_SHA1(…)`, CryptoKit `Insecure.MD5` / `Insecure.SHA1`, CryptoSwift `.md5()` / `.sha1()` — только если в той же функции есть слово password/passphrase/pwd/credential | low / needs_review |

MD5/SHA-1 для кэш-ключей и контрольных сумм — не находка (нет «пароля» рядом). Что именно шифруется — не анализируется.

## Полевой тест (2026-11-16, `FIELD.md`)
Объявление константы-псевдонима в обёртке (`public static let ecbMode = Options(rawValue: kCCOptionECBMode)`) — не использование (Signal); само использование `.ecbMode` в другом файле при этом не видно (ограничение).

## Фикстуры
Позитив: `insecure-app/InsecureApp/Legacy.m:15` (ECB), `Web.swift:20` (`CC_MD5` рядом с паролем); юнит-тест `crypto_patterns`.
Негатив: `cacheKey(url:)` в юнит-тесте, комментарии в `hardened-app`.
