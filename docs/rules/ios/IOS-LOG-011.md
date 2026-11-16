# IOS-LOG-011 — секреты в логах

**Статус:** реализовано (`src/ios_audit/rules/code.rs`, `logging`). **Категория:** `logging`. **CWE:** CWE-532.
**MASVS:** MASVS-STORAGE. Никогда `confirmed`. Все находки — **low / needs_review**.

## Что проверяется
- `print`, `debugPrint`, `NSLog`, `DDLogVerbose/Debug/Info/Warn/Error` (без получателя) с аргументом или интерполяцией
  `\(…)`, где переменная «секретная» по имени (`password`, `token`, `secret`, `apiKey`…) и выводится значением
  (не `.count`, `.isEmpty`, `.length`, `== nil`, не метка `token:`, не КОНСТАНТА);
- `os_log(…)` — только если в формате есть `%{public}` (динамические строки os_log по умолчанию скрыты);
- `<…log…>.debug/info/notice/error/…(…)`: если в файле `import os` и `Logger` — только интерполяции с
  `privacy: .public` (по умолчанию `Logger` их редактирует); иначе (SwiftyBeaver, XCGLogger…) — как `print`;
- внутри `#if DEBUG` / `#ifdef DEBUG` — не находка.

## Полевой тест (2026-11-16, `FIELD.md`)
Не находка: значение внутри `redact(…)`/`mask(…)`/`hash(…)` (Signal), поле объекта `token.version` (Signal), имя с объявленным «несекретным» типом `token: ActionToken` (Firefox), push-токены.

## Фикстуры
Позитив: `insecure-app/InsecureApp/Session.swift:8`, `Legacy.m:8`. Негатив: `Session.swift:20` (`#if DEBUG`),
`hardened-app/Hardened/Secure.swift` (`Logger` без `.public`, `os_log("%@")`, `.isEmpty`/`.count`, `#if DEBUG`),
`hardened-app/Hardened/Legacy.m` (`#ifdef DEBUG`).
