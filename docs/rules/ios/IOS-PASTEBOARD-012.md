# IOS-PASTEBOARD-012 — секреты в общем буфере обмена

**Статус:** реализовано (`src/ios_audit/rules/code.rs`, `pasteboard`). **Категория:** `data_storage`. **CWE:** CWE-200.
**MASVS:** MASVS-PLATFORM. Никогда `confirmed`. **low / needs_review**.

## Что проверяется
`….string = <x>` / `.strings = …` и `setString(…)` / `setString:` / `setValue(…)` на строке, где есть идентификатор с
`pasteboard` (`UIPasteboard.general`, `[UIPasteboard generalPasteboard]`, переменная `pb = UIPasteboard.general` — на той
же строке), и правая часть содержит «секретную» переменную. Общий буфер читают все приложения и Universal Clipboard;
для намеренного копирования пароля — `setItems(_:options:)` с `.localOnly` и `.expirationDate`.

## Полевой тест (2026-11-16, `FIELD.md`)
Все 4 срабатывания — Deb: менеджер паролей копирует пароль по кнопке (DuckDuckGo ×3), отладочная функция копирует пароль БД (Signal). Правило — needs_review именно поэтому.

## Фикстуры
Позитив: `insecure-app/InsecureApp/Session.swift:9`; юнит-тест `pasteboard_writes` (ObjC). Негатив: `label.string = password`
(не pasteboard), имя без «секретного» слова, строки в `hardened-app`.
