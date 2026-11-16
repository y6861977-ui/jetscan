# IOS-STORAGE-006 — токены и пароли в UserDefaults

**Статус:** реализовано (`src/ios_audit/rules/code.rs`, `storage`). **Категория:** `data_storage`. **CWE:** CWE-312.
**MASVS:** MASVS-STORAGE. Никогда `confirmed`.

## Что проверяется (по токенам; комментарии и строки не срабатывают)
- Swift `<получатель>.set(value, forKey: key)` / `.setValue(…, forKey:)`, где в цепочке получателя есть
  `…defaults…` (`UserDefaults.standard`, `UserDefaults(suiteName:)`, `defaults`, `sharedDefaults`);
- `@AppStorage("authToken")`;
- Objective-C `[… setObject:value forKey:key]` / `setValue:forKey:` с получателем `…Defaults…`.

Находка, если ключ (литерал или последний идентификатор: `Keys.authToken`) или переменная-значение «секретные» по
последнему слову имени (`password`, `token`, `secret`, `apiKey`, `credentials`…; `tokenType`, `…ExpiresAt`, `…Date` — нет).
Литеральное значение (`""`, `nil`, `true`, число) — не находка. **medium / needs_review**; в `#if DEBUG` — low.

Не data-flow: что именно лежит в переменной, не известно (отсюда needs_review).

## Полевой тест (2026-11-16, `FIELD.md`)
Токены push/APNs/FCM/VoIP, страниц, синхронизации и отмены (`apnsDeviceToken`, `pushDeviceToken`, `changeToken`) — не секреты: APNs-токеном без ключа провайдера уведомление не отправить (Element ×5).

## Фикстуры
Позитив: `insecure-app/InsecureApp/Session.swift:7`, `Legacy.m:9`, `xcodegen-app/Sources/App.swift` (`@AppStorage`).
Негатив: `hardened-app` (тема, булев флаг), `cache.set(…)` / `dict setObject:` (не UserDefaults) в юнит-тестах `rules/code.rs`.
