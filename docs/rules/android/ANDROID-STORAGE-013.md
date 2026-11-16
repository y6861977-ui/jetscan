# ANDROID-STORAGE-013 — токены в открытых SharedPreferences

**Статус:** реализовано (`src/android_audit/rules/code.rs (`storage`)`). **Категория:** `data_storage`. **CWE:** CWE-312.
**MASVS:** категория MASVS-STORAGE (номер контроля не указываем). `confirmed` не выдаётся никогда.

## Что проверяется
`putString(ключ, значение)` в файле, работающем с SharedPreferences, где ключ (литерал или имя константы) или
переменная значения названы как секрет (`token`, `password`, `apiKey`, `secret`, … — последнее слово имени) →
**info / needs_review**. Файл с `EncryptedSharedPreferences`/`MasterKey` — не проверяется; литеральное значение — не находка.

## Полевой тест (2026-11-16, `FIELD.md`)
Получатель `putString` должен быть похож на редактор SharedPreferences (`….edit().putString`, цепочка `put…`, переменная `editor`/`prefs…`, вызов без получателя внутри `edit { }`); `bundle.putString`/`result.putString` — не находка (Nextcloud).

## Фикстуры
Позитив: `insecure-app/.../Session.kt` (`"auth_token"`). Негатив: `hardened-app/.../Session.kt` (EncryptedSharedPreferences).

Фикстуры: `fixtures/android/<имя>` (наши синтетические проекты; фальшивые ключи — метки `@@…@@`, собираются в `src/android_audit/testutil.rs`). Тесты: `src/android_audit/tests.rs` (сквозные), юнит-тесты в файле правила.

## Что делать
Долгоживущие учётные данные шифровать ключом Android Keystore.
