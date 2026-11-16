# ANDROID-LOG-014 — секретные переменные в логах

**Статус:** реализовано (`src/android_audit/rules/code.rs (`logging`)`). **Категория:** `logging`. **CWE:** CWE-532.
**MASVS:** категория MASVS-STORAGE (номер контроля не указываем). `confirmed` не выдаётся никогда.

## Что проверяется
`Log.v/d/i/w/e/wtf/println(…)` и `Timber.*(…)`, где аргумент (или шаблон `"$password"`, `"${user.token}"`)
содержит идентификатор, чьё последнее слово — password/passwd/pwd/token/secret/credential(s)/apiKey/privateKey →
**low / needs_review**. Не находка: слово только в тексте строки, константы `ALL_CAPS`, `R.string.…`,
`.length`/`.size`/`.isEmpty()`, сравнения `== null`/`!= null`, имена вроде `tokenType`, `tokens`, `passwordHint`.

## Полевой тест (2026-11-16, `FIELD.md`)
Не находка: вызов под `if (BuildConfig.DEBUG)` (константа — ветки нет в release; NewPipe); имена со словами response/error/exception/failure/result/request/callback/listener/state/status/type (`negativeResponseFromOldToken` — исключение, Thunderbird).

## Фикстуры
Позитив: `insecure-app/.../Session.kt` (`"login $user with $password"`). Негатив: `hardened-app/.../Session.kt`
(`"password reset requested"`, `tokens.size`, `${token.isNotEmpty()}`).

Фикстуры: `fixtures/android/<имя>` (наши синтетические проекты; фальшивые ключи — метки `@@…@@`, собираются в `src/android_audit/testutil.rs`). Тесты: `src/android_audit/tests.rs` (сквозные), юнит-тесты в файле правила.

## Что делать
Не логировать секреты (или маскировать); вырезать отладочные логи из release правилами R8 `-assumenosideeffects`.
