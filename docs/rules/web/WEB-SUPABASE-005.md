# WEB-SUPABASE-005 — ключ Supabase service-role/secret на стороне браузера

**Статус:** реализовано (`src/web_audit/rules/supabase.rs`). **Категория:** `secret_exposure`.
**CWE:** CWE-798, CWE-200. **ASVS:** не сопоставлено.

## Риск
Ключ service-role (и новый `sb_secret_…`) обходит Row Level Security: с ним читаются и меняются все
строки всех таблиц. Ему не место нигде, кроме сервера. Ключи anon / `sb_publishable_…`, наоборот,
сделаны для браузера — их наличие в клиенте само по себе **не** уязвимость; данные защищает RLS.

## Что считается доказательством
- JWT, у которого payload (base64url, декодируется локально) содержит `"role":"service_role"`.
  Подпись не проверяется — для определения роли она не нужна, а сеть мы не используем. Если `iss`
  не содержит `supabase`, заголовок находки — «JWT with a service_role claim».
- Ключ с префиксом `sb_secret_` и телом ≥ 20 символов `[A-Za-z0-9_-]`, не заглушка.

| Где | Severity / Confidence |
|---|---|
| Клиентский код (как в WEB-SECRET-001) | critical / potential |
| Модуль без границы | high / needs_review |
| Значение публичной переменной `.env*` (`NEXT_PUBLIC_`/`VITE_`) | critical / potential |
| Клиентский код читает серверную `process.env.*SERVICE_ROLE*` | medium / needs_review |

Последний случай — не утечка (бандлер такую переменную не подставит), а признак того, что
admin-клиент создают в браузере; типичная «починка» переименованием в `NEXT_PUBLIC_` сольёт ключ.

## RLS
RLS проверяет отдельное правило **WEB-RLS-009** (`docs/rules/web/WEB-RLS-009.md`) по SQL-схеме из
репозитория (`supabase/migrations/*.sql`, `supabase/schema.sql`, …). Прежняя проверка
`WEB-SUPABASE-005:rls` (всегда `skipped`) удалена: её заменила проверка `WEB-RLS-009` — `completed`,
когда SQL разобран, и `skipped` с подсказкой `supabase db dump --schema public -f supabase/schema.sql`,
когда SQL нет.

## Не находка
JWT с `role=anon`/`authenticated`, `sb_publishable_…`, `sb_secret_xxxx…`, обрезанный JWT без подписи,
ключ в серверном модуле (`import "server-only"`), серверная переменная окружения, `jetscan:ignore`.

## Фикстуры
Позитив: `fixtures/web/next-app/app/components/AdminPanel.tsx:6` и `:9`,
`fixtures/web/next-app/dot-env.local:23`, `fixtures/web/vite-react/src/supabase.ts:7`.
Негатив: `next-app/app/components/PublicKeys.tsx`, `next-app/lib/supabase-admin.ts`,
`dot-env.local:21`, `vite-react/src/supabase.ts:4`. RLS — см. WEB-RLS-009.
Тесты: `web_supabase_005_*`, модульные — в `supabase.rs`.


### Модуль без границы клиент/сервер: кто импортирует (полевой тест 2026-11-12, паттерн 10)
Для находки в модуле без `"use client"`/`server-only` jetscan смотрит, какие просканированные файлы его
импортируют (относительные пути и алиасы `@/`, `~/`, `paths` из tsconfig). Заголовок — «Module without a
client/server boundary …», не «client-reachable code». Если импортируют только серверные файлы (route
handlers, `"use server"`, `server-only`) — `info`/`needs_review` с перечнем импортёров и советом добавить
`import "server-only"`; если есть клиентский или общий импортёр — уровень прежний, импортёр назван;
если импортёров нет — так и сказано. Фикстура `fixtures/web/supabase-admin/`.

## Что делать
1. **Перевыпустить** service-role/secret ключ в панели Supabase (раздел ключей API проекта) —
   старый считать скомпрометированным.
2. Создавать admin-клиент только в серверном коде (route handler, Server Action, edge function),
   ключ — в переменной без публичного префикса.
3. Проверить, что RLS включён и политики покрывают каждую таблицу, доступную anon-ключу.
