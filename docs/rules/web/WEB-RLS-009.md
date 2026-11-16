# WEB-RLS-009 — Row Level Security Supabase по SQL-схеме из репозитория

**Статус:** реализовано (`src/web_audit/rules/rls.rs`, токенайзер `src/web_audit/sql.rs`).
**Категория:** `access_control`. **CWE:** CWE-862 (нет RLS / открытая политика), CWE-639
(`user_metadata`), CWE-426 (`SECURITY DEFINER` без `search_path`), CWE-284 (представления, бакеты).
**Уверенность:** никогда не `confirmed` — это схема из файлов, а не живая база.

## Риск
Публичный anon/publishable-ключ Supabase лежит в каждом браузерном бандле — так задумано. Данные
защищает только Row Level Security: таблица в открытой схеме без RLS (или с политикой `USING (true)`)
читается и меняется любым, у кого есть этот ключ. Это главный реальный класс утечек у приложений,
собранных ИИ-инструментами (Lovable CVE-2025-48757 и т. п.).

## Что читается (только файлы, ни одного подключения к базе)
| Источник | Когда |
|---|---|
| `**/supabase/**/*.sql` (миграции, `schema.sql`, `seed.sql`, дампы, `supabase/schemas/`) | всегда |
| `prisma/migrations/**/migration.sql`, `drizzle/**/*.sql` | только если в `package.json` есть клиент Supabase |
| `supabase/config.toml` → `[api] schemas`, `enabled` | открытые схемы (по умолчанию `public`) |

Не читаются: `supabase/tests/` (pgTAP), `supabase/functions/`, `.temp`, `.branches`, `snippets`.
Каждый каталог `supabase`/`prisma`/`drizzle` — отдельная база (монорепо). Миграции применяются по
имени файла (как `supabase db push`), затем остальные файлы группы.

## Модель
Токенайзер понимает комментарии `--`/`/* */` (вложенные), строки `'…'`/`E'…'`, `"Идентификаторы"`,
долларовые тела `$$…$$`/`$tag$…$tag$`, `BEGIN ATOMIC … END`, мета-команды psql (`\connect`,
`\restrict` в pg_dump). По порядку файлов отслеживаются:

- `CREATE TABLE` (столбцы), `ALTER TABLE … ENABLE/DISABLE ROW LEVEL SECURITY`, `RENAME TO`,
  `SET SCHEMA`, `ADD COLUMN`, `DROP TABLE` (со списком);
- `CREATE/ALTER/DROP POLICY` (команда, роли, `AS RESTRICTIVE`, `USING`, `WITH CHECK`, `RENAME`);
- `GRANT/REVOKE … ON [TABLE] … / ON ALL TABLES IN SCHEMA` и `ALTER DEFAULT PRIVILEGES` для
  `anon`/`authenticated`/`public`; без отзыва считаем, что у ролей есть стандартные права Supabase;
- `CREATE/ALTER/DROP FUNCTION` (`SECURITY DEFINER/INVOKER`, `SET search_path`, `RETURNS trigger`);
- `CREATE [MATERIALIZED] VIEW` (`security_invoker`), `ALTER VIEW … SET/RESET (security_invoker)`;
- `INSERT INTO storage.buckets (…, public) VALUES …`, `UPDATE storage.buckets SET public = …`.

Прочие известные операторы (индексы, типы, триггеры, `COMMENT`, данные…) не влияют на RLS и
пропускаются. **Неизвестные** считаются и перечисляются в `limitations` («N statement(s) not
understood: create rule ×1»). DO-блок, тело функции или event trigger, где упоминается
`row level security`, — признак динамического включения RLS: такие таблицы без RLS выдаются
как `needs_review`, и это сказано в `limitations`.

## Находки
| Что | Severity / Confidence |
|---|---|
| Таблица в открытой схеме создана, RLS не включён (или выключен `DISABLE`), anon/authenticated не лишены прав | high / potential (needs_review при динамическом RLS) |
| RLS включён, политик нет | info / potential — таблица закрыта для API, не утечка |
| Политика `true` на `UPDATE`/`DELETE`/`ALL` | high / potential |
| Политика `true` на `SELECT`: столбцы вида email/phone/token/address…, «личное» имя таблицы (users, orders, messages…) или `storage.objects` | high / potential |
| То же, «публичное» имя (posts, products, categories…) без чувствительных столбцов | low / needs_review (может быть задумано) |
| То же, прочие таблицы | medium / needs_review |
| Политика `true` на `INSERT` | medium / needs_review (формы, waitlist — бывает задумано) |
| Политика читает `user_metadata`/`raw_user_meta_data` | high / potential |
| Только «вошёл ли» (`auth.uid() is not null`, `auth.role() = 'authenticated'`) на `UPDATE`/`DELETE`/`ALL` | high / needs_review |
| То же на `SELECT` «личной» таблицы | medium / needs_review |
| Изменяющая политика без `auth.*` и без функции-помощника (`using (status = 'draft')`), `INSERT` в `storage.objects` без проверки личности | medium / needs_review |
| `SECURITY DEFINER` в открытой схеме без `SET search_path` | medium / needs_review (триггерная функция — low) |
| Представление без `security_invoker`, материализованное представление в открытой схеме | medium / needs_review |
| Бакет Storage `public = true` | info / needs_review |

Политики `AS RESTRICTIVE`, политики только для `service_role`/своих ролей и политики таблиц с
выключенным RLS (о них уже говорит находка «нет RLS») находок не дают. Есть RESTRICTIVE-политика на
ту же команду → уверенность понижается до `needs_review`. Вызов функции-помощника
(`is_admin()`, `private.is_member_of(team_id)`) считается проверкой личности: её код мы не проверяем.

`id` находки — от (правило, путь, вид + таблица/политика), без номера строки. `evidence.fingerprint`
нет (это не секрет); фрагмент — оператор, строковые значения `'…'` (кроме коротких имён вроде ролей
и бакетов, не похожих на ключи), тела функций — `$$…$$`. `-- jetscan:ignore` на любой строке
оператора подавляет находку.

## Проверка `WEB-RLS-009`
- SQL разобран → `completed` (или `partial`: бюджет обхода, незакрытая строка/комментарий в файле —
  остаток такого файла не анализировался); в `limitations` — сколько файлов/операторов, какие схемы
  считались открытыми, что изменения из панели Supabase не видны.
- Supabase используется, SQL нет → `skipped`, `not_checked: … export it with
  `supabase db dump --schema public -f supabase/schema.sql` and scan again`.
- Supabase не используется → `skipped`, `not_applicable`.

Прежняя проверка `WEB-SUPABASE-005:rls` заменена этой.

## Ограничения (честно)
- Видим только SQL в репозитории. RLS, включённый в панели, и политики, созданные там, не видны:
  «нет RLS» может быть уже исправлено в живой базе (поэтому `potential`, а не `confirmed`).
- Права по умолчанию: считаем, что anon/authenticated получают права на новые таблицы `public`
  (так на большинстве проектов). Проекты с выключенной «Automatically expose new tables» дают меньше.
- Выражения политик сравниваются по нормализованному тексту: `true`, `1 = 1`, «только вошёл» —
  короткий список форм; функция-помощник принимается на веру.
- Динамический SQL (`EXECUTE format(…)`), `CREATE RULE`, триггеры, `search_path` при создании
  объектов без схемы (считаем `public`) не моделируются.
- `INSERT INTO storage.buckets` без списка столбцов и бакеты, созданные из панели/JS, не видны.
- Prisma/Drizzle: SQL без схемы — `public`; читаем только при Supabase в зависимостях корня.

## Фикстуры и тесты
`fixtures/web/supabase-rls/` (позитивы и негативы помечены в комментариях SQL; `supabase/tests/` —
негатив по пути), `fixtures/web/vite-react/supabase/migrations/0001_init.sql` (info).
Тесты: `web_rls_009_supabase_migrations` (`src/web_audit/tests.rs`), модульные — в `rls.rs` и `sql.rs`
(дамп pg_dump, переименование/удаление между файлами, GRANT/REVOKE и default privileges,
`config.toml`, RESTRICTIVE, ALTER POLICY, Storage, SECURITY DEFINER, представления, `jetscan:ignore`,
стабильность id).

## Что делать
1. `alter table <t> enable row level security;` для каждой таблицы открытой схемы.
2. Политики — по команде, с `to authenticated` и сравнением владельца с `(select auth.uid())`;
   `using (true)` — только для действительно публичного содержимого и только на `SELECT`.
3. Права администратора — из `app_metadata` или защищённой таблицы, не из `user_metadata`.
4. `security definer` — вне открытых схем или с `set search_path = ''`; представления —
   `with (security_invoker = true)`.
5. Проверить живую базу: Supabase Advisors (Security) в панели.
