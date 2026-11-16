# WEB-SECRET-001 — привилегированный ключ в клиентском коде

**Статус:** реализовано (`src/web_audit/rules/secret.rs`). **Категория:** `secret_exposure`.
**CWE:** CWE-798 (Use of Hard-coded Credentials), CWE-200 (Exposure of Sensitive Information to an
Unauthorized Actor). **ASVS:** не сопоставлено — номера требований не выверены, не выдумываем.

## Риск
Код клиентского компонента уходит в браузер как JavaScript. Ключ с правами (Stripe `sk_live_`,
GitHub, OpenAI, приватный ключ, пароль в URL БД, ...) в таком файле может прочитать любой посетитель.

## Что считается доказательством
1. **Формат ключа** — матчеры ядра `jetscan secrets` (`src/secrets/rules.rs`), без дублирования.
   Комментарии вырезаются до поиска (в бандл не идут). Заглушки отсеивает ядро.
2. **Файл попадает в браузер** — по правилам фреймворка (не по сборке):

| Файл | Достижимость | Severity / Confidence |
|---|---|---|
| `"use client"` в прологе; `pages/**` (кроме `api/`, `_document`); Vite `src/**`; `public/**`; Vite `index.html` | client | critical / potential |
| Модуль без границы (`lib/*.ts` и пр.), `next.config.*` (его `env` вшивается в бандл) | shared | high / needs_review |
| `"use server"`, `import "server-only"`, `app/**/route.*`, `page/layout/...` без `"use client"`, `pages/api/**`, `middleware`, конфиги инструментов, тесты, stories | server / test | не находка этого правила |

Внутри страницы Pages Router тела `getServerSideProps`/`getStaticProps`/`getStaticPaths` — сервер.
`confirmed` не выдаётся никогда: импорт файла в бандл не доказан.

## Не находка (контрпримеры)
- Публичные по замыслу ключи: Google/Firebase `AIza…` (браузерный ключ, ограничивается в консоли),
  Stripe `pk_…`, Supabase anon / `sb_publishable_…` (последние ядро и не ищет).
- Ключ в комментарии (`//`, `/* */`, `{/* */}` в JSX), регулярка-валидатор `/^sk_live_…$/`,
  строка-подсказка с префиксом, заглушки (`sk_live_xxxx…`, `<your-key>`), ссылка `process.env.X`.
- Тот же ключ в серверном модуле (Demo 2). Ключ там всё равно найдёт `jetscan secrets` — как утечку
  в репозиторий, но не в браузер.
- Строка с `jetscan:ignore`.
- Заголовок PEM без тела: литерал-заголовок «BEGIN … PRIVATE KEY» (пять дефисов с каждой стороны) для разбора/склейки PEM. Ключ
  считается ключом, только если после заголовка (через `
`, переводы строк, склейку литералов) идёт
  тело base64 ≥ 64 символов. Фикстура `fixtures/web/pem-utils/` (полевой тест 2026-11-12, паттерн 11).

## Фикстуры
Позитивные: `fixtures/web/next-app/app/components/Checkout.tsx:6`, `…/Tricky.tsx:6` (`//` внутри
строки), `fixtures/web/next-app/lib/shared-config.ts:3` (needs_review),
`fixtures/web/next-pages/pages/index.tsx:5`, `fixtures/web/vite-react/src/App.tsx:3`,
`fixtures/web/vite-react/index.html:4`.
Негативные: `next-app/app/page.tsx`, `app/api/pay/route.ts`, `app/actions.ts`,
`lib/stripe-admin.ts`, `lib/supabase-admin.ts`, `middleware.ts`, `app/components/Docs.tsx`,
`PublicKeys.tsx`, `Banner.stories.tsx`, `app/__tests__/checkout.test.tsx`, комментарии в
`Checkout.tsx`, `getServerSideProps` в `next-pages/pages/index.tsx`, `next-pages/pages/api/charge.ts`,
`vite-react/vite.config.ts`. Тест: `src/web_audit/tests.rs` (`web_secret_001_*`).


### Модуль без границы клиент/сервер: кто импортирует (полевой тест 2026-11-12, паттерн 10)
Для находки в модуле без `"use client"`/`server-only` jetscan смотрит, какие просканированные файлы его
импортируют (относительные пути и алиасы `@/`, `~/`, `paths` из tsconfig). Заголовок — «Module without a
client/server boundary …», не «client-reachable code». Если импортируют только серверные файлы (route
handlers, `"use server"`, `server-only`) — `info`/`needs_review` с перечнем импортёров и советом добавить
`import "server-only"`; если есть клиентский или общий импортёр — уровень прежний, импортёр назван;
если импортёров нет — так и сказано. Фикстура `fixtures/web/supabase-admin/`.

## Что делать
1. Считать ключ скомпрометированным, если файл хоть раз был задеплоен: **отозвать/перевыпустить**
   у провайдера.
2. Перенести вызов в серверный код (route handler / Server Action / `pages/api`), ключ — в
   переменную окружения без публичного префикса; в модуль с ключом добавить `import "server-only"`.

## Ограничения
Нет графа импортов и сборки; токенайзер, не парсер (см. `src/web_audit/HANDOFF_WEB.md` §7).
