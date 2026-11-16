# WEB-AUTH-004 — изменяющий серверный обработчик без видимой проверки доступа

**Статус:** реализовано, только `needs_review` (`src/web_audit/rules/auth.rs`, модель проекта —
`src/web_audit/project.rs`). **Категория:** `access_control`. **CWE:** CWE-862 (Missing Authorization).
**ASVS:** не сопоставлено.

## Риск
Обработчик, который меняет данные, доступен любому, кто знает URL. Server Actions (`"use server"`)
тоже публичные POST-эндпоинты: их можно вызвать не только из своей формы.

## Что проверяется (только Next.js; иначе `skipped: not_applicable`)
| Файл | Единица |
|---|---|
| `app/**/route.*` | каждый экспорт `POST`/`PUT`/`PATCH`/`DELETE` (`export async function`, `export const X =`, `export const { X } = …`, `export { h as X }`) |
| `pages/api/**` | обработчик, сравнивающий `req.method` со строкой изменяющего метода |
| модуль `"use server"` | каждый экспорт (`export async function`, `export function`, `export const x = …` — включая `unstable_cache(async …)`), кроме revalidate-only |

Единица **защищена**, если:
1. в коде файла (без комментариев) есть признак проверки доступа: `auth`, `session`, `getUser`,
   `currentUser`, `verify`, `jwt`, `bearer`, `cookie`, `clerk`, `signature`, `apiKey`, `x-api-key`,
   `getToken`, `csrf`, `permission`, `isAdmin`, `requireUser`, `guard`, `protect`, `CRON_SECRET`,
   `timingSafeEqual`, `unauthorized`, `forbidden`, `401`, `403`, или `process.env.*SECRET*`/`*TOKEN*`
   сравнивается через `===`/`!==` (список широкий: лучше пропустить находку, чем шуметь);
2. или обработчик **обёрнут** (`export const POST = withCron(…)`, `export const { POST } = serve(…)`,
   `export default withAuth(handler)`, локальный `const handler = withX(…)`), или **делегирует в один
   шаг** (`return [await] f(req)`), и эта функция импортирована из файла проекта с признаком из п. 1
   (путь разрешается: относительный, алиасы `paths` из `tsconfig.json`/`jsconfig.json`, по умолчанию
   `@/` и `~/` → корень и `src/`);
3. или обёртка/делегат — из пакета, который сам проверяет подпись/сессию (`@upstash/workflow`,
   `@upstash/qstash`, `next-auth`, `@auth/*`, `@clerk/nextjs`, `@kinde-oss/*`, `@workos-inc/authkit-nextjs`),
   или называется `with…`/`verify…`/`require…` со словом проверки (`auth`, `session`, `cron`,
   `signature`, `verify`, `admin`, `permission`, `role`, `guard`, `protect`, `apikey`, `token`, `secret`,
   `user`, `workspace`, `team`).

**Server Action, тело которой — только `revalidatePath(…)`/`revalidateTag(…)`, не находка**: она не читает
и не меняет данные (только сбрасывает кэш).

Находка — `medium`/`needs_review`, одна на файл (у Server Actions в заголовке — число незащищённых),
с командой ручной проверки (`curl -i -X POST https://<your-host>/api/items` без cookies → ждём 401/403).

## Не находка
GET-обработчики; пути `…webhook…`, `health`, `healthz`, `ping`, `status`, `og`, `auth`, `callback`, `public`,
`login`, `logout`, `signin`, `signup`, `register`; защищённые единицы (выше).

## Middleware
`middleware.*` (корень или `src/`), а для Next.js ≥ 16 и `proxy.*` — **шлюз доступа**, только если в нём
есть признак проверки **и** блокировка (`redirect(`, `rewrite(`, `new Response(`, `NextResponse.json(`,
`401`/`403`, `unauthorized`, `withAuth(`, `auth as middleware`, `auth((`). Middleware, которое только
обновляет сессию (`return updateSession(request)`), — не шлюз.

Шлюз удерживает находку **маршрута**, только если его `matcher` может этот маршрут покрыть: литеральные
пути сравниваются по префиксу до первого `:`, `*`, `[`, `?` (`/dashboard/:path*` не покрывает `/api/items`);
шаблон, начинающийся с параметра, покрывает только свой литеральный хвост (`/:path*/embed` — только пути,
кончающиеся на `/embed`); регулярка, нелитеральный `matcher` или его отсутствие — «может покрыть».
Проверка `partial` — только если что-то удержано, с числом удержанных.

**Server Actions не удерживаются никогда** (полевой тест, раунд 2, N5): страницу, на которую их POST-ят,
статически не узнать, а удержание прятало именно те находки, ради которых правило есть. Если шлюз есть,
в объяснение добавляется «проверьте, покрывает ли он страницы, использующие эти actions», тег
`gate:unknown-coverage`, проверка остаётся `completed`. Фикстура `fixtures/web/proxy-actions/`.

## Фикстуры (полевой тест 2026-11-12)
- `fixtures/web/next-routes/` — исходные позитивы/негативы.
- `fixtures/web/auth-patterns/` — паттерны 1–3 и W7: обёртка из проекта через `@/` и через относительный
  путь, `export { handler as POST }`, `serve` из `@upstash/workflow`, делегирование в функцию с проверкой
  секрета, revalidate-only actions — негативы; неаутентифицированный POST, action с платной LLM,
  `unstable_cache`-экспорт — позитивы.
- `fixtures/web/middleware-scoped/` (matcher без `/api` — ничего не удержано, скан `completed`),
  `middleware-refresh/` (только обновление сессии — не шлюз), `proxy-next16/` (`proxy.ts` в Next 16 —
  шлюз; в Next 15 — обычный файл).
- `fixtures/web/next-app/middleware.ts` (отвечает 401, без matcher) — удержание и `partial`.

## Ограничения
Обёртка/делегат прослеживаются на один шаг и только через импорт файла проекта; признак засчитывается
по всему файлу обёртки (не по конкретной функции). Проверка в цепочке из нескольких вызовов, классах,
`tRPC`/собственных роутерах не видна. Что именно проверяется (аутентификация ≠ авторизация на запись,
IDOR) не анализируется. Покрытие `matcher` — приближение по литеральным путям.
