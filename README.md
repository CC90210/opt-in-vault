# Opt-in Vault

Opt-in Vault is a private, multi-workspace outbound and consent-evidence platform. The application uses Next.js 15, React 19, Tailwind CSS 4, Turso/libSQL, and Drizzle ORM. Live email delivery is disabled by default.

## Local setup

Requirements: Node.js 20 or newer and npm.

```powershell
npm install
Copy-Item .env.example .env.local
npm run dev
```

The app is available at [http://localhost:3000](http://localhost:3000). Replace every secret placeholder in `.env.local`; never commit that file. A local database can use the checked-in `file:` example without a Turso token.

## Verification

```bash
npm test
npm run lint
npm run typecheck
```

Vitest runs server and integration tests in Node. Tests ending in `.test.tsx` run in jsdom with Testing Library setup.

## Database and workers

These entry points are wired now and will become executable as the corresponding MVP modules land:

```bash
npm run db:generate
npm run db:migrate
npm run worker:dispatch
npm run worker:inboxes
```

Database migrations, dispatch, and inbox polling are bounded operations. They do not enable real delivery. Live sends require a separate runtime gate and explicit campaign approval.

## Safety

- `.env.example` contains documentation placeholders only.
- `.env*`, credentials, private keys, local databases, and generated evidence are ignored.
- Do not connect real inboxes, use production Turso credentials, or enable live sends during local verification.

The approved architecture and implementation sequence live in [`docs/plans`](docs/plans).
