# VaultX Pay

A multi-operator payment gateway, designed initially for the iGaming industry.

> **Status: Version 1, simulator-only payment lifecycle.**
> Authenticated operators can create, retrieve, and simulate successful or failed payments.
> **Real payment processing is disabled** and the app refuses to start if anyone tries to enable it.
>
> Feature branch: `feature/step-1-project-setup`. See `docs/step-1-review-notes.md` for
> what has and has not been verified.

See [Payment API](docs/payments.md) for the lifecycle, authorization, and retry behavior.
See [Staging operator provisioning](docs/staging-provisioning.md) for administrator-only
key issuance, secure one-time delivery, rotation/revocation, and Windows CMD instructions.
The original Step 1 review notes are historical; current verification commands are in
[Safe automated testing](docs/testing.md).

## Safety rules (always true in Version 1)

- `LIVE_MODE_ENABLED` must be `false`, or the app will not start.
- `simulator` is the only permitted payment provider.
- Secrets live only in your local `.env` file (git-ignored) or, later, a secrets manager.
  Never in Git.
- Every commit is scanned for secrets (locally by a pre-commit hook, and again in CI).

## What you need installed

| Tool                               | Check it's installed | Get it                                                                          |
| ---------------------------------- | -------------------- | ------------------------------------------------------------------------------- |
| Node.js 24 LTS (22.12+ also works) | `node --version`     | https://nodejs.org                                                              |
| Git                                | `git --version`      | https://git-scm.com                                                             |
| Docker Desktop                     | `docker --version`   | https://www.docker.com/products/docker-desktop                                  |
| gitleaks                           | `gitleaks version`   | macOS `brew install gitleaks` · Windows `winget install --id Gitleaks.Gitleaks` |

## First-time setup

```bash
# 1. Install dependencies (also switches on the pre-commit secret scan)
npm install

# 2. Create your local settings file, then open .env and change the two
#    "replace-with-a-local-password" values to a password of your choice
cp .env.example .env

# 3. Start the local database (Docker Desktop must be running)
npm run db:up

# 4. Run every check with a separate disposable PostgreSQL container
#    (does not use .env or the development database)
npm run test:isolated -- --check

# 5. Start the app in development mode
npm run dev
```

Then open http://localhost:3000/health. You should see:

```json
{ "status": "ok", "service": "vaultx-pay", "realPaymentsEnabled": false }
```

## Useful commands

See [Safe automated testing](docs/testing.md) for database safeguards, CI configuration,
and exact reproduction commands. Plain `npm test` requires an explicitly provisioned
test database; it never falls back to the application's `DATABASE_URL`.

| Command                                 | What it does                                                              |
| --------------------------------------- | ------------------------------------------------------------------------- |
| `npm run dev`                           | Start the app and restart it automatically when you save a file           |
| `npm run check`                         | Type check, lint, formatting check and tests, all in one                  |
| `npm test`                              | Run the automated tests                                                   |
| `npm run test:isolated -- --check`      | Provision disposable PostgreSQL, run all checks and build, then remove it |
| `npm run typecheck`                     | Check TypeScript types                                                    |
| `npm run lint`                          | Look for likely bugs and unsafe patterns                                  |
| `npm run format`                        | Auto-format all files                                                     |
| `npm run build` / `npm start`           | Compile to `dist/` and run the compiled app                               |
| `npm run secrets:scan`                  | Scan the whole Git history for secrets                                    |
| `npm run db:up` / `db:down` / `db:logs` | Start, stop, or watch the local database                                  |

## Project layout

```
src/
  app.ts              builds the Express app (security headers, request IDs, logging, errors)
  payments/routes.ts  authenticated creation, retrieval, and simulation routes
  db/payments.ts      PostgreSQL persistence, idempotency, and locked state transitions
  server.ts           loads settings and starts the server
  config/index.ts     reads and validates every setting; refuses unsafe ones
  config/safety.ts    second, independent "real payments are off" check
  shared/logger.ts    structured JSON logging with secret redaction
  shared/http-errors.ts  one consistent error format
tests/
  unit/               config and logger tests
  integration/        HTTP tests against the app
docker/postgres/init/ creates the test database on first start
.github/workflows/    CI: checks + secret scan on every push
.githooks/pre-commit  local secret scan before every commit
docs/                 decisions and design notes
```

## Branch workflow

Work on a feature branch, open a pull request into `main`, and merge only when CI is green.
