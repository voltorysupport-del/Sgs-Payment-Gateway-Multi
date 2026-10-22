# Step 1 review notes

- **Project:** VaultX Pay
- **Repository:** SGS-Payment-Gateway (not yet connected; nothing has been pushed)
- **Feature branch:** `feature/step-1-project-setup`
- **Scope:** Version 1, Step 1 - project setup only
- **Packaged:** 2026-10-22

This ZIP does not include the `.git` folder. When you add these files to your repository,
create the branch yourself before committing:

```bash
git checkout -b feature/step-1-project-setup
```

## What Step 1 contains

- TypeScript (strict), ESLint and Prettier
- Configuration validation (Zod). The app refuses to start if `LIVE_MODE_ENABLED` is not
  `false`, if any provider other than `simulator` is configured, or if simulator controls are
  enabled in production.
- A second, independent "real payments are off" check (`src/config/safety.ts`)
- Structured JSON logging (Pino) with secret redaction
- A minimal Express app: security headers, request IDs, a 100kb body limit, consistent JSON
  errors and `GET /health`
- Docker Compose for local PostgreSQL 17, bound to 127.0.0.1 only
- GitHub Actions CI: type check, lint, format check, tests, build, `npm audit` and a gitleaks
  secret scan
- A pre-commit gitleaks hook and Dependabot

## What Step 1 deliberately does NOT contain

No payment endpoints, operator authentication, simulator, database migrations or tables, and no
connection to the database from the app. There is no deployment configuration.

## Verification status (honest)

**Checks that were run and passed in the build workspace:**

- Prettier formatting check (`prettier --check .`)
- TypeScript **syntax** parse of all 11 `.ts` files (a syntax check only, not a type check)
- JavaScript syntax check of `eslint.config.js`
- `docker compose config`: the file is valid, and it refuses to start without `POSTGRES_PASSWORD`
- YAML parse of the CI workflow, the Dependabot config and `docker-compose.yml`
- TOML parse of `.gitleaks.toml`
- JSON parse of `package.json`, `tsconfig.json`, `tsconfig.build.json` and `.prettierrc.json`
- Shell syntax check of `.githooks/pre-commit`

**Checks that have NOT been run** (the npm registry and GitHub downloads were blocked by the
build workspace's network policy):

- `npm install`, so there is no `package-lock.json` yet
- Full TypeScript type check (`npm run typecheck`)
- ESLint (`npm run lint`)
- The automated tests (`npm test`)
- The build (`npm run build`)
- gitleaks secret scan
- Starting the app, or starting PostgreSQL with Docker (including the test-database script)

**Treat the project as unverified until you run, on your own computer:**

```bash
npm install
npm run check
npm run build
gitleaks dir . --redact
```

Then commit the generated `package-lock.json`. CI uses `npm ci`, which requires it.

## Known points to watch on first install

- Dependency versions in `package.json` are ranges chosen without a live registry. If
  `npm install` reports a peer-dependency conflict (for example between ESLint and
  typescript-eslint), report it and it will be fixed.
- The import styles for `pino` and `pino-http` assume their current named exports. If the type
  check reports an import error there, it is a one-line fix.
- The gitleaks version pinned in CI (`8.28.0`) should be confirmed against the latest release.

## Files in this package

| File                                               | Purpose                                                           |
| -------------------------------------------------- | ----------------------------------------------------------------- |
| `.editorconfig`                                    | Consistent editor settings (spaces, line endings)                 |
| `.env.example`                                     | Setting names with harmless placeholders; copy to `.env`          |
| `.gitattributes`                                   | Forces LF line endings (keeps the shell hook working on Windows)  |
| `.githooks/pre-commit`                             | Blocks commits that contain secrets (needs gitleaks installed)    |
| `.github/dependabot.yml`                           | Weekly dependency and GitHub Actions update PRs                   |
| `.github/workflows/ci.yml`                         | CI: checks, tests, build, audit, secret scan                      |
| `.gitignore`                                       | Keeps `.env`, keys, `node_modules` and `dist` out of Git          |
| `.gitleaks.toml`                                   | Secret-scan rules, including VaultX Pay's own API key format      |
| `.nvmrc`                                           | Node.js version (24) for CI and version managers                  |
| `.prettierignore`                                  | Files Prettier skips                                              |
| `.prettierrc.json`                                 | Formatting style                                                  |
| `README.md`                                        | Setup guide and commands                                          |
| `docker-compose.yml`                               | Local PostgreSQL                                                  |
| `docker/postgres/init/01-create-test-database.sql` | Creates the `vaultx_pay_test` database on first start             |
| `docs/decisions.md`                                | Decision log                                                      |
| `docs/step-1-review-notes.md`                      | This file                                                         |
| `eslint.config.js`                                 | Lint rules                                                        |
| `package.json`                                     | Dependencies and npm scripts                                      |
| `src/app.ts`                                       | Builds the Express app                                            |
| `src/config/index.ts`                              | Loads and validates settings                                      |
| `src/config/safety.ts`                             | Independent "real payments disabled" check                        |
| `src/server.ts`                                    | Starts the server                                                 |
| `src/shared/http-errors.ts`                        | Standard error response format                                    |
| `src/shared/logger.ts`                             | Logger with redaction                                             |
| `tests/helpers.ts`                                 | Shared test helpers (test config, in-memory log capture)          |
| `tests/integration/app.test.ts`                    | HTTP tests: health, headers, request IDs, errors, logging, safety |
| `tests/unit/config.test.ts`                        | Settings validation and payment safety-lock tests                 |
| `tests/unit/logger.test.ts`                        | Log redaction tests                                               |
| `tsconfig.build.json`                              | TypeScript settings for building `dist/`                          |
| `tsconfig.json`                                    | TypeScript settings for type checking                             |
| `vitest.config.ts`                                 | Test runner settings                                              |
