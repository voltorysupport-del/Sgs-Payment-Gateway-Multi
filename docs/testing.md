# Safe automated testing

Use Node.js 24 (see `.nvmrc`), npm, and a running local Docker Engine/Desktop with
Linux containers. Tests use PostgreSQL 17. No existing database is required.

## Reproduce all checks

From the repository root:

```sh
npm ci
npm run test:isolated -- --check
```

The second command runs, in order:

```sh
npm run typecheck
npm run lint
npm run format:check
npm test
# Verify migration history and that test fixtures were cleaned up.
npm run build
```

To run just the tests with a fresh database:

```sh
npm run test:isolated
```

To run unit tests without Docker or database configuration:

```sh
npm test -- tests/unit
```

The suite retains all 47 original tests and adds database safety regression tests.
The test runner does not load `.env`. No passwords, database URLs, or provisioning
tokens need to be copied into files or shell history.

## Isolation and fail-closed checks

`scripts/test-isolated.mjs` creates a uniquely named container on the local Docker
socket. It ignores remote Docker endpoint/context selectors. PostgreSQL data is
stored in tmpfs with no host data or persistent volume mounted. Port 5432 is
published on `127.0.0.1` at a randomly allocated host port. It never starts,
stops, resets, or connects to the development Compose database.

Before provisioning, the runner verifies the image, running state, expected
database/administrator names, temporary storage, and loopback-only binding. The
bootstrap transaction refuses an existing nonempty database. It creates a
`vaultx_test` login without superuser, role-creation, database-creation,
replication, or RLS-bypass privileges. This role owns only the test database.

Fresh random values are generated in memory for the test-role password and
provisioning token. The administrator stores the token in a separate guard
schema, granting the test role read access. The initial container uses trust
authentication for bootstrap; before tests start, TCP authentication is changed
to SCRAM password authentication. Unix-socket trust is confined to the disposable
container. SQL containing generated values is passed through stdin and its output
is withheld.

The runner passes these settings only to its child check/test processes:

| Setting               | Required value                                                                                                         |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `NODE_ENV`            | `test`                                                                                                                 |
| `TEST_DATABASE_URL`   | Explicit PostgreSQL URL: `127.0.0.1`, explicit port, role `vaultx_test`, nonempty password, database `vaultx_pay_test` |
| `TEST_DATABASE_TOKEN` | The newly provisioned 64-character hexadecimal token                                                                   |

`tests/test-database.ts` rejects missing or invalid settings **before constructing
a connection pool**. Remote hosts, alternate database/role names, URL query
overrides, and fragments are rejected. All connection identity fields and session
options are set explicitly; application `DATABASE_URL` and ambient PostgreSQL
connection settings are never used as fallbacks. Configuration-only unit fixtures
contain no real connection credentials.

After connecting, the helper performs only a read-only transaction to verify the
actual database, role privileges, ownership, and matching server-side token.
Missing markers, wrong tokens, excessive privileges, or connection failures close
the pool and produce a generic error without credentials. Only a successfully
verified pool is returned. The HTTP integration suite runs migrations and creates
the app **after** this gate. Its fixtures and operator-scoped cleanup all use that
same verified pool; it never runs a reset, truncate, or database drop.

After successful tests, the runner checks that both existing migrations were
applied and that operators, API keys, and payments contain zero leftover fixtures.
It removes only the local container created by this invocation, also on ordinary
test/check failures. It does not remove GitHub-managed service containers.

Plain `npm test` intentionally fails the integration suites if these explicit
settings are missing. Do not point them at an existing development, staging, or
production database. Use the provisioning runner rather than manually adding a
guard marker to an existing database.

## GitHub Actions

The checks job provisions a fresh `postgres:17-alpine` service with tmpfs storage,
a random loopback host port, and a health check. It passes the current service
container ID to:

```sh
npm run test:isolated -- --ci-service
```

Service mode is accepted only inside GitHub Actions with an explicit service ID.
The same container inspection, empty-database bootstrap, generated credentials,
server verification, tests, and post-test fixture checks run in CI. GitHub removes
the service at job completion. Type checking, lint, formatting, dependency audit,
and build remain separate visible workflow steps. No repository database secret
or external database is required.

## Limits and troubleshooting

- Docker failures stop the command. There is no fallback to another database.
- Docker Desktop must expose its local Unix socket; Windows users should run
  these commands in WSL with Docker integration. Remote Docker contexts and
  containerized CI jobs are intentionally unsupported.
- The image tag follows PostgreSQL 17 Alpine updates; the npm lockfile pins Node
  dependencies. Docker image digests are not pinned by this task.
- Docker/root access is trusted. These checks prevent accidental targeting; they
  cannot defend against an administrator deliberately cloning the test identity
  and token into another database or changing the test code.
- A machine crash or forced kill can leave a local container running. Inspect
  containers labelled `com.vaultx.purpose=disposable-integration-tests` and remove
  only the one belonging to the interrupted run. There is no persistent test data.
- `--check` must run before creating unrelated scratch files in the repository,
  since lint/format checks inspect the working tree.

Payment processing code, application migrations, development Docker configuration,
and live-payment restrictions are unchanged.

The staging provisioning tests also use a separate `vaultx_pay_staging` database
inside this same disposable cluster, with an administrator-set staging designation.
They derive its connection only from the verified disposable test connection.
The provisioning CLI refuses the ordinary test database. Both databases must have
zero operator/key/payment fixtures at the end of a successful test run. No Render
database is used. See [staging-provisioning.md](staging-provisioning.md).

## Concurrent migration setup

Vitest integration files may run in parallel. The application and dashboard
suites intentionally share the independently verified disposable database; each
calls the real migration runner. Do not disable parallel execution to conceal
migration races.

`runMigrations` reserves one PostgreSQL connection and takes the database-scoped
session advisory lock `(894318, 1)` before creating migration history or checking
pending files. The same connection applies each file and its history record in
one transaction. Other runners recheck history only after obtaining the lock.
The lock is explicitly released before returning the connection; uncertain
connection/lock state discards that connection. SQL errors propagate unchanged
and failed migrations roll back. No duplicate-object error is treated as success.
This preserves the previous per-file commit behavior, rather than making an
entire batch one transaction. All concurrent runners must use this protocol;
older binaries and manual schema changes do not participate in the lock.

The upgrade-only disposable database also exercises three simultaneous runners,
unchanged timestamps on rerun, and SQL-error propagation/lock release. Its
populated schema-003 upgrade test still rolls back its fixtures first; the race
test then leaves four migrations and zero application/auth fixtures, checked by
the runner. No shared public schema is reset.

The Linux workflow runs on pushes and PRs targeting main or the development base.
Its `--ci-service` mode uses the inspected, tmpfs-backed PostgreSQL 17 service
with fresh restricted credentials, the same safety guards and the same tests.
It does not use staging or an inherited application DATABASE_URL.
