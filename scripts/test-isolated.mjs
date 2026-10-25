/* global process, setTimeout */
import { randomBytes, randomUUID } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, URL } from 'node:url';

// Always use the local daemon, never an inherited remote Docker context.
const dockerEnv = { ...process.env };
for (const key of [
  'DOCKER_HOST',
  'DOCKER_CONTEXT',
  'DOCKER_TLS',
  'DOCKER_TLS_VERIFY',
  'DOCKER_CERT_PATH',
]) {
  delete dockerEnv[key];
}
const cwd = fileURLToPath(new URL('..', import.meta.url));
function docker(args, input) {
  const result = spawnSync(
    'docker',
    [
      process.platform === 'win32'
        ? '--host=npipe:////./pipe/docker_engine'
        : '--host=unix:///var/run/docker.sock',
      ...args,
    ],
    {
      env: dockerEnv,
      encoding: 'utf8',
      input,
      maxBuffer: 1024 * 1024,
      timeout: 120_000,
    },
  );
  if (result.status !== 0) throw new Error('Disposable PostgreSQL Docker operation failed.');
  return result.stdout.trim();
}

let ownedContainer;
try {
  const args = process.argv.slice(2);
  const check = args.includes('--check');
  const ciService = args.includes('--ci-service');
  if (args.some((arg) => !['--check', '--ci-service'].includes(arg))) {
    throw new Error('Usage: npm run test:isolated -- [--check] [--ci-service]');
  }

  let container;
  if (ciService) {
    container = process.env.VAULTX_CI_POSTGRES_ID;
    if (process.env.GITHUB_ACTIONS !== 'true' || !/^[a-f0-9]{64}$/.test(container ?? '')) {
      throw new Error('CI service mode requires the current GitHub Actions service container ID.');
    }
  } else {
    ownedContainer = `vaultx-tests-${randomUUID()}`;
    docker([
      'run',
      '--detach',
      '--rm',
      '--name',
      ownedContainer,
      '--label',
      'com.vaultx.purpose=disposable-integration-tests',
      '--tmpfs',
      '/var/lib/postgresql/data:rw',
      '--publish',
      '127.0.0.1::5432',
      '--env',
      'POSTGRES_USER=vaultx_test_admin',
      '--env',
      'POSTGRES_DB=vaultx_pay_test',
      '--env',
      'POSTGRES_HOST_AUTH_METHOD=trust',
      'postgres:17-alpine',
    ]);
    container = ownedContainer;
  }

  const [details] = JSON.parse(docker(['inspect', container]));
  if (
    details.Config.Image !== 'postgres:17-alpine' ||
    !details.State.Running ||
    !details.Config.Env.includes('POSTGRES_DB=vaultx_pay_test') ||
    !details.Config.Env.includes('POSTGRES_USER=vaultx_test_admin') ||
    details.Mounts.some((mount) => mount.Type !== 'tmpfs')
  ) {
    throw new Error(
      'Refusing a database container with unexpected configuration or persistent data.',
    );
  }
  const bindings = details.NetworkSettings.Ports['5432/tcp'];
  if (bindings?.length !== 1 || bindings[0].HostIp !== '127.0.0.1') {
    throw new Error('Disposable PostgreSQL must be published only on IPv4 loopback.');
  }
  const port = bindings[0].HostPort;

  let ready = false;
  for (let attempt = 0; attempt < 60; attempt++) {
    try {
      // TCP ensures the initialization-only Unix-socket server has finished.
      docker([
        'exec',
        container,
        'pg_isready',
        '-h',
        '127.0.0.1',
        '-U',
        'vaultx_test_admin',
        '-d',
        'vaultx_pay_test',
      ]);
      ready = true;
      break;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
  }
  if (!ready) throw new Error('Disposable PostgreSQL did not become ready.');

  const password = randomBytes(32).toString('hex');
  const token = randomBytes(32).toString('hex');
  // Run only inside the freshly provisioned container. SQL and generated secrets
  // go through stdin, never command arguments or log output. No reset/drop is used.
  docker(
    [
      'exec',
      '--interactive',
      '--user',
      'postgres',
      container,
      'psql',
      '-X',
      '--username=vaultx_test_admin',
      '--dbname=vaultx_pay_test',
      '--set=ON_ERROR_STOP=1',
    ],
    `
    BEGIN;
    DO $$ BEGIN
      IF current_database() <> 'vaultx_pay_test'
        OR EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n
          ON n.oid = c.relnamespace WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
          AND n.nspname NOT LIKE 'pg_toast%')
        OR EXISTS (SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname = 'vaultx_test_guard')
      THEN RAISE EXCEPTION 'Test provisioning requires a new empty database'; END IF;
    END $$;
    CREATE ROLE vaultx_test LOGIN PASSWORD '${password}'
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    CREATE ROLE vaultx_test_switched NOLOGIN;
    GRANT vaultx_test_switched TO vaultx_test;
    ALTER DATABASE vaultx_pay_test OWNER TO vaultx_test;
    GRANT USAGE, CREATE ON SCHEMA public TO vaultx_test;
    CREATE SCHEMA vaultx_test_guard;
    CREATE TABLE vaultx_test_guard.identity (token TEXT PRIMARY KEY);
    INSERT INTO vaultx_test_guard.identity VALUES ('${token}');
    GRANT USAGE ON SCHEMA vaultx_test_guard TO vaultx_test;
    GRANT SELECT ON vaultx_test_guard.identity TO vaultx_test;
    COMMIT;
  `,
  );
  // Separate staging-named database for testing the staging-only CLI. It exists
  // only inside this new disposable cluster, never in Render or a developer DB.
  docker(
    [
      'exec',
      '--interactive',
      '--user',
      'postgres',
      container,
      'psql',
      '-X',
      '--username=vaultx_test_admin',
      '--dbname=vaultx_pay_test',
      '--set=ON_ERROR_STOP=1',
    ],
    `CREATE DATABASE vaultx_pay_staging OWNER vaultx_test;
      COMMENT ON DATABASE vaultx_pay_staging IS 'vaultx-pay:staging';
      CREATE DATABASE vaultx_pay_upgrade_test OWNER vaultx_test;
      COMMENT ON DATABASE vaultx_pay_upgrade_test IS 'vaultx-test-upgrade:${token}';`,
  );
  // Trust was used only to bootstrap this fresh container. TCP test connections
  // must now authenticate; Unix-socket access remains local to the container.
  docker([
    'exec',
    '--user',
    'postgres',
    container,
    'sh',
    '-c',
    'printf "local all all trust\\nhost all all all scram-sha-256\\n" > "$PGDATA/pg_hba.conf"',
  ]);
  docker([
    'exec',
    '--user',
    'postgres',
    container,
    'psql',
    '-X',
    '--username=vaultx_test_admin',
    '--dbname=vaultx_pay_test',
    '--set=ON_ERROR_STOP=1',
    '--command=SELECT pg_reload_conf()',
  ]);

  const testEnv = {
    ...process.env,
    NODE_ENV: 'test',
    DATABASE_URL: '',
    TEST_DATABASE_URL: `postgres://vaultx_test:${password}@127.0.0.1:${port}/vaultx_pay_test`,
    TEST_DATABASE_TOKEN: token,
    LIVE_MODE_ENABLED: 'false',
    ALLOWED_PROVIDERS: 'simulator',
    SIMULATOR_CONTROLS_ENABLED: 'false',
  };
  // Invoke npm's JS entry point directly: never pass paths/arguments through
  // cmd.exe or shell:true (Windows .cmd launchers permit command injection).
  const npmCli =
    process.env.npm_execpath ??
    path.join(path.dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js');
  if (!path.isAbsolute(npmCli) || !existsSync(npmCli) || path.basename(npmCli) !== 'npm-cli.js')
    throw new Error('Run the isolated tests using npm run test:isolated.');
  async function npm(script) {
    const code = await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [npmCli, 'run', script], {
        cwd,
        env: testEnv,
        stdio: 'inherit',
        shell: false,
      });
      child.once('error', reject);
      child.once('exit', (status) => resolve(status ?? 1));
    });
    if (code !== 0) throw new Error(`npm run ${script} failed.`);
  }
  process.stdout.write(
    'Verified disposable PostgreSQL container provisioned; credentials withheld.\n',
  );
  await npm(check ? 'check' : 'test');
  const remaining = docker([
    'exec',
    '--user',
    'postgres',
    container,
    'psql',
    '-X',
    '--quiet',
    '--tuples-only',
    '--no-align',
    '--username=vaultx_test',
    '--dbname=vaultx_pay_test',
    '--set=ON_ERROR_STOP=1',
    '--command=BEGIN READ ONLY; SELECT (SELECT count(*) FROM schema_migrations), (SELECT count(*) FROM operators), (SELECT count(*) FROM operator_api_keys), (SELECT count(*) FROM payments), (SELECT count(*) FROM dashboard_users), (SELECT count(*) FROM dashboard_memberships), (SELECT count(*) FROM dashboard_sessions), (SELECT count(*) FROM dashboard_login_limits); ROLLBACK;',
  ]);
  if (remaining !== '4|0|0|0|0|0|0|0') {
    throw new Error('Expected four migrations and no remaining integration fixtures.');
  }
  const stagingRemaining = docker([
    'exec',
    '--user',
    'postgres',
    container,
    'psql',
    '-X',
    '--quiet',
    '--tuples-only',
    '--no-align',
    '--username=vaultx_test',
    '--dbname=vaultx_pay_staging',
    '--set=ON_ERROR_STOP=1',
    '--command=BEGIN READ ONLY; SELECT (SELECT count(*) FROM schema_migrations), (SELECT count(*) FROM operators), (SELECT count(*) FROM operator_api_keys), (SELECT count(*) FROM payments), (SELECT count(*) FROM dashboard_users), (SELECT count(*) FROM dashboard_memberships), (SELECT count(*) FROM dashboard_sessions), (SELECT count(*) FROM dashboard_login_limits); ROLLBACK;',
  ]);
  if (stagingRemaining !== '4|0|0|0|0|0|0|0')
    throw new Error('Staging CLI test fixtures were not cleaned up.');
  process.stdout.write(
    'Confirmed in both disposable databases: 4 migrations applied; 0 operators, API keys, payments, dashboard users, memberships, sessions or limit buckets remain.\n',
  );
  const upgradeRemaining = docker([
    'exec',
    '--user',
    'postgres',
    container,
    'psql',
    '-X',
    '--quiet',
    '--tuples-only',
    '--no-align',
    '--username=vaultx_test',
    '--dbname=vaultx_pay_upgrade_test',
    '--set=ON_ERROR_STOP=1',
    '--command=BEGIN READ ONLY; SELECT (SELECT count(*) FROM schema_migrations), (SELECT count(*) FROM operators), (SELECT count(*) FROM operator_api_keys), (SELECT count(*) FROM payments), (SELECT count(*) FROM dashboard_users), (SELECT count(*) FROM dashboard_memberships), (SELECT count(*) FROM dashboard_sessions), (SELECT count(*) FROM dashboard_login_limits); ROLLBACK;',
  ]);
  if (upgradeRemaining !== '4|0|0|0|0|0|0|0')
    throw new Error('Upgrade/migration race fixtures were not cleaned up.');
  process.stdout.write(
    'Confirmed upgrade/race disposable database: 4 migrations applied; zero application/auth fixtures remain.\n',
  );
  if (check) await npm('build');
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
} finally {
  if (ownedContainer) {
    try {
      docker(['rm', '--force', ownedContainer]);
    } catch {
      process.stderr.write(
        "Could not remove this run's disposable container. Check local Docker.\n",
      );
      process.exitCode = 1;
    }
  }
}
