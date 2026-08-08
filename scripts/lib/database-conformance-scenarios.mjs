import { createHash } from 'node:crypto'
import {
  conformanceCheck,
  scenarioResult,
} from './database-conformance-runner.mjs'

const POSTGRES_BOOTSTRAP = String.raw`
\set ON_ERROR_STOP on
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
CREATE ROLE migration_role NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
CREATE ROLE runtime_pool LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE tenant_a NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE tenant_b NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT tenant_a, tenant_b TO runtime_pool;
GRANT USAGE ON SCHEMA public TO migration_role, runtime_pool, tenant_a, tenant_b;
GRANT CREATE ON SCHEMA public TO migration_role;

CREATE TABLE public.tenant_rows (
  id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id text NOT NULL,
  marker text NOT NULL UNIQUE,
  value text NOT NULL
);
ALTER TABLE public.tenant_rows ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_rows FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_rows_isolation ON public.tenant_rows
  FOR ALL TO PUBLIC
  USING (tenant_id = current_user)
  WITH CHECK (tenant_id = current_user);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.tenant_rows TO tenant_a, tenant_b;
GRANT USAGE, SELECT ON SEQUENCE public.tenant_rows_id_seq TO tenant_a, tenant_b;

CREATE VIEW public.tenant_rows_view
  WITH (security_invoker = true)
  AS SELECT id, tenant_id, marker, value FROM public.tenant_rows;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.tenant_rows_view TO tenant_a, tenant_b;

CREATE TABLE public.tenant_history (
  history_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id text NOT NULL,
  marker text NOT NULL,
  operation text NOT NULL,
  changed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON public.tenant_history FROM PUBLIC;

CREATE FUNCTION public.capture_tenant_history()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
BEGIN
  INSERT INTO public.tenant_history(tenant_id, marker, operation)
  VALUES (
    COALESCE(NEW.tenant_id, OLD.tenant_id),
    COALESCE(NEW.marker, OLD.marker),
    TG_OP
  );
  RETURN COALESCE(NEW, OLD);
END
$function$;
REVOKE ALL ON FUNCTION public.capture_tenant_history() FROM PUBLIC;
CREATE TRIGGER tenant_rows_history
AFTER INSERT OR UPDATE OR DELETE ON public.tenant_rows
FOR EACH ROW EXECUTE FUNCTION public.capture_tenant_history();

CREATE FUNCTION public.admin_tenant_count()
RETURNS bigint
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $function$
  SELECT count(*) FROM public.tenant_rows
$function$;
REVOKE ALL ON FUNCTION public.admin_tenant_count() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.admin_tenant_count() TO migration_role;

INSERT INTO public.tenant_rows(tenant_id, marker, value) VALUES
  ('tenant_a', 'RTA_TENANT_A_CANARY', 'alpha'),
  ('tenant_b', 'RTA_TENANT_B_CANARY', 'bravo');

CREATE PUBLICATION rta_tenant_publication FOR TABLE public.tenant_rows;
`

const MYSQL_BOOTSTRAP = String.raw`
CREATE USER 'lab_definer'@'localhost' ACCOUNT LOCK;
CREATE USER 'tenant_a_user'@'localhost' IDENTIFIED BY 'RtaTenantA_0!';
CREATE USER 'tenant_b_user'@'localhost' IDENTIFIED BY 'RtaTenantB_0!';
CREATE USER 'shared_pool'@'localhost' IDENTIFIED BY 'RtaPool_0!';
CREATE USER 'migration_user'@'localhost' IDENTIFIED BY 'RtaMigration_0!';
CREATE ROLE 'tenant_a_role', 'tenant_b_role', 'migration_role';

CREATE TABLE rta_lab.tenant_rows (
  id bigint NOT NULL AUTO_INCREMENT,
  tenant_id varchar(32) NOT NULL,
  marker varchar(96) NOT NULL,
  value_text varchar(255) NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_tenant_marker (tenant_id, marker),
  CONSTRAINT ck_tenant_id CHECK (tenant_id IN ('tenant_a', 'tenant_b'))
) ENGINE=InnoDB;

CREATE TABLE rta_lab.tenant_history (
  history_id bigint NOT NULL AUTO_INCREMENT,
  tenant_id varchar(32) NOT NULL,
  marker varchar(96) NOT NULL,
  operation_name varchar(16) NOT NULL,
  changed_at timestamp(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (history_id)
) ENGINE=InnoDB;

GRANT SELECT, INSERT, UPDATE, DELETE, TRIGGER ON rta_lab.tenant_rows TO 'lab_definer'@'localhost';
GRANT SELECT, INSERT, DELETE ON rta_lab.tenant_history TO 'lab_definer'@'localhost';
GRANT SELECT ON rta_lab.* TO 'lab_definer'@'localhost';
GRANT EVENT ON rta_lab.* TO 'lab_definer'@'localhost';

CREATE DEFINER='lab_definer'@'localhost' SQL SECURITY DEFINER VIEW rta_lab.tenant_a_rows AS
  SELECT id, tenant_id, marker, value_text
  FROM rta_lab.tenant_rows
  WHERE tenant_id = 'tenant_a'
  WITH CASCADED CHECK OPTION;
CREATE DEFINER='lab_definer'@'localhost' SQL SECURITY DEFINER VIEW rta_lab.tenant_b_rows AS
  SELECT id, tenant_id, marker, value_text
  FROM rta_lab.tenant_rows
  WHERE tenant_id = 'tenant_b'
  WITH CASCADED CHECK OPTION;
GRANT SELECT ON rta_lab.tenant_a_rows TO 'lab_definer'@'localhost';
GRANT SELECT ON rta_lab.tenant_b_rows TO 'lab_definer'@'localhost';

DELIMITER //
CREATE DEFINER='lab_definer'@'localhost' TRIGGER rta_lab.tenant_rows_history_insert
AFTER INSERT ON rta_lab.tenant_rows
FOR EACH ROW
BEGIN
  INSERT INTO rta_lab.tenant_history(tenant_id, marker, operation_name)
  VALUES (NEW.tenant_id, NEW.marker, 'INSERT');
END//
CREATE DEFINER='lab_definer'@'localhost' TRIGGER rta_lab.tenant_rows_history_update
AFTER UPDATE ON rta_lab.tenant_rows
FOR EACH ROW
BEGIN
  INSERT INTO rta_lab.tenant_history(tenant_id, marker, operation_name)
  VALUES (NEW.tenant_id, NEW.marker, 'UPDATE');
END//
CREATE DEFINER='lab_definer'@'localhost' PROCEDURE rta_lab.tenant_a_count()
SQL SECURITY DEFINER
BEGIN
  SELECT COUNT(*) AS tenant_count FROM rta_lab.tenant_a_rows;
END//
CREATE DEFINER='lab_definer'@'localhost' PROCEDURE rta_lab.tenant_b_count()
SQL SECURITY DEFINER
BEGIN
  SELECT COUNT(*) AS tenant_count FROM rta_lab.tenant_b_rows;
END//
GRANT EXECUTE ON PROCEDURE rta_lab.tenant_a_count TO 'lab_definer'@'localhost'//
GRANT EXECUTE ON PROCEDURE rta_lab.tenant_b_count TO 'lab_definer'@'localhost'//
CREATE DEFINER='lab_definer'@'localhost' EVENT rta_lab.disabled_history_maintenance
ON SCHEDULE EVERY 1 DAY
DISABLE
DO DELETE FROM rta_lab.tenant_history WHERE changed_at < CURRENT_TIMESTAMP - INTERVAL 365 DAY//
DELIMITER ;

GRANT SELECT, INSERT, UPDATE, DELETE ON rta_lab.tenant_a_rows TO 'tenant_a_role';
GRANT SELECT, INSERT, UPDATE, DELETE ON rta_lab.tenant_b_rows TO 'tenant_b_role';
GRANT EXECUTE ON PROCEDURE rta_lab.tenant_a_count TO 'tenant_a_role';
GRANT EXECUTE ON PROCEDURE rta_lab.tenant_b_count TO 'tenant_b_role';
GRANT 'tenant_a_role' TO 'tenant_a_user'@'localhost', 'shared_pool'@'localhost';
GRANT 'tenant_b_role' TO 'tenant_b_user'@'localhost', 'shared_pool'@'localhost';
SET DEFAULT ROLE 'tenant_a_role' TO 'tenant_a_user'@'localhost';
SET DEFAULT ROLE 'tenant_b_role' TO 'tenant_b_user'@'localhost';
SET DEFAULT ROLE NONE TO 'shared_pool'@'localhost';

GRANT CREATE, ALTER, DROP, INDEX, REFERENCES ON rta_lab.* TO 'migration_role';
GRANT 'migration_role' TO 'migration_user'@'localhost';
SET DEFAULT ROLE 'migration_role' TO 'migration_user'@'localhost';

INSERT INTO rta_lab.tenant_rows(tenant_id, marker, value_text) VALUES
  ('tenant_a', 'RTA_TENANT_A_CANARY', 'alpha'),
  ('tenant_b', 'RTA_TENANT_B_CANARY', 'bravo');
`

const MYSQL_CLIENTS = Object.freeze({
  root: Object.freeze({ user: 'root', password: null }),
  tenantA: Object.freeze({ user: 'tenant_a_user', password: 'RtaTenantA_0!' }),
  tenantB: Object.freeze({ user: 'tenant_b_user', password: 'RtaTenantB_0!' }),
  pool: Object.freeze({
    user: 'shared_pool',
    password: 'RtaPool_0!',
    selectDatabase: false,
  }),
  migration: Object.freeze({ user: 'migration_user', password: 'RtaMigration_0!' }),
})

const READINESS_TRANSCRIPT_HEAD = 8
const READINESS_TRANSCRIPT_TAIL = 24

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function transcriptDigest(transcript) {
  return sha256(Buffer.from(JSON.stringify(
    transcript.map(({ code, stderr, stdout, step }) => ({
      code,
      stderr,
      stdout,
      step,
    })),
  ), 'utf8'))
}

function combinedOutput(result) {
  return `${result.stdout ?? ''}\n${result.stderr ?? ''}`.trim()
}

function check(checkId, passed, result, successObservation, failureObservation) {
  const output = combinedOutput(result)
  return conformanceCheck(
    checkId,
    passed ? 'PASSED' : 'FAILED',
    passed
      ? `${successObservation}\n${output}`.trim()
      : `${failureObservation}\n${output}`.trim(),
  )
}

function binding(engine, scenarioId) {
  const value = engine.scenario_rules.find(
    ({ scenario_id: candidate }) => candidate === scenarioId,
  )
  if (!value) throw new Error(`missing conformance binding ${engine.engine_id}/${scenarioId}`)
  return value
}

function containsOnlyCanary(output, allowed, denied) {
  return output.includes(allowed) && !output.includes(denied)
}

async function delay(milliseconds) {
  await new Promise((resolve) => {
    setTimeout(resolve, milliseconds)
  })
}

export function recordReadiness({ transcript, gaps, polls, label }) {
  if (polls.length <= READINESS_TRANSCRIPT_HEAD + READINESS_TRANSCRIPT_TAIL) {
    transcript.push(...polls)
    return
  }
  transcript.push(
    ...polls.slice(0, READINESS_TRANSCRIPT_HEAD),
    ...polls.slice(-READINESS_TRANSCRIPT_TAIL),
  )
  gaps.push({
    area: `${label} readiness`,
    reason: `${polls.length} readiness polls exceeded the ${
      READINESS_TRANSCRIPT_HEAD + READINESS_TRANSCRIPT_TAIL
    }-entry readiness transcript budget; only the first ${
      READINESS_TRANSCRIPT_HEAD
    } and last ${READINESS_TRANSCRIPT_TAIL} polls are retained.`,
  })
}

async function waitForReady({
  command,
  readyArgs,
  startupTimeoutMs,
  transcript,
  gaps,
  label,
  consecutiveSuccesses = 1,
}) {
  const deadline = Date.now() + startupTimeoutMs
  const polls = []
  let last
  let successes = 0
  try {
    do {
      last = await command(readyArgs, { allowNonZero: true })
      polls.push({
        step: `${label}.readiness`,
        code: last.code,
        stdout: last.stdout,
        stderr: last.stderr,
      })
      successes = last.code === 0 ? successes + 1 : 0
      if (successes >= consecutiveSuccesses) return
      if (Date.now() >= deadline) break
      await delay(1000)
    } while (true)
    throw new Error(`${label} did not become ready: ${combinedOutput(last)}`)
  } finally {
    recordReadiness({ transcript, gaps, polls, label })
  }
}

function dockerExecArgs(containerName, executable, args = [], extra = []) {
  return [
    '--context',
    'default',
    'container',
    'exec',
    '--interactive',
    ...extra,
    containerName,
    executable,
    ...args,
  ]
}

async function recordedCommand(transcript, step, command, args, overrides = {}) {
  const result = await command(args, overrides)
  transcript.push({
    step,
    code: result.code,
    stdout: result.stdout,
    stderr: result.stderr,
  })
  return result
}

function postgresPsqlArgs(containerName, user = 'postgres') {
  return dockerExecArgs(containerName, 'psql', [
    '-X',
    '-v',
    'ON_ERROR_STOP=1',
    '-U',
    user,
    '-d',
    'rta_lab',
    '-A',
    '-t',
    '-q',
  ])
}

async function postgresSql({
  transcript,
  step,
  command,
  containerName,
  sql,
  user = 'postgres',
  allowNonZero = false,
}) {
  return recordedCommand(
    transcript,
    step,
    command,
    postgresPsqlArgs(containerName, user),
    { input: `${sql.trim()}\n`, allowNonZero },
  )
}

async function executePostgresql({ engine, config, containerName, command }) {
  const transcript = []
  const gaps = []
  await waitForReady({
    command,
    readyArgs: dockerExecArgs(containerName, 'pg_isready', [
      '-U',
      'postgres',
      '-d',
      'rta_lab',
    ]),
    startupTimeoutMs: config.limits.startup_timeout_ms,
    transcript,
    gaps,
    label: engine.engine_id,
  })
  const version = await postgresSql({
    transcript,
    step: 'postgres.version',
    command,
    containerName,
    sql: 'SHOW server_version;',
  })
  const serverVersion = version.stdout.trim()
  await postgresSql({
    transcript,
    step: 'postgres.bootstrap',
    command,
    containerName,
    sql: POSTGRES_BOOTSTRAP,
  })

  const tenantA = await postgresSql({
    transcript,
    step: 'postgres.tenant-a',
    command,
    containerName,
    user: 'runtime_pool',
    allowNonZero: true,
    sql: `
      SET ROLE tenant_a;
      SELECT marker FROM public.tenant_rows ORDER BY marker;
      UPDATE public.tenant_rows SET value = 'alpha-updated'
      WHERE marker = 'RTA_TENANT_B_CANARY';
      SELECT 'foreign_updates=' || count(*) FROM public.tenant_rows
      WHERE marker = 'RTA_TENANT_B_CANARY' AND value = 'alpha-updated';
    `,
  })
  const tenantB = await postgresSql({
    transcript,
    step: 'postgres.tenant-b',
    command,
    containerName,
    user: 'runtime_pool',
    allowNonZero: true,
    sql: `
      SET ROLE tenant_b;
      SELECT marker FROM public.tenant_rows ORDER BY marker;
    `,
  })
  const crossInsert = await postgresSql({
    transcript,
    step: 'postgres.cross-tenant-write',
    command,
    containerName,
    user: 'runtime_pool',
    allowNonZero: true,
    sql: `
      SET ROLE tenant_a;
      INSERT INTO public.tenant_rows(tenant_id, marker, value)
      VALUES ('tenant_b', 'RTA_FORGED_B_CANARY', 'forged');
    `,
  })

  const poolReset = await postgresSql({
    transcript,
    step: 'postgres.pool-reset',
    command,
    containerName,
    user: 'runtime_pool',
    allowNonZero: true,
    sql: `
      SET ROLE tenant_a;
      SELECT 'role_on=' || current_user || ':' || string_agg(marker, ',')
      FROM public.tenant_rows;
      RESET ROLE;
      SELECT 'role_off=' || current_user || ':' || count(*)
      FROM public.tenant_rows;
    `,
  })
  const rowSecurityOff = await postgresSql({
    transcript,
    step: 'postgres.rls-bypass',
    command,
    containerName,
    user: 'runtime_pool',
    allowNonZero: true,
    sql: `
      SET ROLE tenant_a;
      SET row_security = off;
      SELECT marker FROM public.tenant_rows;
    `,
  })

  const view = await postgresSql({
    transcript,
    step: 'postgres.view',
    command,
    containerName,
    user: 'runtime_pool',
    allowNonZero: true,
    sql: `
      SET ROLE tenant_a;
      SELECT marker FROM public.tenant_rows_view ORDER BY marker;
    `,
  })
  const definerDenied = await postgresSql({
    transcript,
    step: 'postgres.definer-denied',
    command,
    containerName,
    user: 'runtime_pool',
    allowNonZero: true,
    sql: `
      SET ROLE tenant_a;
      SELECT public.admin_tenant_count();
    `,
  })
  const definerCatalog = await postgresSql({
    transcript,
    step: 'postgres.definer-catalog',
    command,
    containerName,
    allowNonZero: true,
    sql: `
      SELECT prosecdef, array_to_string(proconfig, ',')
      FROM pg_proc
      WHERE oid = 'public.admin_tenant_count()'::regprocedure;
    `,
  })

  const cdcHistory = await postgresSql({
    transcript,
    step: 'postgres.cdc-history',
    command,
    containerName,
    allowNonZero: true,
    sql: `
      SELECT 'publication=' || count(*) FROM pg_publication_tables
      WHERE pubname = 'rta_tenant_publication'
        AND schemaname = 'public'
        AND tablename = 'tenant_rows';
      SELECT 'history=' || count(*) FROM public.tenant_history
      WHERE marker IN ('RTA_TENANT_A_CANARY', 'RTA_TENANT_B_CANARY');
      SELECT 'runtime_replication=' || rolreplication
      FROM pg_roles WHERE rolname = 'runtime_pool';
    `,
  })
  const historyDenied = await postgresSql({
    transcript,
    step: 'postgres.history-denied',
    command,
    containerName,
    user: 'runtime_pool',
    allowNonZero: true,
    sql: `
      SET ROLE tenant_a;
      SELECT * FROM public.tenant_history;
    `,
  })

  const schemaDump = await recordedCommand(
    transcript,
    'postgres.backup-schema',
    command,
    dockerExecArgs(containerName, 'pg_dump', [
      '-U',
      'postgres',
      '-d',
      'rta_lab',
      '--schema-only',
      '--no-owner',
    ]),
    { allowNonZero: true },
  )
  const dataDump = await recordedCommand(
    transcript,
    'postgres.backup-data',
    command,
    dockerExecArgs(containerName, 'pg_dump', [
      '-U',
      'postgres',
      '-d',
      'rta_lab',
      '--data-only',
      '--column-inserts',
    ]),
    { allowNonZero: true },
  )
  const exportA = await postgresSql({
    transcript,
    step: 'postgres.export-a',
    command,
    containerName,
    user: 'runtime_pool',
    allowNonZero: true,
    sql: `
      SET ROLE tenant_a;
      COPY (
        SELECT marker FROM public.tenant_rows ORDER BY marker
      ) TO STDOUT;
    `,
  })
  const serverExportDenied = await postgresSql({
    transcript,
    step: 'postgres.server-export-denied',
    command,
    containerName,
    user: 'runtime_pool',
    allowNonZero: true,
    sql: `
      SET ROLE tenant_a;
      COPY public.tenant_rows TO '/tmp/rta-forbidden-export.csv' CSV;
    `,
  })

  const runtimeDdl = await postgresSql({
    transcript,
    step: 'postgres.runtime-ddl-denied',
    command,
    containerName,
    user: 'runtime_pool',
    allowNonZero: true,
    sql: 'CREATE TABLE public.runtime_created(id integer);',
  })
  const migrationDdl = await postgresSql({
    transcript,
    step: 'postgres.migration-ddl-allowed',
    command,
    containerName,
    allowNonZero: true,
    sql: `
      SET ROLE migration_role;
      CREATE TABLE public.migration_created(id integer);
      RESET ROLE;
      SELECT to_regclass('public.migration_created');
    `,
  })

  const scenarios = [
    scenarioResult(binding(engine, 'two-tenant-authorization'), [
      check(
        'postgres.tenant-a-read',
        tenantA.code === 0
          && containsOnlyCanary(
            tenantA.stdout,
            'RTA_TENANT_A_CANARY',
            'RTA_TENANT_B_CANARY',
          )
          && tenantA.stdout.includes('foreign_updates=0'),
        tenantA,
        'Tenant A saw only its canary and changed no tenant-B row.',
        'Tenant A isolation oracle failed.',
      ),
      check(
        'postgres.tenant-b-read',
        tenantB.code === 0 && containsOnlyCanary(
          tenantB.stdout,
          'RTA_TENANT_B_CANARY',
          'RTA_TENANT_A_CANARY',
        ),
        tenantB,
        'Tenant B saw only its canary.',
        'Tenant B isolation oracle failed.',
      ),
      check(
        'postgres.cross-tenant-write-denied',
        crossInsert.code !== 0
          && /row-level security|policy/i.test(combinedOutput(crossInsert)),
        crossInsert,
        'RLS rejected a tenant-A insert carrying tenant B.',
        'Cross-tenant insert did not fail under RLS.',
      ),
    ]),
    scenarioResult(binding(engine, 'pooled-session-reset'), [
      check(
        'postgres.pool-role-reset',
        poolReset.code === 0
          && poolReset.stdout.includes('role_on=tenant_a:RTA_TENANT_A_CANARY')
          && poolReset.stdout.includes('role_off=runtime_pool:0'),
        poolReset,
        'RESET ROLE removed tenant-A authority before session reuse.',
        'Pooled-session role reset oracle failed.',
      ),
    ]),
    scenarioResult(binding(engine, 'direct-table-bypass'), [
      check(
        'postgres.row-security-off-denied',
        rowSecurityOff.code !== 0
          && /row security|row-level security/i.test(combinedOutput(rowSecurityOff)),
        rowSecurityOff,
        'The non-bypass runtime could not disable row security.',
        'Runtime bypassed or did not exercise row security.',
      ),
    ]),
    scenarioResult(binding(engine, 'views-and-stored-code'), [
      check(
        'postgres.security-invoker-view',
        view.code === 0 && containsOnlyCanary(
          view.stdout,
          'RTA_TENANT_A_CANARY',
          'RTA_TENANT_B_CANARY',
        ),
        view,
        'The security-invoker view preserved tenant-A RLS.',
        'The tenant view widened access.',
      ),
      check(
        'postgres.definer-execute-denied',
        definerDenied.code !== 0 && /permission denied/i.test(combinedOutput(definerDenied)),
        definerDenied,
        'Runtime had no EXECUTE grant on the administrative definer routine.',
        'Runtime reached the administrative definer routine.',
      ),
      check(
        'postgres.definer-search-path-pinned',
        definerCatalog.code === 0
          && /^t\|.*search_path=pg_catalog, public/m.test(definerCatalog.stdout),
        definerCatalog,
        'The security-definer routine pins its search path.',
        'Security-definer catalog metadata drifted.',
      ),
    ]),
    scenarioResult(binding(engine, 'cdc-and-history'), [
      check(
        'postgres.publication-and-history-boundaries',
        cdcHistory.code === 0
          && cdcHistory.stdout.includes('publication=1')
          && /history=[2-9]/.test(cdcHistory.stdout)
          && cdcHistory.stdout.includes('runtime_replication=false'),
        cdcHistory,
        'Publication, history canaries, and non-replication runtime were observed.',
        'CDC/history catalog oracle failed.',
      ),
      check(
        'postgres.history-read-denied',
        historyDenied.code !== 0 && /permission denied/i.test(combinedOutput(historyDenied)),
        historyDenied,
        'Tenant runtime could not read the independent history table.',
        'Tenant runtime reached the history table.',
      ),
    ]),
    scenarioResult(binding(engine, 'backup'), [
      check(
        'postgres.schema-backup-security-objects',
        schemaDump.code === 0
          && schemaDump.stdout.includes('ENABLE ROW LEVEL SECURITY')
          && schemaDump.stdout.includes('CREATE POLICY')
          && schemaDump.stdout.includes('admin_tenant_count')
          && schemaDump.stdout.includes('rta_tenant_publication'),
        schemaDump,
        'Schema dump preserved RLS, policy, routine, and publication definitions.',
        'Schema dump omitted a required security object.',
      ),
      check(
        'postgres.data-backup-canaries',
        dataDump.code === 0
          && dataDump.stdout.includes('RTA_TENANT_A_CANARY')
          && dataDump.stdout.includes('RTA_TENANT_B_CANARY'),
        dataDump,
        'Data dump contained both administrative control canaries.',
        'Data dump omitted a tenant canary.',
      ),
    ]),
    scenarioResult(binding(engine, 'export'), [
      check(
        'postgres.tenant-export-scoped',
        exportA.code === 0 && containsOnlyCanary(
          exportA.stdout,
          'RTA_TENANT_A_CANARY',
          'RTA_TENANT_B_CANARY',
        ),
        exportA,
        'Tenant-A query export contained only the tenant-A canary.',
        'Tenant query export crossed the tenant boundary.',
      ),
      check(
        'postgres.server-file-export-denied',
        serverExportDenied.code !== 0
          && /permission denied|superuser|pg_write_server_files/i.test(
            combinedOutput(serverExportDenied),
          ),
        serverExportDenied,
        'Runtime lacked server-side file export authority.',
        'Runtime server-side export did not fail.',
      ),
    ]),
    scenarioResult(binding(engine, 'migration-runtime-role-separation'), [
      check(
        'postgres.runtime-ddl-denied',
        runtimeDdl.code !== 0 && /permission denied/i.test(combinedOutput(runtimeDdl)),
        runtimeDdl,
        'Runtime could not create a relation.',
        'Runtime unexpectedly exercised migration DDL.',
      ),
      check(
        'postgres.migration-ddl-allowed',
        migrationDdl.code === 0 && migrationDdl.stdout.includes('migration_created'),
        migrationDdl,
        'The dedicated migration role created the bounded control relation.',
        'The migration control could not exercise its intended DDL.',
      ),
    ]),
  ]
  return {
    serverVersion,
    scenarios,
    transcript,
    transcript_sha256: transcriptDigest(transcript),
    gaps,
  }
}

function mysqlClientFile(name, client, rootSecret) {
  const password = client.password ?? rootSecret
  return `[client]
user=${client.user}
password=${password}
protocol=socket
socket=/var/run/mysqld/mysqld.sock
${client.selectDatabase === false ? '' : '[mysql]\ndatabase=rta_lab'}
`
}

async function installMysqlClientFiles({
  command,
  containerName,
  transcript,
  rootSecret,
}) {
  for (const [name, client] of Object.entries(MYSQL_CLIENTS)) {
    const stepName = name.replace(
      /[A-Z]/g,
      (letter) => `-${letter.toLowerCase()}`,
    )
    const result = await recordedCommand(
      transcript,
      `mysql.client-file.${stepName}`,
      command,
      dockerExecArgs(containerName, 'sh', [
        '-c',
        `umask 077; cat > /tmp/rta-${name}.cnf`,
      ]),
      { input: mysqlClientFile(name, client, rootSecret) },
    )
    if (result.code !== 0) throw new Error(`failed to install MySQL client file ${name}`)
  }
}

function mysqlArgs(containerName, clientName, executable = 'mysql', extra = []) {
  return dockerExecArgs(containerName, executable, [
    `--defaults-extra-file=/tmp/rta-${clientName}.cnf`,
    ...(executable === 'mysql'
      ? ['--batch', '--skip-column-names', '--raw']
      : []),
    ...extra,
  ])
}

async function mysqlSql({
  transcript,
  step,
  command,
  containerName,
  sql,
  client = 'root',
  allowNonZero = false,
  force = false,
}) {
  const args = mysqlArgs(
    containerName,
    client,
    'mysql',
    force ? ['--force'] : [],
  )
  return recordedCommand(
    transcript,
    step,
    command,
    args,
    { input: `${sql.trim()}\n`, allowNonZero },
  )
}

async function executeMysql({
  engine,
  config,
  containerName,
  secret,
  command,
}) {
  const transcript = []
  const gaps = []
  await waitForReady({
    command,
    readyArgs: dockerExecArgs(
      containerName,
      'sh',
      [
        '-c',
        'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysqladmin --protocol=socket -uroot ping',
      ],
    ),
    startupTimeoutMs: config.limits.startup_timeout_ms,
    transcript,
    gaps,
    label: engine.engine_id,
    consecutiveSuccesses: 3,
  })
  await installMysqlClientFiles({
    command,
    containerName,
    transcript,
    rootSecret: secret,
  })
  const version = await mysqlSql({
    transcript,
    step: 'mysql.version',
    command,
    containerName,
    sql: 'SELECT VERSION();',
  })
  const serverVersion = version.stdout.trim()
  await mysqlSql({
    transcript,
    step: 'mysql.bootstrap',
    command,
    containerName,
    sql: MYSQL_BOOTSTRAP,
  })

  const tenantA = await mysqlSql({
    transcript,
    step: 'mysql.tenant-a',
    command,
    containerName,
    client: 'tenantA',
    allowNonZero: true,
    sql: 'SELECT marker FROM tenant_a_rows ORDER BY marker;',
  })
  const tenantB = await mysqlSql({
    transcript,
    step: 'mysql.tenant-b',
    command,
    containerName,
    client: 'tenantB',
    allowNonZero: true,
    sql: 'SELECT marker FROM tenant_b_rows ORDER BY marker;',
  })
  const crossView = await mysqlSql({
    transcript,
    step: 'mysql.cross-view-denied',
    command,
    containerName,
    client: 'tenantA',
    allowNonZero: true,
    sql: 'SELECT marker FROM tenant_b_rows;',
  })
  const crossInsert = await mysqlSql({
    transcript,
    step: 'mysql.cross-write-denied',
    command,
    containerName,
    client: 'tenantA',
    allowNonZero: true,
    sql: `
      INSERT INTO tenant_a_rows(tenant_id, marker, value_text)
      VALUES ('tenant_b', 'RTA_FORGED_B_CANARY', 'forged');
    `,
  })

  const poolReset = await mysqlSql({
    transcript,
    step: 'mysql.pool-reset',
    command,
    containerName,
    client: 'pool',
    allowNonZero: true,
    force: true,
    sql: `
      SET ROLE 'tenant_a_role';
      USE rta_lab;
      SELECT CONCAT('role_on=', CURRENT_ROLE(), ':', GROUP_CONCAT(marker))
      FROM tenant_a_rows;
      SET ROLE NONE;
      SELECT CONCAT('role_off=', CURRENT_ROLE());
      SELECT marker FROM rta_lab.tenant_a_rows;
    `,
  })
  const baseDenied = await mysqlSql({
    transcript,
    step: 'mysql.base-table-denied',
    command,
    containerName,
    client: 'tenantA',
    allowNonZero: true,
    sql: 'SELECT marker FROM tenant_rows;',
  })

  const routineA = await mysqlSql({
    transcript,
    step: 'mysql.routine-a',
    command,
    containerName,
    client: 'tenantA',
    allowNonZero: true,
    sql: 'CALL tenant_a_count();',
  })
  const routineB = await mysqlSql({
    transcript,
    step: 'mysql.routine-b-denied',
    command,
    containerName,
    client: 'tenantA',
    allowNonZero: true,
    sql: 'CALL tenant_b_count();',
  })
  const objectCatalog = await mysqlSql({
    transcript,
    step: 'mysql.object-catalog',
    command,
    containerName,
    allowNonZero: true,
    sql: `
      SELECT TABLE_NAME, SECURITY_TYPE, DEFINER, CHECK_OPTION
      FROM information_schema.VIEWS
      WHERE TABLE_SCHEMA = 'rta_lab'
      ORDER BY TABLE_NAME;
      SELECT ROUTINE_NAME, SECURITY_TYPE, DEFINER
      FROM information_schema.ROUTINES
      WHERE ROUTINE_SCHEMA = 'rta_lab'
      ORDER BY ROUTINE_NAME;
    `,
  })

  const cdcHistory = await mysqlSql({
    transcript,
    step: 'mysql.cdc-history',
    command,
    containerName,
    allowNonZero: true,
    sql: `
      SELECT CONCAT('binlog=', @@log_bin, ':', @@binlog_format);
      SHOW BINARY LOGS;
      SELECT CONCAT('history=', COUNT(*)) FROM tenant_history
      WHERE marker IN ('RTA_TENANT_A_CANARY', 'RTA_TENANT_B_CANARY');
      SELECT CONCAT('runtime_replication_grants=', COUNT(*))
      FROM information_schema.USER_PRIVILEGES
      WHERE GRANTEE IN (
        '''tenant_a_user''@''localhost''',
        '''tenant_b_user''@''localhost''',
        '''shared_pool''@''localhost'''
      )
      AND PRIVILEGE_TYPE LIKE 'REPLICATION%';
    `,
  })
  const historyDenied = await mysqlSql({
    transcript,
    step: 'mysql.history-denied',
    command,
    containerName,
    client: 'tenantA',
    allowNonZero: true,
    sql: 'SELECT * FROM tenant_history;',
  })

  const schemaDump = await recordedCommand(
    transcript,
    'mysql.backup-schema',
    command,
    mysqlArgs(containerName, 'root', 'mysqldump', [
      '--no-data',
      '--routines',
      '--triggers',
      '--events',
      '--skip-comments',
      'rta_lab',
    ]),
    { allowNonZero: true },
  )
  const dataDump = await recordedCommand(
    transcript,
    'mysql.backup-data',
    command,
    mysqlArgs(containerName, 'root', 'mysqldump', [
      '--no-create-info',
      '--skip-triggers',
      '--skip-comments',
      'rta_lab',
      'tenant_rows',
    ]),
    { allowNonZero: true },
  )
  const exportA = await mysqlSql({
    transcript,
    step: 'mysql.export-a',
    command,
    containerName,
    client: 'tenantA',
    allowNonZero: true,
    sql: 'SELECT marker FROM tenant_a_rows ORDER BY marker;',
  })
  const fileExportDenied = await mysqlSql({
    transcript,
    step: 'mysql.file-export-denied',
    command,
    containerName,
    client: 'tenantA',
    allowNonZero: true,
    sql: `
      SELECT marker FROM tenant_a_rows
      INTO OUTFILE '/var/lib/mysql-files/rta-forbidden-export.csv';
    `,
  })

  const runtimeDdl = await mysqlSql({
    transcript,
    step: 'mysql.runtime-ddl-denied',
    command,
    containerName,
    client: 'tenantA',
    allowNonZero: true,
    sql: 'CREATE TABLE runtime_created(id bigint);',
  })
  const migrationDdl = await mysqlSql({
    transcript,
    step: 'mysql.migration-ddl-allowed',
    command,
    containerName,
    allowNonZero: true,
    client: 'migration',
    sql: `
      CREATE TABLE migration_created(id bigint);
      SELECT TABLE_NAME FROM information_schema.TABLES
      WHERE TABLE_SCHEMA = 'rta_lab' AND TABLE_NAME = 'migration_created';
    `,
  })

  const deniedPattern = /denied|command denied|check option failed/i
  const scenarios = [
    scenarioResult(binding(engine, 'two-tenant-authorization'), [
      check(
        'mysql.tenant-a-read',
        tenantA.code === 0 && containsOnlyCanary(
          tenantA.stdout,
          'RTA_TENANT_A_CANARY',
          'RTA_TENANT_B_CANARY',
        ),
        tenantA,
        'Tenant A saw only its constrained-view canary.',
        'Tenant A view isolation oracle failed.',
      ),
      check(
        'mysql.tenant-b-read',
        tenantB.code === 0 && containsOnlyCanary(
          tenantB.stdout,
          'RTA_TENANT_B_CANARY',
          'RTA_TENANT_A_CANARY',
        ),
        tenantB,
        'Tenant B saw only its constrained-view canary.',
        'Tenant B view isolation oracle failed.',
      ),
      check(
        'mysql.cross-view-denied',
        crossView.code !== 0 && deniedPattern.test(combinedOutput(crossView)),
        crossView,
        'Tenant A had no grant on the tenant-B view.',
        'Tenant A reached the tenant-B view.',
      ),
      check(
        'mysql.cross-write-check-option',
        crossInsert.code !== 0 && deniedPattern.test(combinedOutput(crossInsert)),
        crossInsert,
        'WITH CHECK OPTION rejected a tenant-B row through the tenant-A view.',
        'Cross-tenant write was not rejected by the constrained view.',
      ),
    ]),
    scenarioResult(binding(engine, 'pooled-session-reset'), [
      check(
        'mysql.pool-role-reset',
        poolReset.stdout.includes('role_on=`tenant_a_role`@`%`:RTA_TENANT_A_CANARY')
          && /role_off=NONE/i.test(poolReset.stdout)
          && deniedPattern.test(combinedOutput(poolReset)),
        poolReset,
        'SET ROLE NONE removed the tenant role and the next view read was denied.',
        'Pooled-session role reset oracle failed.',
      ),
    ]),
    scenarioResult(binding(engine, 'direct-table-bypass'), [
      check(
        'mysql.base-table-denied',
        baseDenied.code !== 0 && deniedPattern.test(combinedOutput(baseDenied)),
        baseDenied,
        'Tenant runtime had no base-table grant.',
        'Tenant runtime reached the base table.',
      ),
    ]),
    scenarioResult(binding(engine, 'views-and-stored-code'), [
      check(
        'mysql.allowed-definer-routine',
        routineA.code === 0 && /(?:^|\n)1(?:\n|$)/.test(routineA.stdout),
        routineA,
        'Tenant A reached only its explicitly granted constrained routine.',
        'The tenant-A constrained routine failed.',
      ),
      check(
        'mysql.ungranted-definer-routine-denied',
        routineB.code !== 0 && deniedPattern.test(combinedOutput(routineB)),
        routineB,
        'Tenant A had no EXECUTE grant on the tenant-B routine.',
        'Tenant A reached the tenant-B definer routine.',
      ),
      check(
        'mysql.definer-catalog',
        objectCatalog.code === 0
          && objectCatalog.stdout.includes('tenant_a_rows')
          && objectCatalog.stdout.includes('DEFINER')
          && objectCatalog.stdout.includes('CASCADED')
          && objectCatalog.stdout.includes('lab_definer@localhost'),
        objectCatalog,
        'View/routine catalog retained explicit definer and check-option metadata.',
        'Stored-object security metadata drifted.',
      ),
    ]),
    scenarioResult(binding(engine, 'cdc-and-history'), [
      check(
        'mysql.binlog-and-history-boundaries',
        cdcHistory.code === 0
          && cdcHistory.stdout.includes('binlog=1:ROW')
          && /binlog\.[0-9]+/.test(cdcHistory.stdout)
          && /history=[2-9]/.test(cdcHistory.stdout)
          && cdcHistory.stdout.includes('runtime_replication_grants=0'),
        cdcHistory,
        'ROW binlog, history canaries, and zero runtime replication grants were observed.',
        'MySQL CDC/history oracle failed.',
      ),
      check(
        'mysql.history-read-denied',
        historyDenied.code !== 0 && deniedPattern.test(combinedOutput(historyDenied)),
        historyDenied,
        'Tenant runtime could not read the independent history table.',
        'Tenant runtime reached the history table.',
      ),
    ]),
    scenarioResult(binding(engine, 'backup'), [
      check(
        'mysql.schema-backup-security-objects',
        schemaDump.code === 0
          && schemaDump.stdout.includes('tenant_a_rows')
          && schemaDump.stdout.includes('tenant_a_count')
          && schemaDump.stdout.includes('tenant_rows_history_insert')
          && schemaDump.stdout.includes('disabled_history_maintenance'),
        schemaDump,
        'Schema dump included views, routines, triggers, and events.',
        'Schema dump omitted a required stored security object.',
      ),
      check(
        'mysql.data-backup-canaries',
        dataDump.code === 0
          && dataDump.stdout.includes('RTA_TENANT_A_CANARY')
          && dataDump.stdout.includes('RTA_TENANT_B_CANARY'),
        dataDump,
        'Data dump contained both administrative control canaries.',
        'Data dump omitted a tenant canary.',
      ),
    ]),
    scenarioResult(binding(engine, 'export'), [
      check(
        'mysql.tenant-export-scoped',
        exportA.code === 0 && containsOnlyCanary(
          exportA.stdout,
          'RTA_TENANT_A_CANARY',
          'RTA_TENANT_B_CANARY',
        ),
        exportA,
        'Tenant-A client export contained only the tenant-A canary.',
        'Tenant client export crossed the tenant boundary.',
      ),
      check(
        'mysql.server-file-export-denied',
        fileExportDenied.code !== 0 && deniedPattern.test(combinedOutput(fileExportDenied)),
        fileExportDenied,
        'Tenant runtime lacked FILE/server-side export authority.',
        'Tenant runtime server-side export did not fail.',
      ),
    ]),
    scenarioResult(binding(engine, 'migration-runtime-role-separation'), [
      check(
        'mysql.runtime-ddl-denied',
        runtimeDdl.code !== 0 && deniedPattern.test(combinedOutput(runtimeDdl)),
        runtimeDdl,
        'Runtime could not create a table.',
        'Runtime unexpectedly exercised migration DDL.',
      ),
      check(
        'mysql.migration-ddl-allowed',
        migrationDdl.code === 0 && migrationDdl.stdout.includes('migration_created'),
        migrationDdl,
        'The dedicated migration role created the bounded control table.',
        'The migration control could not exercise its intended DDL.',
      ),
    ]),
  ]
  return {
    serverVersion,
    scenarios,
    transcript,
    transcript_sha256: transcriptDigest(transcript),
    gaps,
  }
}

export async function executeDatabaseConformanceScenarios(options) {
  if (options.engine.engine_id === 'postgresql-18.4') {
    return executePostgresql(options)
  }
  if (options.engine.engine_id === 'mysql-8.4.10') {
    return executeMysql(options)
  }
  throw new Error(`unsupported database conformance engine ${options.engine.engine_id}`)
}
