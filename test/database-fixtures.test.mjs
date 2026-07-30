import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

function fixture(path) {
  return readFileSync(new URL(`../fixtures/${path}`, import.meta.url), 'utf8')
}

function stripCStyleComments(source) {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/--[^\r\n]*/g, '')
}

function sqlStatements(source) {
  return stripCStyleComments(source)
    .replace(/^\s*GO\s*$/gim, ';')
    .split(';')
    .map((statement) => statement.trim())
    .filter(Boolean)
}

function sqlServerCdcExportLeak(source) {
  const statements = sqlStatements(source)
  const exportView = statements.find((statement) =>
    /\bCREATE\s+VIEW\s+Export\.TenantOrderChanges\b/i.test(statement))

  const sourceHasReadPolicy = statements.some((statement) =>
    /\bCREATE\s+SECURITY\s+POLICY\b[\s\S]*\bADD\s+FILTER\s+PREDICATE\b/i.test(statement))
  const cdcEnabled = statements.some((statement) =>
    /\bEXEC(?:UTE)?\s+sys\.sp_cdc_enable_table\b/i.test(statement))
  const exportGranted = statements.some((statement) =>
    /\bGRANT\s+SELECT\s+ON\s+OBJECT::Export\.TenantOrderChanges\s+TO\s+bulk_exporter\b/i.test(statement))
  const readsChangeTable = /\bFROM\s+cdc\.[A-Za-z0-9_$]+\b/i.test(exportView ?? '')
  const reappliesTenantContext = /\bWHERE\b/i.test(exportView ?? '')
    && /\bTenantId\b/i.test(exportView ?? '')
    && /(?:\bSESSION_CONTEXT|\bORIGINAL_LOGIN)\s*\(/i.test(exportView ?? '')
  const sourceDenied = statements.some((statement) =>
    /\bDENY\s+SELECT\s+ON\s+SCHEMA::cdc\s+TO\s+bulk_exporter\b/i.test(statement))

  return sourceHasReadPolicy
    && cdcEnabled
    && exportGranted
    && readsChangeTable
    && (!reappliesTenantContext || !sourceDenied)
}

function mysqlWritableDefinerEscape(source) {
  const statements = sqlStatements(source)
  const view = statements.find((statement) =>
    /\bVIEW\s+app\.tenant_orders\s+AS\b/i.test(statement))
  const writableGrant = statements.some((statement) =>
    /\bGRANT\b[\s\S]*\b(?:INSERT|UPDATE)\b[\s\S]*\bON\s+app\.tenant_orders\b/i.test(statement))

  return /\bSQL\s+SECURITY\s+DEFINER\b/i.test(view ?? '')
    && /\bWHERE\b[\s\S]*\bTenantId\s*=\s*(?:@tenant_id|\d+)\b/i.test(view ?? '')
    && writableGrant
    && !/\bWITH\s+(?:(?:CASCADED|LOCAL)\s+)?CHECK\s+OPTION\b/i.test(view ?? '')
}

function mongodbAdditiveRoleBypass(source) {
  const config = JSON.parse(source)
  const view = config.views.find((candidate) => candidate.name === 'tenant_a_orders')
  const user = config.users.find((candidate) => candidate.name === 'tenant_api')
  const roles = new Map(config.roles.map((role) => [role.name, role]))
  const assigned = user.roles.map((name) => roles.get(name)).filter(Boolean)

  const canFind = (privilege) => privilege.actions.includes('find')
  const canReadView = assigned.some((role) => role.privileges.some((privilege) =>
    canFind(privilege)
      && privilege.resource.db === 'shop'
      && privilege.resource.collection === view.name))
  const canReadSource = assigned.some((role) => role.privileges.some((privilege) =>
    canFind(privilege)
      && privilege.resource.db === 'shop'
      && ['', view.source].includes(privilege.resource.collection)))

  return canReadView && canReadSource
}

function redisBroadAcl(source) {
  const users = source
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'))
    .map((line) => line.split(/\s+/))
    .filter((tokens) => tokens[0]?.toLowerCase() === 'user')

  const defaultUser = users.find((tokens) => tokens[1] === 'default') ?? []
  const defaultIsOpen = ['on', 'nopass', '~*', '&*', '+@all']
    .every((rule) => defaultUser.includes(rule))
  const applicationIsBroad = users
    .filter((tokens) => tokens[1] !== 'default')
    .some((tokens) =>
      tokens.includes('~*')
      && tokens.includes('&*')
      && tokens.some((rule) => ['+@all', '+@admin'].includes(rule)))

  return defaultIsOpen && applicationIsBroad
}

function firestoreAuthOnlyTenantRules(source) {
  const withoutComments = source
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/\/\/[^\r\n]*/g, '')
  const allows = [...withoutComments.matchAll(
    /\ballow\s+([^:]+?)\s*:\s*if\s+([^;]+);/g,
  )].map((match) => ({
    operations: match[1].split(',').map((operation) => operation.trim()),
    condition: match[2].trim(),
  }))

  const permits = (operation) => allows.find((allow) =>
    allow.operations.includes(operation) || allow.operations.includes('write'))
  const authOnly = (allow) =>
    allow != null
      && allow.condition.replace(/[\s()]/g, '') === 'request.auth!=null'
  const mutation = permits('update') ?? permits('create')
  const hasDataBoundary = allows.some((allow) =>
    /\btenantId\b|\badmin\b|\.diff\s*\(|affectedKeys\s*\(/.test(allow.condition))

  return authOnly(permits('get'))
    && authOnly(permits('list'))
    && authOnly(mutation)
    && !hasDataBoundary
}

function wildcardMatches(pattern, value) {
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&')
  return new RegExp(`^${escaped.replaceAll('*', '.*')}$`).test(value)
}

function elasticRoleUnionBypass(source) {
  const config = JSON.parse(source)
  const assignedNames = config.users.tenant_api.roles
  const assignedEntries = assignedNames.flatMap((roleName) =>
    config.roles[roleName].indices.map((entry) => ({ roleName, ...entry })))
  const reads = (entry) =>
    entry.privileges.some((privilege) => ['read', 'all'].includes(privilege))
  const restricted = assignedEntries.filter((entry) =>
    reads(entry) && (entry.query != null || entry.field_security != null))
  const unrestricted = assignedEntries.filter((entry) =>
    reads(entry) && entry.query == null && entry.field_security == null)
  const roleUnionBypass = restricted.some((limited) =>
    unrestricted.some((broad) =>
      limited.names.some((left) =>
        broad.names.some((right) =>
          left === right || left === '*' || right === '*'))))

  const filteredAliasBypass = Object.values(config.aliases ?? {}).some((alias) =>
    alias.filter != null
      && unrestricted.some((entry) =>
        entry.names.some((pattern) => wildcardMatches(pattern, alias.index))))

  return roleUnionBypass || filteredAliasBypass
}

const PAIRS = [
  {
    id: 'V-017/C-037',
    vulnerable: 'vulnerable/database/sqlserver_rls_cdc_export.sql',
    clean: 'clean/database/sqlserver_rls_cdc_export.sql',
    detector: sqlServerCdcExportLeak,
  },
  {
    id: 'V-018/C-038',
    vulnerable: 'vulnerable/database/mysql_definer_updatable_view.sql',
    clean: 'clean/database/mysql_definer_updatable_view.sql',
    detector: mysqlWritableDefinerEscape,
  },
  {
    id: 'V-019/C-039',
    vulnerable: 'vulnerable/database/mongodb_additive_roles.json',
    clean: 'clean/database/mongodb_additive_roles.json',
    detector: mongodbAdditiveRoleBypass,
  },
  {
    id: 'V-020/C-040',
    vulnerable: 'vulnerable/database/redis_broad_acl.acl',
    clean: 'clean/database/redis_broad_acl.acl',
    detector: redisBroadAcl,
  },
  {
    id: 'V-021/C-041',
    vulnerable: 'vulnerable/database/firestore_auth_only.rules',
    clean: 'clean/database/firestore_auth_only.rules',
    detector: firestoreAuthOnlyTenantRules,
  },
  {
    id: 'V-022/C-042',
    vulnerable: 'vulnerable/database/elastic_role_union.json',
    clean: 'clean/database/elastic_role_union.json',
    detector: elasticRoleUnionBypass,
  },
]

for (const pair of PAIRS) {
  test(`${pair.id} database conformance detector discriminates the pair`, () => {
    assert.equal(
      pair.detector(fixture(pair.vulnerable)),
      true,
      `${pair.id}: vulnerable fixture was not detected`,
    )
    assert.equal(
      pair.detector(fixture(pair.clean)),
      false,
      `${pair.id}: clean fixture was falsely detected`,
    )
  })
}
