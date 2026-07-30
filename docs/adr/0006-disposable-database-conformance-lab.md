# ADR: Disposable multi-engine database conformance lab

Date: 2026-07-30
Status: Accepted for 0.7.0

## Context

The database adapter corpus describes engine-specific security semantics and
the static controller binds those semantics to exact adapter rule IDs. Static
fixtures can prove parser and contract behavior, but they cannot establish how
an actual engine handles principals, pooled sessions, direct-table access,
stored code, change streams, history, backups, exports, or deployment-role
separation.

Enabling the general T2 proof broker would be the wrong boundary. Repository
audits are static and read-only by default, while a conformance run executes
controller-owned synthetic SQL against disposable reference engines. Reference
engine behavior also does not prove the configuration or behavior of an
audited deployment.

The first engine pair must test materially different authorization models.
PostgreSQL 18.4 supplies native row-level security and role/session semantics.
MySQL 8.4.10 has no native row-policy catalog and instead exercises constrained
views, stored objects, roles, and base-table grant closure. Both are official
images with multi-platform manifest digests recorded in the lab manifest.

## Decision

Add a standalone `docker-database-lab-v1` controller with `plan`, `run`,
`unlock`, `validate`, and `report` commands. It owns an immutable scenario manifest,
engine lifecycle, synthetic fixtures, result contracts, artifact hashes, and
cleanup verification.

The lab:

- is opt-in `LOCAL_DYNAMIC` execution with an explicit trusted configuration;
- accepts only an absolute Docker runtime path and controller-owned
  digest-pinned images;
- requires the local Docker `default` context to use a local `unix://` or
  `npipe://` endpoint;
- creates one engine container at a time with no external network, no published
  ports, no host bind mounts, no inherited proxy variables, bounded memory,
  CPU, PIDs, file descriptors, wall time, and tmpfs storage;
- uses synthetic tenant-A and tenant-B canaries only;
- records the immutable image ID, repository digest, server version, scenario
  results, checkable bounded transcripts and their hashes, and positive proof
  that the exact container was removed;
- writes each engine result once and content-addresses it from the final run
  manifest;
- reports `CONTROLLER_OBSERVED_DISPOSABLE_ENGINE_BEHAVIOR`, never deployment
  proof, repository proof, or independent proof;
- preserves failed, skipped, and unassessed scenarios as explicit gaps.

The required scenario catalog is:

1. two-tenant authorization;
2. pooled-session reset;
3. direct-table bypass;
4. views and stored code;
5. CDC and history;
6. backup;
7. export;
8. migration/runtime role separation.

Each scenario binds to reviewed adapter rule IDs. A passing receipt establishes
only that the pinned reference image exhibited the recorded behavior under the
controller-owned fixture. Audited store profiles remain provider-declared and
must still establish their own version, deployment, principal, enforcement,
and copy paths. Reports keep reference conformance and target proof separate.

The ordinary `npm test` suite uses injected Docker transcripts and never starts
containers. A dedicated CI job pulls the two digest-pinned images and runs the
real lab. Missing Docker is a hard failure in that dedicated job and irrelevant
to static audit commands.

## Consequences

Positive:

- Adapter semantics gain a reproducible runtime oracle without widening static
  repository-audit authority.
- PostgreSQL and MySQL exercise native and composable tenant-isolation models.
- Exact image and server versions make version drift visible.
- Reference behavior, target configuration, and independent proof remain
  separate assurance statements.
- Container cleanup and artifact integrity are machine-verifiable.

Costs and residual risks:

- The real gate downloads and starts large database images.
- Docker and the official images are part of the trusted computing base.
- A shared-kernel container is not a microVM.
- Reference-engine success does not establish managed-service variants,
  extensions, plugins, production topology, or target configuration.
- Image digests and version-sensitive expectations require deliberate release
  maintenance.
- CDC and backup scenarios are bounded single-node oracles, not full
  replication, disaster-recovery, or failover tests.

## Alternatives considered

- Enable general T2 proof in the audit controller: rejected because repository
  proof and controller-owned adapter conformance have different authority and
  risk boundaries.
- Use Docker Compose: rejected because an additional orchestration layer would
  hide lifecycle and cleanup commands that the controller must record and
  verify.
- Start with PostgreSQL only: rejected because a native-RLS-only lab would not
  test the engine-neutral adapter contract.
- Start all 24 adapter products: rejected because it creates a large operational
  matrix before the result and lifecycle contracts are proven.
- Use SQLite as the contrasting engine: rejected because it cannot exercise the
  required principal, role, pooled-session, CDC, or stored-code boundaries.

## Primary references

- [PostgreSQL 18 row security policies](https://www.postgresql.org/docs/18/ddl-rowsecurity.html)
- [PostgreSQL 18 session authorization](https://www.postgresql.org/docs/18/sql-set-session-authorization.html)
- [MySQL 8.4 stored object access control](https://dev.mysql.com/doc/refman/8.4/en/stored-objects-security.html)
- [MySQL 8.4 view security](https://dev.mysql.com/doc/refman/8.4/en/create-view.html)
- [Docker none network driver](https://docs.docker.com/engine/network/drivers/none/)
- [Docker runtime resource constraints](https://docs.docker.com/engine/containers/resource_constraints/)

## Validation

1. Contract tests reject mutable image tags, relative runtime paths, unbounded
   limits, unknown engines/scenarios/rules, duplicate results, and assurance
   overclaims.
2. Lifecycle tests prove no network, ports, bind mounts, persistent volumes,
   added capabilities, proxy inheritance, or ambiguous cleanup.
3. Adversarial tests reject forged image identity, server-version drift,
   missing scenario results, altered transcripts, and a claimed pass after
   failed cleanup.
4. PostgreSQL and MySQL each run all eight scenarios against controller-owned
   synthetic fixtures.
5. The dedicated real-Docker gate fails rather than skips when prerequisites or
   either engine result are missing.
6. Static planning, manual provider ingestion, and ordinary `npm test` remain
   usable without Docker.

## Rollback

The lab is additive and does not migrate audit bundles. Remove the standalone
controller, schemas, lab manifest/fixtures, dedicated CI job, and reference
conformance report projection. Existing schema 1-5 audit bundles and v0.6
commands remain valid.
