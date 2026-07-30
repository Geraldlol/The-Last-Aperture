-- V-018 — vulnerable database conformance fixture.
-- Lens: database-and-data-stores
-- Topic: database-privileged-code-and-execution-context
-- Expected: High, CWE-269
-- Bug class: a writable SQL SECURITY DEFINER tenant view omits CHECK OPTION, so
-- writes can move rows outside the predicate enforced on reads.
-- STATIC ONLY: no server, schema bootstrap, credentials, or deployment wrapper.

CREATE DEFINER = 'tenant_view_owner'@'localhost'
SQL SECURITY DEFINER
VIEW app.tenant_orders AS
SELECT OrderId, TenantId, Status
FROM app.orders
WHERE TenantId = 42;

GRANT SELECT, INSERT, UPDATE
ON app.tenant_orders
TO 'tenant_42_api'@'localhost';
