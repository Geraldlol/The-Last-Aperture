-- C-038 — clean database conformance fixture.
-- Lens: database-and-data-stores
-- Topic: database-privileged-code-and-execution-context
-- Expected findings at Low or above: zero.
-- A dedicated least-privilege definer owns the view, callers have no base-table
-- grant, and CASCADED CHECK OPTION binds every write to the tenant predicate.
-- STATIC ONLY: no server, schema bootstrap, credentials, or deployment wrapper.

CREATE DEFINER = 'tenant_view_owner'@'localhost'
SQL SECURITY DEFINER
VIEW app.tenant_orders AS
SELECT OrderId, TenantId, Status
FROM app.orders
WHERE TenantId = 42
WITH CASCADED CHECK OPTION;

REVOKE ALL PRIVILEGES
ON app.orders
FROM 'tenant_42_api'@'localhost';

GRANT SELECT, INSERT, UPDATE
ON app.tenant_orders
TO 'tenant_42_api'@'localhost';
