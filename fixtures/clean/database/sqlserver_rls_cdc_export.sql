-- C-037 — clean database conformance fixture.
-- Lens: database-and-data-stores
-- Topics: database-native-authorization-and-tenant-isolation;
--         database-replication-cdc-history-and-sharing
-- Expected findings at Low or above: zero.
-- The CDC source is denied and the only bulk-export view reapplies an immutable
-- login-to-tenant mapping rather than accepting caller-selected session state.
-- STATIC ONLY: no database, deployment wrapper, credentials, or executable job.

CREATE TABLE Sales.Orders (
    OrderId bigint NOT NULL PRIMARY KEY,
    TenantId int NOT NULL,
    TotalCents bigint NOT NULL
);

CREATE TABLE Security.PrincipalTenant (
    PrincipalName sysname NOT NULL PRIMARY KEY,
    TenantId int NOT NULL
);

CREATE FUNCTION Security.tenant_filter(@TenantId int)
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN SELECT 1 AS allowed
WHERE EXISTS (
    SELECT 1
    FROM Security.PrincipalTenant AS binding
    WHERE binding.PrincipalName = ORIGINAL_LOGIN()
      AND binding.TenantId = @TenantId
);

CREATE SECURITY POLICY Security.orders_tenant_policy
ADD FILTER PREDICATE Security.tenant_filter(TenantId) ON Sales.Orders,
ADD BLOCK PREDICATE Security.tenant_filter(TenantId) ON Sales.Orders AFTER INSERT,
ADD BLOCK PREDICATE Security.tenant_filter(TenantId) ON Sales.Orders AFTER UPDATE
WITH (STATE = ON);

EXEC sys.sp_cdc_enable_table
    @source_schema = N'Sales',
    @source_name = N'Orders',
    @role_name = N'cdc_capture';

DENY SELECT ON SCHEMA::cdc TO bulk_exporter;

CREATE VIEW Export.TenantOrderChanges
AS
SELECT OrderId, TenantId, TotalCents, __$operation, __$start_lsn
FROM cdc.Sales_Orders_CT AS changes
WHERE EXISTS (
    SELECT 1
    FROM Security.PrincipalTenant AS binding
    WHERE binding.PrincipalName = ORIGINAL_LOGIN()
      AND binding.TenantId = changes.TenantId
);

GRANT SELECT ON OBJECT::Export.TenantOrderChanges TO bulk_exporter;
