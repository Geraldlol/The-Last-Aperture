-- V-017 — vulnerable database conformance fixture.
-- Lens: database-and-data-stores
-- Topics: database-native-authorization-and-tenant-isolation;
--         database-replication-cdc-history-and-sharing
-- Expected: High, CWE-639
-- Bug class: the protected source has a read filter, but its CDC change table is
-- exposed through an unfiltered view to the bulk-export principal.
-- STATIC ONLY: no database, deployment wrapper, credentials, or executable job.

CREATE TABLE Sales.Orders (
    OrderId bigint NOT NULL PRIMARY KEY,
    TenantId int NOT NULL,
    TotalCents bigint NOT NULL
);

CREATE FUNCTION Security.tenant_filter(@TenantId int)
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN SELECT 1 AS allowed
WHERE @TenantId = TRY_CONVERT(int, SESSION_CONTEXT(N'tenant_id'));

CREATE SECURITY POLICY Security.orders_tenant_policy
ADD FILTER PREDICATE Security.tenant_filter(TenantId) ON Sales.Orders
WITH (STATE = ON);

EXEC sys.sp_cdc_enable_table
    @source_schema = N'Sales',
    @source_name = N'Orders',
    @role_name = N'cdc_capture';

CREATE VIEW Export.TenantOrderChanges
AS
SELECT OrderId, TenantId, TotalCents, __$operation, __$start_lsn
FROM cdc.Sales_Orders_CT;

GRANT SELECT ON OBJECT::Export.TenantOrderChanges TO bulk_exporter;
