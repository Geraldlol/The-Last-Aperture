// V-016 — VULNERABLE fixture. NOT RUNNABLE. Written from scratch.
//
// CHAIN fixture, and it says so, per fixtures/README.md rule 1. Two defects, one
// file, because neither half is the finding on its own: an internet-reachable
// managed data plane is what an attacker uses, and the total absence of
// diagnostic settings is why nobody would ever know they did.
//
//   leg 1  Managed database and secret store reachable from the public internet
//          Lens: cloud-and-iac / topic `network-exposure-and-segmentation`
//          Expected: Critical, CWE-1327
//   leg 2  No control-plane or resource diagnostic logging anywhere in the
//          deployment
//          Lens: cloud-and-iac / topic `control-plane-audit-logging`
//          Expected: High, CWE-778
//
// The shape this reproduces, and why a Terraform-shaped sweep reports it clean:
//
//   * `publicNetworkAccess: 'Enabled'` is the camelCase sibling of
//     `public_network_access_enabled = true`. It shares no substring with it.
//   * The firewall rule below is Azure's "allow all Azure services" sentinel:
//     `startIpAddress: '0.0.0.0'` with `endIpAddress: '0.0.0.0'`. It is not
//     `0.0.0.0/0`, it does not contain `0.0.0.0/0`, and it is not a range at
//     all — Azure reads the pair as a flag meaning "accept connections from any
//     IP inside Azure", which is every other Azure tenant's compute, not just
//     this subscription's. A sweep keyed to `0\.0\.0\.0/0` returns nothing here.
//   * There is no `Microsoft.Insights/diagnosticSettings` resource in this file,
//     and that is leg 2. The absence is the finding: nothing in Azure logs a
//     Postgres connection or a Key Vault secret read until a diagnostic setting
//     routes it somewhere.
//
// Deliberately NOT in this file, so the two legs stay legible: TLS is pinned
// (`minimumTlsVersion`), the vault uses RBAC rather than a wildcard access
// policy, soft delete and purge protection are on, storage encryption is
// untouched (Azure has no off switch for it), no secret literal appears, and no
// role assignment is declared at subscription scope.
//
// NOT RUNNABLE: no target scope beyond the default, no parameter file, no
// resource group, no subscription and no credentials. The administrator password
// is a `@secure()` parameter with no default, so there is nothing to leak and
// nothing to deploy — `az deployment group create` has no arguments to satisfy.

@description('Azure region for every resource in this file.')
param location string

@description('Name of the PostgreSQL flexible server.')
param serverName string

@description('Name of the Key Vault.')
param vaultName string

@description('Administrator login for the PostgreSQL flexible server.')
param administratorLogin string

@secure()
@description('Supplied at deployment time. No default, deliberately.')
param administratorLoginPassword string

// ---------------------------------------------------------------------------
// leg 1a — the managed database, with its public data plane switched on.
// ---------------------------------------------------------------------------
resource postgres 'Microsoft.DBforPostgreSQL/flexibleServers@2023-06-01-preview' = {
  name: serverName
  location: location
  sku: {
    name: 'Standard_D2ds_v4'
    tier: 'GeneralPurpose'
  }
  properties: {
    version: '16'
    administratorLogin: administratorLogin
    administratorLoginPassword: administratorLoginPassword
    storage: {
      storageSizeGB: 256
    }
    backup: {
      backupRetentionDays: 14
      geoRedundantBackup: 'Disabled'
    }
    // --- the finding -----------------------------------------------------
    // Public access on, and no delegatedSubnetResourceId, so the server has a
    // routable endpoint and the firewall rules below are the only boundary.
    network: {
      publicNetworkAccess: 'Enabled'
    }
    // --- end of the finding ----------------------------------------------
  }
}

// ---------------------------------------------------------------------------
// leg 1b — the sentinel. `0.0.0.0` to `0.0.0.0` is not a range: it is the flag
// Azure uses for "any IP inside Azure", so any VM in any tenant can open a TCP
// session to port 5432 and the administrator password is all that stands there.
// ---------------------------------------------------------------------------
resource allowAzureServices 'Microsoft.DBforPostgreSQL/flexibleServers/firewallRules@2023-06-01-preview' = {
  parent: postgres
  name: 'AllowAllAzureServicesAndResourcesWithinAzureIps'
  properties: {
    startIpAddress: '0.0.0.0'
    endIpAddress: '0.0.0.0'
  }
}

// ---------------------------------------------------------------------------
// leg 1c — the secret store, same defect, second resource type. A vault with a
// public data plane is reachable from anywhere; `defaultAction: 'Allow'` means
// the network ACL list below it narrows nothing.
// ---------------------------------------------------------------------------
resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: vaultName
  location: location
  properties: {
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    enablePurgeProtection: true
    // --- the finding -----------------------------------------------------
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      defaultAction: 'Allow'
      bypass: 'AzureServices'
    }
    // --- end of the finding ----------------------------------------------
  }
}

// ---------------------------------------------------------------------------
// leg 2 — what is missing. There is no `Microsoft.Insights/diagnosticSettings`
// resource for the server, for the vault, or at any other scope in this
// deployment, and no `Microsoft.Network/privateEndpoints` either. Both are
// absences, so both are invisible to any grep keyed to a dangerous value.
// ---------------------------------------------------------------------------

output serverFqdn string = postgres.properties.fullyQualifiedDomainName
output vaultUri string = vault.properties.vaultUri
