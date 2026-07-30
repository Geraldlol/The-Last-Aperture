//////////////////////////////////////////////////////////////////////////////
// C-034 — clean fixture. Expected findings at Low or above: ZERO.
//
// Stack: Azure Bicep. This is the discriminating half of the Bicep pair — the
// file that proves the new Bicep sweeps in `cloud-and-iac` §0 fire on a defect
// rather than on the mere presence of Bicep.
//
// Why this pattern-matches as vulnerable:
//   * `publicNetworkAccess` appears three times, so §0's
//     `public_network_access_enabled|…|publicNetworkAccess` sweep hits this file
//     on every store in it.
//   * `bypass: 'AzureServices'` appears twice and reads as the same "let all of
//     Azure in" grant as the `0.0.0.0`–`0.0.0.0` firewall sentinel.
//   * An NSG rule allows `sourceAddressPrefix: 'Internet'` inbound, and the rule
//     eight lines below it names port 22.
//   * A `Microsoft.OperationalInsights/workspaces` declaration carries no
//     properties at all, which is the shape a per-resource absence sweep flags.
//
// Why none of it is a finding:
//   * Every `publicNetworkAccess` here reads `'Disabled'`. The value is the
//     finding, never the key — and the data plane of all three stores is reached
//     through VNet injection (Postgres) or a private endpoint (storage, vault).
//   * `bypass: 'AzureServices'` sits beside `defaultAction: 'Deny'`, so it is not
//     an open door: it exempts named first-party services from a default-deny
//     ACL, which is what lets the diagnostic settings below write at all. The
//     Azure sentinel this resembles is a *firewall rule* on a server with public
//     access enabled, and neither exists here — there is no
//     `Microsoft.DBforPostgreSQL/flexibleServers/firewallRules` resource in this
//     file, because a VNet-injected server cannot have one.
//   * The `'Internet'` NSG rule is 443 to the application-gateway subnet, which
//     is the intended design and is not on item 3's sensitive-port list. Port 22
//     is a separate rule whose source is the bastion subnet prefix, not
//     `'Internet'` and not `'*'`; the rule after both denies all remaining
//     inbound traffic.
//   * The workspace is declared `existing`, so it is a *reference* to a resource
//     this file does not deploy. It has no properties because there are none to
//     set. `bicep_absent` excludes an `existing` header for exactly this reason,
//     and a hand-written sweep that does not is reading a reference as a
//     deployment.
//   * There is one `Microsoft.Insights/diagnosticSettings` resource per store,
//     each naming its store in `scope:`, so the count comparison in §0 balances
//     AND the pairing resolves — which the sweep's own comment says to check
//     rather than trusting the arithmetic.
//
// False-positive entries exercised:
//   cloud-and-iac (6)  an "internet" source rule reported as exposure — held to
//                      the sensitive-port list, in the camelCase stack, and with
//                      the Azure `0.0.0.0`–`0.0.0.0` sentinel clause read the
//                      way the entry states it rather than as `0.0.0.0/0`
//
// NOT RUNNABLE: no parameter file, no resource group, no subscription, no
// credentials, and every network and DNS resource id arrives as a parameter this
// repository does not supply. The administrator password is a `@secure()`
// parameter with no default.
//////////////////////////////////////////////////////////////////////////////

@description('Azure region for every resource in this file.')
param location string

@description('Name of the PostgreSQL flexible server.')
param serverName string

@description('Name of the Key Vault.')
param vaultName string

@description('Name of the storage account holding exported reports.')
param storageAccountName string

@description('Name of a Log Analytics workspace this deployment does not own.')
param workspaceName string

@description('Resource id of the delegated subnet for the database.')
param databaseSubnetId string

@description('Resource id of the subnet holding the private endpoints.')
param privateEndpointSubnetId string

@description('Resource id of the private DNS zone for the database.')
param databasePrivateDnsZoneId string

@description('Resource id of the private DNS zone for blob storage.')
param blobPrivateDnsZoneId string

@description('Resource id of the private DNS zone for Key Vault.')
param vaultPrivateDnsZoneId string

@description('Address prefix of the bastion subnet, the only source for SSH.')
param bastionSubnetPrefix string

@description('Address prefix of the application gateway subnet.')
param gatewaySubnetPrefix string

@description('Administrator login for the PostgreSQL flexible server.')
param administratorLogin string

@secure()
@description('Supplied at deployment time. No default, deliberately.')
param administratorLoginPassword string

// ---------------------------------------------------------------------------
// A reference, not a deployment. `existing` means Bicep resolves the id and
// deploys nothing, which is why this block carries no properties.
// ---------------------------------------------------------------------------
resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
}

// ---------------------------------------------------------------------------
// The database. VNet-injected: no public endpoint exists, so there is no
// firewall rule to write and no sentinel to get wrong.
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
      geoRedundantBackup: 'Enabled'
    }
    network: {
      publicNetworkAccess: 'Disabled'
      delegatedSubnetResourceId: databaseSubnetId
      privateDnsZoneArmResourceId: databasePrivateDnsZoneId
    }
  }
}

// ---------------------------------------------------------------------------
// The storage account. Public data plane off, anonymous blob access off, TLS
// pinned, and a default-deny network ACL.
// ---------------------------------------------------------------------------
resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: storageAccountName
  location: location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_ZRS'
  }
  properties: {
    publicNetworkAccess: 'Disabled'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'AzureServices'
    }
  }
}

// ---------------------------------------------------------------------------
// The vault. Same three properties, plus RBAC rather than access policies.
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
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'AzureServices'
    }
  }
}

// ---------------------------------------------------------------------------
// The private endpoints that replace the public data planes above.
// ---------------------------------------------------------------------------
resource storageEndpoint 'Microsoft.Network/privateEndpoints@2023-09-01' = {
  name: '${storageAccountName}-blob-pe'
  location: location
  properties: {
    subnet: {
      id: privateEndpointSubnetId
    }
    privateLinkServiceConnections: [
      {
        name: 'blob'
        properties: {
          privateLinkServiceId: storage.id
          groupIds: [
            'blob'
          ]
        }
      }
    ]
  }

  resource dnsGroup 'privateDnsZoneGroups' = {
    name: 'default'
    properties: {
      privateDnsZoneConfigs: [
        {
          name: 'blob'
          properties: {
            privateDnsZoneId: blobPrivateDnsZoneId
          }
        }
      ]
    }
  }
}

resource vaultEndpoint 'Microsoft.Network/privateEndpoints@2023-09-01' = {
  name: '${vaultName}-pe'
  location: location
  properties: {
    subnet: {
      id: privateEndpointSubnetId
    }
    privateLinkServiceConnections: [
      {
        name: 'vault'
        properties: {
          privateLinkServiceId: vault.id
          groupIds: [
            'vault'
          ]
        }
      }
    ]
  }

  resource dnsGroup 'privateDnsZoneGroups' = {
    name: 'default'
    properties: {
      privateDnsZoneConfigs: [
        {
          name: 'vault'
          properties: {
            privateDnsZoneId: vaultPrivateDnsZoneId
          }
        }
      ]
    }
  }
}

// ---------------------------------------------------------------------------
// The NSG. One rule takes 'Internet' — on 443, to the gateway subnet, which is
// what the application is for. SSH is a separate rule with a subnet source, and
// the last rule denies whatever the first two did not allow.
// ---------------------------------------------------------------------------
resource appGatewayNsg 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {
  name: '${serverName}-agw-nsg'
  location: location
  properties: {
    securityRules: [
      {
        name: 'allow-https-from-internet'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: 'Internet'
          sourcePortRange: '*'
          destinationAddressPrefix: gatewaySubnetPrefix
          destinationPortRange: '443'
        }
      }
      {
        name: 'allow-ssh-from-bastion-only'
        properties: {
          priority: 200
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: bastionSubnetPrefix
          sourcePortRange: '*'
          destinationAddressPrefix: gatewaySubnetPrefix
          destinationPortRange: '22'
        }
      }
      {
        name: 'deny-all-other-inbound'
        properties: {
          priority: 4096
          direction: 'Inbound'
          access: 'Deny'
          protocol: '*'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
    ]
  }
}

// ---------------------------------------------------------------------------
// One diagnostic setting per store, each naming its store in `scope:`. This is
// the half V-016 has none of.
// ---------------------------------------------------------------------------
resource postgresDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: postgres
  name: 'audit-to-workspace'
  properties: {
    workspaceId: workspace.id
    logs: [
      {
        categoryGroup: 'audit'
        enabled: true
      }
      {
        categoryGroup: 'allLogs'
        enabled: true
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
}

resource storageDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: storage
  name: 'audit-to-workspace'
  properties: {
    workspaceId: workspace.id
    metrics: [
      {
        category: 'Transaction'
        enabled: true
      }
    ]
  }
}

resource vaultDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: vault
  name: 'audit-to-workspace'
  properties: {
    workspaceId: workspace.id
    logs: [
      {
        categoryGroup: 'audit'
        enabled: true
      }
      {
        categoryGroup: 'allLogs'
        enabled: true
      }
    ]
  }
}
