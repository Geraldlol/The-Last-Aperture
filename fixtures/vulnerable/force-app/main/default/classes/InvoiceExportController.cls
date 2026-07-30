// V-012 — VULNERABLE fixture. NOT RUNNABLE (not deployable). Written from scratch.
//
// Bug class (exactly one): record-level sharing bypass — an @AuraEnabled entry
// point on a `without sharing` class returning SObjects, over an object whose
// org-wide default is Private.
// Lens: salesforce-platform / topic `apex-sharing-declaration`
// Expected: High, CWE-862
//
// `without sharing` is legitimate for system-level work — rollups, sharing
// recalculation, batch jobs. It is a finding here because a user-supplied Id
// crosses into it from an entry point any authenticated community or internal
// user can call from Lightning. The org-wide default that the bypass defeats is
// established inside this corpus: see
// force-app/main/default/objects/Invoice__c/Invoice__c.object-meta.xml, which
// carries <sharingModel>Private</sharingModel>.
//
// Deliberately NOT in this file, so the fixture carries one bug class only: the
// filters are bound (`:accountId`), so there is no SOQL injection; there is no
// Database.query, no JSON.deserialize onto an SObject, no OwnerId write, no
// __Share insert and no PermissionSetAssignment insert.
//
// NOT DEPLOYABLE: there is no sfdx-project.json, no package.xml, no test class,
// and no meta.xml beside this file, so no deploy or retrieve can pick it up.

public without sharing class InvoiceExportController {

    // Entry point. Reachable from any Lightning component the caller can load,
    // and `accountId` is whatever the caller sends.
    @AuraEnabled
    public static List<Invoice__c> invoicesForAccount(Id accountId) {
        // Bound filter, so no injection — and no sharing either. The class
        // declaration puts this query in system mode, so the row-level access the
        // running user has to Invoice__c is not consulted. There is no
        // WITH USER_MODE, no WITH SECURITY_ENFORCED, and no Security.stripInaccessible.
        return [
            SELECT Id, Name, Account__c, Amount__c, Status__c, InternalMemo__c
            FROM Invoice__c
            WHERE Account__c = :accountId
            ORDER BY CreatedDate DESC
            LIMIT 200
        ];
    }

    // Second entry point, same defect, no identifier at all: the caller does not
    // even need to know an Account Id to read across the org.
    @AuraEnabled(cacheable=true)
    public static List<Invoice__c> recentInvoices() {
        return [
            SELECT Id, Name, Account__c, Amount__c, Status__c
            FROM Invoice__c
            ORDER BY CreatedDate DESC
            LIMIT 50
        ];
    }
}
