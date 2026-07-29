/**
 * C-015 — clean fixture. Expected findings at Low or above: ZERO.
 *
 * Why this pattern-matches as vulnerable:
 *   The class is declared `without sharing`. That literal is the single
 *   highest-signal grep in salesforce-platform, and a reflex reading grades it
 *   High as a sharing bypass. There is also a `Database.query` with string
 *   building, three lines below.
 *
 * Why it is not a finding — three independent reasons, any one of which is
 * sufficient, and the entry demands the first two be established rather than
 * assumed:
 *
 *   1. SHARING DOES NOT EXIST FOR ONE OF THE TWO OBJECTS. `Shipping_Rule__mdt`
 *      is a custom metadata type. Custom metadata types, custom settings and
 *      platform events have no sharing model at all — there is no record-level
 *      access to bypass — so `without sharing` is a no-op with respect to that
 *      query, structurally and permanently.
 *
 *   2. THE OTHER OBJECT'S ORG-WIDE DEFAULT IS PUBLIC READ/WRITE. Read it in the
 *      metadata file shipped in this fixture at
 *      `force-app/main/default/objects/Shipping_Zone__c/Shipping_Zone__c.object-meta.xml`
 *      declares `<sharingModel>ReadWrite</sharingModel>` and
 *      `<externalSharingModel>ReadWrite</externalSharingModel>`. Sharing only
 *      restricts objects with a restrictive OWD, so on a Public Read/Write object
 *      `with sharing` and `without sharing` compute the same row set. The
 *      declaration is inert.
 *
 *   3. NO USER-SUPPLIED ID OR FILTER CROSSES THE BOUNDARY. Every method here
 *      takes ids that the trigger context supplied (`Trigger.newMap.keySet()`),
 *      never a parameter from an `@AuraEnabled`, `@RestResource`,
 *      `@InvocableMethod` or `ApexPages.currentPage().getParameters()` source.
 *      There is no entry-point annotation anywhere in this file, and the class is
 *      not `global`, so it cannot be called from a managed-package boundary
 *      either.
 *
 *   And the declaration is not decorative even so: it is the correct declaration
 *   for a rollup that must recompute totals across every zone regardless of who
 *   triggered the save, which is the use false positive 2 names explicitly.
 *
 *   NOTE ON THE CARVE-OUT'S LIMIT. False positive 2 says the trigger clearance
 *   covers the handler AS INVOKED FROM THE TRIGGER, and that the same class is
 *   frequently also called from an `@AuraEnabled` method where the declaration is
 *   load-bearing again. Every caller of this class is enumerated in the comment
 *   above `recalculateForZones` and there is exactly one: the trigger. That is why
 *   the carve-out applies here and why a reader must check it rather than infer it.
 *
 * Why the dynamic SOQL is not injectable:
 *   The only interpolated token is a field API name resolved out of
 *   `Schema.getGlobalDescribe()`; a name absent from the describe map raises. All
 *   values are bound (`:zoneIds`). `Database.query` with a bind and no
 *   concatenated value is already parameterised.
 *
 * False-positive entries exercised:
 *   salesforce-platform (2)  `without sharing` treated as a bypass on sight —
 *                            both discriminators (object type, OWD) established
 *   salesforce-platform (3)  dynamic SOQL with a describe-resolved identifier and
 *                            bound values
 */
public without sharing class ShippingRuleRollup {

    public class UnknownFieldException extends Exception {}

    /**
     * Recompute zone surcharges after a rule changes.
     *
     * CALLERS — enumerated, because false positive 2's carve-out requires it:
     *   ShippingRuleTrigger (after insert, after update, after delete)  <-- only caller
     * There is no @AuraEnabled, @RestResource, @InvocableMethod, webservice or
     * Visualforce controller path into this class.
     */
    public static void recalculateForZones(Set<Id> zoneIds) {
        if (zoneIds == null || zoneIds.isEmpty()) {
            return;
        }

        // Custom metadata type. No sharing model exists for __mdt, so the class
        // declaration cannot be widening anything here.
        Map<String, Decimal> surchargeByCarrier = new Map<String, Decimal>();
        for (Shipping_Rule__mdt rule : [
            SELECT Carrier_Code__c, Surcharge__c
            FROM Shipping_Rule__mdt
            WHERE Active__c = true
        ]) {
            surchargeByCarrier.put(rule.Carrier_Code__c, rule.Surcharge__c);
        }

        String amountField = resolveFieldName('Shipping_Zone__c', 'Base_Rate__c');

        // Reads like injection. `amountField` is the describe's own spelling of a
        // known field; `zoneIds` is bound.
        String soql =
            'SELECT Id, Carrier_Code__c, ' + amountField +
            ' FROM Shipping_Zone__c WHERE Id IN :zoneIds';

        List<Shipping_Zone__c> zones = Database.query(soql);

        List<Shipping_Zone__c> updates = new List<Shipping_Zone__c>();
        for (Shipping_Zone__c zone : zones) {
            Decimal surcharge = surchargeByCarrier.get(zone.Carrier_Code__c);
            if (surcharge == null) {
                continue;
            }
            zone.Total_Rate__c = (Decimal) zone.get(amountField) + surcharge;
            updates.add(zone);
        }

        if (!updates.isEmpty()) {
            update updates;
        }
    }

    private static String resolveFieldName(String objectApiName, String requested) {
        Schema.SObjectType sobjType = Schema.getGlobalDescribe().get(objectApiName);
        if (sobjType == null) {
            throw new UnknownFieldException('unknown object: ' + objectApiName);
        }
        Schema.SObjectField field = sobjType.getDescribe().fields.getMap().get(requested.toLowerCase());
        if (field == null) {
            throw new UnknownFieldException('unknown field: ' + requested);
        }
        return field.getDescribe().getName();
    }
}
