/**
 * C-005 — clean fixture. Expected findings at Low or above: ZERO.
 *
 * Why this pattern-matches as vulnerable:
 *   String concatenation goes directly into a dynamic SOQL execution call, and
 *   one of the concatenated tokens arrives from an `@AuraEnabled` parameter.
 *   Visually this is indistinguishable from the SOQL-injection fixture: the
 *   `+` operator, a caller-supplied string, `Database.queryWithBinds`.
 *
 * Why it is not a finding:
 *   The only caller-supplied token that reaches the query text is a FIELD NAME,
 *   and it is resolved through `Schema.getGlobalDescribe()` before it is used —
 *   a name absent from the describe map raises and never reaches the string.
 *   The describe map is the allowlist, and it is closed by the platform rather
 *   than by a hand-maintained list that can drift. Every *value* is bound
 *   (`:accountIds`, `:rowLimit`, `:namePrefix`), and the query runs in
 *   `AccessLevel.USER_MODE` so object and field permissions and sharing are all
 *   enforced by the platform on the way out.
 *
 *   The reason concatenation is correct here rather than lazy: a field name in
 *   the SELECT list or in ORDER BY cannot be bound. There is no bind syntax for
 *   a column position in SOQL, so an allowlist is the fix, not a workaround.
 *
 * False-positive entries exercised:
 *   salesforce-platform (3)  `Database.query`-family string building where the
 *                            concatenated token is a describe-resolved field
 *                            name and every value is bound
 *   salesforce-platform (4)  no `Security.stripInaccessible()` and no
 *                            `isAccessible()` — enforcement is `USER_MODE`
 *   salesforce-platform (6)  an `@AuraEnabled` method with no permission check,
 *                            correctly scoped by sharing and FLS in user mode
 *   salesforce-platform (1)  a declared sharing keyword on the entry point
 */
public with sharing class ReportColumnQuery {
    /** Columns the report builder is allowed to project, beyond the fixed set. */
    private static final Set<String> FIXED_COLUMNS = new Set<String>{
        'Id', 'Name'
    };

    /** Sort directions are a two-element closed domain, so an enum-shaped check. */
    private static final Set<String> SORT_DIRECTIONS = new Set<String>{
        'ASC', 'DESC'
    };

    public class UnknownColumnException extends Exception {}

    /**
     * Resolve a caller-supplied field name against the object's describe.
     *
     * Two things make this an allowlist and not an escape: the map comes from
     * the platform's own metadata, and a miss RAISES rather than falling back to
     * the raw input. The returned value is the describe's own name for the
     * field, so even a case variant is normalised to a known-good literal
     * before it is concatenated.
     */
    private static String resolveFieldName(String objectApiName, String requested) {
        if (String.isBlank(requested)) {
            throw new UnknownColumnException('no column requested');
        }

        Schema.SObjectType sobjType = Schema.getGlobalDescribe().get(objectApiName);
        if (sobjType == null) {
            throw new UnknownColumnException('unknown object: ' + objectApiName);
        }

        Map<String, Schema.SObjectField> fields = sobjType.getDescribe().fields.getMap();
        Schema.SObjectField field = fields.get(requested.toLowerCase());
        if (field == null) {
            throw new UnknownColumnException('unknown column: ' + requested);
        }

        // The describe's own spelling, never the caller's string.
        return field.getDescribe().getName();
    }

    private static String resolveDirection(String requested) {
        String upper = String.isBlank(requested) ? 'ASC' : requested.toUpperCase();
        if (!SORT_DIRECTIONS.contains(upper)) {
            throw new UnknownColumnException('unknown sort direction: ' + requested);
        }
        return upper;
    }

    /**
     * Project a caller-chosen column over accounts the caller can already see.
     *
     * No Id parameter widens scope: `accountIds` narrows within what user mode
     * already permits, so a permission check here would be defence in depth
     * rather than the fix. `cacheable=true` is safe for the same reason — the
     * result is what this user is entitled to see.
     */
    @AuraEnabled(cacheable=true)
    public static List<SObject> fetchColumn(
        String extraColumn,
        String sortDirection,
        List<Id> accountIds,
        String namePrefix,
        Integer rowLimit
    ) {
        String safeColumn = resolveFieldName('Account', extraColumn);
        String safeDirection = resolveDirection(sortDirection);
        Integer safeLimit = (rowLimit == null || rowLimit <= 0 || rowLimit > 2000) ? 200 : rowLimit;

        List<String> projection = new List<String>(FIXED_COLUMNS);
        if (!FIXED_COLUMNS.contains(safeColumn)) {
            projection.add(safeColumn);
        }

        // Reads like injection. Every interpolated token is either a literal
        // declared in this file or a describe-resolved API name; every value is
        // a named bind resolved from the map below.
        String soql =
            'SELECT ' + String.join(projection, ', ') +
            ' FROM Account' +
            ' WHERE Id IN :accountIds' +
            ' AND Name LIKE :namePattern' +
            ' ORDER BY ' + safeColumn + ' ' + safeDirection +
            ' LIMIT :rowLimit';

        Map<String, Object> binds = new Map<String, Object>{
            'accountIds' => accountIds,
            // Bound as a value, so the caller's `%` and `_` are data to the
            // LIKE operator's argument rather than syntax in the query text.
            'namePattern' => (String.isBlank(namePrefix) ? '%' : namePrefix + '%'),
            'rowLimit' => safeLimit
        };

        return Database.queryWithBinds(soql, binds, AccessLevel.USER_MODE);
    }
}
