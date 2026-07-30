// V-002 — VULNERABLE fixture. NOT RUNNABLE. Written from scratch.
//
// Bug class (exactly one): SQL injection — caller-controlled text concatenated
// into a query string.
// Lens: web-and-api / topic `injection-sql-nosql-orm`
// Expected: Critical, CWE-89
//
// Two injectable positions, one defect class:
//   * `status` stands where a VALUE stands and is concatenated anyway.
//   * `sortColumn` stands where an IDENTIFIER stands, which a bound parameter
//     cannot occupy — so the fix there is an allowlist the code owns, not a
//     placeholder. Both are the same finding at one site.
//
// The taint source is named on the entry point (`ReportRequest`, populated from
// an HTTP query string by the controller that is deliberately not in this
// corpus), so the trace is readable without a second file.
//
// No JDBC URL, no driver, no credentials, no main method. It cannot run.

package fixtures.vulnerable;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

public final class LedgerReportDao {

    /** Values arrive straight off the request query string. Nothing coerces them. */
    public static final class ReportRequest {
        public String status;      // ?status=
        public String sortColumn;  // ?sort=
        public long orgId;         // ?org=
    }

    public static final class LedgerRow {
        public long id;
        public String title;
        public long amountCents;
    }

    private final Connection connection;

    public LedgerReportDao(Connection connection) {
        this.connection = connection;
    }

    // The concatenation is the finding. `status` closes the quoted literal;
    // `sortColumn` needs no quote to escape at all. The ORDER BY position is why
    // "just parameterise it" is incomplete advice and an allowlist is required.
    public List<LedgerRow> rowsFor(ReportRequest request) throws SQLException {
        String sql =
            "SELECT id, title, amount_cents FROM ledger_entries "
                + "WHERE org_id = " + request.orgId + " "
                + "AND status = '" + request.status + "' "
                + "ORDER BY " + request.sortColumn + " DESC";

        List<LedgerRow> rows = new ArrayList<>();
        try (Statement statement = connection.createStatement();
             ResultSet results = statement.executeQuery(sql)) {
            while (results.next()) {
                LedgerRow row = new LedgerRow();
                row.id = results.getLong("id");
                row.title = results.getString("title");
                row.amountCents = results.getLong("amount_cents");
                rows.add(row);
            }
        }
        return rows;
    }

    // Second-order shape at the same site: `title` was stored through a bound
    // parameter on the write path, and is concatenated here by a different code
    // path. The taint source for this query is the database, not the request,
    // which is why a review of the insert never finds it.
    public int countLike(String storedTitle) throws SQLException {
        String sql =
            "SELECT COUNT(*) FROM ledger_entries WHERE title LIKE '%" + storedTitle + "%'";
        try (Statement statement = connection.createStatement();
             ResultSet results = statement.executeQuery(sql)) {
            return results.next() ? results.getInt(1) : 0;
        }
    }
}
