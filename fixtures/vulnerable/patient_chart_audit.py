# V-026 — hipaa-and-phi / phi-access-audit-controls / High / CWE-778
# Inert detector fixture: a pooled service identity replaces the acting human in every application audit record.

POOL_USER = "app_service"

def get_chart(patient_id):
    rows = db.query("SELECT * FROM encounters WHERE patient_id = %s", patient_id)
    audit.write(actor=POOL_USER, action="read_chart", record=patient_id)
    return rows
