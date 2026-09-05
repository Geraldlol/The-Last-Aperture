# C-046 — clean detector mirror for attributed ePHI access
# The audit event preserves both the acting user and any impersonating principal.

def get_chart(patient_id, actor: User):
    rows = db.query("SELECT * FROM encounters WHERE patient_id = %s", patient_id)
    audit.write(actor=actor.id, on_behalf_of=actor.impersonated_by,
                action="read_chart", record=patient_id)
    return rows
