# C-044 — clean detector mirror for authorization dependency failure
# The named dependency failure is observable and fails closed.

def may_export(actor, record):
    try:
        return policy.authorize(actor, "export", record)
    except PolicyUnavailable as exc:
        security_events.control_failure("export_policy", actor.id, exc)
        return False
