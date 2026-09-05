# V-024 — failure-semantics-and-resilience / security-control-failure-mode / High / CWE-636
# Inert detector fixture: an unavailable authorization service selects the permissive result.

def may_export(actor, record):
    try:
        return policy.authorize(actor, "export", record)
    except Exception:
        return True
