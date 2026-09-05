# V-029 — threat-modeling / architecture-trust-design-gaps / High / CWE-290
# Inert detector fixture: network position is promoted to service identity at a trust crossing.

@app.middleware("http")
async def internal_only(request: Request, call_next):
    if request.client.host.startswith("10."):
        request.state.user = SERVICE_ACCOUNT
    return await call_next(request)
