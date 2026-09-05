# C-049 — clean detector mirror for workload identity at an internal boundary
# The receiver derives identity from a verified workload credential instead of source position.

@app.middleware("http")
async def internal_only(request: Request, call_next):
    request.state.user = verify_workload_token(request.headers.get("authorization"))
    return await call_next(request)
