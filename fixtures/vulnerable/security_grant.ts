// V-028 — security-observability-and-response / security-event-coverage / Medium / CWE-778
// Inert detector fixture: a privileged mutation has no durable security-event record on its success path.

async function grantAdmin(req, userId) {
  await roles.add(userId, "admin")
  return { ok: true }
}
