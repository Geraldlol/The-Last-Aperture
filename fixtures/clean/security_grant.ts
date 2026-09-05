// C-048 — clean detector mirror for a privileged-role grant
// The role mutation and attributed security event commit in one transaction.

async function grantAdmin(req, userId) {
  await db.transaction(async (tx) => {
    await roles.add(tx, userId, "admin")
    await securityOutbox.append(tx, "identity.admin_role_granted", {
      actorId: req.auth.subject,
      subjectId: userId,
      outcome: "success",
      requestId: req.id
    })
  })
  return { ok: true }
}
