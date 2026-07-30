# C-029 — clean fixture. Expected findings at Low or above: ZERO.
#
# Why this pattern-matches as vulnerable:
#   A soft-delete column (`deleted_at`) and an erasure handler that does not issue
#   a `DELETE`. "Right to erasure not implemented" is the reflex, and the grep for
#   `deleted_at` / `is_deleted` / `SoftDeletes` lands on line 60.
#
# Why it is not a finding:
#   Erasure is an OUTCOME obligation, not a requirement to issue a synchronous
#   DELETE. Art 17(1) requires erasure without undue delay, Art 12(3) requires the
#   response within one month, and Art 17(3) plus independent statutory duties —
#   tax and accounting, AML/KYC, employment, product liability, litigation hold —
#   affirmatively require keeping some records. What the entry asks for is the purge
#   path, its schedule and its coverage, and all three are here:
#
#     * THE PURGE PATH EXISTS. `purge_due_erasures` irreversibly overwrites or
#       deletes every non-retained field, and it is not a `DELETE` on one table: it
#       walks `ERASURE_PLAN`, which names every store that holds a copy.
#     * THE WINDOW IS INSIDE THE DEADLINE. `PURGE_INTERVAL_HOURS = 6` and
#       `RESPONSE_DEADLINE_DAYS = 30`, and `assert_schedule_meets_deadline` makes
#       that arithmetic a runtime check rather than a comment. A purge window that
#       extends past the response deadline is one of the two surviving findings, so
#       it is asserted rather than described.
#     * RETAINED ROWS ARE NOT USED FOR THE ORIGINAL PURPOSE. The other surviving
#       finding is a "deleted" user still resolving in a marketing send.
#       `marketing_audience` excludes erased subjects at the query, and the
#       invoice rows kept under the tax duty are pseudonymised: the subject
#       reference is replaced with a one-way token, so the row supports an audit and
#       cannot be re-associated with the person by anyone holding only this database.
#     * BACKUPS. Named explicitly rather than waved at: the backup set cannot be
#       selectively edited, so it is handled under the put-beyond-use approach —
#       restores run through `apply_pending_erasures_after_restore`, which is
#       registered as a post-restore hook so a restore cannot resurrect an erased
#       subject.
#
# False-positive entries exercised:
#   privacy-and-data-protection (1)  a soft-delete column / retained invoice rows
#                                    after an erasure request

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from django.db import transaction

from .models import (
    AuditEvent,
    ErasureRequest,
    Invoice,
    MarketingProfile,
    Subject,
    SupportMessage,
)

PURGE_INTERVAL_HOURS = 6
RESPONSE_DEADLINE_DAYS = 30

# Grace window before the purge runs, so an erasure raised in error can be
# withdrawn by the subject. Deliberately far inside the response deadline.
GRACE_HOURS = 24


@dataclass(frozen=True)
class StoreRule:
    """One store, and what happens to it on erasure."""

    model: type
    subject_field: str
    action: str  # "delete" | "pseudonymise" | "redact"
    lawful_basis_to_retain: str | None


# Every store that holds a copy. Coverage is the thing the entry asks for, so it
# is a declared table rather than a sequence of ad-hoc calls in one function.
ERASURE_PLAN: tuple[StoreRule, ...] = (
    StoreRule(MarketingProfile, "subject_id", "delete", None),
    StoreRule(SupportMessage, "subject_id", "redact", None),
    StoreRule(
        Invoice,
        "subject_id",
        "pseudonymise",
        "tax and accounting retention — statutory, 7 years",
    ),
    StoreRule(
        AuditEvent,
        "subject_id",
        "pseudonymise",
        "security audit trail — Art 17(3)(b) legal obligation",
    ),
)


def assert_schedule_meets_deadline() -> None:
    """Make the window an assertion instead of a claim.

    Worst-case latency from request to purge is the grace window plus one full
    purge interval. If that ever exceeds the response deadline, this fails in CI
    rather than a reviewer having to recompute it.
    """
    worst_case = timedelta(hours=GRACE_HOURS + PURGE_INTERVAL_HOURS)
    assert worst_case < timedelta(days=RESPONSE_DEADLINE_DAYS), (
        f"purge window {worst_case} exceeds the Art 12(3) response deadline"
    )


def request_erasure(subject: Subject, now: datetime | None = None) -> ErasureRequest:
    """Record the request and soft-delete the subject.

    The soft delete is what stops the account being usable immediately; it is not
    the erasure. The erasure is `purge_due_erasures`, and the row below is what
    guarantees it runs.
    """
    now = now or datetime.now(timezone.utc)
    with transaction.atomic():
        subject.deleted_at = now
        subject.save(update_fields=["deleted_at"])
        return ErasureRequest.objects.create(
            subject_id=subject.id,
            requested_at=now,
            purge_after=now + timedelta(hours=GRACE_HOURS),
            completed_at=None,
        )


def _pseudonym(pepper: bytes, subject_id: str) -> str:
    """One-way subject reference for rows a statute requires us to keep.

    HMAC with a pepper held in the key service, not in this database. A holder of
    the database alone cannot invert it or test a candidate id, so the retained
    invoice row supports an audit without re-identifying the person.
    """
    return hmac.new(pepper, subject_id.encode(), hashlib.sha256).hexdigest()


def purge_due_erasures(pepper: bytes, now: datetime | None = None) -> int:
    """Run the purge. Scheduled every PURGE_INTERVAL_HOURS.

    Irreversible: `delete` removes the rows, `redact` overwrites the free-text
    columns in place, and `pseudonymise` replaces the subject reference with a
    one-way token. None of the three leaves a reversible copy behind in this
    database.
    """
    now = now or datetime.now(timezone.utc)
    assert_schedule_meets_deadline()

    completed = 0
    due = ErasureRequest.objects.filter(completed_at__isnull=True, purge_after__lte=now)

    for request in due:
        with transaction.atomic():
            token = _pseudonym(pepper, str(request.subject_id))

            for rule in ERASURE_PLAN:
                rows = rule.model.objects.filter(**{rule.subject_field: request.subject_id})
                if rule.action == "delete":
                    rows.delete()
                elif rule.action == "redact":
                    rows.update(body="[erased]", author_name="[erased]", author_email="")
                elif rule.action == "pseudonymise":
                    rows.update(**{rule.subject_field: None, "subject_pseudonym": token})
                else:  # pragma: no cover — the table is closed
                    raise ValueError(f"unknown erasure action {rule.action!r}")

            Subject.objects.filter(id=request.subject_id).delete()
            request.completed_at = now
            request.save(update_fields=["completed_at"])
            completed += 1

    return completed


def marketing_audience():
    """The query that decides who receives a send.

    Excludes soft-deleted subjects at the source, so an erased subject cannot
    resolve in a marketing send during the grace window. That is the concrete
    surviving finding this entry names, and it is closed here rather than assumed
    to be closed by the purge.
    """
    return MarketingProfile.objects.filter(
        subject__deleted_at__isnull=True,
        marketing_consent=True,
    )


def apply_pending_erasures_after_restore(pepper: bytes) -> int:
    """Post-restore hook.

    A backup set cannot be selectively edited, so an erasure cannot be applied
    retroactively to the archive. The put-beyond-use answer is that a restore is
    never used directly: this hook runs before the restored database serves
    traffic and re-applies every erasure recorded up to the restore point.
    """
    return purge_due_erasures(pepper)
