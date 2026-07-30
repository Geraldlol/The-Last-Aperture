# C-022 — clean fixture. Expected findings at Low or above: ZERO.
#
# Five business-logic reflexes fire on this file, and every one of them is the
# product working as designed rather than a defect.
#
#   1. NEGATIVE AMOUNTS IN A LEDGER. `post_refund` writes a negative
#      `amount_cents`. That is double-entry bookkeeping: a refund, a chargeback, a
#      credit and an adjustment are negative by construction, and a
#      `CHECK (amount_cents > 0)` on this table would itself be the bug. The
#      surviving finding — a negative crossing OUT of the ledger into an
#      availability, balance or entitlement check written for non-negative values
#      — is closed by `available_balance_cents`, which sums signed rows and clamps
#      at zero before any entitlement decision reads it.
#
#   2. INVENTORY GOING NEGATIVE. `reserve_stock` can drive `on_hand` below zero,
#      and that is the stated product design: backorder is a feature, the
#      `backorderable` column says which SKUs allow it, and the code's own
#      invariant is the one it enforces. The surviving finding — a seat, a licence,
#      a slot or a one-per-customer grant where uniqueness IS the product — is a
#      different table, and it is handled with a unique index in `claim_seat`
#      below rather than with a count.
#
#   3. A "DUPLICATE" CHARGE THAT IS A LEGITIMATE RETRY. Two provider calls carry
#      the same idempotency key and the provider deduplicates them. The key is
#      derived from the INTENT — order id plus a monotonically assigned attempt
#      *group*, not from a timestamp, not from `uuid4()`, not from the attempt
#      number — so a retry produces the same key. And the local ledger is written
#      with a unique constraint on that same key, so the case where the provider
#      charges once and the local ledger writes two rows cannot happen.
#
#   4. A MISSING APPLICATION LOCK. There is no mutex, no advisory lock and no
#      `SELECT ... FOR UPDATE`, because the database already closes the window:
#      `reserve_stock` is a single atomic `UPDATE ... WHERE` whose row count is
#      checked, and `claim_seat` relies on a unique index and handles the
#      integrity error. Naming which mechanism is absent is what a real TOCTOU
#      finding requires; here none is absent.
#
#   6. FLOAT MONEY. `format_amount` divides by 100 and formats through a float.
#      Nothing arithmetic happens on that float: it is produced at the display
#      edge, from an integer that has already been fully computed, and it is never
#      persisted, summed or sent to the provider. Every value that reaches
#      persistence or a charge is an `int` of cents.
#
# False-positive entries exercised:
#   business-logic (1)  negative amounts in a ledger
#   business-logic (2)  inventory going negative / overselling
#   business-logic (3)  a duplicate charge that is a legitimate retry
#   business-logic (4)  a missing application lock where the database closes it
#   business-logic (6)  integer cents formatted through a float at the edge

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from django.db import IntegrityError, transaction
from django.db.models import Sum

from .models import LedgerEntry, SeatClaim, StockLevel


class BackorderNotAllowed(Exception):
    """The SKU's own record says it may not go negative."""


class SeatAlreadyClaimed(Exception):
    """Uniqueness IS the product for a seat, unlike for stock."""


# ---------------------------------------------------------------------------
# (1) The ledger. Signed by design.
# ---------------------------------------------------------------------------


def post_charge(order_id: int, amount_cents: int, idempotency_key: str) -> LedgerEntry:
    if amount_cents <= 0:
        raise ValueError("a charge is positive; use post_refund for the other direction")
    return LedgerEntry.objects.create(
        order_id=order_id,
        kind="charge",
        amount_cents=amount_cents,
        idempotency_key=idempotency_key,
    )


def post_refund(order_id: int, amount_cents: int, idempotency_key: str) -> LedgerEntry:
    """Write the negative side.

    `amount_cents` arrives positive from the caller and is negated here, so the
    sign is this function's decision rather than something the caller can steer
    into the wrong direction.
    """
    if amount_cents <= 0:
        raise ValueError("refund magnitude must be positive")

    charged = (
        LedgerEntry.objects.filter(order_id=order_id, kind="charge").aggregate(
            total=Sum("amount_cents")
        )["total"]
        or 0
    )
    refunded = -(
        LedgerEntry.objects.filter(order_id=order_id, kind="refund").aggregate(
            total=Sum("amount_cents")
        )["total"]
        or 0
    )

    # The floor the product states: you cannot refund more than was charged.
    if refunded + amount_cents > charged:
        raise ValueError("refund exceeds the amount charged")

    return LedgerEntry.objects.create(
        order_id=order_id,
        kind="refund",
        amount_cents=-amount_cents,
        idempotency_key=idempotency_key,
    )


def available_balance_cents(order_id: int) -> int:
    """Sum signed rows, then clamp.

    This is the boundary the negative sign must not cross. Everything downstream
    of here — entitlement, availability, "can this order ship" — reads a
    non-negative integer, so a negative ledger row cannot become a negative
    balance in a check written for non-negative values.
    """
    total = (
        LedgerEntry.objects.filter(order_id=order_id).aggregate(total=Sum("amount_cents"))["total"]
        or 0
    )
    return max(0, total)


# ---------------------------------------------------------------------------
# (3) Idempotency derived from the intent.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ChargeIntent:
    """The intent, not the attempt. Two retries of one intent are one key."""

    order_id: int
    amount_cents: int
    intent_seq: int  # assigned once when the intent is created, never per attempt

    @property
    def idempotency_key(self) -> str:
        # No clock, no random source, no attempt counter. Recomputing this from
        # the same intent on the fifth retry yields byte-identical output.
        return f"order-{self.order_id}-intent-{self.intent_seq}-cents-{self.amount_cents}"


def charge_with_retries(intent: ChargeIntent, provider, attempts: int = 3) -> LedgerEntry:
    """Charge, retrying on a transient provider error.

    The provider deduplicates on the key. The LOCAL side is protected separately,
    by a unique constraint on `idempotency_key` — because "the provider charged
    once and the system now believes two things" is the failure the key alone does
    not prevent.
    """
    key = intent.idempotency_key

    for _ in range(attempts):
        try:
            provider.charge(
                amount_cents=intent.amount_cents,
                order_id=intent.order_id,
                idempotency_key=key,
            )
            break
        except provider.TransientError:
            continue
    else:
        raise RuntimeError("provider unavailable")

    try:
        with transaction.atomic():
            return post_charge(intent.order_id, intent.amount_cents, key)
    except IntegrityError:
        # The unique index on idempotency_key fired: a previous attempt already
        # wrote this row. Return the existing one rather than a second.
        return LedgerEntry.objects.get(idempotency_key=key)


# ---------------------------------------------------------------------------
# (2) and (4) Stock that may go negative, and a seat that may not.
# ---------------------------------------------------------------------------


def reserve_stock(sku: str, quantity: int) -> int:
    """Decrement stock atomically.

    One statement. The database evaluates the predicate and the write together,
    so there is no window between the check and the act and no application lock to
    be missing. The row count is checked, which is the half that makes a
    conditional update a control rather than a hope.
    """
    if quantity <= 0:
        raise ValueError("quantity must be positive")

    # Backorder-allowed SKUs: no floor, by design. The product sells the backorder.
    updated = StockLevel.objects.filter(sku=sku, backorderable=True).extra(
        where=["true"]
    ).update(on_hand=StockLevel.on_hand_expr(-quantity))

    if updated == 1:
        return StockLevel.objects.values_list("on_hand", flat=True).get(sku=sku)

    # Non-backorderable SKUs: the floor is in the predicate, and the row count is
    # the answer. Zero rows means the stock was not there.
    updated = StockLevel.objects.filter(
        sku=sku, backorderable=False, on_hand__gte=quantity
    ).update(on_hand=StockLevel.on_hand_expr(-quantity))

    if updated == 0:
        raise BackorderNotAllowed(f"insufficient stock for {sku}")

    return StockLevel.objects.values_list("on_hand", flat=True).get(sku=sku)


def claim_seat(licence_id: int, user_id: int) -> SeatClaim:
    """One seat per user per licence.

    Here uniqueness IS the product, so a count is the wrong instrument and a
    unique index is the right one. `(licence_id, user_id)` is unique in the
    migration; the integrity error is the enforcement and it is handled rather
    than swallowed.
    """
    try:
        with transaction.atomic():
            return SeatClaim.objects.create(licence_id=licence_id, user_id=user_id)
    except IntegrityError as exc:
        raise SeatAlreadyClaimed(f"user {user_id} already holds a seat on {licence_id}") from exc


# ---------------------------------------------------------------------------
# (6) Money as an integer everywhere except the last inch.
# ---------------------------------------------------------------------------


def format_amount(amount_cents: int, currency: str = "USD") -> str:
    """Render for display only.

    The float exists for the length of this expression. Nothing sums it, nothing
    persists it, and nothing sends it to the provider — `charge_with_retries`
    passes `amount_cents`, an int. Rounding is per ORDER here, and the product
    states per order, which is the thing the entry says changes the total when it
    disagrees.
    """
    return f"{currency} {Decimal(amount_cents) / 100:,.2f}"
