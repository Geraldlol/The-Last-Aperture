# C-018 — clean fixture. Expected findings at Low or above: ZERO.
#
# Why this pattern-matches as vulnerable:
#   A clinical endpoint returns the WHOLE chart through a serializer with
#   `fields = "__all__"` — the minimum-necessary reflex — and the record is
#   addressed by an identifier in the URL PATH, which is the "PHI in URLs:
#   Critical" reflex. Both are among the most common wrong findings in a HIPAA
#   review, and both are here on purpose.
#
# Why it is not a finding:
#
#   MINIMUM NECESSARY DOES NOT APPLY. §164.502(b)(2)(i) exempts disclosures to,
#   and requests by, a health care provider FOR TREATMENT from the
#   minimum-necessary standard entirely. This endpoint's only authorized callers
#   are the patient's own treating clinicians — enforced by
#   `_assert_treatment_relationship`, which requires an active care-team row — and
#   a treating clinician is supposed to see the whole chart. Narrowing it is a
#   patient-safety problem, not a compliance win. The same exemption covers the
#   patient's own portal read, which is the second branch below.
#   Minimum-necessary findings belong on billing, scheduling, analytics, vendor
#   integration and broad admin surfaces; this is none of those, and the
#   non-treatment surface in this file (`billing_summary`) is projected down to
#   four fields precisely because the exemption does not reach it.
#
#   THE URL IDENTIFIER IS AN OPAQUE SURROGATE KEY. Be precise about why this is
#   not Critical, because the obvious argument is wrong: a surrogate key IS an
#   identifier under §164.514(b)(2)(i)(R), and in a live system the whole record is
#   PHI regardless — the Safe Harbor list is the wrong instrument for scoring a
#   URL. The reason it is not Critical is severity: a random UUIDv4 reveals no
#   condition, is not derived from anything about the patient, is not enumerable,
#   and needs a channel to carry it somewhere before anything is disclosed. This
#   file closes the channels it can: the path carries no name, MRN, DOB, SSN or
#   diagnosis code; no query parameter carries any of those either; the response
#   sets `Referrer-Policy: no-referrer` so the path does not ride a `Referer`
#   off-origin; and no analytics or tracker snippet appears anywhere in the
#   response pipeline. The Critical case is a URL whose CONTENT identifies or
#   reveals condition, and none of `?patient_name=`, `?ssn=`, `?dob=`, `?mrn=` or
#   `?dx=` appears in this module.
#
#   AUDIT CONTROLS ARE SATISFIED AT THE LAYER THAT CAN NAME THE ACTOR. The
#   §164.312(b) finding that actually survives the false-positive entry is "reads
#   are logged, but the log records only the pooled service account, so the acting
#   user is unrecoverable." That is closed here: `audit.record_phi_access` writes
#   the acting user's id, the patient id, the purpose of use and the request id, in
#   the same transaction as the read, and the write is NOT in a try/except — an
#   audit failure fails the request rather than being swallowed.
#
# False-positive entries exercised:
#   hipaa-and-phi (1)  a read path graded against §164.312(b) — closed here by an
#                      audit write that names the ACTING USER, not the pool
#   hipaa-and-phi (2)  a clinician-facing chart endpoint returning the full record
#   hipaa-and-phi (5)  a record identifier in a URL path
#   web-and-api (3)    `get_object_or_404`-shaped lookup where the ownership /
#                      relationship scope is applied explicitly on every path

from __future__ import annotations

import logging
from uuid import UUID

from django.db import transaction
from django.http import Http404
from rest_framework import serializers, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .models import CareTeamMembership, Encounter, Patient
from .services import audit

log = logging.getLogger(__name__)


class FullChartSerializer(serializers.ModelSerializer):
    """The whole chart. Deliberately unfiltered — see the header."""

    class Meta:
        model = Encounter
        fields = "__all__"


class BillingLineSerializer(serializers.ModelSerializer):
    """The non-treatment surface. Four fields, because the exemption stops here."""

    class Meta:
        model = Encounter
        fields = ["id", "service_date", "cpt_code", "charge_cents"]


class NoTreatmentRelationship(Http404):
    """404 rather than 403: existence of a chart is itself disclosive."""


def _assert_treatment_relationship(user, patient_id: UUID) -> Patient:
    """Resolve the patient, or 404.

    The relationship is the authorization. There is no path in this module that
    loads a patient without going through this function, and it takes the acting
    user rather than trusting a client-supplied clinician id.
    """
    membership = CareTeamMembership.objects.filter(
        clinician_id=user.id,
        patient_id=patient_id,
        active=True,
    ).exists()

    if not membership:
        raise NoTreatmentRelationship("no active care-team relationship")

    try:
        return Patient.objects.get(id=patient_id)
    except Patient.DoesNotExist as exc:
        raise NoTreatmentRelationship("no such patient") from exc


def _no_referrer(response: Response) -> Response:
    """Keep the surrogate key out of the `Referer` on any off-origin navigation."""
    response["Referrer-Policy"] = "no-referrer"
    response["Cache-Control"] = "no-store"
    return response


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def clinician_chart(request, patient_id: UUID):
    """GET /clinical/patients/<uuid:patient_id>/chart

    Returns the full chart to a treating clinician.
    """
    patient = _assert_treatment_relationship(request.user, patient_id)

    with transaction.atomic():
        encounters = list(
            Encounter.objects.filter(patient_id=patient.id).order_by("-service_date")
        )

        # Not wrapped in try/except: if the audit write fails, the read fails.
        # The acting user is recorded, which is the half that makes the log
        # answer "who read this record" rather than "the app read this record".
        audit.record_phi_access(
            actor_id=request.user.id,
            actor_role=request.user.clinical_role,
            patient_id=patient.id,
            purpose_of_use="TREAT",
            resource="Encounter",
            resource_ids=[e.id for e in encounters],
            request_id=request.headers.get("X-Request-Id"),
        )

    # Ids only. The chart itself is never written to the application log.
    log.info(
        "chart read patient=%s encounters=%d actor=%s",
        patient.id,
        len(encounters),
        request.user.id,
    )

    body = FullChartSerializer(encounters, many=True).data
    return _no_referrer(Response(body, status=status.HTTP_200_OK))


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def billing_summary(request, patient_id: UUID):
    """GET /billing/patients/<uuid:patient_id>/summary

    A non-treatment surface, so minimum necessary applies with full force and the
    projection is narrow. Same relationship gate, same audit write, different
    purpose of use.
    """
    patient = _assert_treatment_relationship(request.user, patient_id)

    with transaction.atomic():
        encounters = list(
            Encounter.objects.filter(patient_id=patient.id)
            .only("id", "service_date", "cpt_code", "charge_cents")
            .order_by("-service_date")
        )

        audit.record_phi_access(
            actor_id=request.user.id,
            actor_role=request.user.clinical_role,
            patient_id=patient.id,
            purpose_of_use="HPAYMT",
            resource="Encounter",
            resource_ids=[e.id for e in encounters],
            request_id=request.headers.get("X-Request-Id"),
        )

    body = BillingLineSerializer(encounters, many=True).data
    return _no_referrer(Response(body, status=status.HTTP_200_OK))
