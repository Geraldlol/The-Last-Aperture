# C-021 — clean fixture. Expected findings at Low or above: ZERO.
#
# Four llm-and-ai reflexes fire on this file. None is a finding.
#
#   1. UNTRUSTED CONTENT CONCATENATED INTO A PROMPT, separated only by XML tags.
#      Lines 118-132. The delimiters are hygiene and are NOT cited here as the
#      reason this is clean — the capability inventory is, and it is written out
#      below rather than gestured at:
#        * tools reachable from the injected text: exactly one, `lookup_my_tickets`,
#          which is read-only and whose only argument is the caller's own session
#          subject (the model cannot pass a principal — see the closure);
#        * sinks: the answer is returned as `text/plain` and rendered as a React
#          child by the caller; there is no `eval`, no `exec`, no subprocess, no
#          SQL, no template render, and no shell anywhere in this module;
#        * outbound channels: none. No image URL, no link, no webhook, no
#          markdown renderer, and the HTML shell that displays the answer sends an
#          ENFORCING `Content-Security-Policy` with `img-src 'self' data:` — not
#          `Content-Security-Policy-Report-Only`, which would enforce nothing;
#        * budget: `max_iterations` and a wall clock are both set;
#        * audience: the retrieved content is a PUBLISHED help-centre article and
#          the query runner is the person who asked. The indirect case — where the
#          content author and the query runner are different people — does not
#          arise, because the only writer to this index is the CMS publish hook in
#          this file.
#      With no privileged tool, no unsanitised sink, a bounded budget and an
#      audience of exactly the asker, injection here is Informational.
#
#   2. A RETRIEVER WITH NO PER-USER METADATA FILTER, which reads as cross-tenant
#      RAG leakage. The index is uniformly public within its audience: the
#      ingestion path in this same file writes ONLY CMS articles whose state is
#      `published`, and it is the only writer. That claim is established from the
#      WRITER, not from the reader, which is what the entry demands — and it is
#      written down as the assumption it is, so one backfill of internal documents
#      into this index inverts the conclusion and the `assert` below is what would
#      fail first.
#
#   3. A DESTRUCTIVE TOOL WITH NO CONFIRMATION DIALOG. Approval is a server-side
#      pending-action record, which is why grepping near the tool body finds
#      nothing. The resume path RE-CHECKS: it matches on a hash of the exact
#      arguments, not on the action name, and it refuses an approval token that
#      the server did not mint. "Approve" is never remembered across actions.
#
#   4. AN IN-PROCESS VECTOR STORE. `InMemoryVectorStore` appears below, which is
#      the class the lens's own mirror-image false positive warns about: written up
#      as a Critical cross-tenant leak on the strength of the store class alone.
#      There is no tenancy in this index at all, so there is no foreign chunk that
#      could reach the candidate set.
#
# False-positive entries exercised:
#   llm-and-ai (1)  untrusted content in a prompt with delimiters — the reportable
#                   defect is the reachable capability, and the inventory is empty
#   llm-and-ai (3)  model output rendered — CSP directive read, not pattern-matched
#   llm-and-ai (4)  filterless retrieval over a uniformly public index, with the
#                   claim established from the ingestion path
#   llm-and-ai (5)  approval expressed as an interrupt / pending-action record

from __future__ import annotations

import hashlib
import hmac
import logging
from dataclasses import dataclass
from typing import Iterable

from fastapi import Depends, FastAPI, HTTPException, Response
from langchain_core.documents import Document
from langchain_core.vectorstores import InMemoryVectorStore

from .auth import Session, current_session
from .cms import PublishedArticle, iter_published_articles
from .embeddings import embeddings
from .llm import chat_model
from .tickets import TicketRow, tickets_for_subject

log = logging.getLogger(__name__)

app = FastAPI()

MAX_ITERATIONS = 4
WALL_CLOCK_SECONDS = 20

# ---------------------------------------------------------------------------
# The index, and the ONLY writer to it.
# ---------------------------------------------------------------------------

help_centre = InMemoryVectorStore(embeddings)


def ingest_published_articles() -> int:
    """Load the public help centre into the index.

    This is the only function in the codebase that writes to `help_centre`, and it
    writes only articles the CMS has marked `published` — the same documents the
    marketing site serves anonymously. There is no tenant id on any document
    because there is no per-tenant document in the corpus.

    The assertion is the guard on the assumption the retrieval clearance rests on:
    if a future backfill starts pushing internal or per-customer documents through
    here, this fails at ingestion rather than leaking at query time.
    """
    docs: list[Document] = []
    for article in iter_published_articles():
        assert article.visibility == "public", (
            f"non-public article {article.slug} reached the public help-centre index"
        )
        assert article.tenant_id is None, (
            f"tenant-scoped article {article.slug} reached the public help-centre index"
        )
        docs.append(
            Document(
                page_content=article.body,
                metadata={"slug": article.slug, "title": article.title, "visibility": "public"},
            )
        )

    help_centre.add_documents(docs)
    return len(docs)


# ---------------------------------------------------------------------------
# The capability inventory: one read-only tool, closed over the session.
# ---------------------------------------------------------------------------


def make_ticket_tool(session: Session):
    """Build the one tool the model can call.

    The principal is closed over, not a parameter. There is no argument the model
    could fill with another subject's id, so a well-formed tool call naming
    another principal's resource is not expressible.
    """

    def lookup_my_tickets(status: str = "open") -> list[dict]:
        if status not in {"open", "closed", "pending"}:
            raise ValueError(f"unknown status: {status}")
        rows: Iterable[TicketRow] = tickets_for_subject(session.subject, status=status)
        return [{"id": r.id, "subject": r.subject_line, "status": r.status} for r in rows]

    return lookup_my_tickets


# ---------------------------------------------------------------------------
# Prompt assembly.
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are a support assistant for a note-taking product.
Answer only from the help-centre excerpts provided. If they do not contain the
answer, say so. Never claim to have taken an action."""


def build_prompt(question: str, excerpts: list[Document]) -> list[dict]:
    """Assemble the request.

    The `<help_centre_excerpt>` wrapper is a legibility aid for the model. It is
    NOT a control and is not the reason this file is clean — a determined
    injection in a help-centre article defeats any delimiter. What bounds the
    blast radius is that the article is public, the reader is the asker, and the
    reachable capability set is one read-only tool scoped to that same reader.
    """
    body = "\n".join(
        f"<help_centre_excerpt slug={d.metadata['slug']!r}>\n{d.page_content}\n</help_centre_excerpt>"
        for d in excerpts
    )
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"{body}\n\n<question>\n{question}\n</question>"},
    ]


@app.post("/support/ask", response_class=Response)
def ask(question: str, session: Session = Depends(current_session)) -> Response:
    # No metadata filter, and none is needed: every document in this index is a
    # published article. See `ingest_published_articles`.
    excerpts = help_centre.similarity_search(question, k=4)

    answer = chat_model.invoke(
        build_prompt(question, excerpts),
        tools=[make_ticket_tool(session)],
        max_iterations=MAX_ITERATIONS,
        timeout=WALL_CLOCK_SECONDS,
    )

    # text/plain, so nothing the model emits is parsed as markup or markdown and
    # no image or link is fetched. The channel does not exist rather than being
    # filtered.
    return Response(content=answer.text, media_type="text/plain; charset=utf-8")


@app.get("/support/shell")
def shell() -> Response:
    """The HTML host for the widget.

    An ENFORCING policy — the header name is `Content-Security-Policy`, not
    `Content-Security-Policy-Report-Only` — and `img-src` is explicit rather than
    inherited from a permissive `default-src`. Both halves matter: a missing
    `img-src` under `default-src https:` would be wide open and look identical to
    a grep.
    """
    return Response(
        content="<!doctype html><meta charset=utf-8><div id=support-widget></div>",
        media_type="text/html; charset=utf-8",
        headers={
            "Content-Security-Policy": (
                "default-src 'self'; img-src 'self' data:; connect-src 'self'; "
                "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
            )
        },
    )


# ---------------------------------------------------------------------------
# The destructive action, and the approval that is not a dialog.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PendingAction:
    action_id: str
    subject: str
    action_name: str
    argument_digest: str
    approved_by: str | None
    executed_at: float | None


def _argument_digest(action_name: str, args: dict) -> str:
    """Bind the approval to the exact arguments, not to the action name."""
    canonical = "|".join(f"{k}={args[k]!r}" for k in sorted(args))
    return hashlib.sha256(f"{action_name}\x00{canonical}".encode()).hexdigest()


def request_account_closure(session: Session, args: dict, store) -> PendingAction:
    """Record the intent. Nothing is closed here.

    The model can reach this. It cannot reach `execute_account_closure`, which is
    driven only by the human-facing approval route below.
    """
    return store.insert_pending(
        subject=session.subject,
        action_name="close_account",
        argument_digest=_argument_digest("close_account", args),
    )


def execute_account_closure(
    approver: Session, action_id: str, args: dict, store, close_account
) -> None:
    """The resume path. It re-checks; it does not trust the client's word.

    Four checks, and each one closes a bug the entry names:
      * the pending record is read back from the server store, so a client-supplied
        "approved" flag is not consulted at all;
      * the argument digest is recomputed from the arguments being executed and
        compared to the stored one with a constant-time compare, so an approval for
        one account cannot be replayed against another;
      * the approver must not be the requester;
      * the record is marked executed inside the same transaction, so an approval
        is single-use and "approve" is never remembered as "always approve".
    """
    pending = store.get_pending(action_id)
    if pending is None or pending.executed_at is not None:
        raise HTTPException(status_code=409, detail="no pending action")
    if pending.approved_by is not None:
        raise HTTPException(status_code=409, detail="already decided")
    if pending.subject == approver.subject:
        raise HTTPException(status_code=403, detail="requester may not approve")

    presented = _argument_digest(pending.action_name, args)
    if not hmac.compare_digest(presented, pending.argument_digest):
        raise HTTPException(status_code=409, detail="arguments do not match the approval")

    with store.transaction():
        store.mark_executed(action_id, approver.subject)
        close_account(**args)

    log.info("account closure %s approved by %s", action_id, approver.subject)
