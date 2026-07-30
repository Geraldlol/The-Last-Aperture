# C-026 — clean fixture. Expected findings at Low or above: ZERO.
#
# Four crypto reflexes, four discriminators.
#
#   1. HS256 REPORTED AS "SHOULD USE RS256". This service both issues and verifies
#      its own queue tokens — one party, one key, no third-party verifier. The
#      escalations the entry names are all absent: `algorithms=["HS256"]` is pinned
#      at the verify call (so no cross-class list and no unpinned call that could
#      fail open), the secret is 32 bytes of managed key material rather than a
#      password, and there is NO verify-only party holding it — the only holder is
#      the issuer, so nobody gains minting power they should not have.
#
#   2. ECB IN THE CODE. `keywrap.aes_key_wrap` is AES-KW, which is built from the
#      ECB primitive. A single-block or key-wrapping ECB operation is not the ECB
#      bug: the bug is ECB over multi-block, attacker-visible, low-diversity
#      plaintext. Here the plaintext is one 32-byte key, never attacker-visible.
#      The other ECB-adjacent shape — Java's `Cipher.getInstance("AES")`, which
#      silently resolves to ECB — is not the API used here.
#
#   3. AN ENCRYPT API THAT TAKES NO NONCE. `Fernet.encrypt` draws its own IV per
#      call and prepends it, which is a design that removes the choice rather than
#      a missing parameter. The wrapper below does not undo that: it derives no
#      nonce, caches nothing across calls, and holds one key per tenant well inside
#      the mode's message limit. (This is an API property, not nonce-misuse
#      resistance, and it clears nothing about a deterministic construction — which
#      is why there is not one here.)
#
#   4. A MONOTONIC COUNTER AS A GCM NONCE. `SequencedSealer` uses the SP 800-38D
#      §8.2.1 deterministic construction: a fixed field plus an invocation counter.
#      Predictability is not GCM's requirement; uniqueness is. The two conditions
#      that would make it a finding are both closed and both visible:
#        * the counter cannot RESET relative to the key — it is loaded from and
#          written back to a durable store on every seal, and the initial value is
#          read from that store rather than from a constructor default;
#        * two writers cannot share a key with the same FIXED FIELD — the fixed
#          field is the writer's own id, allocated once per replica by the store,
#          and `assert` rejects a duplicate at construction.
#      A CBC IV is a different rule and is deliberately not conflated: for CBC,
#      predictability genuinely is the defect.

from __future__ import annotations

import os
import struct

import jwt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap
from cryptography.fernet import Fernet

# ---------------------------------------------------------------------------
# (1) HS256, issued and verified by the same party.
# ---------------------------------------------------------------------------

QUEUE_TOKEN_ISSUER = "urn:internal:queue"
QUEUE_TOKEN_AUDIENCE = "urn:internal:queue"


def issue_queue_token(secret: bytes, job_id: str, ttl_seconds: int, now: int) -> str:
    """Mint a short-lived token this same service will verify.

    `secret` is 32 bytes from the key service. It is never distributed: no other
    process verifies these tokens, so no other process needs the key, so no other
    process acquires the ability to mint.
    """
    assert len(secret) >= 32, "queue token key must be at least 256 bits"
    return jwt.encode(
        {
            "iss": QUEUE_TOKEN_ISSUER,
            "aud": QUEUE_TOKEN_AUDIENCE,
            "sub": job_id,
            "iat": now,
            "exp": now + ttl_seconds,
        },
        secret,
        algorithm="HS256",
    )


def verify_queue_token(secret: bytes, token: str) -> dict:
    """Verify with the algorithm pinned to one member of one class."""
    return jwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        audience=QUEUE_TOKEN_AUDIENCE,
        issuer=QUEUE_TOKEN_ISSUER,
        options={"require": ["exp", "iat", "aud", "iss", "sub"]},
    )


# ---------------------------------------------------------------------------
# (2) AES-KW — the ECB primitive used as a building block.
# ---------------------------------------------------------------------------


def wrap_data_key(kek: bytes, data_key: bytes) -> bytes:
    """Wrap one 32-byte data key under the key-encryption key.

    AES-KW. The plaintext is a single key, it is high-entropy, and it is never
    visible to an attacker in either form — so none of the three conditions that
    make ECB a defect applies.
    """
    assert len(data_key) == 32
    return aes_key_wrap(kek, data_key)


def unwrap_data_key(kek: bytes, wrapped: bytes) -> bytes:
    return aes_key_unwrap(kek, wrapped)


# ---------------------------------------------------------------------------
# (3) Fernet — the API with no nonce argument, not undone by the wrapper.
# ---------------------------------------------------------------------------


class TenantNoteSealer:
    """Seal note bodies with a per-tenant Fernet key.

    The wrapper adds a key lookup and nothing else. It derives no nonce, caches no
    ciphertext-affecting state, and calls `encrypt` once per message — so the
    library's own fresh-IV-per-call behaviour is preserved exactly.
    """

    def __init__(self, key_provider) -> None:
        self._key_provider = key_provider

    def seal(self, tenant_id: str, plaintext: bytes) -> bytes:
        return Fernet(self._key_provider.fernet_key_for(tenant_id)).encrypt(plaintext)

    def open(self, tenant_id: str, token: bytes) -> bytes:
        return Fernet(self._key_provider.fernet_key_for(tenant_id)).decrypt(token)


# ---------------------------------------------------------------------------
# (4) The deterministic GCM nonce, with both failure conditions closed.
# ---------------------------------------------------------------------------


class SequencedSealer:
    """AES-GCM with an SP 800-38D §8.2.1 nonce: 4-byte fixed field + 8-byte counter.

    Deliberately NOT a random nonce, because this writer seals far more than 2**32
    messages under one key and a random 96-bit nonce's collision probability is the
    thing that constrains that. The deterministic construction has no such cap
    while uniqueness holds — which is what the store below guarantees.
    """

    FIXED_FIELD_BYTES = 4
    COUNTER_BYTES = 8

    def __init__(self, key: bytes, writer_id: int, counter_store) -> None:
        assert len(key) == 32
        # The fixed field is this replica's own id, allocated once by the store and
        # never reused. Two writers therefore cannot share a key AND a fixed field.
        assert counter_store.claim_writer_id(writer_id), (
            f"writer id {writer_id} is already claimed by another replica"
        )
        assert 0 <= writer_id < 2 ** (8 * self.FIXED_FIELD_BYTES)

        self._aead = AESGCM(key)
        self._fixed = struct.pack(">I", writer_id)
        self._store = counter_store
        self._writer_id = writer_id

    def seal(self, plaintext: bytes, aad: bytes) -> bytes:
        # Read-then-advance against a durable store, so a process restart or a
        # snapshot restore cannot rewind the counter relative to the key. The
        # counter is NOT initialised in this constructor or at module scope, which
        # is the shape that rewinds.
        counter = self._store.next_counter(self._writer_id)
        assert counter < 2 ** (8 * self.COUNTER_BYTES)

        nonce = self._fixed + struct.pack(">Q", counter)
        assert len(nonce) == 12

        return nonce + self._aead.encrypt(nonce, plaintext, aad)

    def open(self, sealed: bytes, aad: bytes) -> bytes:
        nonce, ciphertext = sealed[:12], sealed[12:]
        return self._aead.decrypt(nonce, ciphertext, aad)


def fresh_data_key() -> bytes:
    """32 bytes straight from the kernel CSPRNG.

    `os.urandom` reaches the kernel on every call, so it holds no userspace pool
    state and is unaffected by a fork or a snapshot restore.
    """
    return os.urandom(32)
