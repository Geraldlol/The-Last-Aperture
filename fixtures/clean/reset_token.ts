// C-003 — clean fixture. Expected findings at Low or above: ZERO.
//
// Why this pattern-matches as vulnerable:
//   `Math.random()` is the single strongest "predictable token" signal in the
//   JavaScript ecosystem, and this file is called `reset_token.ts`. Every
//   csprng sweep in crypto-and-key-management hits line 60. The file also
//   compares a token the caller supplied, which is the timing-attack shape.
//
// Why it is not a finding:
//   There are two random number generators in this file and only one of them
//   needs to be strong. `Math.random()` produces retry-backoff *jitter* on the
//   mailer call — its output is never persisted, never compared, never sent to
//   the user, and an attacker who predicts it learns how many milliseconds a
//   retry waited. The reset token itself is `randomBytes(32)`, 256 bits from
//   the platform CSPRNG. Redemption hashes the presented token with SHA-256 and
//   compares the two digests with `timingSafeEqual` behind an explicit length
//   check, so the throws-on-length-mismatch variant is absent too.
//
// False-positive entries exercised:
//   crypto-and-key-management (3)  a length guard ahead of `timingSafeEqual`,
//                                  and a comparison of two locally derived
//                                  digests
//   ai-generated-code (1)          a swallowed exception where nothing
//                                  security-relevant was swallowed (the mailer
//                                  retry), narrowly typed
//   ai-generated-code (7)          an anchored allowlist regex over a closed
//                                  domain, used to reject rather than rewrite

import { randomBytes, createHash, timingSafeEqual } from "node:crypto";

/** Reset tokens are 32 raw bytes rendered base64url: 43 characters, no padding. */
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;

const TOKEN_TTL_MS = 15 * 60 * 1000;
const MAX_MAIL_ATTEMPTS = 4;

export interface StoredReset {
  /** Only the digest is stored. The token itself exists in one email. */
  tokenDigest: Buffer;
  userId: string;
  expiresAt: number;
  consumedAt: number | null;
}

class TransientMailError extends Error {}

/**
 * Mint a reset token.
 *
 * 256 bits from the platform CSPRNG. `randomBytes` is synchronous here on
 * purpose: the async form's callback makes the failure mode "token is
 * undefined", and a caller that ignores it ships an empty token.
 */
export function mintResetToken(userId: string): { token: string; stored: StoredReset } {
  const raw = randomBytes(32);
  const token = raw.toString("base64url");

  return {
    token,
    stored: {
      tokenDigest: createHash("sha256").update(raw).digest(),
      userId,
      expiresAt: Date.now() + TOKEN_TTL_MS,
      consumedAt: null,
    },
  };
}

/**
 * Backoff for the transactional mailer.
 *
 * `Math.random()` here decorrelates concurrent retries so a mailer outage does
 * not produce a synchronised thundering herd when it recovers. The value is a
 * duration in milliseconds. It is not a token, not a key, not a nonce, not an
 * identifier, and it is never written anywhere an attacker can read.
 */
function backoffDelayMs(attempt: number): number {
  const base = 250 * 2 ** attempt;
  const jitter = Math.random() * base * 0.25;
  return Math.min(base + jitter, 10_000);
}

export async function sendResetMail(
  send: (userId: string, token: string) => Promise<void>,
  userId: string,
  token: string,
  sleep: (ms: number) => Promise<void>,
): Promise<boolean> {
  for (let attempt = 0; attempt < MAX_MAIL_ATTEMPTS; attempt += 1) {
    try {
      await send(userId, token);
      return true;
    } catch (err) {
      // Narrow type, and the swallowed call is a *notification*, not a control.
      // A permanent failure is a different class and is deliberately not caught
      // here — it propagates so the caller can surface it.
      if (!(err instanceof TransientMailError)) throw err;
      await sleep(backoffDelayMs(attempt));
    }
  }
  return false;
}

/**
 * Redeem a token.
 *
 * The anchored allowlist rejects anything that is not exactly 43 base64url
 * characters. It rejects — it does not strip characters and continue — so it is
 * a validator, not a sanitiser standing where an encoder belongs.
 */
export function redeemResetToken(presented: string, stored: StoredReset, now = Date.now()): string | null {
  if (!TOKEN_PATTERN.test(presented)) return null;
  if (stored.consumedAt !== null) return null;
  if (now >= stored.expiresAt) return null;

  const presentedDigest = createHash("sha256").update(Buffer.from(presented, "base64url")).digest();

  // Both operands are SHA-256 digests this process computed, so the length is
  // structurally 32 bytes on both sides. The check is here anyway because
  // `timingSafeEqual` throws on a length mismatch, and a throw out of a
  // comparison is a 500 that distinguishes inputs just as loudly as a `===`.
  if (presentedDigest.length !== stored.tokenDigest.length) return null;
  if (!timingSafeEqual(presentedDigest, stored.tokenDigest)) return null;

  stored.consumedAt = now;
  return stored.userId;
}
