// C-016 — clean fixture. Expected findings at Low or above: ZERO.
//
// Why this pattern-matches as vulnerable:
//   Three session-replay SDKs are imported in one file — `rrweb`, `logrocket`
//   and `@sentry/replay` — and an analytics tag is written into the document.
//   Every privacy sweep that keys on vendor names fires here, and "replay SDK in
//   the bundle" plus "tag in the layout" is the shape of a Critical pre-consent
//   finding.
//
// Why it is not a finding:
//
//   MASKING, PER VENDOR, because the defaults are not the same across these SDKs
//   and clearing them as a group is how a real High gets closed:
//     * `rrweb` RECORDS INPUT BY DEFAULT (`maskAllInputs` defaults to false and
//       text is unmasked unless a selector is configured). The finding is the
//       ABSENCE of those options, so both are set explicitly below — there is no
//       `maskAllInputs: false` anywhere in this file, because that is the default
//       and writing it would be redundant rather than protective.
//     * `logrocket` RECORDS INPUT BY DEFAULT. `dom.inputSanitizer` is opt-in and
//       is set to true below.
//     * `@sentry/replay` masks all text and all inputs by default, so presence
//       alone is not the finding; the defaults are pinned explicitly anyway so a
//       future SDK-default change cannot silently unmask.
//     * `@fullstory/browser` and `smartlook` are deliberately NOT used. The lens
//       records their current input-capture defaults as unverified and refuses to
//       clear either on that entry, so a clean fixture cannot honestly include
//       one — a reader would have to take an unverified default on trust.
//
//   NO UNMASK ALLOWLIST. There is no `data-hj-allow`, no `fs-unmask`, no
//   `data-clarity-unmask`, and no permissive block/ignore class set anywhere in
//   this component.
//
//   SENSITIVE VALUES ARE NOT PAGE TEXT. Input masking does not mask rendered
//   text, so the one sensitive value this screen shows — the payment method — is
//   rendered inside `.replay-mask`, which is in `maskTextSelector`.
//
//   CONSENT. Nothing initialises until `readConsent()` returns a stored,
//   affirmative choice. Consent Mode is defaulted to `denied` for both
//   `analytics_storage` and `ad_storage` BEFORE the container is written, so even
//   the tag's own pre-consent behaviour is constrained. The only storage written
//   before a choice is the consent record itself, which ePrivacy Art 5(3) exempts
//   as strictly necessary for a service the user requested.
//
//   GPC. `navigator.globalPrivacyControl` is consulted on the client and treated
//   as an opt-out, so the half-implementation the lens names — header honoured
//   server-side while client tag loading never consults the signal — is absent.
//   This application sells and shares nothing (no advertising pixel appears in
//   the file at all), so the duty is not even engaged; it is honoured regardless.
//
// False-positive entries exercised:
//   privacy-and-data-protection (2)  a tag/SDK initialiser present in code that
//                                    runs before the banner is answered
//   privacy-and-data-protection (4)  session-replay SDKs read per vendor against
//                                    their documented defaults
//   privacy-and-data-protection (5)  GPC and the sale-or-share predicate

import * as React from "react";
import * as rrweb from "rrweb";
import LogRocket from "logrocket";
import { replayIntegration } from "@sentry/replay";
import * as Sentry from "@sentry/browser";

const CONSENT_COOKIE = "consent_v3";

/** Elements whose rendered TEXT must never enter a replay. */
const MASK_TEXT_SELECTOR = ".replay-mask, [data-replay-mask]";

type ConsentChoice = "granted" | "denied" | "unset";

interface ConsentRecord {
  analytics: ConsentChoice;
  /** No advertising vendor is loaded by this application; recorded for audit. */
  advertising: "denied";
  decidedAt: string | null;
}

/**
 * Read the stored consent decision.
 *
 * This cookie is the ONLY storage written before a choice is made. It is the
 * consent-state cookie itself, which ePrivacy Art 5(3) exempts as strictly
 * necessary — without it the banner cannot remember the answer it was given.
 */
function readConsent(): ConsentRecord {
  const raw = document.cookie
    .split("; ")
    .find((c) => c.startsWith(`${CONSENT_COOKIE}=`))
    ?.slice(CONSENT_COOKIE.length + 1);

  if (!raw) return { analytics: "unset", advertising: "denied", decidedAt: null };

  try {
    const parsed = JSON.parse(decodeURIComponent(raw)) as Partial<ConsentRecord>;
    return {
      analytics: parsed.analytics === "granted" ? "granted" : "denied",
      advertising: "denied",
      decidedAt: typeof parsed.decidedAt === "string" ? parsed.decidedAt : null,
    };
  } catch (err) {
    // Narrow type. A corrupt cookie is treated as no consent, which is the
    // restrictive answer — this catch cannot fail open.
    if (!(err instanceof SyntaxError)) throw err;
    return { analytics: "unset", advertising: "denied", decidedAt: null };
  }
}

/** Global Privacy Control, read from the browser. Absent means unset, not opt-out. */
function gpcOptOut(): boolean {
  return (navigator as Navigator & { globalPrivacyControl?: boolean }).globalPrivacyControl === true;
}

/**
 * Default Consent Mode to denied, then write the container tag.
 *
 * Order matters: the `default` command must be queued before the container
 * script is inserted, or the container's first hits run under the implicit
 * granted state. That is why this function writes both, in this order, and why
 * the tag is not in the static document head.
 */
function installTagManagerDenied(): void {
  const w = window as unknown as { dataLayer?: unknown[] };
  w.dataLayer = w.dataLayer ?? [];
  w.dataLayer.push(["consent", "default", {
    analytics_storage: "denied",
    ad_storage: "denied",
    ad_user_data: "denied",
    ad_personalization: "denied",
    wait_for_update: 500,
  }]);

  const tag = document.createElement("script");
  tag.async = true;
  tag.src = "https://tags.example.invalid/container.js";
  document.head.appendChild(tag);
}

function startReplay(): () => void {
  // rrweb records input by default. Both absence-checks are answered here.
  const stopRrweb = rrweb.record({
    maskAllInputs: true,
    maskTextSelector: MASK_TEXT_SELECTOR,
    maskInputOptions: { password: true, email: true, tel: true, text: true },
    blockClass: "replay-block",
    recordCanvas: false,
    collectFonts: false,
    emit(event) {
      void fetch("/api/replay", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(event),
      });
    },
  });

  // LogRocket records input by default. `inputSanitizer` is the opt-in.
  LogRocket.init("example/notes-web", {
    dom: {
      inputSanitizer: true,
      textSanitizer: true,
      privateAttributeBlocklist: ["data-replay-mask"],
    },
    network: { requestSanitizer: () => null, responseSanitizer: () => null },
  });

  // Sentry masks by default; pinned anyway so a default change cannot unmask.
  Sentry.addIntegration(
    replayIntegration({ maskAllText: true, maskAllInputs: true, blockAllMedia: true }),
  );

  return () => {
    if (typeof stopRrweb === "function") stopRrweb();
  };
}

export function AnalyticsGate({ children }: { children: React.ReactNode }): React.ReactElement {
  React.useEffect(() => {
    if (gpcOptOut()) return;

    const consent = readConsent();
    if (consent.analytics !== "granted") return;

    installTagManagerDenied();
    return startReplay();
  }, []);

  return <>{children}</>;
}

/** The one sensitive value on this screen, rendered inside the masked selector. */
export function PaymentSummary({ brand, last4 }: { brand: string; last4: string }) {
  return (
    <p className="replay-mask">
      {brand} ending {last4}
    </p>
  );
}
