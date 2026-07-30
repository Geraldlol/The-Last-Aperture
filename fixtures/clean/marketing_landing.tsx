// C-028 — clean fixture. Expected findings at Low or above: ZERO.
//
// Why this pattern-matches as vulnerable:
//   A tag-manager container script in the root layout of a healthcare
//   application, on a page about a clinical condition. Under the pre-2024 reading
//   of the OCR tracking-technologies bulletin that was an automatic Critical: IP
//   address plus a visit to a page about a condition equals PHI.
//
// Why it is not a finding:
//   The theory that made this automatically Critical was VACATED in
//   *American Hospital Association v. Becerra* (N.D. Tex., 20 June 2024).
//   Post-vacatur, a tracker on a public marketing or condition-information page is
//   not per se a HIPAA violation. So the question becomes what the page is and what
//   the tracker sends, and all four of the conditions that would keep it Critical
//   are absent and checkable in this file:
//
//     * NOT BEHIND AUTHENTICATION. `export const dynamic = "force-static"` and
//       there is no session read, no auth import, and no `cookies()` call. The
//       route is prerendered and served to anonymous visitors.
//     * NOT PART OF A SCHEDULING, INTAKE OR SYMPTOM-CHECKER FLOW. The only
//       interactive element is a link to the public clinic directory. There is no
//       form, no `<input>`, no symptom questionnaire, and the appointment link is
//       an outbound `<a href>` to a separate authenticated origin rather than a
//       first step of a flow that begins here.
//     * TRANSMITS NO IDENTIFIER AND NO CONDITION CONTEXT. `sendPageView` sends a
//       fixed page group string, not `location.pathname` and not
//       `location.search`; `dataLayer` receives exactly two keys, both constants;
//       and the canonical URL has no query string to leak.
//     * URL CARRIES NOTHING. The route is `/learn/anxiety-support`, a static
//       marketing slug. It is not `?dx=`, `?mrn=`, `?patient_name=` or a
//       program-specific path segment tied to an individual.
//
//   Recorded rather than glossed, because the entry says so: FTC Act §5, the
//   amended Health Breach Notification Rule and state health-privacy statutes can
//   still apply where HIPAA does not. That is a disclosure and governance question
//   about this page, not a code finding, and it is why the page group string below
//   is deliberately coarse.
//
// False-positive entries exercised:
//   hipaa-and-phi (3)                a marketing pixel / tag-manager container on
//                                    an unauthenticated public page, post-Becerra
//   privacy-and-data-protection (2)  the tag is present AND gated: Consent Mode is
//                                    defaulted to denied before the container loads

import Script from "next/script";

/** Prerendered. No session, no cookies, no request-time personalisation. */
export const dynamic = "force-static";
export const revalidate = 3600;

/** Coarse on purpose: a page GROUP, never the path and never the query string. */
const PAGE_GROUP = "marketing/learn";

export const metadata = {
  title: "Understanding anxiety support",
  alternates: { canonical: "https://www.example.invalid/learn/anxiety-support" },
  robots: { index: true, follow: true },
};

export default function AnxietySupportPage() {
  return (
    <main>
      {/*
        Consent Mode defaults are queued BEFORE the container script is inserted.
        Order is the control: a container that loads first runs its initial hits
        under the implicit granted state.
      */}
      <Script id="consent-default" strategy="beforeInteractive">
        {`window.dataLayer=window.dataLayer||[];
window.dataLayer.push(["consent","default",{analytics_storage:"denied",ad_storage:"denied",ad_user_data:"denied",ad_personalization:"denied",wait_for_update:500}]);
window.dataLayer.push({page_group:${JSON.stringify(PAGE_GROUP)},content_type:"education"});`}
      </Script>

      <Script
        id="tag-container"
        src="https://tags.example.invalid/container.js"
        strategy="afterInteractive"
      />

      <h1>Understanding anxiety support</h1>

      <p>
        This page explains what peer and clinical support for anxiety involves. It
        is general information and is not a medical assessment.
      </p>

      <h2>Finding support near you</h2>
      <p>
        Our public clinic directory lists locations and opening hours. Booking
        happens in the patient portal, on a separate authenticated origin.
      </p>

      {/*
        An outbound link, not the first step of an intake flow. There is no form on
        this page, so nothing a visitor types can reach a tag.
      */}
      <a href="https://portal.example.invalid/appointments">Book in the patient portal</a>
    </main>
  );
}
