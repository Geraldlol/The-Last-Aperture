// C-035 (part 1 of 5) — clean fixture. Expected findings at Low or above: ZERO.
//
// Why this pattern-matches as vulnerable:
//   Run hipaa-and-phi's tracker and telemetry signals over this fixture and they
//   hit. The error-reporting vendor's name, the tag-function call, the tag queue
//   and a replay-adapter switch are all present in the tree, and the repository is
//   a patient portal — an authenticated ePHI surface, which is the condition that
//   makes a tracker Critical rather than Info. So two of the lens's signals fire on
//   a healthcare codebase at the exact place its severity table grades highest.
//
//   This is the 100%-false-positive case reproduced. On a real audit those two
//   signals matched sixteen files between them, every one a minified bundle under a
//   build directory, and first-party source contained no telemetry SDK at all.
//
// Why it is not a finding:
//   Every occurrence is inside `dist/assets/vendor.9f3c1a2b.min.js` — build output,
//   part 2 of this fixture, whose banner is the one place in the corpus that spells
//   the strings out. Four independent legs establish it, and none of them is an
//   assumption about what a `dist/` directory usually contains:
//
//     * PATH AND IDENTITY. Content-hashed filename, `.min.js` suffix, `dist/assets/`
//       location, and a banner naming the upstream package and version. Part 3 is a
//       directory-scoped `.gitattributes` marking `*.min.js` generated and vendored,
//       so `git check-attr linguist-generated` answers the question mechanically
//       rather than by inspection.
//     * THE MANIFEST HAS NO TELEMETRY SDK. Part 4 lists every dependency of this
//       application, and no error-reporting, product-analytics, session-replay or
//       tag-manager package is among them. An SDK that is not installed cannot be
//       initialized. The thirteen package names that were checked for are assembled
//       at runtime in part 5, so the check is executed and the names still do not
//       appear as literals anywhere outside the bundle.
//     * NO FIRST-PARTY IMPORT, INITIALIZER, TAG OR CALL SITE. This file is the
//       authenticated ePHI surface, and it is where a tracker would have to be
//       wired up. There is no script element in any spelling, plain or framework;
//       no assignment to the tag global; no push onto the tag queue; no SDK
//       initializer; and no logging call of any kind. The chart data arrives as
//       props and leaves as markup.
//     * THE ADAPTERS ARE DEAD CODE, AND THE SWITCH IS CHECKABLE. The vendored kit
//       selects an adapter from a single global config object, and with that object
//       absent it returns its no-op. The key is set nowhere under `src/`, which
//       part 5 asserts rather than states.
//
//   The residual is recorded instead of being called clean by silence: a shipped
//   bundle carrying dormant adapters is worth an inventory line, because a future
//   first-party assignment to that config global turns one on. Per false positive 7
//   that is an Info observation filed against the build input — the dependency —
//   and not a §164.502(a) disclosure by this application, which transmits nothing.
//
//   What this fixture must NOT be read as: a licence to skip the rendered artifact.
//   `## Proof recipes` R5 still requires the tracker check to run over built page
//   markup, which is exactly where a real first-party tag appears. The clearance
//   here rests on the excluded paths plus the manifest, and it would collapse the
//   moment either changed.
//
// EDITING WARNING, and it is not decoration. This fixture's whole value is that the
// vendor strings occur in exactly one place — the bundle, which every form of the
// guard excludes. That is why this header describes them in words instead of
// writing them out, and why part 5 assembles its needles from fragments at runtime.
// Spelling any of them into this file, into `package.json`, or into the test would
// put a first-party-looking hit in the files whose job is to have none, and the
// measured result in EXPECTED.md would change from "no hits outside build output"
// to "hits an auditor has to read and dismiss".
//
// False-positive entries exercised:
//   hipaa-and-phi (7)  a tracker or telemetry string matched inside committed
//                      build output, reported as a telemetry finding

import type { ReactElement } from "react";

/**
 * ePHI, and classified at the point of use. Nothing below is logged, serialized
 * into an analytics payload, or placed in a URL — the panel renders it and stops.
 */
export interface EncounterSummary {
  /** Surrogate key. Opaque, and not derived from any identifier. */
  readonly encounterRef: string;
  readonly serviceDate: string;
  readonly programName: string;
  readonly problemList: readonly string[];
  readonly nextAppointment: string | null;
}

export interface ChartPanelProps {
  readonly summary: EncounterSummary;
  /**
   * Resolved by the route's server-side session guard before this component is
   * reached. Carried here only so the heading can name the acting clinician; it is
   * never used to make an access decision on the client.
   */
  readonly viewerDisplayName: string;
}

function ProblemList({ problems }: { readonly problems: readonly string[] }): ReactElement {
  return (
    <ul className="chart-panel__problems">
      {problems.map((problem) => (
        // Rendered as text. No dangerouslySetInnerHTML anywhere in this tree.
        <li key={problem}>{problem}</li>
      ))}
    </ul>
  );
}

export function ChartPanel({ summary, viewerDisplayName }: ChartPanelProps): ReactElement {
  return (
    <section className="chart-panel" aria-label="Encounter summary">
      <header>
        <h2>Encounter summary</h2>
        <p className="chart-panel__viewer">Viewing as {viewerDisplayName}</p>
      </header>

      <dl>
        <dt>Service date</dt>
        <dd>{summary.serviceDate}</dd>
        <dt>Program</dt>
        <dd>{summary.programName}</dd>
        <dt>Next appointment</dt>
        <dd>{summary.nextAppointment ?? "Not scheduled"}</dd>
      </dl>

      <ProblemList problems={summary.problemList} />
    </section>
  );
}
