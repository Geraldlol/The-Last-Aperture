// C-035 (part 5 of 5) — clean fixture. Expected findings at Low or above: ZERO.
//
// The negative control, and the reason this fixture is checkable rather than
// asserted. hipaa-and-phi false positive 7 clears a tracker string that lives only
// in build output, and the clearance has two legs it insists on: the excluded
// paths, and the confirmation that first-party source carries no import,
// initializer, tag or call site. Both are executed here instead of claimed.
//
// The needles are ASSEMBLED FROM FRAGMENTS AT RUNTIME, deliberately. A test that
// spelled them out would put the searched-for strings inside the searched tree, so
// the sweep it exists to model would then hit this file forever and every future
// reader would have to re-derive that the hit is a test fixture and not a tracker.
// Same argument as `scripts/scan-residue.mjs`, applied one directory down.
//
// Not runnable here: `vitest` is declared in the fixture's own manifest and is
// vendored nowhere in this repository, and `FIXTURE_ROOT` is resolved relative to
// this file rather than to any real project. Per fixtures/README.md, if you can run
// it, it does not belong in this corpus.

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { describe, expect, it } from "vitest";

const FIXTURE_ROOT = join(import.meta.dirname, "..");

/**
 * The exclusion the guard is made of. A committed bundle under any of these is
 * the vendor's own code, so a hit inside one establishes no caller — which is the
 * whole finding false positive 7 refuses to write.
 */
const EXCLUDED_DIRS = ["dist", "build", "out", ".next", "node_modules", "vendor"] as const;
const EXCLUDED_SUFFIXES = [".min.js", ".bundle.js", ".chunk.js", ".map"] as const;

/** Assembled, never written out. See the header. */
const VENDOR_NEEDLES: readonly string[] = [
  "sen" + "try",
  "gta" + "g(",
  "data" + "Layer",
  "__REPORT_KIT_" + "ANALYTICS__",
];

/**
 * What actually grades. A vendor name in a comment is not a finding; an import, an
 * initializer, a tag element or a call site is. These are the shapes to look for
 * in first-party source, and every one of them is absent from `src/`.
 */
const FIRST_PARTY_WIRING: readonly string[] = [
  "@sen" + "try/",
  "sen" + "try_sdk.in" + "it(",
  "Sen" + "try.in" + "it(",
  "window.gta" + "g =",
  "window.gta" + "g=",
  "data" + "Layer.push(",
  "<" + "script",
  "next" + "/script",
  "__REPORT_KIT_" + "ANALYTICS__ =",
];

const TELEMETRY_PACKAGE_FRAGMENTS: readonly string[] = [
  "@sen" + "try/",
  "dd-" + "trace",
  "new" + "relic",
  "log" + "rocket",
  "post" + "hog",
  "mix" + "panel",
  "ampli" + "tude",
  "@seg" + "ment/analytics",
  "react-" + "ga",
  "full" + "story",
  "hot" + "jar",
  "clarity" + ".ms",
  "smart" + "look",
];

function walk(dir: string, acc: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const abs = join(dir, entry);
    if (statSync(abs).isDirectory()) {
      if ((EXCLUDED_DIRS as readonly string[]).includes(entry)) continue;
      walk(abs, acc);
      continue;
    }
    if (EXCLUDED_SUFFIXES.some((s) => entry.endsWith(s))) continue;
    acc.push(abs);
  }
  return acc;
}

function firstPartySourceFiles(): string[] {
  return walk(join(FIXTURE_ROOT, "src"));
}

function hits(files: readonly string[], needles: readonly string[]): string[] {
  const found: string[] = [];
  for (const file of files) {
    const text = readFileSync(file, "utf8");
    for (const needle of needles) {
      if (text.includes(needle)) found.push(`${relative(FIXTURE_ROOT, file).split(sep).join("/")}: ${needle}`);
    }
  }
  return found;
}

describe("telemetry is absent from first-party source", () => {
  // The control that stops a silent zero from passing as a clearance. If the
  // needles ever stop matching the bundle, the walk or the fragments broke, and
  // every assertion below would pass while proving nothing.
  it("finds the vendor strings in the committed bundle", () => {
    const bundle = readFileSync(join(FIXTURE_ROOT, "dist/assets/vendor.9f3c1a2b.min.js"), "utf8");
    for (const needle of VENDOR_NEEDLES) expect(bundle).toContain(needle);
  });

  it("enumerates a non-empty first-party source set", () => {
    expect(firstPartySourceFiles().length).toBeGreaterThan(0);
  });

  it("has no telemetry import, initializer, tag or call site in src/", () => {
    expect(hits(firstPartySourceFiles(), FIRST_PARTY_WIRING)).toEqual([]);
  });

  it("has no telemetry, analytics or session-replay SDK in the manifest", () => {
    const manifest = readFileSync(join(FIXTURE_ROOT, "package.json"), "utf8");
    const declared = JSON.stringify({
      dependencies: JSON.parse(manifest).dependencies,
      devDependencies: JSON.parse(manifest).devDependencies,
    });
    for (const fragment of TELEMETRY_PACKAGE_FRAGMENTS) expect(declared).not.toContain(fragment);
  });

  it("never activates the vendored adapters", () => {
    // The adapter switch. Absent from src/, so the kit's selector returns its
    // no-op and both vendor branches in the bundle are unreachable in this app.
    expect(hits(firstPartySourceFiles(), ["__REPORT_KIT_" + "ANALYTICS__"])).toEqual([]);
  });
});
