// C-008 — clean fixture. Expected findings at Low or above: ZERO.
//
// Why this pattern-matches as vulnerable:
//   `dangerouslySetInnerHTML` is the highest-signal XSS sink in the React
//   ecosystem, and the value handed to it derives from MODEL OUTPUT — which is
//   also the LLM render-channel finding. Every output-sink sweep in web-and-api
//   and llm-and-ai lands on line 78, and the variable feeding it is called
//   `iconMarkup`.
//
// Why it is not a finding:
//   The model does not supply markup. It supplies an icon *name*, which is used
//   as a key into `ICON_SVG` — a frozen `Record<string, string>` of inline SVG
//   literals declared above, in this file, at module scope. `Object.hasOwn` is
//   the membership test (so `"__proto__"`, `"constructor"` and `"toString"`
//   resolve to nothing), and an unknown name yields `null`, which renders no
//   element at all. No substring of the model's output reaches the sink: the
//   value handed to `dangerouslySetInnerHTML` is always one of exactly five
//   string literals written by hand in this file.
//
//   The message *text* beside the icon is rendered as a React child, which React
//   escapes. It is deliberately not passed through the same sink.
//
// False-positive entries exercised:
//   llm-and-ai (3)         rendering of model output flagged as an
//                          exfiltration/XSS channel without reading what the
//                          renderer actually receives
//   ai-generated-code (6)  a validator in front of a correct sink rather than
//                          instead of one
//   web-and-api            the `dangerouslySetInnerHTML` sweep hit whose sink
//                          value is a closed set of in-file literals
//
// Deliberately NOT the DOMPurify variant: web-and-api rejects "it goes through
// DOMPurify, so it is not XSS" as a suppression rule, so a fixture built on it
// would be testing the rejected reasoning rather than a supported clearance.

import * as React from "react";

/**
 * Every icon the assistant is allowed to name. Hand-written, inline, frozen.
 *
 * These five strings are the ONLY values that can ever reach
 * `dangerouslySetInnerHTML` in this component. `Object.freeze` is belt-and-braces
 * — the lookup below cannot write — but it also documents the intent for the
 * next reader.
 */
const ICON_SVG: Readonly<Record<string, string>> = Object.freeze({
  info: '<svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="7" fill="none" stroke="currentColor"/><path d="M8 7v5M8 4.5v1" stroke="currentColor"/></svg>',
  warning:
    '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 1.5 15 14H1z" fill="none" stroke="currentColor"/><path d="M8 6v4M8 11.5v1" stroke="currentColor"/></svg>',
  success:
    '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M2 9l4 4 8-9" fill="none" stroke="currentColor"/></svg>',
  clock:
    '<svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="7" fill="none" stroke="currentColor"/><path d="M8 4v4l3 2" stroke="currentColor"/></svg>',
  document:
    '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M4 1h5l3 3v11H4z" fill="none" stroke="currentColor"/><path d="M6 7h4M6 10h4" stroke="currentColor"/></svg>',
});

export interface AssistantNotice {
  /** Chosen by the model from the tool schema's enum. Treated as untrusted. */
  icon: string;
  /** Free text from the model. Rendered as a React child, so React escapes it. */
  text: string;
}

/**
 * Resolve a model-supplied icon name to markup, or to nothing.
 *
 * `Object.hasOwn` rather than `name in ICON_SVG` or a truthiness check on the
 * indexed value: the prototype chain is not part of the allowlist, and a model
 * that emits `"__proto__"` or `"constructor"` gets `null` here rather than a
 * function's source or an inherited property.
 */
function iconMarkupFor(name: string): string | null {
  if (typeof name !== "string") return null;
  if (!Object.hasOwn(ICON_SVG, name)) return null;
  return ICON_SVG[name];
}

export function IconMessage({ notice }: { notice: AssistantNotice }): React.ReactElement {
  const iconMarkup = iconMarkupFor(notice.icon);

  return (
    <div className="assistant-notice" role="status">
      {iconMarkup === null ? null : (
        // The value here is one of the five literals above and nothing else.
        <span className="assistant-notice__icon" dangerouslySetInnerHTML={{ __html: iconMarkup }} />
      )}
      <span className="assistant-notice__text">{notice.text}</span>
    </div>
  );
}
