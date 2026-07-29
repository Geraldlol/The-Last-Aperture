// C-025 — clean fixture. Expected findings at Low or above: ZERO.
//
// GENERATED FILE. Do not edit.
//   generator: openapi-typescript-codegen 0.29.0
//   source:    openapi/notes-api.v3.yaml (sha256 4f1c…, tracked in this repo)
//   command:   npm run codegen
//
// Why this pattern-matches as vulnerable:
//   Generated clients contain every tell in the ai-generated-code lens. This one
//   has an empty `catch {}`, a `_` discard, a bare `strict: false`, a `token`
//   compared with `===`, and a `fetch` with no timeout — five sweep hits in
//   ninety lines.
//
// Why it is not a finding:
//   The file is not hand-maintained, and the tells are the generator's template
//   rather than anybody's decision. Establishing that is mechanical and three
//   independent signals say so: the header banner above, the `.gen.ts` suffix and
//   `gen/` path, and a `linguist-generated=true` attribute for this path in
//   `.gitattributes`. The fix for anything wrong here is a generator or spec
//   change, so a finding filed against this file is filed at the wrong artifact.
//
//   This is NOT the vendored case, which is narrow and real: a vendored file is
//   shipped code and a defect in it is live. This tree is regenerated from a spec
//   that is itself in the repository and reviewed.
//
// False-positive entries exercised:
//   ai-generated-code (12)  generated, vendored and migration files
//   completeness (1)        a file matched by no lens that no lens should match —
//                           and the surviving case named there (a generated file
//                           whose generator INPUT is in scope) is answered: the
//                           input is `openapi/notes-api.v3.yaml`, which is in scope
//                           and is where a real finding here would live

/* eslint-disable */
/* tslint:disable */

export type CancelablePromise<T> = Promise<T> & { cancel(): void };

export interface OpenAPIConfig {
  BASE: string;
  VERSION: string;
  WITH_CREDENTIALS: boolean;
  TOKEN?: string | (() => Promise<string>);
}

export const OpenAPI: OpenAPIConfig = {
  BASE: "",
  VERSION: "3.0.0",
  WITH_CREDENTIALS: false,
  TOKEN: undefined,
};

// Template artefact: the generator emits a JSON-parse guard with an empty catch
// because the response may legitimately have no body (204).
function parseBody(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {}
  return undefined;
}

// Template artefact: the generator discards the resolved value when the operation
// is declared as returning `void` in the spec.
async function drain(response: Response): Promise<void> {
  const _ = await response.text();
}

// Template artefact: `strict` here is the generator's own query-serialisation
// mode, not a validator setting.
const SERIALIZER_OPTIONS = { arrayFormat: "repeat", strict: false } as const;

async function resolveToken(): Promise<string | undefined> {
  const token = OpenAPI.TOKEN;
  if (typeof token === "function") return token();
  // Template artefact: an identity comparison on an option value.
  if (token === undefined) return undefined;
  return token;
}

function serializeQuery(params: Record<string, unknown>): string {
  const parts: string[] = [];
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null) continue;
    if (Array.isArray(value) && SERIALIZER_OPTIONS.arrayFormat === "repeat") {
      for (const item of value) parts.push(`${encodeURIComponent(key)}=${encodeURIComponent(String(item))}`);
    } else {
      parts.push(`${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`);
    }
  }
  return parts.length ? `?${parts.join("&")}` : "";
}

export function request<T>(
  method: string,
  path: string,
  query: Record<string, unknown> = {},
  body?: unknown,
): CancelablePromise<T> {
  const controller = new AbortController();

  const promise = (async () => {
    const headers: Record<string, string> = { accept: "application/json" };
    const token = await resolveToken();
    if (token) headers["authorization"] = `Bearer ${token}`;
    if (body !== undefined) headers["content-type"] = "application/json";

    const response = await fetch(`${OpenAPI.BASE}${path}${serializeQuery(query)}`, {
      method,
      headers,
      credentials: OpenAPI.WITH_CREDENTIALS ? "include" : "same-origin",
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: controller.signal,
    });

    if (response.status === 204) {
      await drain(response);
      return undefined as T;
    }
    return parseBody(await response.text()) as T;
  })() as CancelablePromise<T>;

  promise.cancel = () => controller.abort();
  return promise;
}

export const NotesService = {
  listNotes: (limit = 50) => request<unknown[]>("GET", "/v3/notes", { limit }),
  getNote: (id: string) => request<unknown>("GET", `/v3/notes/${encodeURIComponent(id)}`),
  deleteNote: (id: string) => request<void>("DELETE", `/v3/notes/${encodeURIComponent(id)}`),
};
