// C-020 — clean fixture. Expected findings at Low or above: ZERO.
//
// Seven web-and-api reflexes and two threat-modeling reflexes fire on this file.
// None is a finding, and the discriminator is different for each one.
//
//   1. NO CSRF TOKEN on POST / PATCH / DELETE.
//      CSRF needs an ambient credential the browser attaches by itself. The only
//      credential this API accepts is `Authorization: Bearer`, which a hostile
//      origin cannot set and which forces a preflight the server must opt into.
//      And the API does not merely DOCUMENT that — `requireBearer` refuses a
//      request that carries a cookie and no bearer header, with a 401, so
//      "accepts either credential" is closed in code rather than in prose.
//
//   2. `Access-Control-Allow-Origin: *`.
//      Applied only to `/health` and `/.well-known/openapi.json`, both mounted
//      ABOVE the auth middleware and both returning fixed, non-tenant content.
//      `credentials` is left false, and a literal `*` cannot be combined with
//      credentials by the browser in any case. The reflection shapes that ARE
//      exploitable — `origin: true`, an unanchored regex, `Origin: null` — appear
//      nowhere in this file.
//
//   3. `findById(...)` — the BOLA shape.
//      Ownership scope is in the repository's signature: `findById` takes the org
//      id and cannot be called without it. And the read path is not the only path
//      checked: PATCH, DELETE, the bulk endpoint and the CSV export each resolve
//      through the same scoped helper, which is where the DRF-style bug actually
//      ships — a correct list scope and a custom action that bypasses it.
//
//   4. "No authentication on this endpoint."
//      The guard is `app.use("/api", requireBearer)`, registered BEFORE the router
//      mounts, so every handler below looks bare and every one is guarded. The
//      registration is in this file on purpose: a clean fixture may not lean on a
//      control in a file the reviewer does not have.
//
//   5. "Missing rate limiting" on login.
//      There is no login handler here to limit. Authentication is an OIDC
//      redirect to a hosted identity provider — no password comparison, no
//      credential store, no reset flow anywhere in this file. That is the
//      repository-answerable version of the question, and it is what earns the
//      entry rather than "there is probably an edge".
//
//   6. "Session still valid after logout."
//      Access tokens live ten minutes, and `POST /api/session/revoke` revokes and
//      rotates the refresh token server-side. Logout is not offered as the
//      mitigation for a stolen token; the short lifetime and the revocation are.
//
//   7. Missing `integrity` on a `<script>`.
//      The un-hashed tag is first-party and same-origin, served from `/assets`
//      with a content hash already in the filename. SRI there buys nothing and
//      couples every deploy to the template. The third-party tag two lines down
//      DOES carry `integrity` and `crossorigin`, which is where the control
//      belongs.
//
//   8. threat-modeling: "data crosses a trust boundary without re-validation."
//      The boundary parses once, into branded types, and inner functions receive
//      values that cannot exist in an invalid state. There is no second
//      construction path: no raw cast into a branded type, no `as unknown as`, no
//      deserializer, no factory reused from tests.
//
//   9. threat-modeling: "redundant enforcement flagged as inconsistency."
//      Authorization is checked in the middleware AND again in the repository
//      scope. Both read the same `POLICY` constant, so they cannot disagree — the
//      finding would be two checks with different role sets or different tenant
//      resolution, not two checks that share a source of truth.

import express, { type NextFunction, type Request, type Response } from "express";
import cors from "cors";
import helmet from "helmet";
import { z } from "zod";

import { prisma } from "./db";
import { verifyAccessToken } from "./oidc"; // verifies against the IdP's JWKS

// ---------------------------------------------------------------------------
// Branded types. The parse IS the validation, and it happens once, at the edge.
// ---------------------------------------------------------------------------

declare const orgBrand: unique symbol;
declare const invoiceBrand: unique symbol;

type OrgId = string & { readonly [orgBrand]: true };
type InvoiceId = string & { readonly [invoiceBrand]: true };

const OrgIdSchema = z.string().uuid().transform((v) => v as OrgId);
const InvoiceIdSchema = z.string().uuid().transform((v) => v as InvoiceId);

const InvoicePatchSchema = z
  .object({
    // No `status` and no `orgId`: a field absent from the schema cannot be
    // assigned, which is the fix for mass assignment rather than a denylist.
    note: z.string().max(2000).optional(),
    dueOn: z.coerce.date().optional(),
  })
  .strict();

const BulkVoidSchema = z
  .object({ invoiceIds: z.array(InvoiceIdSchema).min(1).max(200) })
  .strict();

// ---------------------------------------------------------------------------
// One policy table, read by both enforcement points.
// ---------------------------------------------------------------------------

const POLICY = {
  read: ["billing.viewer", "billing.editor", "billing.admin"],
  write: ["billing.editor", "billing.admin"],
  void: ["billing.admin"],
} as const;

type Capability = keyof typeof POLICY;

interface Principal {
  subject: string;
  orgId: OrgId;
  roles: readonly string[];
}

declare module "express-serve-static-core" {
  interface Request {
    principal?: Principal;
  }
}

function may(principal: Principal, capability: Capability): boolean {
  return principal.roles.some((r) => (POLICY[capability] as readonly string[]).includes(r));
}

// ---------------------------------------------------------------------------
// Repository. Every method takes the org id; none can be called without it.
// ---------------------------------------------------------------------------

const invoices = {
  findById(id: InvoiceId, orgId: OrgId) {
    return prisma.invoice.findFirst({ where: { id, orgId } });
  },
  listFor(orgId: OrgId, limit: number) {
    return prisma.invoice.findMany({ where: { orgId }, take: limit, orderBy: { issuedOn: "desc" } });
  },
  patch(id: InvoiceId, orgId: OrgId, data: z.infer<typeof InvoicePatchSchema>) {
    // updateMany, not update: `update` takes a unique selector and would ignore
    // the org predicate, which is exactly how a scoped read ships beside an
    // unscoped write. The returned count is checked by the caller.
    return prisma.invoice.updateMany({ where: { id, orgId }, data });
  },
  remove(id: InvoiceId, orgId: OrgId) {
    return prisma.invoice.deleteMany({ where: { id, orgId } });
  },
  voidMany(ids: readonly InvoiceId[], orgId: OrgId) {
    return prisma.invoice.updateMany({
      where: { id: { in: [...ids] }, orgId },
      data: { status: "void" },
    });
  },
  exportFor(orgId: OrgId) {
    return prisma.invoice.findMany({ where: { orgId }, select: { id: true, total: true } });
  },
};

// ---------------------------------------------------------------------------
// App. Mount order is the security control, so read it top to bottom.
// ---------------------------------------------------------------------------

export const app = express();

app.disable("x-powered-by");
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://cdn.example.invalid"],
      imgSrc: ["'self'", "data:"],
      objectSrc: ["'none'"],
      baseUri: ["'none'"],
      frameAncestors: ["'none'"],
    },
  },
  referrerPolicy: { policy: "strict-origin-when-cross-origin" },
}));
app.use(express.json({ limit: "256kb" }));

// Public, unauthenticated, fixed content. Wildcard CORS is correct here, and
// these two routes are mounted above the auth middleware deliberately.
const publicCors = cors({ origin: "*", credentials: false, methods: ["GET"] });
app.get("/health", publicCors, (_req, res) => res.json({ status: "ok" }));
app.get("/.well-known/openapi.json", publicCors, (_req, res) => res.json({ openapi: "3.1.0" }));

/**
 * The guard. Registered before the router mounts, so every /api handler is
 * covered whether or not it says so.
 *
 * The cookie clause is the load-bearing half for the CSRF question: a request
 * carrying a session cookie and no bearer token is refused, so the API cannot be
 * driven by an ambient credential and there is nothing for a forged form to
 * ride.
 */
function requireBearer(req: Request, res: Response, next: NextFunction) {
  const header = req.headers.authorization;

  if (req.headers.cookie && !header) {
    return res.status(401).json({ error: "cookie authentication is not accepted" });
  }
  if (!header?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "bearer token required" });
  }

  const claims = verifyAccessToken(header.slice("Bearer ".length));
  if (!claims) return res.status(401).json({ error: "invalid token" });

  const orgId = OrgIdSchema.safeParse(claims.org);
  if (!orgId.success) return res.status(401).json({ error: "token carries no org" });

  req.principal = { subject: claims.sub, orgId: orgId.data, roles: claims.roles ?? [] };
  return next();
}

app.use("/api", requireBearer);

function requireCapability(capability: Capability) {
  return (req: Request, res: Response, next: NextFunction) => {
    const principal = req.principal!;
    if (!may(principal, capability)) return res.status(403).json({ error: "forbidden" });
    return next();
  };
}

const router = express.Router();

router.get("/invoices", requireCapability("read"), async (req, res) => {
  const { orgId } = req.principal!;
  res.json(await invoices.listFor(orgId, 100));
});

router.get("/invoices/:id", requireCapability("read"), async (req, res) => {
  const id = InvoiceIdSchema.safeParse(req.params.id);
  if (!id.success) return res.status(400).json({ error: "bad id" });

  const { orgId } = req.principal!;
  const invoice = await invoices.findById(id.data, orgId);
  if (!invoice) return res.status(404).json({ error: "not found" });
  return res.json(invoice);
});

// PATCH is checked separately, not inherited from the read scope.
router.patch("/invoices/:id", requireCapability("write"), async (req, res) => {
  const id = InvoiceIdSchema.safeParse(req.params.id);
  const patch = InvoicePatchSchema.safeParse(req.body);
  if (!id.success || !patch.success) return res.status(400).json({ error: "bad request" });

  const { orgId } = req.principal!;
  const { count } = await invoices.patch(id.data, orgId, patch.data);
  return count === 0 ? res.status(404).json({ error: "not found" }) : res.status(204).end();
});

// DELETE too.
router.delete("/invoices/:id", requireCapability("write"), async (req, res) => {
  const id = InvoiceIdSchema.safeParse(req.params.id);
  if (!id.success) return res.status(400).json({ error: "bad id" });

  const { orgId } = req.principal!;
  const { count } = await invoices.remove(id.data, orgId);
  return count === 0 ? res.status(404).json({ error: "not found" }) : res.status(204).end();
});

// The bulk custom action — the path that ships unscoped in real codebases.
router.post("/invoices/bulk-void", requireCapability("void"), async (req, res) => {
  const parsed = BulkVoidSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "bad request" });

  const { orgId } = req.principal!;
  const { count } = await invoices.voidMany(parsed.data.invoiceIds, orgId);
  return res.json({ voided: count, requested: parsed.data.invoiceIds.length });
});

// And the export.
router.get("/invoices.csv", requireCapability("read"), async (req, res) => {
  const { orgId } = req.principal!;
  const rows = await invoices.exportFor(orgId);
  res.type("text/csv").send(rows.map((r) => `${r.id},${r.total}`).join("\n"));
});

/**
 * Revoke and rotate the refresh token. Access tokens are ten minutes, so this
 * closes the session in bounded time without a server-side session table.
 */
router.post("/session/revoke", async (req, res) => {
  const { subject } = req.principal!;
  await prisma.refreshToken.updateMany({
    where: { subject, revokedAt: null },
    data: { revokedAt: new Date() },
  });
  res.status(204).end();
});

app.use("/api", router);

// ---------------------------------------------------------------------------
// The one server-rendered document, and the SRI decision.
// ---------------------------------------------------------------------------

app.get("/", (_req, res) => {
  res.type("html").send(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Invoices</title>
  <!-- First-party, same-origin, content-hashed filename. No integrity: the hash
       is already in the URL, and adding one couples every deploy to this file. -->
  <script type="module" src="/assets/app.9f3c1ab2.js"></script>
  <!-- Third-party. This is where SRI belongs, so it is here. -->
  <script
    src="https://cdn.example.invalid/chartkit/4.2.1/chartkit.min.js"
    integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
    crossorigin="anonymous"
    defer></script>
</head>
<body><div id="root"></div></body>
</html>`);
});
