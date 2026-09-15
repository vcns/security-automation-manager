<!--
HOW TO USE THIS DOCUMENT

This is the first message to paste into a fresh Claude Code session in a
new, empty vcns/sam-portal repository. That session will have no memory of
this repository, this conversation, or any decision made here -- everything
it needs to start is either in this file or explicitly referenced by it.

Paste, in order:
  1. The full content of docs/sam-portal-requirements-spec.md (the fixed
     architecture and requirements baseline -- this brief does not repeat
     it, only points at it).
  2. This file.

If the new session also has filesystem access to a local checkout of
vcns/sam-licensing-service, tell it the path -- §3 below names specific
files worth reading directly rather than taking this brief's word for their
contents.
-->

# SAM Portal -- Kickoff Brief

**For:** a fresh Claude Code session starting `vcns/sam-portal` from nothing.
**Written:** 14 September 2026, in `vcns/security-automation-manager`'s own
`.roadmap/sam_portal_plan.md`, which is the living tracker this brief was
drafted from. That tracker is not being pasted here in full -- this brief
extracts what a fresh session actually needs to start; the tracker itself
stays in `security-automation-manager` as the historical record.

## 1. What SAM Portal is, in one paragraph

SAM (Security Automation Manager) is a three-repository product family:
`vcns/security-automation-manager` (a WordPress plugin, the free/commercial
edge component), `vcns/sam-licensing-service` (a Cloudflare Worker, the
sole Stripe/entitlement authority -- already built, see §3), and
`vcns/sam-portal` (this repository -- customer accounts, protected-resource
management, hosted CSP reporting, external verification/scanning, fleet
posture and policy governance). The full requirements and fixed
architecture decisions are in the pasted spec above; this brief does not
restate them.

## 2. Fixed decisions -- do not re-litigate these

Per the spec's own §24 ("Decisions Fixed by This Specification"), all of
the following are settled and out of scope for debate in this new
repository:

- Three separate repositories, three separate deployments, no shared
  writable database.
- `sam-portal` owns fleet management, hosted reporting, external
  verification, and policy governance -- never a fork of the WordPress
  plugin.
- Stripe secrets live only in `sam-licensing-service`; `sam-portal` consumes
  signed/authenticated entitlement state, never Stripe directly.
- Privileged component-to-component messages are mutually authenticated,
  signed, and (where sensitive) encrypted, on top of TLS.
- Remote control the portal ever sends to an enrolled WordPress site is
  typed and bounded -- never arbitrary remote code/shell execution.
- Domains are fixed: `sam.vcns.tech` (portal), `licensing.vcns.tech`
  (licensing service, already live).

## 3. Stack decision (resolved 14 September 2026)

**Cloudflare Workers, matching `vcns/sam-licensing-service`'s stack.**
Reasoning: one platform to operate (billing, credentials, observability),
and several of that repository's patterns are directly reusable rather than
needing to be reinvented. Confirmed present in `sam-licensing-service` as
of this writing (read these files directly if you have access to that
checkout, rather than trusting this summary of them):

- **Deploy pipeline, verbatim-reusable pattern:** `wrangler.toml` uses a
  Cloudflare *Custom Domain* route (not a plain Route) -- `routes = [{
  pattern = "…", custom_domain = true, zone_id = "${ZONE_ID}" }]` --
  because the Worker is the origin for its hostname, not sitting in front
  of one. `${DOMAIN_NAME}`/`${ZONE_ID}` are literal tokens rendered by
  `scripts/render-wrangler-toml.mjs` (a small, dependency-free Node script)
  from each GitHub Environment's own variables before `wrangler deploy`
  runs, since TOML has no native env-var interpolation. `.github/workflows/
  deploy.yml` deploys staging on every push to `main`, then production
  (gated by a required-reviewers rule on the `production` GitHub
  Environment, not by the workflow itself). `docs/06-deploy-the-main-
  service.md` and `docs/07-github-actions-cicd.md` in that repository are a
  complete, working walkthrough -- read them directly and adapt, don't
  re-derive this from scratch.
- **Admin-portal session auth, directly reusable pattern:**
  `src/adminPortal/session.ts` -- an HttpOnly, Secure, SameSite=Strict,
  path-scoped session cookie; session records in KV with a TTL; a
  `requireAdminSession()` guard every protected page calls first, throwing
  a typed error whose `toResponse()` redirects to `/login` and is picked up
  polymorphically by the router's own catch-all (so every rejection is
  centrally audited for free, no bespoke per-page audit call needed). This
  is a good pattern for the portal's own tenant/user auth too, though the
  portal needs real multi-tenant RBAC (6 roles per the spec -- see §6
  there), not just a single admin-user session.
- **Data layer:** `sam-licensing-service` uses Durable Objects with SQLite
  storage as the mutation authority per entity (one DO class per
  Installation/Licence/StripeEvent), with KV holding read-optimised
  projections. **This may not be the right default for the portal's own
  core data.** The portal's dashboards, fleet views, and findings/evidence
  browsing are genuinely relational and query-heavy (filter/sort/join
  across tenants, resources, and findings) in a way licensing-service's
  mostly write-then-read-by-key model isn't. Worth deciding explicitly,
  not defaulting silently: **D1** (real SQL, easy joins/indexes) for
  tenants/resources/findings/policy-versions is a reasonable choice, while
  still using **Durable Objects** wherever genuine strong per-entity
  consistency is needed (e.g. a protected resource's own enrolment state
  machine, rate-limit counters) and **KV** for the same "cheap, cached
  projection" role it already plays in licensing-service. Make this
  decision explicitly in an early architecture-decision record; don't
  carry the DO-only model over by default just because licensing-service
  used it.
- **Rate limiting:** native Cloudflare `[[ratelimits]]` wrangler bindings
  (fixed-window, `period` is 10 or 60 seconds only), not a hand-rolled
  KV-based limiter -- one binding per distinct limit (per-IP, per-endpoint,
  per-admin-login-attempt, etc.).
- **Zero production dependencies.** `sam-licensing-service`'s
  `package.json` has no runtime dependencies at all -- only
  `devDependencies` (`wrangler`, `typescript`, `vitest`,
  `@cloudflare/vitest-pool-workers`, `@cloudflare/workers-types`). Matches
  `security-automation-manager`'s own zero-production-dependency
  architecture (see that repo's `docs/architecture.md`) -- worth carrying
  over as a deliberate constraint, not an accident.
- **File structure worth adapting, not copying literally:** `protocol/`
  (shared request-parsing/signature-verification helpers), `handlers/`
  (one file per API endpoint), `kv/` (KV-backed read models and sessions),
  `durable-objects/` (mutation-authority entities, if used), `adminPortal/`
  (session/render/pages for the human-facing UI). The portal's own
  equivalent shape is likely `protocol/`, `handlers/`, `kv/` or `d1/`,
  `durable-objects/` (for whichever entities need one), and a customer-
  facing UI equivalent to `adminPortal/`.
- **Testing:** Vitest with `@cloudflare/vitest-pool-workers` (runs tests
  inside an actual `workerd` runtime, not a Node shim) -- `npm run test` /
  `npm run test:watch` / `npm run test:all`.

## 4. Build order (from `.roadmap/sam_portal_plan.md`, resolved
   12 September 2026)

The spec's own §20 delivery plan is Foundation → Portal minimum viable
service → Integrated SAM → Assurance and fleet expansion. Within
"Foundation" and "Portal minimum viable service," build order was
explicitly decided:

**Foundation** (some of this may already be partly done in
`security-automation-manager` and `sam-licensing-service` -- check their
own roadmaps before redoing anything):
1. Repository setup: ownership, CI/CD, environments -- follow §3 above.
2. Threat model and data-flow inventory -- the spec makes this a
   Definition-of-Done item, not optional, and it should exist before the
   first line of real ingestion/auth code, not be retrofitted after.
3. Publish the SAM protocol schemas and cross-runtime test vectors (spec
   §8, §19) -- the one artifact all three repositories need to validate
   against without a runtime dependency between them. A versioned schema
   package (JSON Schema or similar); decide whether it lives in its own
   small repo or inside `sam-portal`.

**Portal minimum viable service** -- build in this order (resolved
12 September 2026, reasoning below each):
1. **Licensing-service Checkout, subscription and entitlement
   integration** (spec §15). *First slice, deliberately.* Most of the
   server side already exists in `sam-licensing-service` (Checkout,
   subscriptions, entitlement signing are already built and merged there)
   -- this is mostly wiring against an existing API, not new design, and
   it gives every later portal feature a real tenant-to-entitlement spine
   to build against rather than mocking one.
2. **Tenant auth and RBAC** (spec §6) -- the 6-role model (Owner /
   Administrator / Approver / Analyst / Viewer / Service identity) is
   spec-fixed. Extend the session pattern in §3 above rather than starting
   from scratch.
3. **CSP reporting ingestion and safe normalisation** (spec §9) -- the
   highest-leverage customer-facing feature once auth exists: it's the one
   thing that works in Portal-only mode (spec §3.2) with zero WordPress
   dependency, so it's what makes a non-WordPress customer possible at
   all. Bounded, well-specified problem (accept/reject/normalise/
   neutralise); no scanning-safety surface to design yet.
4. **Protected-resource enrolment and domain verification** (spec §7) --
   needed before ingestion can be tenant-scoped for real. Smallest
   defensible v1: DNS TXT verification only; defer HTTP well-known and
   adapter-based enrolment to a later slice.
5. **Findings, evidence and notification workflow** (spec §11) -- depends
   on ingestion existing first.
6. **Public external header/CSP/TLS scanning** (spec §10). Build
   in-house, exactly as specified -- SSRF prevention, DNS re-check at
   connection time, blocked-range enforcement, per-tenant/global kill
   switches (spec §10.1). No third-party shortcut, no deferral. This is a
   substantial standalone engineering effort with real infrastructure cost
   (egress, compute, abuse potential) -- sequence it after ingestion and
   the dashboard shell exist to show its output in, not before.
7. **Portal-only setup instructions** for common host-header
   configurations (spec §14 onboarding) -- documentation-shaped, can trail
   the features it documents.

**Integrated SAM** and **Assurance and fleet expansion** come after Portal
MVP -- see the spec's own §13, §10.2, and §3.3 for what they cover. Not
detailed further here since real Portal MVP usage should inform how they're
actually scoped, not a guess made before the portal exists.

## 5. Build model

Solo, Claude-Code-assisted -- the same model already proven across
`security-automation-manager` (~100 shipped PRs) and `sam-licensing-service`
(Phase 0-4 plus a catalog/admin-portal track, PRs #1-19). No new process
needed. Standard operating pattern from both of those repositories, worth
carrying over here:

- Design → schema/data-model decision if needed → implementation → tests →
  lint/typecheck clean → live verification (real Cloudflare environment,
  not just unit tests against mocks) → version/changelog bump → PR → CI
  green → merge.
- Small, sequential, reviewable increments rather than one large change --
  see §4's own build order for how the first several increments are
  already scoped.
- Write down *why*, not just *what*, in commit messages and code comments
  -- both existing repositories lean heavily on this, and it's what makes
  a solo, session-to-session build model work without losing context.

## 6. Immediate first steps for session 1

1. Read the pasted spec (above) and this brief in full before writing
   anything.
2. Create the `vcns/sam-portal` repository (empty, or with a minimal
   `wrangler.toml`/`package.json` skeleton adapted from §3's references).
3. Make the D1-vs-Durable-Objects-vs-KV decision from §3 explicitly, in
   writing (an ADR or a roadmap-doc entry, matching how
   `security-automation-manager` records architecture decisions in
   `.roadmap/`) -- don't let it default silently to whatever
   `sam-licensing-service` happened to use.
4. Set up CI/CD following `sam-licensing-service`'s `docs/06`/`docs/07`
   pattern (staging + production GitHub Environments, the Custom Domain
   deploy, required-reviewer gate on production).
5. Write the threat model and data-flow inventory (§4's Foundation item 2)
   before the first real endpoint.
6. Start on Portal MVP build order item 1 (licensing/Checkout integration)
   once the above is in place.

## 7. Open items this brief deliberately leaves for the new session

- The D1/DO/KV split (§3) -- explicitly not decided here.
- Where the shared protocol schema package (§4, Foundation item 3) should
  live -- its own repo, or inside `sam-portal`.
- Everything in the spec's §20 "Integrated SAM" and "Assurance and fleet
  expansion" phases -- deliberately not detailed in this brief; revisit
  once Portal MVP is real and there's operational data to scope against,
  the same reasoning `security-automation-manager`'s own Phase 4F
  (Recommendations Engine) used before it was built.
