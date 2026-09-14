# SAM Portal (`vcns/sam-portal`)
## Delivery Status, Capability Ideation, and Open Questions

**Product:** VCNS SAM Platform -- portal component
**Repository:** `vcns/sam-portal` (does not exist yet -- confirmed against GitHub, 12 September 2026, re-confirmed 14 September 2026)
**Companion document:** `docs/sam-portal-requirements-spec.md` -- that document is the fixed architecture and requirements baseline (rewritten 2026-09-04; its own §24 "Decisions Fixed by This Specification" settles naming, repo boundaries, and non-negotiable security properties). **This document does not repeat or reinterpret that spec.** It tracks delivery status, breaks the spec's §20 delivery plan into a concrete feature backlog, and holds the open questions that are genuinely product/sequencing decisions rather than architecture -- the kind of living tracker `.roadmap/phase4_plan.md` is for `vcns/security-automation-manager`.
**Operating boundary (stated explicitly, 14 September 2026):** the SAM Portal is built entirely outside this repository. This document plans and tracks it because `vcns/sam-portal` doesn't exist yet to hold its own roadmap -- it does not authorise, and should never be read as inviting, portal *code* to be written inside `vcns/security-automation-manager`. When Foundation-phase work actually starts, it happens in a session/workspace pointed at `vcns/sam-portal` (once created) or `vcns/sam-licensing-service` for the licensing-side leg -- never here. Once `vcns/sam-portal` exists, this document's content should migrate there; what's left behind here should shrink to a short pointer, the same way a repository split is handled elsewhere in this project.
**Status:** Pre-implementation, `vcns/sam-portal` side. Split out of `.roadmap/phase4_plan.md`'s former Phase 4E.2 entry on 12 September 2026 because this is a separate product with its own repository, delivery plan, and (eventually) release cadence -- it doesn't fit that document's WordPress-plugin-scoped phase numbering. **Sequencing decided 12 September 2026: Phase 4F (Recommendations Engine, on the `security-automation-manager` side) goes first; Foundation-phase portal work begins after 4F, not in parallel with it.** **Phase 4F is now fully delivered (13 September 2026) -- that gate has passed.** One Foundation-phase bullet has also already been completed, from the `security-automation-manager` side alone, without `vcns/sam-portal` existing (see §3.1). See §5 for the sequencing decision and the other open questions.
**Date:** 12 September 2026; revised 14 September 2026 (Phase 4F completion, Stripe-secret removal, operating-boundary clarification)

---

# 1. Where This Sits Relative to the Rest of SAM

Three repositories, three independent delivery tracks:

- `vcns/security-automation-manager` (this repo) -- tracked in `.roadmap/phase4_plan.md`. Phase 4A-4G all delivered, including 4F (Recommendations Engine, completed 13 September 2026 -- the gate §5.2 set for portal Foundation-phase work to begin). A further fix (not part of Phase 4, but directly relevant to this document's own §3.1 Foundation bullet) removed this repo's direct-Stripe checkout path on 14 September 2026 -- see §3.1.
- `vcns/sam-licensing-service` -- has no roadmap doc in this repo (it's a separate repository with its own history), but its progress is directly relevant here since the portal consumes it. **Confirmed 12 September 2026:** repository rename done; that service's own Phase 0-4 (production hardening, service-identity auth, licensing-model breadth, Stripe subscription adoption, audit logging) and a catalog/admin-portal track (PRs #14-19: KV-backed catalogue, coupons, admin-write endpoints, admin-auth foundation, a session-based admin portal shell) are merged. PR #13 (per-installation fleet detail) was correctly closed unmerged after a design-flaw review. Uncommitted local WIP adds a full Cloudflare Custom Domain deploy pipeline (render-script + GitHub Actions staging/production workflow + 9 numbered docs). None of this is `sam-portal` work, but it's directly reusable: see §3 below.
- `vcns/sam-portal` -- this document. Not started.

---

# 2. Current Status

Still nothing to report for `vcns/sam-portal` itself: no repository, no code, no CI/CD, no threat model. Almost all of the spec's §20 delivery plan -- Foundation through Assurance and fleet expansion -- is ahead of us.

Two things have changed since this document was first written, both worth recording precisely because they happened *without* `vcns/sam-portal` existing yet -- proof the Foundation phase isn't strictly gated on that repository being created first:

- **The sequencing gate has passed.** Phase 4F (Recommendations Engine) was the condition §5.2 set for Foundation-phase portal work to begin; it's now fully delivered (13 September 2026, `.roadmap/phase4_plan.md`).
- **One Foundation-phase bullet is done.** The spec's own §20 lists "Remove production Stripe secrets from every customer-controlled WordPress path" under Foundation. `includes/extensions/fully-automatic-mode.php`'s direct-Stripe checkout path was removed from `vcns/security-automation-manager` on 14 September 2026 (plaintext secret/price/webhook option storage, the checkout AJAX handler; a migration actively scrubs any previously-stored values). See §3.1 for detail.

The one substantive fact worth restating here (moved from `phase4_plan.md`'s old 4E.2 entry): `sam-licensing-service`'s existing, merged work already gives the portal a proven, working pattern for several things it will need on day one -- Ed25519 service-identity auth, a session-based admin-auth model, KV-backed storage, and a Cloudflare Custom Domain deploy pipeline with staging/production GitHub Environments. None of that is portal code, but none of it needs to be reinvented either. See §3's Foundation section.

With the sequencing gate now passed, the practical next decision isn't architectural -- it's *when* (not *whether*) to actually create `vcns/sam-portal` and begin Foundation-phase work there, and in what session/workspace that happens, given the operating boundary stated above. Nothing here should be read as that decision having been made.

---

# 3. Capability Backlog, by Delivery Phase

The spec's §20 gives four dependency-ordered phases with one-line bullets. Below, each bullet is expanded into something closer to a feature backlog, plus sequencing judgment -- not new architecture, just breaking the spec's requirements into a buildable order. Spec section references are in brackets so nothing here drifts from the fixed baseline.

## 3.1 Foundation

- **Create the `vcns/sam-portal` repository.** Ownership, CI/CD, environments (staging/production, matching `sam-licensing-service`'s existing pattern), architecture decision records. *Stack still open -- §5.1, deliberately deferred.* The sequencing gate (Phase 4F) has now passed -- this bullet is unblocked, not "must start immediately." Per the operating boundary stated at the top of this document, creating and building this repository happens in its own session/workspace, not inside `vcns/security-automation-manager`.
- **Threat model and data-flow inventory** [§17, §18, §23] -- the spec makes this a Definition-of-Done item, not a nice-to-have; worth doing before the first line of ingestion/auth code, not after.
- **Publish the SAM protocol schemas and cross-runtime test vectors** [§8, §19] -- this is the one artifact all three repositories need to agree on without a runtime dependency between them. Concretely: a versioned schema package (JSON Schema or similar) that `security-automation-manager` (PHP) and `sam-portal` (whatever its runtime turns out to be) both validate against. This can live in its own small repo, or inside `sam-portal` if the portal is the natural owner -- worth deciding once the portal's own stack is chosen.
- ~~**Remove production Stripe secrets from every customer-controlled WordPress path**~~ [§21.2] **Done, 14 September 2026.** `includes/extensions/fully-automatic-mode.php`'s direct-Stripe checkout path (Stripe secret/price/webhook plaintext option storage, the `wp_ajax_wp_sam_create_checkout_session` handler, the pricing-card upgrade UI) was removed from `vcns/security-automation-manager`; a new migration actively deletes any previously-stored values from a site that had configured them, rather than merely stopping new writes. This resolved a real, standing finding in that repo's own threat model (`docs/threat-model.md`, "Stripe secret exposure on customer installs" -- previously the primary blocker on its public-hosting readiness gate), independent of `vcns/sam-portal` existing. `fully_automatic` remains a registered automation-mode concept there but is unreachable until a `sam-licensing-service`-backed entitlement source is built -- see the note immediately below.
  - **Follow-on, not yet scoped:** `vcns/security-automation-manager`'s `Feature_Gate` class already accepts its entitlement source as a duck-typed `?object $entitlements` (just needs a `get_for_site()` method) -- confirmed while removing the code above. A `sam-licensing-service`-backed entitlement source could be wired in the same way `includes/extensions/commercial-services.php` wires today's dormant one, without `Feature_Gate` itself needing a rewrite. This is a `security-automation-manager`-side task, not a `sam-portal` one, and isn't part of this document's own backlog -- noted here only because it was discovered as a direct consequence of the bullet above, and belongs in that repo's own roadmap once scoped.

## 3.2 Portal minimum viable service

The spec's own MVP phase is still seven substantial items. Build order, resolved 12 September 2026 (§5.3) -- licensing/Checkout integration first, since most of its server side already exists and it's the lowest new-design risk of the seven:

1. **Licensing-service Checkout, subscription and entitlement integration** [§15] -- **first slice.** Mostly wiring against an API that already exists server-side (`sam-licensing-service`'s Phase 2/Phase 3 work covers Checkout and subscriptions already) -- less new design than it sounds, and gives the portal a real, working spine (tenant-to-customer linkage, entitlement state) that every later feature can build against.
2. **Tenant auth and RBAC** [§6] -- the 6-role model (Owner/Administrator/Approver/Analyst/Viewer/Service identity) is spec-fixed. `sam-licensing-service`'s admin-auth foundation (password hashing, admin users, sessions -- PR #18) is the closest existing pattern to extend, not a from-scratch build.
3. **CSP reporting ingestion and safe normalisation** [§9] -- still the highest-leverage customer-facing feature once auth exists: it's the one thing that works in Portal-only mode [§3.2] with zero WordPress dependency, so it's what makes a non-WordPress customer possible at all, and it's a bounded, well-specified problem (accept/reject/normalise/neutralise, no scanning-safety surface to design yet).
4. **Protected-resource enrolment and domain verification** [§7] -- needed before ingestion can be tenant-scoped for real. Smallest defensible v1: DNS TXT only, defer HTTP well-known and adapter-based enrolment to a later slice.
5. **Findings, evidence and notification workflow** [§11] -- depends on ingestion existing first; this is where "a report came in" becomes "here's what it means."
6. **Public external header/CSP/TLS scanning** [§10] -- resolved 12 September 2026 (§5.4): build in-house, per §10.1's spec as written -- SSRF prevention, DNS re-check at connection time, blocked-range enforcement, per-tenant/global kill switches, no third-party shortcut or deferral. Still sequenced later within MVP since it's a substantial standalone engineering effort best done once ingestion and the dashboard shell exist to show its output in.
7. **Portal-only setup instructions for common host-header configurations** [§14 onboarding] -- documentation-shaped work, can trail the features it documents.

## 3.3 Integrated SAM

- WordPress enrolment, signed/encrypted evidence upload, fleet posture, signed policy proposals, local approval/rollback, offline queues and key rotation [§3.3, §8, §12].
- This is where `security-automation-manager` gains new work of its own (a future phase on that repo's side -- not tracked here, would need its own entry in `phase4_plan.md` or a successor once scoped). It can't start meaningfully until the portal's tenant/resource/policy-versioning model exists to enrol into, so it's correctly sequenced after Portal MVP, not in parallel with it.

## 3.4 Assurance and fleet expansion

- Cross-resource governance, dependency/payload intelligence, certificate/drift risk, broader adapters (proxy/Linux/Windows/Docker/Kubernetes), federated intelligence, time-bound exceptions and advanced simulation [§13, §10.2].
- Last, deliberately -- same rationale `phase4_plan.md` already gives for Phase 4F (Recommendations Engine): this class of work benefits from real operational data existing first, and there's no fleet to manage until customers with multiple protected resources exist.

---

# 4. What This Document Deliberately Does Not Decide

Per the companion spec's §24, these are already fixed and this document does not revisit them: the three-repository boundary, `sam-portal` as the fleet/assurance/hosted-reporting owner, no shared writable database between components, Stripe secrets confined to the licensing service, mutual authentication/signing/encryption for privileged component messages, and typed/bounded remote control (no arbitrary remote execution).

---

# 5. Open Questions

These are sequencing, resourcing, and scope decisions -- not architecture, which the spec already settles. Flagging them here rather than guessing.

## 5.1 Stack for `vcns/sam-portal`

**Open, deliberately deferred (12 September 2026; still open as of 14 September 2026).** The spec is stack-agnostic. `sam-licensing-service` is Cloudflare Workers + KV + Durable Objects, and its admin-auth/deploy-pipeline patterns are directly reusable *if* the portal uses the same stack. But the portal is a materially bigger surface than a licensing worker -- multi-tenant dashboards, fleet views, findings/evidence browsing -- which is a different shape of problem than a lightweight API worker. Explicitly not decided now; revisit as its own architecture-decision task once Foundation-phase portal work is actually about to start. Phase 4F (the condition originally attached to this) is now done, so this question is the practical remaining blocker on creating `vcns/sam-portal` at all.

## 5.2 Sequencing against Phase 4F

**Resolved, 12 September 2026: Phase 4F first.** Phase 4F (Recommendations Engine, `security-automation-manager` side) is scoped and built before any `sam-portal` Foundation work begins -- not in parallel. `phase4_plan.md`'s older recommendation (portal before 4F) is superseded by this decision.

**Gate passed, 13 September 2026.** Phase 4F is fully delivered (`.roadmap/phase4_plan.md`). Foundation-phase portal work is therefore unblocked by this decision -- whether and when to actually begin it is a separate, not-yet-made decision (see §5.1 and §5.5, and the operating-boundary note at the top of this document).

## 5.3 First build slice

**Resolved, 12 September 2026: licensing/Checkout integration first.** Not CSP ingestion -- see the reordered build list in §3.2. Reasoning given: most of the server side already exists in `sam-licensing-service`, so it's the lowest-new-design-risk starting point and gives every later feature a real tenant-to-entitlement spine to build against.

## 5.4 External scanning: build, defer, or buy

**Resolved, 12 September 2026: build in-house, as specified.** Full SSRF-safety/kill-switch/egress control per §10.1, no third-party shortcut and no deferral to a later milestone.

## 5.5 Solo build or scoped-for-help

Everything shipped so far across all three repositories has been built through this same Claude-Code-assisted, single-operator workflow. The portal is a bigger, longer-lived surface than anything built to date. Worth a deliberate check-in on whether that continues to be the intended build model for `sam-portal` specifically, since it affects how much upfront architecture documentation versus just-in-time decision-making makes sense.
