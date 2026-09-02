# Product Specification

## Plugin: Security Automation Manager

**Version:** 1.0
**Date:** 2026-08-19
**DB schema alignment:** v32
**Status:** Active

**Supersedes:** v0.3 (2026-06-07), which described a CSP-only product aligned to
DB schema v4. That version is preserved in git history
(`git show v2.4.0:SPECIFICATION.md` or earlier) for anyone who needs it; it is
not retained in the working tree because a stale copy sitting alongside the
current one is exactly the kind of drift this revision exists to close (see
`docs/consolidation-ledger.md`).

This document, `README.md`, `readme.txt`, and `docs/*` are required to agree.
`test/unit/VersionConsistencyTest.php` enforces the version/schema numbers
above against the live code on every CI run - see "Keeping this document
honest" at the end.

---

## 1. Product Purpose

Security Automation Manager is a WordPress plugin covering three product
areas that share one administrative surface, one audit log, and one
free/commercial boundary, but are otherwise independent of each other:

1. **Security-header controls** - Content Security Policy (CSP) plus nine
   simpler per-surface headers, each rolled out with a report-only-first,
   evidence-based promotion path where the header mechanism supports one.
2. **Script and stylesheet integrity governance** - third-party origin
   classification with Subresource Integrity, and first-party integrity
   hashing, both rewriting the rendered page rather than emitting a header.
3. **TLS certificate lifecycle management** - a self-contained ACME v2
   client, unrelated to the header pillars beyond shared plumbing.

The unifying design principle across all three: nothing the plugin does not
already know is safe gets applied silently. Discovery and observation always
happen before a decision is asked for; a decision is always visible in the
audit log; and enforcement - where the underlying mechanism has a
report-only concept at all - is always a deliberate, separately-gated step
from approval.

The plugin does not implement a web application firewall, authentication
hardening, malware scanning/cleanup, or automated core/plugin patching. It
does not manage TLS for services outside this WordPress installation, and it
does not manage certificates for anything other than the domains an
administrator explicitly configures.

---

## 2. Governing Standards

**Security headers (W3C):**

- Content Security Policy Level 2 - W3C Recommendation (2015)
- Content Security Policy Level 3 - W3C Working Draft
- Trusted Types - W3C Working Draft
- Upgrade Insecure Requests - W3C Candidate Recommendation
- Mixed Content - W3C Recommendation
- Reporting API - W3C Working Draft (governs both CSP's Reporting API mode
  and the COOP/COEP report-only evidence mechanism)
- Cross-Origin-Opener-Policy and Cross-Origin-Embedder-Policy are defined
  across the HTML Living Standard (browsing-context group isolation) and the
  Fetch Living Standard (`Cross-Origin-Resource-Policy`); neither is a
  finished W3C/WHATWG Recommendation, and implementations vary - see
  "Cross-Origin Policy Learning" below for the concrete consequence
  (Reporting API delivery is Chromium-only today).

**Security headers (IETF):**

- RFC 7762 - Content Security Policy Directives registry (Informational);
  lags the living standard, not authoritative for the full directive set.
- RFC 7034 - X-Frame-Options (Informational); superseded in capable browsers
  by CSP `frame-ancestors`, retained here as a fallback.
- RFC 6454 - The Web Origin Concept; origin serialisation used throughout.
- RFC 9110 - HTTP Semantics, STD 97.
- RFC 9651 - Structured Field Values for HTTP; governs `Reporting-Endpoints`
  header construction.
- RFC 6797 - HTTP Strict Transport Security; complementary to, not replaced
  by, `upgrade-insecure-requests`.
- BCP 14 (RFC 2119 / RFC 8174) - normative language.

**Certificates (IETF):**

- RFC 8555 - Automatic Certificate Management Environment (ACME) v2. This
  plugin implements ACME v2 only; there is no ACME v1 code path.
- RFC 8737 - TLS-ALPN-01 is not implemented; only `http-01` and `dns-01`
  challenge types are supported.
- RFC 2136 - DNS Update, used by the `rfc2136` DNS provider driver for
  authoritative-server-direct DNS-01 record management.

**Directive/browser-support caveat carried over from the prior specification:**
CSP Level 3 remains a Working Draft. Directive availability is
browser-dependent; directive presence in this specification does not imply
universal support. Safari lacks `script-src-elem`, `script-src-attr`,
`style-src-elem`, and `style-src-attr`; the plugin maintains `script-src` and
`style-src` as portable fallbacks.

---

## 3. Security Header Controls

Ten header pillars in total: CSP (§4, the most capable) and nine simpler
per-surface pillars, each configured independently for the `frontend`,
`admin`, `login`, and `api` surfaces from its own admin page.

| Pillar | Values | Notes |
|---|---|---|
| X-Frame-Options | `DENY` / `SAMEORIGIN` | Fallback for browsers that don't honour CSP `frame-ancestors` |
| X-Content-Type-Options | on/off | `nosniff` |
| Referrer-Policy | 8 standard tokens | Defaults to `strict-origin-when-cross-origin` |
| Permissions-Policy | `none`/`self`/`all` per directive | Starter set of 7 features: geolocation, camera, microphone, fullscreen, payment, usb, autoplay - not the full W3C registry |
| Strict-Transport-Security | `max-age`, `includeSubDomains`, `preload` | HTTPS-only emission; `preload` gated behind `max-age`/`includeSubDomains` already meeting hstspreload.org's submission minimum, since preload removal can take months once a domain is listed |
| Cross-Origin-Resource-Policy | `same-site`/`same-origin`/`cross-origin` | Low risk - restricts who may embed this site's resources, not what this site embeds |
| Cross-Origin-Opener-Policy | `unsafe-none`/`same-origin`/`same-origin-allow-popups` | See §6, has a report-only learning workflow |
| Cross-Origin-Embedder-Policy | `unsafe-none`/`require-corp`/`credentialless` | See §6, has a report-only learning workflow; highest breakage risk of the ten pillars - `require-corp` blocks any cross-origin subresource that doesn't opt in via CORP/CORS |
| X-Permitted-Cross-Domain-Policies | `none`/`master-only`/`by-content-type`/`all` | Legacy Flash/Acrobat-era header; `none` is almost always correct |

**Default state.** Since DB schema v18, a fresh install seeds every surface
with a vetted, enabled configuration for all nine of these pillars (HSTS
excluded - it stays a deliberate per-surface opt-in because of its
stickiness). An upgraded install is never retroactively changed: the v18
seed only fills a `(pillar, surface)` row that has no existing setting.

**Report-only, discovery, automation.** Seven of the nine (all except
Cross-Origin-Opener-Policy and Cross-Origin-Embedder-Policy) have none of
these: each header is either sent exactly as configured, or not sent at all.
There is no equivalent of "external sources this page happens to load" for a
single-value or small-allowlist header, so there is nothing to discover.
COOP and COEP are the exceptions - see §6.

**Reverse Tabnabbing Protection** is a further, related control that rewrites
the page body rather than emits a header: it adds `rel="noopener"` to
`target="_blank"` links missing `noopener`/`noreferrer`, purely additive,
never blocking or breaking a link.

---

## 4. CSP Learning and Governance

CSP is deliberately the most capable pillar: per-surface profiles, nonce
injection, source discovery, violation reporting, and audit-first
policy-change review, built on a report-only-first, evidence-gated promotion
path.

**Supported surfaces.** `frontend`, `admin`, `login`, `api` - each with its
own profile, directives, sources, and mode.

**Configuration model.** A per-surface profile stores directives, an
approved-source list, active hashes, a mode (report-only/enforce per
surface), and per-directive automation posture. `strict-dynamic` support
includes automatic host-source suppression when active. Trusted Types is a
per-surface toggle that always stays report-only regardless of surface mode
(`require-trusted-types-for 'script'`).

**Discovery.** Runtime discovery observes real page loads; a manual or
scheduled rescan can also run. A freshly discovered source is always
`unclassified` until an administrator (or, within bounds, the deterministic
automation engine - see §9) decides.

**Report-only behaviour.** CSP always starts report-only on every surface,
regardless of automation posture. `report-sample` is supported in fetch
directives so inline snippets appear in violation reports. Direct
`report-uri` reporting is the default transport, with optional Reporting API
headers.

**Enforcement.** Promotion from report-only to enforce is always a
deliberate, per-surface administrator action through the learning window and
promotion gate - automation, where enabled, only ever governs *approval* of
a proposed source, never the report-only-to-enforce transition itself. See
§9 for the exact automation boundary.

**Approval requirements.** Every proposed source carries a risk ranking.
Approve/reject/revert/undo decisions require a reason. A reversed source is
suppressed from future automatic re-proposal (revert-and-suppress).

**Risk of breakage.** A misconfigured CSP can block legitimate first- or
third-party resources; the report-only-first design exists specifically to
surface this before enforcement, and per-directive/scheme automation limits
and hard exclusions bound what the deterministic engine may auto-approve
even in an automatic posture.

**Data stored.** Policy profiles, source inventory, hash inventory, decision
records with provenance, policy version snapshots and diffs, and violation
reports (blocked URI, document URI, violated directive, referrer, user
agent, line/column, and an optional sample). See `docs/database-schema.md`.

**External services contacted.** None by default - violation reports post
to this site's own REST endpoint (`/wp-json/sam/v1/report`, with a legacy
`/wp-json/security-manager/v1/report` alias for browsers holding an
older-issued header). An administrator may redirect the reporting URL to a
different host (proxy/CDN scenarios); doing so means local report learning
only continues to work if that host routes back to this plugin's endpoint.

**Audit events.** Every proposal, decision, promotion, and reset is recorded
in the append-only audit log (e.g. `auto_approved`, `wp_sam_reset`) - see §8.

**Rollback behaviour.** A decision can be undone without rewriting history.
The Recovery admin view offers an authenticated reset that clears all plugin
data (every pillar, not just CSP) and disables header emission until rollout
is deliberately restarted; it also offers pre-migration snapshot restore and
configuration export/import. See §13.

**Known limitations.** Conflict detection covers competing CSP headers from
`.htaccess`, server config, or other security-header plugins, but cannot see
CSP emitted by a layer entirely outside WordPress's control (e.g. a CDN edge
worker not configured to be visible to this check). Violation reports are
client-submitted and spoofable - treated as advisory signal, not ground
truth.

---

## 5. Script and Stylesheet Integrity

Two further protections rewrite the rendered HTML body rather than emit a
header, sharing a `Content_Rewriter` envelope (request/response eligibility,
buffering, fail-open on any uncertainty); a third is architecturally
distinct.

**External Scripts.** Passively inventories third-party `<script>`/`<link
rel="stylesheet">` origins from real page loads - no dedicated crawl,
deduplicated at the origin level (most recently observed full URL retained
separately for the SRI "Suggest" helper). An administrator classifies each
origin: Unclassified / Approved-immutable with SRI / Approved-mutable
provider / Exception / Blocked. A freshly discovered origin is always
`unclassified`, never blocked, matching CSP's report-first philosophy.
Report mode (default) never removes anything; enforce mode only removes an
origin explicitly marked Blocked, or an "immutable" origin whose SRI hash no
longer matches what the page actually served. SRI hashes are never fetched
from a third party and auto-trusted - only computed from a URL the
administrator themselves supplies, or typed in directly. A daily check
re-verifies pinned hashes against this site's own homepage (never
third-party content) so drift is caught before a real visitor triggers a
removal.

**Internal Script Integrity.** Per-surface opt-in; when enabled, reads a
first-party script/stylesheet's local file directly (never a network fetch),
computes its SHA-384 hash, and adds it as the tag's `integrity` attribute.
Cached by file size/mtime - an unchanged file is never re-read; a changed
one (plugin/theme update, manual edit) is picked up on the next request that
serves it. Nothing to classify or approve: the hash can never legitimately
drift from what's on disk.

**Data stored.** Dependency inventory (origin, classification, last-seen
URL), hash inventory, and a separate first-party asset inventory table
(`sam_internal_asset_inventory`).

**External services contacted.** None automatically. The "Suggest" SRI
helper fetches only a URL the administrator explicitly supplies and returns
only the computed hash - the fetched content itself is never stored or sent
elsewhere.

**Known limitations.** SRI enforcement assumes a third-party origin serves
byte-stable content at a pinned URL; a provider that legitimately rotates
content at the same URL (without a content-hashed filename) will need the
"Approved-mutable provider" classification instead of SRI pinning.

---

## 6. Cross-Origin Policy Learning

Cross-Origin-Opener-Policy and Cross-Origin-Embedder-Policy are the two
pillars among the nine "simple" pillars (§3) that have a real report-only
learning workflow, distinct from - and narrower than - CSP's discovery and
approval workflow.

**Configuration model.** Each pillar has a per-surface mode: Disabled /
Report-Only / Enforce, replacing what was previously a plain enabled
checkbox.

**Discovery / report-only behaviour.** In Report-Only mode, the browser's
Reporting API delivers violation reports to this plugin's shared reporting
endpoint, stored in `sam_pillar_violation_reports` (DB schema v13). The
Cross-Origin Policies admin page renders a Report-Only Evidence table
showing what's actually been observed for that pillar and surface, with a
"N violations in the last 7 days" summary.

**Enforcement.** Promoting a surface to Enforce is always a deliberate,
manual choice - there is no automation for COOP/COEP promotion.

**Browser-support limitation - read this before trusting an empty evidence
table.** Reporting API delivery for COOP/COEP is Chromium-based-browser-only
today (Chrome, Edge, Opera, and other Chromium-derived browsers). The
Report-Only *header* itself is honoured by every modern browser regardless;
only the *evidence you see back* is Chromium-only. A site with meaningful
non-Chromium traffic (Safari, Firefox) will under-count violations in the
evidence table - an empty or sparse table is inconclusive on such a site,
not proof the policy is safe to enforce.

**Risk of breakage.** `same-origin` COOP severs `window.opener` access from
any cross-origin popup, including popup-based OAuth/SSO flows -
`same-origin-allow-popups` is the safer choice for sites that rely on those.
`require-corp` COEP blocks any cross-origin subresource that doesn't
explicitly opt in via CORP or CORS; most third-party embeds don't, so
enabling it carelessly can silently break unrelated page content. Both are
worth revisiting whenever a new third-party embed, popup-based login, or
payment flow is added to the site.

**Data stored.** COOP/COEP violation reports in `sam_pillar_violation_reports`.

**External services contacted.** None - reports post to this site's own
reporting endpoint, the same shared mechanism CSP uses.

---

## 7. TLS Certificate Lifecycle Management

A separate, self-contained product domain: an ACME v2 (RFC 8555) client,
unrelated to the header pillars above beyond sharing the same admin/audit
plumbing and free/commercial boundary.

**Supported surfaces.** Not per-WordPress-surface - certificates are
per-domain (with optional wildcard and SAN support), independent of the
`frontend`/`admin`/`login`/`api` model the header pillars use.

**ACME protocol.** Account registration, order/authorization polling, nonce
handling with bad-nonce retry (max 3 attempts), CSR construction (with
optional organisation/department/country/state/city subject fields - note
that domain-validated CAs like Let's Encrypt issue on domain names only and
omit these from the final certificate even though they're included in the
CSR), certificate chain retrieval, and a staging/production environment
switch. Staging certificates are never auto-renewed.

**Challenge validation.** `dns-01` (41 built-in provider drivers, extensible
via the `wp_sam_dns_providers` filter - see the DNS-provider list in
`docs/certificates.md`) and `http-01`. `tls-alpn-01` is not implemented.
Wildcard certificates require `dns-01` (an ACME protocol constraint, not a
plugin limitation).

**Key types.** EC-P256 (default) or RSA-2048, generated via
`openssl_pkey_new`. A "bring your own private key" option is available when
this server can't reliably generate one - the Configuration tab runs a live
capability probe (an actual throwaway key generation attempt, not just an
`extension_loaded('openssl')` check) to decide whether to surface it, since
the extension can be present and still fail at runtime (a missing
`openssl.cnf`, `RANDFILE` write restrictions, other host lockdowns).

**Renewal.** WP-Cron based, 30-day-before-expiry threshold, duplicate-event
guards on both the daily check and a manual "issue now" trigger. Real system
cron is recommended over WordPress's request-triggered pseudo-cron on
low-traffic sites - see `docs/certificates.md` for configuration.

**Deployment.** cPanel (`SSL::install_ssl` UAPI, credentialled), filesystem
export (rejected if the resolved target path is inside the web root - a
`realpath()` check, not just a string-prefix deny-rule), or manual PEM
download. Export additionally best-effort `chmod`s the private key file to
`0600`.

**Failure and recovery behaviour.** Every issuance/renewal/deployment
attempt - success or failure - writes an audit-log entry
(`cert_issued`/`cert_deployed`/`cert_exported` on success,
`cert_issue_failed` on failure, severity `error`). A failed order does not
retry automatically until the next scheduled cron cycle; there is currently
no separate email/notification channel beyond the audit log and the
admin-visible "last run" status.

**Private-key handling.** Generated (or BYOK-supplied) keys and DNS-provider
/cPanel credentials are encrypted at rest via the credential vault (§10 of
`docs/consolidation-ledger.md` has the security review of this mechanism)
before they reach the database. Keys are never logged, never round-tripped
through the browser, and never included in evidence/export output.

**External services contacted.** The configured ACME endpoint (Let's
Encrypt production or staging), and - for `dns-01` - the selected DNS
provider's API, only once an administrator has configured Certificates.
Nothing is contacted automatically or in the background beyond the WP-Cron
renewal check for certificates that already exist.

**Known limitations.** DNS-provider driver test coverage is registry-level
only as of this document (instantiability and schema shape for all 41
drivers); no driver currently has a test exercising its actual
`create_txt_record`/`delete_txt_record` request logic against that
provider's real or mocked API - see `docs/consolidation-ledger.md` §6 for
the tracked remediation. No provider is described as "live-verified" unless
separately confirmed; absence of that claim means untested against a live
account.

---

## 8. Audit Evidence

A single append-only audit log spans all three product areas - CSP
decisions, other pillar changes, script/style integrity classifications,
and certificate lifecycle events all write to the same table and admin view.

**Purpose.** Every significant state change is attributable, timestamped,
and reversible-in-record even when the underlying state itself isn't (a
promotion decision can be undone; the fact that it happened and why cannot
be edited out).

**Structure.** Append-only - no update or delete path exists in the schema
for audit rows (`sam_audit_log`, DB schema v4; renamed from `csp_audit_log`
in schema v9 ahead of multi-pillar support). Each entry carries an event
type, severity, and event-specific detail.

**Coverage.** CSP proposal/decision/promotion/reset events, certificate
issuance/renewal/deployment success and failure, and (per §5-§6) the same
plumbing is available to script/style and cross-origin-policy changes.
Administrator dashboard access includes a Policy Audit tab for inspecting
why a proposal exists and what policy version resulted from a decision.

**Known limitations.** The audit log is a WordPress-database table, not an
external, tamper-evident log - a database-level compromise (see the
certificate threat model work referenced in
`docs/consolidation-ledger.md` §9) could in principle alter historical
entries; no cryptographic chaining or external mirroring exists today.

---

## 9. Automation

Automation exists only for CSP source approval. It does not exist for
COOP/COEP promotion, header-pillar values generally, or certificate
issuance/renewal (renewal is scheduled, not "automated" in the
approval-workflow sense this section describes).

**Automation postures (per CSP surface):** `Manual`, `Automatic (medium+high
approvals)`, `Automatic (high approvals only)`, `Fully Automatic`
(commercial - see §11).

**Default state.** A fresh install (DB schema v18+) seeds every surface to
`automatic_high_approval`: every proposed source below the high-risk
threshold is auto-approved into the report-only policy on its own evidence;
high-risk sources still require a human decision. An upgraded install is
never retroactively changed - the seed only fills a surface with no existing
automation setting.

**What automation governs - and what it never governs.** Automation posture
governs *approval of a proposed source* only. It never governs
*enforcement*: CSP always starts report-only on every surface regardless of
posture, and promotion to enforce always requires a deliberate,
per-surface administrator action through the learning window and promotion
gate. This distinction is the single most important fact in this
specification to get right in any derived documentation - see
`docs/consolidation-ledger.md` for the drift this correction addresses.

**Bounds on automatic approval.** Deterministic risk rules, hard exclusions,
configured directive/scheme limits, evidence requirements, and per-run caps.
Automatic decisions record `automation_engine` provenance and can be undone
without rewriting history, the same as a human decision.

**Future work constraint.** Any future AI-assisted recommendation work must
keep these deterministic product rules as the authority; AI output must
never directly modify an enforced CSP policy.

---

## 10. Distribution and Updates

Two build channels from one codebase, produced only by CI - never by a
runtime toggle a customer sets.

**WordPress.org channel.** `WP_SAM_DISTRIBUTION_CHANNEL` defaults to
`'wordpress-org'`. This build never contains the GitHub update checker and
never carries an `Update URI` header. It is built and deployed straight to
the WordPress.org SVN repository by the release pipeline; it is never a
GitHub Release download.

**GitHub channel.** Set only via `includes/build-channel.php`, which CI
generates and injects only into this build tree.
`Github_Update_Checker` is only ever instantiated when the channel is
`'github'`. It validates: package host and path against an allowlist, HTTPS
scheme, no `..` path-traversal segments, `.zip` suffix, and SHA-256
checksum via `hash_equals()` - before allowing WordPress to apply an update.
Exactly one asset is published per GitHub Release:
`security-automation-manager-vX.Y.Z.zip`, which *is* this build. Define
`WP_SAM_DISABLE_AUTO_UPDATE` as `true` in `wp-config.php` to prevent
background auto-updates.

**One updater.** No second or conflicting update mechanism exists in either
build.

**Release flow.** A `release/*` branch (cut from `main`) is the only branch
CI allows a pull request directly into `main`, alongside `development`
itself. Merging bumps the plugin header `Version`, `WP_SAM_VERSION`,
`readme.txt`'s stable tag, and `CHANGELOG.md` together. Tagging the merged
commit `vX.Y.Z` triggers the release pipeline, which builds and publishes
the GitHub Release asset and separately deploys the WordPress.org-safe
package to SVN, from the same tagged commit in the same run.

**Known limitations.** Release verification (clean install, upgrade,
rollback, package-content separation, interrupted-update recovery, all
against a real WordPress instance rather than hand-written stubs) is
incomplete as of this document - tracked in `docs/consolidation-ledger.md`
as the highest-priority remaining release blocker after documentation
correction. Rollback has no automated or even manually-documented-in-detail
process yet - same tracking document, same priority tier.

---

## 11. Commercial Boundaries

**Free vs. commercial.** Every header pillar, every script/stylesheet
integrity control, certificate management in full, and three of the four
CSP automation modes are free in both public builds, with no payment,
remote entitlement check, or third-party licensing call. The single
exception is Fully Automatic CSP mode (zero-review auto-apply of
deterministic policy changes): £1.99/month or £19.99/year, billed via
Stripe Checkout. A surface selecting Fully Automatic without an active
entitlement is kept on `Automatic (high approvals only)` instead - silently
downgraded, never disabled or blocked from working entirely.

**Where commercial code lives.** All Stripe/checkout/webhook/entitlement
logic lives in `offline/`, a git-ignored directory that ships empty in both
public builds (WordPress.org and GitHub). `Feature_Gate::FREE_FEATURES`
enumerates the free capability set explicitly (currently: CSP report-only,
basic scan, basic dashboard, the violation endpoint, manual policy review,
policy history, the decision-evidence explorer, `strict-dynamic`, Trusted
Types, multi-surface scan, and analytics export) - anything not on that list
falls through to `is_pro()`, which is unconditionally `false` when no
`Entitlement_Store` is present, i.e. in both public builds.

**Entitlement failure behaviour.** An entitlement-check failure never
disables already-configured headers, policies, script/style integrity
classifications, or certificates - it only ever affects whether the single
Fully Automatic mode is available going forward.

**VCNS-hosted control plane.** Not yet built as of this document. A design
exists (`docs/checkout-proxy-design.md`) covering Stripe Checkout, webhook
verification, signed entitlement issuance, site-specific activation,
revocation, grace periods, and key rotation - explicitly marked
unimplemented. No customer installation may contain a VCNS-owned Stripe
secret; this is a release blocker for enabling the commercial service (not
for a free-channel release, since commercial code is already excluded from
both public builds).

---

## 12. Privacy and Data Handling

The plugin keeps operational data local to WordPress by default across all
three product areas.

| Data | Storage | Encrypted | External recipient |
|---|---|---|---|
| CSP violation reports | Local DB | No | None by default |
| COOP/COEP violation reports | Local DB (`sam_pillar_violation_reports`) | No | None |
| Source/dependency/hash inventory | Local DB | No | None |
| Policy versions, decisions, audit log | Local DB | No | None |
| DNS-provider / cPanel credentials | Local DB | Yes (credential vault) | The configured provider's own API, only during issuance/renewal |
| ACME account keys, certificate private keys | Local DB | Yes (credential vault) | Never transmitted outside this site except signed ACME requests to the configured CA |
| Issued certificates (public material) | Local DB + deployed to web server/cPanel | N/A (public) | The deployment target only |

No telemetry or background tracking is part of normal plugin runtime in
either public build. See `docs/data-protection-and-retention.md` for
retention periods, deletion mechanics, and export/uninstall behaviour in
full - this section is a summary, that document is authoritative for
retention specifics.

---

## 13. Operational Resilience

**Fail-open design.** The `Content_Rewriter` envelope shared by script/style
integrity and Reverse Tabnabbing Protection fails open on any uncertainty -
a page is served unmodified rather than risk corrupting output.

**Conflict detection.** CSP conflict detection covers competing headers
from `.htaccess`, server config, or other security-header plugins.

**Certificate failure handling.** See §7 - every failure is audit-logged; a
failed order/renewal does not retry until the next scheduled cycle; no
separate notification channel exists yet beyond the audit log and
admin-visible status.

**Reset and recovery.** The Recovery admin view offers an authenticated
reset that clears all plugin data (every pillar, not just CSP) and disables
header emission until rollout is deliberately restarted.

**Schema-downgrade protection and configuration rollback (`Rollback_Guard`,
schema v23).** A plugin cannot swap its own PHP files back to an older
release from inside a running request -- that happens at the
WordPress/hosting level, outside any plugin's control. What this class
provides instead: (1) on every boot, `Plugin::maybe_upgrade_db()` checks
whether the installed database schema is *ahead* of the running code's
`WP_SAM_DB_VERSION` -- the state produced when older plugin code is
installed over a site a newer version already migrated -- and if so,
refuses to run `Activator::activate()` at all (its `dbDelta()` calls only
know how to add columns/tables, never remove ones a newer schema added,
and several of its migration functions assume they're moving a site
forward), instead recording a persistent admin notice and an audit-log
entry; (2) immediately before every forward migration, it snapshots every
row of the config-state tables (policy profiles, source/hash approvals,
other pillar profiles, dependency classifications, certificate records --
explicitly never the audit log or other append-only/log-shaped tables,
which need no snapshot because nothing ever overwrites them) into a
bounded (last 5) history; (3) an administrator can restore a snapshot from
the Recovery tab, but only when the running code's schema still matches
exactly what the snapshot was taken for -- restoring across a schema
change is refused with a clear reason rather than attempted partially.
This covers a migration whose *data* effects turn out to be unwanted while
staying on current code; it does not cover restoring older plugin code
itself, which remains a manual process (`docs/rollback-and-recovery.md`).

**Cross-site configuration export/import (`Config_Portability`).** Distinct
from `Rollback_Guard`'s snapshot/restore above -- that is same-site,
same-exact-schema-version only, and exists to undo a migration's data
effects. `Config_Portability` moves administrator-authored configuration
(policy profiles, source/hash approvals, other pillar profiles, dependency
classifications, non-secret certificate settings, and automation/reporting
options) between sites, or archives it outside the database entirely, and
is schema-version-independent within reason. Export and import are both
allowlist-based on both table and option names: neither will ever touch a
table or option outside its declared list, and import treats every key in
an uploaded file as untrusted, writing only what was already on the
allowlist regardless of what else the file contains. Never included:
secrets, credentials, private key material (`Certificate_Store::
SECRET_FIELDS`, stripped on export and never written by import), the audit
log, or any other log/ledger-shaped table. Available from the Recovery tab.

**Known limitations.** No release-verification test suite covering every
named scenario runs against a real WordPress instance yet (partial
coverage exists -- see `docs/testing-requirements.md`). Rollback support
covers configuration-state data only, not certificate private keys' or
credentials' *decryptability* across a vault-key change (see
`docs/credential-vault-assessment.md` for that specific, separate risk) or
the plugin's own code version. `docs/consolidation-ledger.md` tracks
remaining gaps.

---

## 14. Known Limitations

Consolidated from the sections above, plus items that don't belong to one
specific domain:

- No WordPress Multisite support (network-admin awareness untested and
  unimplemented).
- No WP-CLI commands.
- No configuration-as-code import/export.
- No generalised security posture score - only a per-source CSP risk badge
  exists (5 levels), not a whole-site score.
- No generalised policy/configuration drift detection beyond the two
  targeted mechanisms that do exist and are considered stable: Subresource
  Integrity drift detection, and competing-CSP-header detection (§4).
- No compliance evidence pack export.
- No time-bound exceptions with expiry/review workflow.
- No fleet/multi-site management.
- No SIEM/webhook-out integrations (the existing webhook setting is an
  *inbound* Stripe receiver for the offline-only commercial build, not
  outbound SIEM delivery).
- Certificate DNS-provider drivers are tested at the registry level only,
  not per-provider request-logic level, as of this document.
- No rollback mechanism for plugin releases.
- No release-verification test suite runs against a real WordPress
  instance.
- Every request is observed and classified by surface (frontend/admin/
  login/api) as a framework-level foundation for future traffic
  intelligence, but no detector is registered against it yet -- the
  Continuous Intelligence admin page and its underlying event table are
  present and empty in every build. Nothing is written to that table, and
  no request metadata (IP, user agent, path) is retained anywhere, until a
  detector exists to evaluate it.

This list is deliberately conservative - a capability not listed as a
limitation elsewhere in this document and not listed here should be assumed
implemented, not assumed absent; open a documentation-drift issue if you
find a gap in that assumption.

---

## Keeping this document honest

The version/schema numbers in the front matter above are checked by
`test/unit/VersionConsistencyTest.php`, extended alongside this document to
assert this file's declared `DB schema alignment` matches the live
`WP_SAM_DB_VERSION` constant, in addition to the version-string checks it
already performed. A mismatch fails CI on any PR that bumps the schema
without updating this document. See `docs/consolidation-ledger.md` for the
older SPECIFICATION.md-was-5-generations-stale incident this check exists to
prevent from recurring.
