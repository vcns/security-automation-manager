# VCNS Security Automation Manager
## Phase 4 Development Plan

**Product:** VCNS Security Automation Manager
**Repository:** `vcns/security-automation-manager`
**Phase:** 4
**Baseline:** v2.9.44 (Phase 4A delivered through v2.9.47)
**Status:** Draft for sign-off; Phase 4A delivered, Phase 4B in progress
**Date:** 2 September 2026

---

# 1. Why This Document Exists

Three roadmap-numbering schemes have accumulated in this project, and they were never reconciled with each other:

- **`docs/consolidation-ledger.md`**'s "Phase 0-6" scheme (issue-label based, written 2026-08-18). Its own "Phase 4" means *posture, drift, evidence, resilience* -- unrelated numbering to what follows here, and now visibly stale after the 2026-09-02 GitHub issue audit closed or rewrote 19 of the 38 issues it covers.
- A phantom **`roadmap-spec.md`**, never committed to this repository, cited by "Section N" in roughly 15 still-open GitHub issues. Confirmed absent from the entire git history on every branch.
- **`.roadmap/phase3_early_plan.md`** (this document's predecessor), which substantially delivered what several of those Section-N issues asked for, under entirely different section numbers nobody cross-referenced until the 2026-09-02 audit.

**Going forward: `.roadmap/` is the living, authoritative roadmap for this product.** `docs/consolidation-ledger.md` is retired as a planning document -- it remains a valid historical audit of its own date, not something to keep patching. "Phase 4" in this document means *the next slice of `.roadmap/phase3_early_plan.md`'s own numbering*, successor to that document's Phase 3A-3J, not `docs/consolidation-ledger.md`'s unrelated "Phase 4."

This document assumes `.roadmap/phase3_early_plan.md`'s §1-3 (Purpose, Product Model, Operational Lifecycle), §28-34 (UX, Explainability, Default-Safety, Architecture, Testing, Performance, Privacy), and §36/§38 (Non-Goals, Strategic Outcome) as still-authoritative living principles. They are not repeated here.

---

# 2. Where Phase 3 Actually Landed

Full detail lives in `.roadmap/phase3_early_plan.md`'s per-section status notes (added 2026-09-02) and its Definition of Done (§37: **13 of 15 criteria met**). Summary:

- **Delivered:** identity/scanner intelligence, per-surface traffic controls (IP/CIDR only), baseline and drift, change attribution, security change windows, campaign detection (one signal), deception/honey paths, partial integrity monitoring (2 of 9 signals), site security health, evidence export (JSON), 10 of 13 detector families, the full Observe/Decide/Control/Verify admin IA.
- **Deferred by explicit product decision** (2026-09-02, not oversight): external verification (3G) and federated intelligence (3H) -- both depend on central VCNS-operated infrastructure that doesn't exist yet.
- **Real remaining work**, identified by the same 2026-09-02 audit: this is what Phase 4 is built from.

---

# 3. Phase 4 Scope

## Phase 4A: Traffic Intelligence Data Sourcing

**Status: Delivered, v2.9.45-v2.9.47 (2 September 2026).** All three increments shipped sequentially, each through the full schema-bump/class/admin-UI/tests/lint/live-Docker-verification/release cycle, following the provider decisions below.

**Addresses:** `.roadmap/phase3_early_plan.md` §13.4 (Geo-IP), §13.5 (ASN), §13.6 (Tor Awareness), §8's missing ASN identity field, §31's missing `Network_Intelligence_Resolver`.

**Provider decisions made:** Tor Project's official bulk exit-node list (`torbulkexitlist`) for §13.6, daily-refreshed. Team Cymru DNS (`origin.asn.cymru.com` / `asn.cymru.com`) for §13.5 ASN lookups -- no API key required. IPinfo (`ipinfo.io`) live API, customer-supplied token, for §13.4 Geo-IP -- MaxMind was scoped (product decision: BYO-credentials option to "upgrade" Geo-IP quality) but its free tier has no live-lookup API, only a downloadable MMDB binary requiring either a new Composer production dependency or a hand-rolled binary parser; both were weighed against this product's zero-production-dependency architecture and the decision was to skip MaxMind entirely and ship IPinfo only.

- `includes/intelligence/class-tor-exit-list-store.php` (`Tor_Exit_List_Store`, v2.9.45, PR #325) -- daily-refreshed exit-node table, wholesale-replace on a plausibility-checked successful fetch, never touched on failure.
- `includes/intelligence/class-asn-lookup-store.php` (`Asn_Lookup_Store`, v2.9.46, PR #326) -- Team Cymru two-step DNS TXT lookup, 30-day cache including negative results.
- `includes/intelligence/class-geo-ip-store.php` (`Geo_Ip_Store`, v2.9.47, PR #327) -- opt-in, customer-supplied IPinfo token sealed via `WP_SAM\Certificates\Credential_Vault`, 30-day cache including negative results.
- `includes/intelligence/class-network-intelligence-resolver.php` (`Network_Intelligence_Resolver`) -- merges all three into one `resolve(string $ip): array` call, wired into `includes/intelligence/class-request-observer.php` as a lazy enrichment (only resolved when some other detector already produced a finding, per §33 Performance Requirements) that adds `is_tor_exit`/`asn`/`asn_org`/`geo_country`/`geo_region`/`geo_city` to `Event_Store` evidence. Pure Observe -- no default blocking, matching §30's Default-Safety Requirements.

**Exit criteria -- all met:**
- ~~A verified data source is selected and its licensing confirmed compatible with this product's distribution model.~~ Done (see provider decisions above).
- ~~Geo-IP/ASN/Tor identification is available as evidence (§3.1 Observe) with no default blocking, per `.roadmap/phase3_early_plan.md` §30's Default-Safety Requirements.~~ Done.
- **Not done, carried forward:** §8's identity record does not yet gain a persisted ASN field on the identity record itself (ASN is resolved and recorded in `Event_Store` evidence per-request, not yet merged into `Scanner_Identity_Store`'s identity model).
- **Not done, carried forward:** §13.1/§13.3's rate-limiting and firewalling dimensions do not yet extend to subnet/ASN/country -- `Traffic_Guard` remains generic rate/IP-based. This is exactly what Phase 4B's control-action framework is for; §13.3's "firewalling by detector family" and network-intelligence-aware controls are explicitly in Phase 4B's scope below.

## Phase 4B: Remaining Detector Families and Control-Action Wiring

**Status: Delivered, v2.9.48-v2.9.53 (2-3 September 2026). All 13 detector families, the control-action framework, and §12 method classification are shipped.**

**Addresses:** `.roadmap/phase3_early_plan.md` §11.4 (HTML Injection), §11.6 (PHP/PHPUnit Probes), §11.13 (Legacy WordPress Endpoints/XML-RPC), the missing "allowed control actions / default action" field on the shared detector metadata contract, and §12 (HTTP Method Intelligence).

- `Detector::allowed_control_actions()` / `default_control_action()` (v2.9.48, PR #329) -- every detector declares which control actions it may trigger and a default, both defaulting to observation-only. `Detector_Policy_Store` (new `sam_detector_policies` table, schema v34) holds an optional per-detector admin override (enabled/disabled, chosen action, validated against that detector's own allowed set). `Detector_Engine` skips a disabled detector and embeds the resolved `control_action` on every Finding; `Request_Observer` calls the existing `Traffic_Block_Store::record_violation()` (the same call login-brute-force protection already uses) when that action is `enforce` -- no new blocking path, still gated behind each surface's existing Observe/Enforce mode. New "Detectors" tab on the Traffic Controls admin page.
- §11.4 HTML Injection (v2.9.49, PR #330) -- `Html_Injection_Detector`, 11th core family. Requires actual tag-open syntax or a `javascript:` scheme, never a bare `<`. First detector to declare itself enforce-capable, per §11.4's own "unless the endpoint is known not to accept HTML" guidance.
- §11.6 PHP/PHPUnit Probes (v2.9.50, PR #331) -- `Php_Probe_Detector`, 12th core family. Specific, versioned vulnerability signatures (PHPUnit `eval-stdin.php` RCE/CVE-2017-9841, Laravel Ignition RCE/CVE-2021-3129, php-cgi argument injection/CVE-2012-1823, exposed `phpinfo()`, Symfony profiler) -- kept non-overlapping with the existing `Script_Webshell_Probe_Detector` (§11.5) and `Vulnerability_Probe_Detector` (§11.12) rulesets.
- §11.13 Legacy WordPress Endpoints (v2.9.51, PR #332) -- `Legacy_Endpoint_Detector`, 13th and final core family. `xmlrpc.php`, `wp-trackback.php`, `wp-app.php`. Per §11.13's own "must be configurable rather than assumed universally safe to block," the second detector (after HTML Injection) to be enforce-capable. **All 13 detector families from §11 are now registered.**
- Also fixed alongside the Legacy Endpoints increment, found live in Docker rather than by the test suite: `Request_Observer` now also hooks `init` (priority 20) -- `xmlrpc.php`/`wp-cron.php` bootstrap WordPress directly via `wp-load.php` and never fire `send_headers`, so they were structurally invisible to every detector until this fix, not just the new one.
- §12 HTTP Method Intelligence (v2.9.53) -- `Http_Method_Detector` classifies OPTIONS requests (`cors_preflight` when both `Origin` and `Access-Control-Request-Method` are present, per the Fetch/CORS spec; `unclassified_options` otherwise, since §12 itself lists legitimate API-discovery tooling and reconnaissance as both real possibilities headers alone can't distinguish). Implements `Detector` directly (no regex pattern) and is registered alongside `Honeypath_Detector`, outside `register_defaults()`, since §12 isn't one of §11's 13 named families. Enforce-capable, defaults to observe.

**Exit criteria -- all met:**
- ~~All 13 detector families from §11 are registered, each with the full test-fixture set §32 requires (positive/negative/encoded-variant/benign-lookalike/surface-applicability/action-eligibility/confidence/false-positive-regression).~~ Done.
- ~~A detector's Finding can carry a control-action recommendation that `Traffic_Guard` can act on, still gated behind the same observe-by-default posture every other control in this product uses.~~ Done.
- ~~§12's method classification (OPTIONS-as-CORS-preflight vs. reconnaissance, per §12's own worked example) is implemented on top of already-captured method data.~~ Done.

## Phase 4C: Bot, Crawler, and Scraper Classification

**Status: In progress, eight increments delivered v2.9.52-v2.9.58 plus v2.9.66 (2-4 September 2026). Both named exit criteria fully met. All of §10's remaining signal list is now covered except cross-site intelligence (explicitly deferred) and a broader session/cookie-persistence test (a privacy/product decision, not something to build without sign-off). v2.9.66 (Custom Rules) is a user-requested extension beyond §10's own original scope, not part of the exit criteria.**

**Addresses:** `.roadmap/phase3_early_plan.md` §10.

**Confirmed status:** the identity-matching substrate (§8, §9) this depends on is fully delivered.

- AI-crawler identity seeding (v2.9.52) -- `Activator::seed_default_scanner_vendors()` extended with GPTBot (OpenAI), ClaudeBot (Anthropic), CCBot (Common Crawl), and PerplexityBot, verified against each vendor's own current published documentation (fetched live, not fabricated): CCBot by forward-confirmed reverse DNS (matching Googlebot/Bingbot exactly); the other three by their vendor's published IP-range JSON (`verification_method = 'cidr'`, `cidr_ranges` shipped empty -- never a guessed range -- with the source URL so an admin can add current ranges via the existing Scanner Vendors form). Reuses the existing `known_crawler` category end to end. Schema v35 (no new table, bumped only so the idempotent seed re-runs on an already-upgraded site).
- Bot/crawler classification (v2.9.54) -- `Bot_Classifier` combines identity (`Identity_Resolver`'s verification_state + network_match) and request-rate (`Traffic_Block_Store`'s existing escalation stage) signals into six states, avoiding the binary "bot/not bot" model: an admin decision always wins; else a recognised vendor splits into `verified_crawler` vs. `claimed_crawler_unverified` (§10's "impersonated crawlers"); else an unrecognised source splits into `aggressive_unidentified` vs. `unclassified`. Pure and read-only, surfaced on the Identities admin tab.
- Robots.txt visit recognition (v2.9.55) -- `Robots_Txt_Detector` records a source examining `/robots.txt` as low-severity, positive-leaning evidence, correlatable by IP.
- Session/cookie behaviour, first piece (v2.9.56) -- `Login_Cookie_Consistency_Detector` records a login POST missing WordPress core's own `wordpress_test_cookie`, consistent with scripted credential stuffing bypassing the normal form load.
- Header consistency (v2.9.56) -- `Header_Consistency_Detector` records a browser-claiming User-Agent (matched narrowly on each browser's own version token) sent without an `Accept-Language` header.
- URI-pattern signal (v2.9.57) -- `Scanner_Identity_Store` now logs each identity's last 10 request paths (`recent_paths`, schema v36); new `Uri_Pattern_Analyzer` recognises a fixed-step sequential-ID pattern across them (e.g. `/product/101..104`). `Bot_Classifier` checks this for an unrecognised source ahead of its rate-escalation check -- new `enumerating_scraper` state. A known vendor's path history is never checked this way (crawling a site's posts is normal crawler behaviour). This closes out all three signals §10's exit criteria named.
- Robots.txt disallow-rule compliance (v2.9.58) -- `Robots_Rules_Store` fetches this site's own `/robots.txt` over real HTTP the same way any real crawler would (rather than reimplementing WordPress core's `do_robots()`/`robots_txt`-filter resolution), refreshed daily. `Robots_Compliance_Detector` records a source already recognised as a known crawler/scanner vendor requesting a path it disallows -- an ordinary unrecognised visitor is never evaluated, since robots.txt is a voluntary convention for automated crawlers. Completes the robots.txt behaviour signal. Required reordering `Request_Observer` so identity resolution runs before detector evaluation (purely additive -- proven by the full existing test suite passing unchanged).
- **Custom Rules (v2.9.66, user-requested extension)** -- a fail2ban-style custom regex detection feature, requested alongside "do more with bot/crawler detection." New `Custom_Rule_Store`/`Custom_Rule_Detector` (`Custom_Rule_Detector extends Pattern_Detector`, one instance per stored row) let an administrator define their own regex rule (matched against the request URI, path, query string, or User-Agent) that flows through the exact same `Detector_Registry`/`Detector_Policy_Store`/`Detector_Engine`/`Traffic_Block_Store` pipeline every built-in §11 family already uses -- a saved rule shows up automatically on the existing Detectors tab with zero admin-UI changes needed there. New "Custom Rules" tab on Traffic Controls (list/add/edit/delete plus a "Test a pattern" tool). Confirmed live in Docker end-to-end: registration, real-request matching, evidence recording, and enforce-mode feeding the progressive-response ladder all work correctly.

**Exit criteria -- both met:**
- ~~At minimum, AI-crawler identities are seeded into `Scanner_Vendor_Store` the same way Googlebot/Bingbot are today -- forward-confirmed-reverse-DNS-verifiable identities only, not fabricated ranges (same rule §9's audit already established).~~ Done.
- ~~Bot classification avoiding the binary "bot/not bot" model §10 explicitly warns against, combining at least request-rate, URI-pattern, and identity signals already available from delivered work.~~ Done -- all three signals combined in `Bot_Classifier`.
- Cross-site intelligence signal explicitly deferred -- depends on §23 (Federated Intelligence), itself deferred.

**Not done, carried forward:**
- A broader, site-wide session/cookie-persistence test beyond the login-specific piece already shipped -- would need this plugin to set its own first-party cookie for every visitor. A genuine privacy/product decision (is a security-purpose-only cookie worth the consent-posture question it raises), not something to build without explicit sign-off.
- Timing and repeated-error correlation (§10's own signal list names these; neither built -- both would need new time-series tracking per source, not just another detector).

## Phase 4D: Documentation and Technical Debt Closeout

**Status: Delivered. All 8 issues (#162, #163, #167, #168, #169, #170, #220, #221) closed, v2.9.59-v2.9.65 (3-4 September 2026).**

**Addresses:** GitHub issues #162, #163, #167, #168, #169, #170, #220, #221 -- all confirmed still accurately open by the 2026-09-02 audit, none touched by anything in Phase 3.

| Issue | What it needs |
|---|---|
| #162 | ~~Full security-controls inventory doc -- 12-field-per-control format, doesn't exist yet~~ **Delivered, v2.9.64.** |
| #163 | ~~Extend `VersionConsistencyTest.php`-style automated checks to SECURITY.md, COMMERCIAL_TERMS.md, and the remaining `docs/*` files not yet covered~~ **Delivered, v2.9.65.** |
| #167 | ~~Per-table pagination regression tests beyond the shared `Table_Query` helper's own test~~ **Delivered, v2.9.63 -- also fixed a real bug the new coverage found (External Scripts table never capped an out-of-range page).** |
| #168 | ~~Reorder `test/bootstrap.php` so the autoloader and `NonceBridge.php` aren't ~1043 lines apart; remove the `offline/` fallback dependency from tests~~ **Already closed on GitHub (2026-09-02), completed prior to this phase's own tracking catching up -- no remaining work.** |
| #169 | ~~Extend the `wpdb::prepare()` test stub beyond `%s`/`%d`/`%%`~~ **Delivered, v2.9.61.** |
| #170 | ~~Give `Policy_Builder`'s data-loading methods a real dependency boundary instead of `protected` subclass-extension methods~~ **Delivered, v2.9.62.** |
| #220 | ~~Information-masking admin section (Server/X-Powered-By/version-header suppression) -- zero implementation~~ **Delivered, v2.9.59.** |
| #221 | ~~Session & cache-control admin section with competing-mechanism detection -- zero implementation~~ **Delivered, v2.9.60 (Cache-Control only -- see note below on scope).** |

This is deliberately grouped as one phase: none of these individually justify their own phase, but they're real, unambiguous, low-risk work worth clearing in one pass rather than letting them accumulate further.

- #220 Information Masking (v2.9.59) -- `Information_Masking_Builder` (new `Pillar_Header_Builder` subclass) removes `X-Powered-By`, `Server`, and `X-Pingback` on every enabled surface. Resolved the issue's own open questions: "hostname masking" means `X-Pingback` (discloses this site's own `xmlrpc.php` URL); the full target header list is `X-Powered-By`/`Server`/`X-Pingback` only -- `X-Generator` was confirmed live to be feed-body content (a `<generator>` element via the `the_generator` filter), never an actual HTTP header, so it's out of scope for this header-only pillar; `Server`'s host-dependent technical ceiling is resolved as documented best-effort (option (a) from the issue) rather than scoped out entirely, backed by `Information_Masking_Diagnostic`'s live self-probe against the site's own front page so a host where `header_remove('Server')` doesn't take effect is visible rather than silently assumed to work. No schema change -- reuses `sam_pillar_profiles`'s existing per-pillar row shape (13th pillar in `Pillar_Registry`).
- #221 Cache-Control (v2.9.60) -- scoped to Cache-Control specifically: the issue's title says "Session & Cache Control," but its body, context, and every acceptance criterion discuss Cache-Control only -- nothing session/cookie-related was specified, so nothing session-related was built, and this closes the issue as delivered against what it actually asked for. `Cache_Control_Builder` offers a small named-preset value per surface (`no-store`/`private-no-cache`/`public-short`/`public-long`) rather than a free-form directive builder, since Cache-Control directives interact (`public`/`private` are mutually exclusive) and a preset can't express a contradictory combination. Seeded `enabled => 0` on every surface, unlike every other simple pillar -- a deliberate exception, since this is a performance/behaviour decision, not a universal security default, and WordPress core already sends its own strict Cache-Control wherever one is needed. `Cache_Control_Conflict_Detector` implements the issue's own explicit safety requirement ("must be disabled/grayed out rather than emit a competing header"): a known caching plugin (9 verified live, extensible list) or an admin-acknowledged CDN always wins over a stored `enabled=1` row -- confirmed live that acknowledging a CDN silently stops emission even with the row still enabled. No schema change -- 14th pillar in `Pillar_Registry`.
- #169 `wpdb::prepare()` test stub (v2.9.61) -- `wpdb_stub::prepare()` (`test/bootstrap.php`) now mirrors real WordPress `wpdb::prepare()` (confirmed against current core source): added `%f`/`%i` support, an argument-count mismatch now returns `null` exactly like real WordPress (confirmed via a full test-suite run that no existing call site anywhere in this codebase was relying on the old lenient behaviour), and the single-array-argument backward-compat calling convention real `wpdb::prepare()` also accepts. Deliberately skips positional (`%1$s`)/width-precision (`%05d`) syntax -- confirmed via full codebase grep that nothing here uses either. Test-infrastructure only; no production code changed.
- #170 `Policy_Builder` dependency boundary (v2.9.62) -- `load_profile()`/`load_approved_hashes()`/`load_approved_sources()` were `protected` methods on `Policy_Builder` itself, a de facto subclass extension point for a security-sensitive header-emitting class (this codebase's own tests were already exploiting it, with two different, coexisting seams for the same job). Replaced with an explicit `Policy_Data_Loader` interface plus `Wpdb_Policy_Data_Loader`'s real implementation (query logic relocated verbatim), constructor-injected into `Policy_Builder` and defaulting to the real loader in production. `load_approved_hashes()`/`load_approved_sources()` are now `private`; `load_profile()` stays `protected` only because `Header_Builder`'s own abstract contract requires it, but is now `final`. Tests inject a `Policy_Data_Loader` implementation (new shared `test/unit/Stub_Policy_Data_Loader.php`) instead of subclassing `Policy_Builder`. Confirmed live in Docker: CSP headers (nonces, hashes, sources, every directive) emit exactly as before -- no behaviour change, internal architecture only.
- #167 per-table pagination regression tests (v2.9.63) -- all 7 `Table_Query`-driven admin tables now have real-view-render regression coverage (out-of-range page caps, filter survival across a page change, empty-result handling); `page-csp-dashboard.php` and `page-intelligence.php` had never been directly rendered by any test before. Writing that coverage found a genuine bug: the External Scripts table (`scripts-external.php`) floored its page number at 1 but never capped it at the real last page, unlike every other paginated table in this codebase -- `?ext_paged=9999` against a 3-page list rendered "Page 9999 of 3" instead of the real last page. Fixed to match the same clamp pattern (`min(max(1, $page), $pages)`) every other table already used.
- #162 security-controls inventory (v2.9.64) -- new `docs/security-controls-inventory.md`, all 19 implemented controls (the issue's own 17 plus Information Masking and Cache-Control, shipped after the issue was written), each field grounded directly in the current codebase. Surfaced several non-obvious findings while grounding it in real behaviour rather than assumption: Reverse Tabnabbing Protection and External Script Integrity share `Content_Rewriter`'s exclusion gate, so their `admin`/`login`/`api` configuration rows exist but are never actually live -- only the `frontend` row has an observable effect, undocumented anywhere the admin UI would surface it; across every simple pillar, saving a config change never writes an audit-log entry (confirmed by grepping every `Audit_Log`/`->log()` call site); and Trusted Types' own code comment claiming "always report-only regardless of surface mode" does not match `build_policy_string()`'s actual behaviour on an enforce-mode surface -- corrected the comment itself (documentation-only fix, no behaviour change) rather than silently repeating a false claim in the new inventory doc. Whether to build the always-report-only behaviour the old comment promised is flagged as an open product decision, not resolved here.
- #163 documentation consistency (v2.9.65, narrowed scope per the issue's own 2026-09-02 status comment) -- reviewed and corrected drift in the 9 remaining files: `SECURITY.md` named a specific stale release line (replaced with an evergreen "latest version only" policy); `COMMERCIAL_TERMS.md` still used the plugin's pre-rename name "CSP Automation Manager"; `docs/architecture.md` and `docs/testing-and-quality.md` still referenced pre-schema-v9 `wp_csp_*`/`csp_*` identifiers (plus a stale automation-default claim `docs/testing-and-quality.md` made); `docs/database-schema.md`'s version table stopped at v12 while the code had reached v36 -- backfilled v13 through v36. `docs/release-and-publishing.md`, `docs/user-guide.html`, `docs/faq.html` were reviewed and found already accurate, no changes needed. Added 6 new automated checks to `VersionConsistencyTest.php` covering schema-doc version, WP/PHP requirement wording, subscription price, manifest URL, product name, and a regression guard against reintroducing pre-v9 identifiers -- so this class of drift is now caught by CI, not found by manual audit again.

**Phase 4D is now fully delivered -- all 8 issues closed.**

## Phase 4E: Commercial Product Boundary and the SAM Portal

**Addresses:** `.roadmap/phase3_early_plan.md` §25 (Commercial Product Boundary, real remaining work), GitHub #172 (closed 2026-09-02, redirected here), #173 (closed, schema shipped), #174 (grace-period entitlement logic, still open), and `docs/sam-portal-requirements-spec.md` (new, 2026-09-02).

This is the phase most directly shaped by the commercial-direction shift: the product owner confirmed 2026-09-02 that the project is moving from MVP into a real commercial release cadence (the same conversation that produced the two-stage branch policy in `pr-branch-policy.yml`). Two related but distinct tracks:

**4E.1 -- Tier packaging design** (§25 proper): decide what capability actually maps to Community / Professional / Managed. Currently moot for most of Professional/Managed's candidate list, since most of it (advanced detector packs, extended Geo-IP/ASN policy, deeper integrity monitoring, federated intelligence, fleet posture) is itself still Phase 4A/4C/deferred-3G/3H/deferred-3-27 work. Recommend sequencing this *after* enough of 4A-4C exists to make the tier boundaries mean something concrete, not before.

**4E.2 -- SAM Portal build** (`docs/sam-portal-requirements-spec.md`): a new, separate repository (Cloudflare Worker) handling checkout and license-key issuance/validation, replacing the interim direct-Stripe-in-plugin implementation currently in `includes/extensions/fully-automatic-mode.php`. Five open decisions block implementation start (spec §14): domain/repo naming, license-key site-binding policy, whether `/buy` needs its own hosted page, migration-window length, and admin-lookup authentication. GitHub #174's grace-period requirement is directly specified as part of this track (spec §10.2) -- building the portal integration is what actually closes #174, not a separate effort.

**Exit criteria:**
- Every open decision in `docs/sam-portal-requirements-spec.md` §14 has an explicit answer.
- No Stripe secret exists in any customer WordPress database or in this repository, in any form (matching the design goal `docs/checkout-proxy-design.md` stated from the start).
- GitHub #174 is closed with working grace-period behaviour, not just schema.

## Phase 4F: Recommendations Engine

**Addresses:** `.roadmap/phase3_early_plan.md` §22.

**Confirmed status:** zero implementation, confirmed by direct grep. Nothing to build on beyond the general evidence infrastructure (`Security_Health`, `Evidence_Exporter`) this would need to draw from.

Lowest priority in this document, deliberately -- §22's own text and the original Phase 3J framing both suggest recommendation-quality work benefits from more operational data existing first (more detector families live, more traffic-control dimensions live, more real drift/campaign history accumulated). Revisit sequencing once Phase 4A-4C have shipped and there's real evidence to recommend against.

## Phase 4G: UI Documentation Retrofit and Guided Onboarding

**Status: In progress. First increment (Settings/Overview page) delivered v2.9.67 (4 September 2026).**

**Addresses:** a direct user request, not tied to any numbered section in `.roadmap/phase3_early_plan.md` -- the admin UI covers a subject area "few technicians know the full domain of, and even more people know absolutely nothing about at all," and needs UI text that actually teaches, not just labels. User confirmed via clarifying question: retrofit existing pages first, then build a separate guided onboarding/getting-started flow.

- Settings/Overview page (v2.9.67) -- `includes/admin/views/page-overview.php`'s Overview, Readiness, and Security Health tabs gained explainer paragraphs: a framing paragraph for the five-layer model, one paragraph per layer (what it covers, why it matters, how it relates to the layers around it), and short intros for the Readiness and Security Health tabs explaining what their checks are actually for. Established the voice for the rest of this retrofit: concrete stakes over jargon-dropping (e.g. explain what deterministic automation buys an administrator, not just name it), matching the tone already used successfully in the existing About tab and the X-Frame-Options/Referrer-Policy pillar intros -- both used as a reference rather than invented from scratch. No behaviour change, `<p class="description">` copy only, confirmed live in Docker across all three tabs.
- Plugins-list "Settings" link fix (v2.9.68) -- discovered while reviewing this work: `Admin_UI::add_plugin_action_links()`'s Settings link pointed at the CSP dashboard's own Settings tab instead of the new Settings/Overview landing page. Fixed to match the top-level admin menu's own first entry, also labelled "Settings."
- CSP Dashboard (v2.9.69) -- `includes/admin/views/page-csp-dashboard.php`'s Profiles, For Review (Sources), Policy Audit, Violations, Scan Log, and Settings tabs each gained an explainer paragraph. Start Here already had this level of detail from earlier work and was left unchanged.
- **Also user-requested alongside this track:** bring the same treatment to the public GitHub Pages help site (`docs/index.html`, `docs/user-guide.html`, `docs/faq.html`, `docs/operating-model.html`, published as-is via `.github/workflows/pages.yml`). A background-agent assessment (2026-09-04) found `docs/user-guide.html` already close to the target voice in several sections (STS-is-sticky callout, COOP/COEP breakage warning, Reverse Tabnabbing phishing explanation), but the whole site never once explains what CSP actually defends against (no mention of "cross-site scripting"/"XSS" anywhere) -- the single biggest missing hook. `docs/faq.html`'s ~50 answers are accurate but terse reference-manual prose, not explanations. `docs/operating-model.html` is intentionally thin (a diagram) and needs no rewrite. **Caution for whoever does this:** `test/unit/VersionConsistencyTest.php` asserts exact substrings in `user-guide.html` and `faq.html` (WP/PHP minimum-version wording, the `£X.XX/month or £Y.YY/year` subscription price) -- check that test file before rewording near those spots. Recommended starting point: `docs/index.html`'s `#start-here` intro and `#pillars` card grid, mirroring how the admin retrofit started with the single highest-traffic page.

**Remaining admin pages, not yet started** (rough order):
- Traffic Controls (`page-traffic.php`) -- Policy, IP Rules, Blocks, Network Intelligence, Detectors, Custom Rules tabs.
- The 14 pillar pages -- both the shared `page-pillar-simple.php` template's per-pillar `$intro_html` (set in `Admin_UI`'s `render_*` methods, several already reasonably detailed) and the dedicated pillar view files (HSTS, Cross-Origin, Reverse Tabnabbing, Cache-Control, Permissions-Policy, Information Masking, Scripts internal/external).
- Continuous Intelligence (`page-intelligence.php`), Baseline & Drift (`page-baseline.php`), Certificates (`page-certificates.php`).

**Not started:** the GitHub Pages help site retrofit (assessed, not yet written -- see above) and the guided onboarding/getting-started flow (deliberately sequenced after the admin-UI retrofit) -- no design work done yet on the latter.

---

# 4. Explicitly Not In Scope for Phase 4

Carried forward, unchanged, from `.roadmap/phase3_early_plan.md` and the 2026-09-02 GitHub issue audit -- listed here so "not mentioned" doesn't get misread as "forgotten":

- **External Verification** (§20, Phase 3G) and **Federated Intelligence** (§23-24, Phase 3H) -- still deferred, same reason as before (no central service infrastructure exists).
- **Fleet Management** (§27, GitHub #186-190) -- still deferred pending real-world operational validation, per the original document's own explicit instruction not to overbuild this before evidence exists.
- **Time-bound exceptions** (GitHub #177) -- no unified exception-record concept exists; genuinely not started, no urgency signal from this audit.
- **WP-CLI support** (GitHub #184), **webhook/SIEM integrations** (GitHub #183) -- both confirmed still zero-implementation, both still correctly deferred.
- **Safe policy simulation / promotion gates** (GitHub #179) -- `Policy_Change_Manager` still only builds proposal records; no diff-preview UI or promotion gates. Confirmed unchanged, not part of this phase.
- **DNS-01 provider setup guidance** (GitHub #291) -- accurately scoped as-is, explicitly deferred until after WordPress.org resubmission work settles; unrelated to this phase's scope.

---

# 5. Sequencing Recommendation

Not a commitment, a starting proposal -- reorder freely:

1. **4D (Documentation and Technical Debt Closeout) first.** Lowest risk, no dependencies, clears real accumulated debt before it compounds further. Can run in parallel with anything else.
2. **4E.2 (SAM Portal build) second**, given the explicit commercial-direction shift and that GitHub #172's closure already named this as the intended near-term direction. The five open decisions in the portal spec should be resolved before implementation starts, but resolving them doesn't block other work.
3. **4B (remaining detector families) third.** Individually small, no external dependencies, extends already-proven infrastructure.
4. **4A (Geo-IP/ASN/Tor data sourcing) and 4C (bot/crawler classification) in parallel**, once 4A's data-provider decision is made -- 4C's AI-crawler seeding doesn't depend on 4A at all and can start immediately.
5. **4E.1 (tier packaging design) after 4A-4C have real capability to package**, not before -- packaging decisions made against a mostly-empty Professional/Managed feature list would just need re-doing.
6. **4F (Recommendations engine) last**, deliberately, per its own §22 rationale above.

---

# 6. Definition of Done for Phase 4

Phase 4 should be considered complete when:

- Geo-IP, ASN, and Tor awareness are available as observation-only evidence, backed by a licensed, verified data source;
- all 13 detector families from §11 are registered with full test coverage, and detector-family-aware control actions exist;
- HTTP method classification distinguishes legitimate CORS preflight from reconnaissance;
- bot/crawler classification moves beyond identity-matching alone into the multi-signal model §10 specifies;
- ~~documentation and technical-debt issues #162/#163/#167/#168/#169/#170/#220/#221 are closed or formally re-scoped~~ **Done -- all 8 closed, v2.9.59-v2.9.65.**
- the SAM Portal is live, no Stripe secret exists on any customer WordPress install, and GitHub #174's grace-period requirement is closed with working code, not just schema;
- a tier-packaging decision (§25) exists and is documented, grounded in capability that actually ships by that point.

Everything in §4 (External Verification, Federated Intelligence, Fleet Management, time-bound exceptions, WP-CLI, webhook/SIEM, policy simulation) remains correctly out of scope regardless of what else in this document ships first.
