# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project follows semantic versioning for plugin releases.

## [2.9.69] - 2026-09-04

### Added

- Second installment of the UI documentation retrofit (Phase 4G): `includes/admin/views/page-csp-dashboard.php`'s Profiles, For Review (Sources), Policy Audit, Violations, Scan Log, and Settings tabs each gained a `<p class="description">` explainer paragraph. Start Here already carried this level of detail from earlier work and was left unchanged. Written to explain what the data on each tab actually means and why, not just what the column headers say -- e.g. Profiles explains what Trusted Types and Bypass Best Practices actually are and why enforcing Trusted Types isn't the default; Violations explains that Occurrences is a lifetime count that never resets even when the date filter narrows what's shown; Scan Log explains what a scan actually inspects and what "Policy Changed" means. No behaviour change; explanatory copy only, confirmed live in Docker across all six tabs.

## [2.9.68] - 2026-09-04

### Fixed

- The "Settings" link `Admin_UI::add_plugin_action_links()` adds to this plugin's row on the Plugins list page pointed at `admin.php?page=security-automation-manager-dashboard&tab=settings` (the CSP dashboard's own Settings tab) instead of the plugin's actual top-level landing page. Now points at `admin.php?page=security-automation-manager` (Settings/Overview), matching the top-level admin menu's own first submenu entry, which is also labelled "Settings" and renders the same page. No schema change; behaviour-only fix confirmed live in Docker.

## [2.9.67] - 2026-09-04

### Added

- First installment of a wider UI documentation retrofit (user-requested): the Settings/Overview page's Overview, Readiness, and Security Health tabs now carry plain-language explainer paragraphs, not just table headings. The Overview tab gets a framing paragraph up front ("everything below is organised into five layers, roughly ordered from foundational to visible") plus one paragraph per layer explaining what it covers, why it matters, and how it relates to the layers around it -- e.g. Layer 2 (Controlled Automation) explains what "deterministic automation" actually buys an administrator who doesn't want to hand-author a Content Security Policy, and Layer 5 (Transport & Certificate Trust) explains why every layer above it depends on this one being right. Readiness and Security Health each get a short intro explaining what the checks below them are actually for and what a Fail/Warning means in practice. Written for an administrator who may know nothing about CSP, clickjacking, or MIME-sniffing, not just for someone who already does -- existing technical copy (e.g. the About tab, the per-pillar intro text on X-Frame-Options/Referrer-Policy/etc.) was already reasonably strong and used as the voice/tone reference for this pass. No behaviour change; explanatory copy only. Remaining admin pages (CSP dashboard, Traffic Controls, the individual pillar pages, Continuous Intelligence, Baseline & Drift, Certificates) follow in subsequent releases, then a separate guided onboarding flow.

## [2.9.66] - 2026-09-04

### Added

- Phase 4C extension (requested alongside the bot/crawler classification work): Custom Rules, a fail2ban-style custom regex detection feature. New `sam_custom_detector_rules` table (schema v37), `includes/intelligence/class-custom-rule-store.php` (`Custom_Rule_Store` -- CRUD, validation, and a `test()` dry-run helper), and `includes/intelligence/detectors/class-custom-rule-detector.php` (`Custom_Rule_Detector extends Pattern_Detector` -- one instance per stored rule, registered fresh by `Plugin::register_detectors()` on every request, flowing through the exact same `Detector_Registry`/`Detector_Policy_Store`/`Detector_Engine`/`Traffic_Block_Store` pipeline every built-in §11 family already uses -- no new blocking path). A rule matches against one of `request_uri` (path + query string, the same convention `Sql_Injection_Detector`/`Html_Injection_Detector` already use), `path`, `query_string`, or `user_agent`, with a severity and optional surface restriction. A saved rule shows up automatically on the existing Detectors tab for enable/control-action management -- no admin UI changes needed there. New "Custom Rules" tab on Traffic Controls (list/add/edit/delete, plus a "Test a pattern" AJAX tool that compiles a pattern against a sample value without persisting anything). A pattern that fails to compile is rejected at save time.
- Regex safety: patterns are capped at 500 characters and required to actually compile at save time. No attempt is made to detect or reject a pathologically slow-but-valid pattern (catastrophic backtracking) -- PHP's own `pcre.backtrack_limit`/`pcre.recursion_limit` already bound a single `preg_match()` call's worst case, the same backstop every other `Pattern_Detector` subclass in this codebase already relies on, and a rule is only ever authored by a `manage_options` administrator, the same trust level already required for a raw CSP directive override.
- Confirmed live in Docker end-to-end: a created rule registers into `Detector_Registry`; a real HTTP request matching its pattern is recorded as evidence; switching it to Enforce correctly feeds `Traffic_Block_Store`'s progressive-response ladder; the rule appears correctly on both the Custom Rules and Detectors tabs.

## [2.9.65] - 2026-09-04

### Fixed

- Phase 4D of `.roadmap/phase4_plan.md`, GitHub issue #163 (documentation consistency, narrowed scope per the issue's own 2026-09-02 status comment -- `README.md`/`readme.txt`/`SPECIFICATION.md`/`CHANGELOG.md` were already covered by `VersionConsistencyTest.php`; this closes the remaining 9 files): `SECURITY.md`'s supported-versions table named a specific old release line (`2.4.x`) that had been stale since the plugin moved past it -- replaced with an evergreen "latest released version only" policy. `COMMERCIAL_TERMS.md` still opened as "CSP Automation Manager Commercial Terms" and used that retired trademark, three years after the plugin's actual rename (`CHANGELOG.md`'s `[2.0.0]` entry) to "VCNS Security Automation Manager" -- corrected throughout. `docs/architecture.md` and, much more extensively, `docs/testing-and-quality.md` still referenced `wp_csp_*` options and `csp_*` table names schema v9 renamed to `wp_sam_*`/`sam_*` years ago; `docs/testing-and-quality.md` also asserted CSP automation seeds to `manual` by default, contradicted by schema v18's change to `automatic_high_approval`. `docs/database-schema.md`'s version-history table stopped at schema v12 while `WP_SAM_DB_VERSION` had reached 36 -- backfilled v13 through v36 (also correcting two existing rows that had drifted to describe what are now v20's and v22's changes), and corrected an example `product_key` value that didn't match `Feature_Gate::PRODUCT_KEY`'s actual (deliberately pre-rename, for entitlement-matching continuity) value.
- Reviewed `docs/release-and-publishing.md`, `docs/user-guide.html`, and `docs/faq.html` against the same authoritative sources (plugin header, `SPECIFICATION.md`, `Github_Update_Checker::UPDATE_URL`) -- no drift found in any of the three.

### Added

- Extended `test/unit/VersionConsistencyTest.php` with 6 new automated checks so this drift is caught by CI going forward: the database-schema doc's latest version row against `WP_SAM_DB_VERSION`; WordPress/PHP minimum-requirement wording across `docs/architecture.md`/`docs/user-guide.html`/`docs/faq.html` against the plugin header; the subscription price across `docs/user-guide.html`/`docs/faq.html` against `SPECIFICATION.md`; the update manifest URL in `docs/release-and-publishing.md` against `Github_Update_Checker::UPDATE_URL`; `COMMERCIAL_TERMS.md`'s product name; and a regression guard across `docs/testing-and-quality.md`/`docs/architecture.md`/`docs/threat-model.md` against reintroducing any pre-schema-v9 table/option identifier.
- No schema change; documentation and test-infrastructure only.

## [2.9.64] - 2026-09-04

### Added

- Phase 4D of `.roadmap/phase4_plan.md`, GitHub issue #162 (security-controls inventory): new `docs/security-controls-inventory.md` documenting all 19 implemented HTTP security/content-protection controls (the 17 named in the issue's own acceptance criteria, plus Information Masking and Cache-Control, shipped after the issue was written) -- purpose, supported surfaces, default state, report-only/enforcement/discovery capability, approval requirements, breakage risk, rollback behaviour, audit events, limitations, and relevant standards for each. Grounded directly in the current codebase (each control's own class, `Pillar_Registry`, `Activator`'s seeding logic, every `Audit_Log::log()` call site, `Rollback_Guard`) rather than general assumptions about header behaviour.
- Registered the new doc in `docs/README.md`'s Internal Documentation index.

### Fixed

- `includes/csp/class-policy-builder.php`: corrected a misleading code comment claiming Trusted Types directives (`require-trusted-types-for`, `trusted-types`) are "always emitted as report-only regardless of surface mode" -- confirmed by reading `emit_profile_header()`/`get_policy_header_name()` directly that no such carve-out exists; on an enforce-mode surface these directives go out in the real, blocking `Content-Security-Policy` header along with everything else. This is a comment-only fix (documents reality accurately instead of an inaccurate claim); it does not change runtime behaviour. Whether to build the (materially larger) always-report-only Trusted Types behaviour the old comment promised is an open product decision, not resolved by this change -- see the security-controls inventory's own Trusted Types section.

## [2.9.63] - 2026-09-04

### Fixed

- Phase 4D of `.roadmap/phase4_plan.md`, GitHub issue #167 (per-table pagination regression coverage): `includes/admin/views/partials/scripts-external.php` (the External Scripts table) floored its page number at 1 but never capped it at the real last page -- every other `Table_Query`-driven table in this codebase clamps both ends (`min( max( 1, $page ), $pages )`); this was the one that didn't. `?ext_paged=9999` against a 3-page result set rendered "Page 9999 of 3" instead of serving (and reporting) the real last page. Fixed by reordering the count query ahead of the page-number calculation and applying the same clamp every other table already uses.

### Added

- New regression coverage across all seven of this plugin's `Table_Query`-driven admin tables (External Scripts, Report-Only Evidence, CSP Sources/Policy Changes/Violations, Continuous Intelligence Events/Identities) confirming each one, rendered through its real view file: caps an out-of-range page number at the true last page, preserves at least one filter across a page change, and renders an empty result set without a fatal. `page-csp-dashboard.php` and `page-intelligence.php` had never been directly rendered by any test before (new `test/unit/PageCspDashboardTest.php`, `test/unit/PageIntelligenceTest.php`); the External Scripts and Report-Only Evidence tables gained coverage in the existing `test/unit/AdminUITest.php`. `Table_Query` itself was already covered in isolation (`test/unit/Admin/TableQueryTest.php`) -- this proves each table actually wires it up correctly, not just that the shared helper works.
- No schema change; no production behaviour change beyond the one bug fix above.

## [2.9.62] - 2026-09-03

### Changed

- Phase 4D of `.roadmap/phase4_plan.md`, GitHub issue #170 (`Policy_Builder` dependency boundary): `load_profile()`, `load_approved_hashes()`, and `load_approved_sources()` were `protected` methods on `Policy_Builder` itself -- a de facto subclass extension point for a security-sensitive, header-emitting class, and this codebase's own tests were already exploiting it (an `extends Policy_Builder` anonymous class in `PolicyBuilderTest.php` overrode `load_approved_sources()`, and its `hash_loader`/`source_loader` constructor callables coexisted with the same protected methods being independently overridden elsewhere in the same file -- two different seams for the same job). Replaced with `includes/csp/class-policy-data-loader.php` (`Policy_Data_Loader` interface: `load_profile()`/`load_approved_hashes()`/`load_approved_sources()`) and `includes/csp/class-wpdb-policy-data-loader.php` (`Wpdb_Policy_Data_Loader`, the real implementation -- the exact query logic relocated verbatim, unchanged).
- `Policy_Builder`'s constructor now takes `(Feature_Gate $gate, ?Policy_Data_Loader $data_loader = null, ?Audit_Log $audit = null)`, defaulting to `Wpdb_Policy_Data_Loader` -- production wiring (`Plugin::bootstrap()`) never has to pass one explicitly. `load_approved_hashes()`/`load_approved_sources()` are now `private` (no longer overridable at all); `load_profile()` stays `protected` only because `Header_Builder`'s own abstract contract requires it, but is now `final` to close that one remaining seam.
- Tests inject a `Policy_Data_Loader` implementation (`test/unit/Stub_Policy_Data_Loader.php`, a new shared test double, loaded the same way `NonceBridge.php` already is) instead of subclassing `Policy_Builder`. Moved the one DB-query-shape regression test that belonged with the data-loading implementation, not `Policy_Builder` itself, into new `test/unit/WpdbPolicyDataLoaderTest.php`.
- Confirmed live in Docker: CSP headers (nonces, approved hashes, approved sources, every directive) are emitted exactly as before this refactor -- no behaviour change, internal architecture only.
- No schema change.

## [2.9.61] - 2026-09-03

### Changed

- Phase 4D of `.roadmap/phase4_plan.md`, GitHub issue #169 (`wpdb::prepare()` test stub): `test/bootstrap.php`'s `wpdb_stub::prepare()` now mirrors real `wpdb::prepare()` (`wp-includes/class-wpdb.php`, confirmed against current WordPress core source) far more closely than the previous `%s`/`%d`-only regex swap. Added `%f` (cast to float, formatted like PHP's own `%f` sprintf conversion) and `%i` (wrapped in backticks, with any embedded backtick doubled, matching `_escape_identifier_value()` -- for dynamic table/column identifiers, never quoted like `%s`). An argument-count mismatch between the query's placeholders and the arguments passed now returns `null`, exactly like real WordPress, instead of silently truncating or padding -- confirmed via a full test-suite run that no existing `->prepare()` call site in this codebase was relying on the old lenient behaviour. Also supports the single-array-argument backward-compatibility calling convention real `wpdb::prepare()` accepts, even though nothing in this codebase currently calls it that way. Deliberately does not implement positional (`%1$s`) or width/precision (`%05d`) placeholder syntax -- confirmed via a full codebase grep that no `->prepare()` call anywhere uses either, so WordPress core's considerably more complex placeholder regex would only add untested surface here. New `test/unit/WpdbStubTest.php` covers every placeholder type, `%%`, multiple placeholders, LIKE-expression wildcard survival, null arguments, and the count-mismatch/array-unpacking edge cases.
- No production code changed -- `test/bootstrap.php` and its own test coverage only, never loaded outside the PHPUnit test suite.

## [2.9.60] - 2026-09-03

### Added

- Phase 4D of `.roadmap/phase4_plan.md`, GitHub issue #221 (Session & Cache Control -- the issue body and acceptance criteria only ever discuss Cache-Control specifically; nothing session/cookie-related was specified, so nothing session-related was built here): a new pillar setting `Cache-Control` per surface via a small named-preset value model (`includes/security/class-cache-control-builder.php`, `Cache_Control_Builder::PRESET_VALUES` -- `no-store`, `private-no-cache`, `public-short` (max-age=300), `public-long` (max-age=3600)), rather than a free-form directive builder -- Cache-Control directives interact (`public`/`private` are mutually exclusive, `max-age` is meaningless with `no-store`), and a preset can never express a self-contradictory combination.
- Unlike every other simple pillar, `Cache_Control_Builder` is seeded `enabled => 0` on every surface (`Activator::seed_cache_control_pillar_profiles()`, called separately from `seed_default_pillar_profiles()`) -- a deliberate exception, since Cache-Control is a performance/behaviour decision, not a universal security hardening default; WordPress core already sends a strict Cache-Control on every surface that needs one via `nocache_headers()` (confirmed live: `no-cache, must-revalidate, max-age=0, no-store, private` on wp-admin/wp-login.php), and shipping this pillar pre-enabled would risk silently changing a site's frontend caching behaviour on upgrade.
- `includes/security/class-cache-control-conflict-detector.php` (`Cache_Control_Conflict_Detector`): issue #221's own explicit safety requirement -- "if another caching mechanism is detected, this section must be disabled/grayed out rather than emit a competing Cache-Control header." `Cache_Control_Builder::is_profile_active()` consults this on every request; a stored `enabled=1` row is never sufficient on its own. Two conditions: (1) a known caching plugin's own stable bootstrap-time marker (`known_plugins()`, currently WP Rocket/W3 Total Cache/WP Super Cache/LiteSpeed Cache/WP Fastest Cache/Cache Enabler/SiteGround Speed Optimizer/WP-Optimize/Breeze -- every signature confirmed live against that plugin's own current WordPress.org SVN trunk or, for WP Rocket, its GitHub repo, not guessed); (2) a manual CDN/edge-cache acknowledgement (`wp_sam_cache_control_cdn_acknowledged` option) -- deliberately NOT auto-detected, since a reverse proxy's caching behaviour isn't observable from inside a single origin-server PHP request, per the issue's own admission. Deliberately NOT built the same way CSP's `Conflict_Detector` works (HEAD-probe/`.htaccess`-scan): that approach exists because a competing CSP header is inherently unusual, whereas WordPress core itself sends a Cache-Control header on nearly every dynamic request -- simple "header already exists" detection would gray this pillar out on every WordPress site unconditionally.
- New "Cache-Control" admin page: per-surface enable + preset picker, a warning notice with every control disabled when blocked, and a CDN-acknowledgement checkbox -- mirrors the CSP conflict banner's warning-notice visual language, not its literal mechanism (that banner is dismissible/informational and never disables a control).
- No schema change -- 14th pillar in `Pillar_Registry`, reuses the existing `sam_pillar_profiles` row shape.

## [2.9.59] - 2026-09-03

### Added

- Phase 4D of `.roadmap/phase4_plan.md`, GitHub issue #220 (Information Masking): a new pillar removing headers that disclose the server stack, PHP version, or this site's own hostname. `includes/security/class-information-masking-builder.php` (`Information_Masking_Builder extends Pillar_Header_Builder`) removes `X-Powered-By`, `Server`, and `X-Pingback` on every enabled surface -- no configurable value, same shape as `X_Content_Type_Options_Builder`. `X-Powered-By` and `X-Pingback` are set by PHP/WordPress itself and always removable; `Server` is best-effort, since most hosts set it at the web-server layer before PHP ever runs, a layer `header_remove()` cannot reach.
- `includes/security/class-information-masking-diagnostic.php` (`Information_Masking_Diagnostic`): a live self-probe (`home_url('/')` over real HTTP, same "observe real behaviour" approach as `Robots_Rules_Store`/`Tor_Exit_List_Store`) reporting per-header whether the removal actually took effect on this specific install -- resolves issue #220's own "readiness/diagnostic check" acceptance criterion, since `Server`'s effectiveness genuinely varies by host and should never be silently assumed. A transient probe failure never overwrites the previous result.
- New "Information Masking" admin page (per-surface enable toggle + readiness check with a manual "Check Now" button); registered in `Pillar_Registry` (13th pillar) so it also appears on the Settings Overview page's Layer 4 table.
- `X-Generator` (WordPress core's version tag) is deliberately out of scope: confirmed live that WordPress emits it as a `<generator>` element in RSS/Atom feed body content, never as an actual HTTP header -- doesn't fit this plugin's header-only architecture.
- No schema change -- reuses the existing `sam_pillar_profiles` table's per-pillar row shape.

## [2.9.58] - 2026-09-03

### Added

- Phase 4C of `.roadmap/phase4_plan.md`, sixth increment (robots.txt disallow-rule compliance, `.roadmap/phase3_early_plan.md` §10 -- completing the "robots.txt behaviour" signal, whose fetch-recognition half shipped in v2.9.55): `includes/intelligence/class-robots-rules-store.php` (`Robots_Rules_Store`) fetches this site's own `/robots.txt` over real HTTP (`home_url()`), the same way any real crawler would, rather than reimplementing WordPress core's `do_robots()`/`robots_txt`-filter resolution logic. Parses the generic `User-agent: *` block's Disallow directives; refreshed daily via `Scheduler::refresh_robots_rules()`, mirroring `Tor_Exit_List_Store`'s cadence -- a fetch failure never clears already-cached rules.
- `includes/intelligence/detectors/class-robots-compliance-detector.php` (`Robots_Compliance_Detector`): records a source already recognised as a known crawler/scanner vendor requesting a path this site's robots.txt disallows. Deliberately scoped to recognised identities only -- robots.txt is a voluntary convention for automated crawlers, and an ordinary unrecognised visitor is never evaluated against it. Enforce-capable, defaults to observe.
- `includes/intelligence/class-request-observer.php`: identity resolution now runs before detector evaluation (previously after) so a detector can read the already-resolved `identity_verification_state` -- purely additive, no existing detector consumed this field before, so no behaviour changes for anything already shipped.
- New "Robots.txt Rules" section on the Network Intelligence tab (cached rule count, last refresh status, manual refresh).
- No schema change.

## [2.9.57] - 2026-09-03

### Added

- Phase 4C of `.roadmap/phase4_plan.md`, fifth increment (URI-pattern signal, `.roadmap/phase3_early_plan.md` §10): the last of the three signals §10's exit criteria names (identity, request-rate, URI-pattern) is now combined into `Bot_Classifier`.
- `includes/intelligence/class-scanner-identity-store.php`: new `recent_paths` column (bounded JSON array, `MAX_RECENT_PATHS = 10`, oldest dropped first) logging each identity's recent request paths -- directly answers §10's "log the fact they're hitting the endpoint." `record()` gains an optional `$path` parameter.
- `includes/intelligence/class-uri-pattern-analyzer.php` (`Uri_Pattern_Analyzer`): recognises a fixed-step sequential pattern across at least 4 consecutive numeric-ending paths (e.g. `/product/101`, `/product/102`, `/product/103`, `/product/104`) -- the classic signature of a script walking IDs. Pure and read-only, like `Bot_Classifier`.
- `Bot_Classifier` now checks enumeration for an unrecognised source before its existing rate-escalation check -- a script walking IDs is worth flagging whether or not it's also tripped a rate limit. A known vendor's own recent_paths is never checked this way: systematically crawling a site's posts is normal, expected behaviour for a real search engine.
- `includes/admin/views/page-intelligence.php`: the Identities tab's Classification column now shows a hover tooltip with the identity's logged recent paths.
- Schema v36 (`recent_paths` column, no new table).

## [2.9.56] - 2026-09-03

### Added

- Phase 4C of `.roadmap/phase4_plan.md`, fourth increment (session/cookie behaviour and header-consistency signals, `.roadmap/phase3_early_plan.md` §10): `includes/intelligence/detectors/class-login-cookie-consistency-detector.php` (`Login_Cookie_Consistency_Detector`) records a login-surface POST that never carries back `wordpress_test_cookie` -- a cookie WordPress core itself sets when rendering the login form, never introduced by this plugin -- consistent with a script posting credentials straight to `wp-login.php` rather than a real browser that loaded the form first. A broader, site-wide first-party tracking cookie for cookie-persistence testing beyond this is a bigger product/privacy decision, deliberately not built here -- see the detector's own docblock.
- `includes/intelligence/detectors/class-header-consistency-detector.php` (`Header_Consistency_Detector`) records a request whose User-Agent claims a specific versioned browser (matched on each browser's own token -- `Chrome/`, `Firefox/`, `Edg(e)/`, or `Version/... Safari/`, deliberately not the bare `Safari/537.36` substring that appears in many legitimate WebKit-based crawlers) but sends no `Accept-Language` header, which every mainstream browser always does.
- `includes/intelligence/class-request-observer.php`: `build_context()` now also captures `has_login_test_cookie`, `accept`, and `accept_language` for these two detectors to read.
- Both registered outside `register_defaults()` alongside the other §10/§12 signals -- neither is one of §11's 13 named detector families. Both default to observation only.

## [2.9.55] - 2026-09-03

### Added

- Phase 4C of `.roadmap/phase4_plan.md`, third increment (robots.txt behaviour tracking, first piece, `.roadmap/phase3_early_plan.md` §10): `includes/intelligence/detectors/class-robots-txt-detector.php` (`Robots_Txt_Detector`) recognises a source examining `/robots.txt`, recorded as low-severity, observation-only evidence -- deliberately not treated as adverse (checking robots.txt is well-behaved-crawler etiquette), just made correlatable by IP against `Scanner_Identity_Store`/`Bot_Classifier`.
- Registered separately from `register_defaults()` alongside `Honeypath_Detector`/`Http_Method_Detector` -- §10 isn't one of §11's 13 named detector families.
- Explicitly not built in this pass: actually parsing robots.txt's disallow rules and checking whether a source goes on to violate them -- carried forward.

## [2.9.54] - 2026-09-03

### Added

- Phase 4C of `.roadmap/phase4_plan.md`, second increment (bot/crawler classification, `.roadmap/phase3_early_plan.md` §10): `includes/intelligence/class-bot-classifier.php` (`Bot_Classifier`) combines identity and request-rate signals into a multi-state classification, avoiding the binary "bot/not bot" model §10 explicitly warns against. Pure and read-only -- takes an already-recorded `Scanner_Identity_Store` row and the matching `Traffic_Block_Store` row (if any) for the same (ip, surface); writes nothing new to the database.
- Priority order: an administrator's own decision (`customer_authorised`/`explicitly_denied`/`previously_authorised_expired`) always wins. Below that, a recognised vendor match splits on `network_match`: `verified_crawler` if it matches the vendor's own published network data, `claimed_crawler_unverified` otherwise -- §10's "impersonated crawlers" category. An unrecognised source splits on whether it's actually escalated through `Traffic_Block_Store`'s progressive-response ladder (throttle or worse): `aggressive_unidentified` if so, else `unclassified`.
- `includes/admin/views/page-intelligence.php`: the Identities tab gains a Classification column, computed on demand per visible row.
- URI-pattern (the third signal §10's exit criteria names) is not incorporated in this pass -- carried forward.

## [2.9.53] - 2026-09-03

### Added

- HTTP Method Intelligence (`.roadmap/phase3_early_plan.md` §12, carried forward from Phase 4B): `includes/intelligence/detectors/class-http-method-detector.php` (`Http_Method_Detector`) classifies OPTIONS requests instead of treating every one as reconnaissance, per §12's explicit "OPTIONS must not be considered malicious merely because it is OPTIONS." A genuine browser CORS preflight always carries both an `Origin` header and an `Access-Control-Request-Method` header (the Fetch/CORS spec's own mechanism, not a heuristic) -- classified `cors_preflight`, low severity. An OPTIONS request missing that pair is classified `unclassified_options`, medium severity -- §12 itself lists both legitimate API-discovery tooling and reconnaissance as real possibilities headers alone can't distinguish, so this doesn't over-claim maliciousness.
- Implements `Detector` directly rather than `Pattern_Detector` (no string to regex-match), and is registered separately from `Detector_Registry::register_defaults()` alongside `Honeypath_Detector` -- §12 is its own roadmap section, not one of §11's 13 named detector families, so it doesn't change that count. Enforce-capable under the Phase 4B control-action framework, still defaulting to `observe`.
- `includes/intelligence/class-request-observer.php`: `build_context()` now also captures the `Origin`/`Access-Control-Request-Method` headers for this detector to read. No schema change.

## [2.9.52] - 2026-09-02

### Added

- Phase 4C of `.roadmap/phase4_plan.md`, first increment (AI-crawler identity seeding, `.roadmap/phase3_early_plan.md` §10): `Activator::seed_default_scanner_vendors()` now also seeds GPTBot (OpenAI), ClaudeBot (Anthropic), CCBot (Common Crawl), and PerplexityBot into `sam_scanner_vendors`, reusing the existing `known_crawler` category and the identical fcrdns/cidr verification machinery Googlebot/Bingbot already exercise -- no new code in `Identity_Resolver`, `Scanner_Identity_Store`, or the admin label maps was needed. Verified against each vendor's own current published documentation (fetched live, not from training memory), not fabricated: CCBot documents forward-confirmable reverse DNS (`*.crawl.commoncrawl.org`); GPTBot, ClaudeBot, and PerplexityBot instead publish IP-range JSON, so those three ship with `verification_method = 'cidr'` and empty `cidr_ranges` (never a guessed range) plus the real published source URL, so an administrator can paste in current ranges via the existing Scanner Vendors admin form.
- Schema v35 -- no new table; bumped purely so `maybe_upgrade_db()` re-runs the (idempotent, missing-row-only) seed on every already-upgraded site, not just fresh installs.

## [2.9.51] - 2026-09-02

### Added

- Phase 4B of `.roadmap/phase4_plan.md`, fourth and final increment (Legacy WordPress Endpoints, `.roadmap/phase3_early_plan.md` §11.13): `includes/intelligence/detectors/class-legacy-endpoint-detector.php`, the 13th and final core detector family. Recognises xmlrpc.php, wp-trackback.php, and the long-removed wp-app.php. Per the roadmap's explicit "RPC/XML-RPC controls must be configurable rather than assumed universally safe to block," `allowed_control_actions() = ['observe', 'enforce']` -- the second detector (after HTML Injection) to be enforce-capable, still defaulting to observe. **This completes Phase 4B**: all 13 detector families from §11 are registered, and the control-action framework (2.9.48) is fully wired end to end.
- `Vulnerability_Probe_Detector`'s docblock (which already deliberately excluded xmlrpc.php, deferring to this family) updated to point at the now-shipped `Legacy_Endpoint_Detector`.

### Fixed

- `includes/intelligence/class-request-observer.php`: also hooks `init` (priority 20, after `Detector_Registry::register_defaults()`'s priority 10), discovered live in Docker while verifying the new detector -- xmlrpc.php and wp-cron.php bootstrap WordPress via `wp-load.php` directly and never run the `wp()`/template-loader pipeline that fires `send_headers`, so they were structurally invisible to every detector, not just this one. The existing `$observed` guard means a request that also fires `send_headers`/`login_init` later is never double-recorded.

## [2.9.50] - 2026-09-02

### Added

- Phase 4B of `.roadmap/phase4_plan.md`, third increment (PHP and PHPUnit Probes, `.roadmap/phase3_early_plan.md` §11.6): `includes/intelligence/detectors/class-php-probe-detector.php`, the 12th core detector family. Distinct from §11.5's `Script_Webshell_Probe_Detector` (well-known malicious filenames) and §11.12's `Vulnerability_Probe_Detector` (general admin-tool paths) -- this family matches specific, versioned vulnerability signatures instead: the PHPUnit `eval-stdin.php` RCE (CVE-2017-9841), an exposed `phpinfo()`-style script, Laravel Ignition's debug RCE path (CVE-2021-3129), the php-cgi argument-injection query string (CVE-2012-1823), and a Symfony profiler path.
- `includes/intelligence/class-detector-registry.php`: registered in `register_defaults()`. Defaults to observation only (no roadmap guidance calling for enforce-capability on this family, unlike HTML Injection and the upcoming Legacy WordPress Endpoints family).

## [2.9.49] - 2026-09-02

### Added

- Phase 4B of `.roadmap/phase4_plan.md`, second increment (HTML Injection, `.roadmap/phase3_early_plan.md` §11.4): `includes/intelligence/detectors/class-html-injection-detector.php`, the 11th core detector family, following the same `Pattern_Detector` convention as the other ten. Every rule requires actual tag-open syntax or a `javascript:` scheme -- a bare "<" or a word containing "on" never matches, per §11.4's explicit "must be treated carefully" guidance.
- Per that same guidance ("default posture should therefore be observation unless the protected endpoint is known not to accept HTML"), this is the first detector to declare itself enforce-capable (`allowed_control_actions() = ['observe', 'enforce']`) under the control-action framework shipped in 2.9.48 -- still defaults to `observe`, opt-in only via the Detectors tab.
- `includes/intelligence/class-detector-registry.php`: registered in `register_defaults()`.

## [2.9.48] - 2026-09-02

### Added

- Phase 4B of `.roadmap/phase4_plan.md`, first increment: the control-action framework (`.roadmap/phase3_early_plan.md` §11's shared detector metadata contract -- the "allowed control actions / default action" field, previously missing). `includes/intelligence/class-detector.php`: every `Detector` now declares `allowed_control_actions()` (subset of `observe`/`enforce`) and `default_control_action()`, both defaulting to observation-only -- zero behaviour change for any detector shipped before this.
- `includes/intelligence/class-detector-policy-store.php` (new): per-detector admin override -- enabled/disabled, and which control action a match should trigger. A missing row means "enabled, detector's own default"; a saved `enforce` override is only honoured while it remains a member of that detector's own `allowed_control_actions()`. New `sam_detector_policies` table, schema v34.
- `includes/intelligence/class-detector-engine.php`: skips a detector an administrator has disabled; every Finding now carries its resolved `control_action`.
- `includes/intelligence/class-request-observer.php`: when a Finding's `control_action` is `enforce`, calls the same `Traffic_Block_Store::record_violation()` login-brute-force protection already uses -- a detector match becomes another source feeding the existing progressive-response ladder (warn -> throttle -> temporary block -> extended block -> admin-only persistent block), with no new blocking path and no change to the existing per-surface Observe/Enforce gate.
- `includes/admin/views/page-traffic.php`: new "Detectors" tab -- enable/disable each registered detector and, where its family allows it, switch its control action between Observe and Enforce.

## [2.9.47] - 2026-09-02

### Added

- Phase 4A of `.roadmap/phase4_plan.md`, third and final increment (Geo-IP Controls, `.roadmap/phase3_early_plan.md` §13.4): `includes/intelligence/class-geo-ip-store.php` resolves a source IP's country/region/city via IPinfo's API, entirely opt-in and bring-your-own-credentials -- disabled until an administrator enters their own IPinfo token, sealed with `Certificates\Credential_Vault` (the existing encryption-at-rest mechanism already protecting certificate and DNS-provider secrets), never a shared VCNS credential. Results cached in the new `sam_geoip_cache` table (30-day TTL, including a cached negative result on failure).
- MaxMind support explicitly deferred: its free GeoLite2 tier is a downloaded binary database, not a live API, and reading it correctly needs either a hand-rolled MMDB parser or this plugin's first-ever production Composer dependency (`geoip2/geoip2`) -- a real architectural decision, confirmed deferred rather than built silently either way.
- `includes/intelligence/class-network-intelligence-resolver.php`: extended with the new collaborator; `geo_country`/`geo_region`/`geo_city` now attached alongside `is_tor_exit`/`asn`/`asn_org` on any Finding's evidence, same lazy-resolution pattern. `Geo_Ip_Store::resolve()` is a complete no-op (no DB query, no network call) until Geo-IP is configured.
- `includes/admin/views/page-traffic.php`: Network Intelligence tab gains a Geo-IP settings section (token entry/clear, decrypt-failure warning) and its own "Look Up" tool.
- Schema v33. This completes Phase 4A (Tor Awareness, ASN Controls, Geo-IP Controls).

## [2.9.46] - 2026-09-02

### Added

- Phase 4A of `.roadmap/phase4_plan.md`, second increment (ASN Controls, `.roadmap/phase3_early_plan.md` §13.5): `includes/intelligence/class-asn-lookup-store.php` resolves a source IP's Autonomous System Number and organisation name via Team Cymru's free, unauthenticated DNS-based lookup (no account or licensing decision needed, same reasoning as Tor Awareness). Results are cached in the new `sam_asn_cache` table (30-day TTL, including a cached negative result on lookup failure) so the DNS round-trip is paid once per IP, not per request -- the lookup itself is injectable (mirroring `Identity_Resolver`'s `reverse_lookup`/`forward_lookup` pattern) so no test makes a real DNS call. IPv4 only for this increment; IPv6 (a different Team Cymru query format) is not implemented.
- `includes/intelligence/class-network-intelligence-resolver.php`: extended with the new `Asn_Lookup_Store` collaborator; `asn`/`asn_org` are now attached alongside `is_tor_exit` on any Finding's evidence, using the same lazy-resolution-only-when-needed pattern.
- `includes/csp/class-scheduler.php`: daily housekeeping prune for stale `sam_asn_cache` rows, reusing the existing `wp_sam_violation_retention_days` retention window rather than a new option.
- `includes/admin/views/page-traffic.php`: the Network Intelligence tab gains a "Look Up" tool (any IP -> its ASN and organisation, via a simple GET query) for direct admin visibility into what the resolver would report.
- Schema v32.

## [2.9.45] - 2026-09-02

### Added

- Phase 4A of `.roadmap/phase4_plan.md` (Traffic Intelligence Data Sourcing -- Tor Awareness, `.roadmap/phase3_early_plan.md` §13.6): `includes/intelligence/class-tor-exit-list-store.php` fetches the Tor Project's own public bulk exit-node list (`https://check.torproject.org/torbulkexitlist` -- no account, API key, or licensing decision required, unlike Geo-IP/ASN) and replaces the stored set wholesale on a successful, plausibility-checked fetch; a failed or suspiciously small fetch leaves existing data untouched. Refreshed daily via the existing `wp_sam_daily_scan` cron, with a manual "Refresh Now" admin action.
- `includes/intelligence/class-network-intelligence-resolver.php`: the `Network_Intelligence_Resolver` component named as missing in `.roadmap/phase3_early_plan.md` §31, built now as the umbrella ASN/Geo-IP will extend later. Resolves Tor exit status via a single indexed local lookup, never a network call on the request path.
- `includes/intelligence/class-request-observer.php`: network intelligence is resolved only when a detector has already produced a Finding for the request (not on every request), and `is_tor_exit` is attached to that Finding's evidence -- Tor identity is recorded as context on evidence that already exists, never as its own noise-generating event, and never implies malicious intent on its own.
- `includes/admin/views/page-traffic.php`: new "Network Intelligence" tab showing exit-list status (count, last refresh, last fetch outcome) and the manual refresh action; notes ASN and Geo-IP as planned next.

## [2.9.44] - 2026-09-02

### Added

- Phase 3J of `.roadmap/phase3_early_plan.md` (§14 Campaign Detection, §15 Deception and Honey Paths, §16 Integrity Monitoring, §17 Change Attribution extension, §18 Security Change Window) -- built at the user's explicit request ahead of real-world validation of Phases 3D-3I, since the roadmap frames this set as optional/exploratory. Schema v30 adds `sam_campaigns`, `sam_honeypaths`, `sam_change_windows`, and an indexed `ip` column on `sam_request_events`.
- `includes/intelligence/class-campaign-detector.php` + `class-campaign-store.php` (§14): correlates distinct source IPs hitting the same detector+surface within a window into a possible-campaign record. Implements exactly one of the roadmap's listed signals (distributed source IPs) -- the others (payload-fingerprint clustering, ASN/provider diversity, path sequencing) would need infrastructure this build doesn't have and aren't faked. Runs as part of the existing daily cron scan; observe/correlate/notify only. `block_participants()` is the one action with a real side effect (adds every live participant IP to `sam_ip_rules` as an explicit block) and is only ever triggered by an explicit administrator action with a required reason, never automatically.
- `includes/intelligence/class-honeypath-store.php` + `includes/intelligence/detectors/class-honeypath-detector.php` (§15): an administrator-managed list of decoy paths. With zero configured paths (every fresh install/upgrade), the detector's rule list is empty and it structurally never matches anything -- satisfying "disabled by default" without a separate flag. A hit is recorded through the same `Event_Store` path as every other detector, never a special-cased second bookkeeping mechanism, and the request's actual response is never altered.
- `includes/intelligence/class-account-integrity-recorder.php` (§16): records new administrator accounts and role escalations to administrator into the existing `Change_Log_Store` (two new change types: `admin_account_created`, `admin_role_granted`), so they appear in both the existing Change Log tab and the new Timeline tab automatically. Other §16 candidate signals (unexpected files, cron entries, plugin/theme file changes) are not implemented -- explicit gap, not partial/faked coverage.
- `includes/intelligence/class-change-window-store.php` (§18): a thin, declared-intent wrapper around the existing `Baseline_Store`/`Drift_Scanner` machinery rather than a parallel mechanism. Covers 5 of the roadmap's 8 workflow steps (snapshot reference, continuous change/behaviour recording via existing infrastructure, delta presentation on close, retained rollback reference via baseline history); "increase observation" and "run external verification" are not implemented (no lever for the former exists yet; the latter depends on the Phase 3G/3H infrastructure already deferred).
- `includes/admin/class-change-timeline-builder.php` (§17 extension): merges `Change_Log_Store`, `Drift_Store`, and `Campaign_Store` into one chronological view, modeled on the existing `Policy_Events_Builder` pattern. Every row is worded as correlation only ("Correlates with...") per the roadmap's explicit "must not claim causation where only correlation exists."
- `includes/admin/views/page-advanced.php` (new "Advanced Intelligence" page): Campaigns, Honey Paths, Change Windows, and Timeline tabs; `includes/admin/class-admin-ui.php` gains nine new `admin_post` handlers for these actions.

## [2.9.43] - 2026-09-02

### Added

- Phase 3I of `.roadmap/phase3_early_plan.md` (§21 Site Security Health, §26 Evidence and Assurance): `includes/intelligence/class-security-health.php` computes a non-gamified, cross-pillar operational summary -- enforcement (CSP/Traffic Controls surfaces in enforce mode), drift (open `sam_drift_records`), certificates (expired/expiring-soon/healthy), third-party dependencies (unclassified count), exceptions (a single aggregate across IP allow rules, permanent traffic blocks, dependency exceptions, and CSP/pillar overrides), automation posture, and evidence freshness (time since the last completed scan). Each row reuses the `{label, value, status, detail}` shape `Readiness_Checker` already uses, adding a new `info` status (and matching CSS) for genuinely neutral rows. "External verification" is included, always `info`, honestly stating it isn't available yet rather than omitting the roadmap's own example row or faking a status -- Phase 3G (the service it would report on) is deliberately deferred.
- `includes/intelligence/class-evidence-exporter.php`: a read-only JSON evidence bundle (health summary, per-pillar controls, exception detail, certificate state, current baseline, open drift count, recent change log, and a warning/error audit-log excerpt) for security reviews, MSP reporting, and audit preparation -- deliberately distinct from `Config_Portability`, which is destructive backup/restore, not evidence for a third party. Every export carries an explicit disclaimer that it supports a review rather than establishing compliance or certification (§26), with named frameworks (Cyber Essentials, ISO/IEC 27001, PCI DSS, OWASP ASVS, CIS Controls) listed only as informational context.
- `includes/admin/views/page-overview.php`: new "Security Health" tab (Settings page) rendering the health summary and an "Evidence Export" download button; `includes/admin/class-admin-ui.php` gains `admin_post_wp_sam_export_evidence`, mirroring the existing certificate-download handler's pattern.
- No new schema in this phase -- both the health summary and the evidence export are computed live from existing tables; nothing new is persisted.

## [2.9.42] - 2026-09-02

### Added

- Phase 3F of `.roadmap/phase3_early_plan.md` (§19 Baseline and Drift, §17 Change Attribution): `includes/intelligence/class-baseline-state-builder.php` assembles a flat, diffable snapshot of locally-known configuration state -- effective CSP header per surface, simple pillar toggles, the external dependency and internal-asset-integrity inventories, certificate expiry, and WordPress/theme/plugin versions. Deliberately scoped to state this server already knows about itself; externally-observed state (redirects, DNS, cookies, what a client actually receives) is §20 External Verification, a later phase with its own infrastructure decisions.
- `includes/intelligence/class-baseline-store.php` (new `sam_security_baselines` table, schema v29): administrator-approved snapshots, only ever written by an explicit "Capture baseline" action -- there is no automatic baseline capture.
- `includes/intelligence/class-drift-scanner.php` + `class-drift-store.php` (new `sam_drift_records` table): diffs current state against the approved baseline, risk-classifies each difference (reusing the existing `low`/`medium`/`high`/`critical`/`unknown` scale and `Risk_Badge`), and attempts correlation with recent plugin/theme/core changes -- worded as correlation only, never causation, per §17. Differences that revert to match the baseline are marked resolved automatically; escalation of an open drift record's disposition (`expected`/`approved`) is always an explicit administrator action with a required reason.
- `includes/intelligence/class-change-log-store.php` + `class-change-attribution-recorder.php` (new `sam_change_log` table, §17 Change Attribution): a real event log of plugin/theme/core changes (item identity, version), hooked from the same `upgrader_process_complete`/`activated_plugin`/`deactivated_plugin` events `Learning_Window` already listens to, plus `switch_theme` -- kept entirely separate from `Learning_Window` so this can't affect its existing CSP-source-learning behaviour.
- `includes/admin/views/page-baseline.php`: new "Baseline & Drift" admin page (Drift / Baseline History / Change Log tabs); `page-verify.php` gains a link to it, since confirming resolved drift is explicitly part of this plugin's "Verify" lifecycle stage (§3.4).
- `includes/csp/class-scheduler.php`: a drift scan now runs as part of the existing daily cron job when a baseline has been approved.
- Fixed during development, before shipping: `Policy_Builder::build_policy_string()` embeds a fresh CSP nonce on every call (by design -- that's what makes a nonce meaningful as a security control), which would have made every CSP-header drift check a permanent false positive. `Baseline_State_Builder::normalise_nonce()` replaces the nonce token with a fixed placeholder before the value is ever stored or diffed, so only the *structural* policy is compared. Verified live: a fresh baseline followed by two consecutive scans produces zero false-positive drift.

## [2.9.41] - 2026-09-02

### Added

- Phase 3E of `.roadmap/phase3_early_plan.md` (§13 Traffic Protection Controls): this plugin's first schema and code path that can actively reject a request -- every prior pillar only ever adds response headers. `includes/intelligence/class-traffic-guard.php` is the enforcement engine, hooked on `init` (priority 1, ahead of routing) and `wp_login_failed`.
- `includes/intelligence/class-traffic-policy-store.php`: CRUD for the new `sam_traffic_policies` table (schema v28), one row per surface (`mode`: `observe`/`enforce`, rate-limit thresholds, login lockout thresholds). Every surface seeds in `observe` mode -- default-safety is structural, not a setting an installer could miss.
- `includes/intelligence/class-ip-rule-store.php`: CRUD and CIDR lookup (reusing Phase 3D's `Cidr_Matcher`) for the new `sam_ip_rules` table -- a manual admin allow/block list that applies regardless of a surface's mode, since it's a deliberate decision rather than automatic detection.
- `includes/intelligence/class-traffic-block-store.php`: automatic progressive-response state (`sam_traffic_blocks`) per (ip, surface) -- `observe -> warn -> throttle -> temporary_block -> extended_block -> persistent_block` (§13.7). Automatic escalation never reaches `persistent_block` on its own; only an explicit administrator action can.
- `includes/intelligence/class-rate-limiter.php`: fixed-window request counter, the same transient-based pattern `Event_Store`/`Hash_Manager` already use.
- `includes/admin/views/page-traffic.php` + three `admin_post_wp_sam_traffic_*`/`wp_sam_ip_rule_*` handlers in `includes/admin/class-admin-ui.php`: the new Traffic Controls page (Policy / IP Rules / Blocks tabs).
- `includes/csp/class-scheduler.php`: `purge_stale_traffic_blocks()` deletes non-persistent block rows not seen again within 30 days, run from the existing daily scan -- a source that stopped offending isn't penalised forever.
- Safety, verified live against a real WordPress instance, not just unit tests: an already-authenticated administrator (`is_user_logged_in()` + `manage_options`) is never blocked by automatic escalation, confirmed by hammering a tightly rate-limited, enforce-mode surface as both an anonymous visitor (blocked with `403` once over the limit) and the logged-in admin (unaffected, `200`) at the same time.
- ASN observation/control and Geo-IP controls (roadmap §13.4/§13.5) are deliberately deferred, not implemented as stubs: this plugin has no verified ASN/GeoIP data source yet, and fabricating one would be worse than omitting it (same reasoning as Phase 3D's scanner-vendor CIDR data).
- `includes/admin/views/page-control.php`: updated to reflect that this plugin can now block traffic (in Enforce mode only) -- the page previously stated flatly that nothing on the site is ever blocked, which Phase 3E makes no longer true.

## [2.9.40] - 2026-09-02

### Added

- Phase 3D of `.roadmap/phase3_early_plan.md` (§8 Identity Verification, §9 Commercial Scanner Intelligence, §31 "Identity Resolver" / "Network Intelligence Resolver"): `includes/intelligence/class-identity-resolver.php` resolves a request's claimed identity against a known-vendor catalogue -- a cheap, synchronous, per-request User-Agent match plus an optional in-memory CIDR check (`class-cidr-matcher.php`, IPv4 and IPv6), with a deliberately separate, never-automatic `verify_fcrdns()` for forward-confirmed reverse DNS, only ever triggered by an explicit admin action.
- `includes/intelligence/class-scanner-vendor-store.php`: CRUD for the new `sam_scanner_vendors` table (schema v27), the known-identity catalogue. Ships with two built-in rows (Googlebot, Bingbot) verified by FCrDNS against a vendor-published hostname suffix, not a hardcoded IP range -- see the class docblock for why commercial scanner vendors (Qualys, Tenable, etc.) are deliberately NOT seeded with guessed network data. Administrators can add their own, each requiring a `source_url` (§9.2).
- `includes/intelligence/class-scanner-identity-store.php`: storage for the new `sam_scanner_identities` table (schema v27). Enforces the roadmap's core rule -- "recognition is not authorisation" -- structurally: `record()`, the automatic per-request write `Request_Observer` now calls on every hit, can only ever set an automatic recognition state (`unknown` / `known_commercial_scanner` / `known_research_scanner` / `known_crawler` / `identity_conflict`); it can never overwrite an existing `customer_authorised` / `explicitly_denied` / `previously_authorised_expired` decision. Only an explicit admin action (`authorise()` / `deny()` / `clear_decision()`, each requiring a non-empty reason) can set or clear a decision.
- `includes/admin/views/page-intelligence.php`: the Continuous Intelligence page gains "Identities" and "Vendors" tabs alongside the existing Events tab. Identities shows every resolved identity with its recognition state and a same-row Authorise/Deny decision form (or Clear decision, once one exists); Vendors lists and manages the catalogue.
- `includes/admin/class-admin-ui.php`: three new `admin_post_wp_sam_scanner_*` handlers (`identity_decide`, `vendor_upsert`, `vendor_delete`), each nonce- and capability-gated, following this codebase's existing `admin_post_` convention.

## [2.9.39] - 2026-09-02

### Fixed

- `includes/csp/class-learning-window.php`: the CSP learning window -- the bounded period after a "material change" during which newly-discovered hosts from real browser violation reports get re-evaluated (`Violation_Reporter::learn_source_from_report()`) -- only reopened for `activated_plugin`/`deactivated_plugin` and `save_post_post`/`save_post_page`, plus `upgrader_process_complete` when `hook_extra['type'] === 'plugin'`. A theme update or WordPress core update never reopened it, even though either can change the exact bytes of inline scripts/styles and the third-party hosts a page depends on just as much as a plugin update can. `mark_plugin_upgrader_change()` is renamed to `mark_upgrader_change()` and now also recognises `'theme'` and `'core'` from `upgrader_process_complete`'s `hook_extra['type']`.
- `test/unit/LearningWindowTest.php`: added coverage for the renamed handler across all three recognised upgrader types plus an unrecognised type (`'translation'`) to confirm it's correctly ignored.

## [2.9.38] - 2026-09-02

### Changed

- `includes/admin/views/page-overview.php`: Layer 2's ("Controlled Automation") CSP row now shows the actual per-surface automation-mode badges in its Status cell (moved from Layer 4), replacing placeholder text that pointed down at Layer 4's Automation column. Layer 4's Automation column is removed entirely -- CSP was the only pillar row that ever populated it; every other pillar row hardcoded a bare `&mdash;` there.

## [2.9.37] - 2026-09-01

### Added

- Phase 3A of `.roadmap/phase3_early_plan.md` (§6.1 Primary Navigation): four new lifecycle landing pages -- Observe (`includes/admin/views/page-observe.php`), Decide (`page-decide.php`), Control (`page-control.php`), Verify (`page-verify.php`) -- each a curated set of links into existing pages/tabs with plain-language explanations of that lifecycle stage (§3), honest about what isn't built yet (Control explicitly disclaims real-time traffic blocking, still a future phase; Verify explicitly disclaims external verification, still a future phase). Rendered by four new `Admin_UI::render_observe()`/`render_decide()`/`render_control()`/`render_verify()` methods.

### Changed

- `includes/admin/class-admin-ui.php`: `add_menu_pages()` now registers Settings first (was "Overview", same slug/callback, still the default landing page -- deliberately registered first, not last, to avoid a real WordPress quirk where `add_submenu_page()` auto-inserts an extra "link back to parent" item the first time a differently-slugged page registers before the parent's own slug has been registered at all), then the four roadmap-ordered primary navigation entries (Observe, Decide, Control, Verify). The eleven existing technology-standard pages (Certificates, Continuous Intelligence, Cross-Origin Policies, CSP, HSTS, Permissions-Policy, Referrer-Policy, Reverse Tabnabbing, Scripts, X-Content-Type-Options, X-Frame-Options) are still registered exactly as before and stay fully reachable at their existing URLs, but a new `print_hidden_menu_css()` (hooked to `admin_head`, every wp-admin screen) visually hides their left-nav rows via CSS. This is deliberately not done with `remove_submenu_page()`: that call removes an entry from the `$submenu` global, but WordPress's own `user_can_access_admin_page()` walks that same array to authorize a requested page, so removing the entry 403s the page even by direct URL -- confirmed against a real running instance during this change. A CSS-only hide leaves every WordPress registry untouched. `plugin_page_hooks()` gains the four new pages' hook suffixes so they share the existing admin CSS/JS bundle and footer-text suppression.
- `test/bootstrap.php`: added stubs for `add_menu_page()` and `add_submenu_page()` (previously entirely unstubbed) so the new navigation structure is directly testable.

## [2.9.36] - 2026-09-01

### Added

- Phase 3C of `.roadmap/phase3_early_plan.md`: ten deterministic detector families for the Request Observation Framework (Layer 3: Continuous Intelligence), registered by default via `WP_SAM\Intelligence\Detector_Registry::register_defaults()` (mirrors `Automation_Mode_Registry::register_defaults()`'s established idempotent-registration pattern, called from `Plugin::register_detectors()` immediately before the existing `wp_sam_register_detectors` extension point). New abstract base `WP_SAM\Intelligence\Detectors\Pattern_Detector` (namespace/directory `includes/intelligence/detectors/`): concrete detectors declare only `rules()` (named regex patterns with severity/confidence/description) and `subject()` (what to match against); shared logic decodes the subject once (`urldecode()`, not `rawurldecode()` -- the subject mixes path and query string, and a query string's `+` conventionally means a literal space, exactly how PHP populates `$_GET` and how a browser encodes a space typed into a GET `<form>`), caps it at 4096 bytes, and reports the single highest-severity matching rule (not first-match -- a broad rule and a more specific, more severe rule can both match the same URL, e.g. `.git/` and `.git/config`).
  - Families: technology mismatch, command injection, SQL injection, sensitive-directory probing, sensitive-file probing, setup/install probes, script/web-shell probes, protocol injection, version-control artefacts, vulnerability probes -- exactly the ten named in the roadmap's Phase 3C deliverable list. Every family is Observe-only by construction (no Control Engine exists until a future phase); patterns were deliberately scoped against real false-positive traps the roadmap itself flags: a bare `.php`/`.cgi`/etc. extension is never matched outside two constrained contexts (a known web-shell filename, or any script file inside `wp-content/uploads/`, which should never contain one); sensitive-file rules match specific named files (`id_rsa`, `.env`, `wp-config.php.bak`, ...), never a generic extension; a SQL `UNION SELECT` keyword match is scored `medium`/`0.5` confidence rather than `critical`, since it also matches ordinary free-text search; every command-injection rule requires the matched word not be immediately followed by `=`, so it can never fire on an ordinary WordPress query var that happens to share a name with a shell utility (`?cat=5`, `?id=5`).
  - `WP_SAM\Intelligence\Surface_Classifier` gains `query_string()` (mirrors the existing `request_path()`'s sanitization exactly); `Request_Observer::build_context()` and the `detail` recorded to `Event_Store` both gain a `query_string` key -- three of the ten families (command injection, SQL injection, protocol injection) need to inspect parameter values, not just the path, to do their job. Deliberately does not inspect `$_POST` bodies (privacy: WordPress POST bodies routinely carry credentials; and realistic threat model: automated reconnaissance/scanning overwhelmingly probes via GET/query-string, since a scanner rarely has a valid POST target) -- a scope boundary, not an oversight.
  - No schema change (`WP_SAM_DB_VERSION` stays at 26) -- `sam_request_events` (added in 2.9.35) already has every column a Finding needs.

## [2.9.35] - 2026-09-01

### Added

- Phase 3B of `.roadmap/phase3_early_plan.md`: the Request Observation Framework (Layer 3: Continuous Intelligence), skeleton only -- no detector content, no blocking behaviour, matching the roadmap's own exit criteria ("detectors can be added without rewriting core request-flow architecture"). New `WP_SAM\Intelligence` namespace: `Surface_Classifier` (extracted from `Request_Surface`'s three surface-detection methods, which now delegate to it -- pure refactor, no behaviour change), `Ip_Resolver` (`REMOTE_ADDR` only, deliberately not `X-Forwarded-For`/`X-Real-IP`, which are spoofable without a trusted-proxy configuration this codebase doesn't have), `Detector` (abstract base for a future detector), `Detector_Registry` (ships genuinely empty in every build -- mirrors `Automation_Mode_Registry`'s extension-point pattern via a new `wp_sam_register_detectors` action), `Detector_Engine` (iterates registered detectors, fails open on a throwing detector), `Request_Observer` (hooks the same `send_headers` + `login_init` + `wp_redirect` combination `Header_Builder` already proves covers every surface, skips the plugin's own conflict-probe request), and `Event_Store` (new `sam_request_events` table, schema v26, modeled on `Pillar_Violation_Store`'s hourly rate-limited upsert pattern).
- New "Continuous Intelligence" admin page (Overview menu, alphabetically between Certificates and Cross-Origin Policies), showing whatever `sam_request_events` holds via the same `Table_Query` sort/filter/pagination convention as the CSP Violations and Cross-Origin Report-Only Evidence tabs, with an honest empty state ("no detectors are registered yet") rather than implying something is broken. The Overview tab's previously-static Layer 3 placeholder row now shows a real "Observing" status and links here.

### Changed

- `WP_SAM_DB_VERSION` 25 -> 26: adds `sam_request_events` (see above). Ships empty; self-heals onto an existing install the same way every other schema bump does.

## [2.9.34] - 2026-09-01

### Changed

- `includes/admin/views/page-overview.php`: the Overview tab's status table now renders all five protection layers as consistent `<h2>` + table sections, in roadmap order (1 -> 5), instead of Layer 4/5 getting real tables while Layers 1-3 were reduced to a single sentence (and Layer 2 wasn't mentioned at all). Layer 1 (Governance and Operations) gets a real per-row status: a computed pass/warning/fail rollup for Readiness (reusing the same `$readiness` data and `$status_badge` closure the Readiness tab itself uses), pass/fail for Recovery (from the existing `$downgrade_flag`), and the active distribution channel for Updates -- all three link to their respective tab on this same page. Layer 2 (Controlled Automation) links to CSP's Settings tab where automation mode is actually configured, rather than just being implied by the Automation column on the Layer 4 CSP row. Layer 3 (Continuous Intelligence) gets an honest placeholder row ("Planned for a future phase") in its correct structural position, ready for Phase 3B to fill in later instead of requiring new page structure at that point.

## [2.9.33] - 2026-09-01

### Changed

- `.github/workflows/wporg-deploy.yml`: decoupled the WordPress.org SVN deploy from `release-package.yml`'s `v*.*.*` trigger entirely. A plain version tag (`v2.9.33`) now only ever produces a GitHub release -- it was previously also the sole trigger for the WordPress.org deploy job, which meant every routine version bump had to be deliberately held back (no tag at all) to avoid an unwanted WordPress.org submission, which in turn also blocked the GitHub release. WordPress.org submission is now a second, explicit action: push a `wporg-vX.Y.Z` tag at the same commit once that version is confirmed ready (`git tag wporg-v2.9.33 v2.9.33`), which the deploy job's existing provenance and 24h rate-limit checks (added in 2.9.32) still gate as before.
- Fixed a real bug this surfaced: `10up/action-wordpress-plugin-deploy`'s `deploy.sh` derives its `tags/<VERSION>` SVN path from the triggering git ref itself when no `VERSION` env var is supplied (`${GITHUB_REF#refs/tags/}` with a leading `v` stripped) -- left alone, a `wporg-v2.9.33` tag would have published an SVN tag literally named `wporg-v2.9.33` instead of `2.9.33`. The provenance-check step now resolves and passes `VERSION` explicitly.

## [2.9.32] - 2026-09-01

### Changed

- Rewrote the plugin's one-line description (plugin header `Description:` and readme.txt's short description) -- the previous line ("Security headers that learn your site before they enforce -- plus free, automatic SSL/TLS certificate management.") mentioned only CSP and TLS certificates, leaving out the other eight header pillars and script integrity entirely. New line stays within WordPress.org's 150-character short-description limit (148 chars) while covering breadth (ten headers, TLS certificates, script integrity) and the free/no-paywall promise.
- `.github/workflows/wporg-deploy.yml`: the actual SVN publish step (and its stray-file-cleanup step) now only runs when both are true: (1) the tagged commit is the merge commit of a pull request from a `release/v<version>` branch into `main` (not a direct push, and not any other branch name) -- verified via `gh api repos/{owner}/{repo}/commits/{sha}/pulls`; (2) at least 24 hours have passed since the live SVN repository's last commit, read directly from `svn log` (WordPress.org human-reviews every submission and does not allow more than one per day). Neither gate affects `release-package.yml` (GitHub Release ZIP + update feed), which continues to run unrestricted on every version tag as before. The provenance check is a hard failure (an untracked-provenance deploy attempt is a policy violation); the rate-limit check is a graceful skip (tagging twice in a day just means the second one waits, re-runnable via `workflow_dispatch`). Approval semantics: this enforces "merged via PR from the correctly-named branch," not a literal GitHub review-approval, since GitHub does not allow a PR author to approve their own PR and this repo has no second collaborator account today.

## [2.9.31] - 2026-09-01

### Added

- Phase 3A of `.roadmap/phase3_early_plan.md` ("Settings-first" scope): the Overview tab's pillar table is now grouped into "Layer 4: Browser Security Policies" and "Layer 5: Transport & Certificate Trust", matching the plugin's own defence-in-depth model (already public on the docs site's `sam-security-layers.svg`, but never reflected in the admin UI itself until now). Closes a real gap where Certificates had no row in this table at all.
- `WP_SAM\Admin\Pillar_Registry`: single source of truth for the 12 pillars backed by `sam_pillar_profiles` (label, target admin page/tab, and a `resolve_status()` that distinguishes "no row exists yet" from "explicitly disabled" -- previously indistinguishable, both rendered as a plain "Off"). Replaces a view-local array in `page-overview.php` that had already drifted from `Activator::seed_default_pillar_profiles()`'s own pillar list once.
- `WP_SAM\Admin\Status_Badge`: shared status-badge component for the new table (`Not configured` / `Disabled` / `Report-only` / `Active`, plus a distinct style for CSP's per-surface automation posture), modeled on the existing `Risk_Badge` component. Does not touch CSP's own `enforce`/`report-only`/`disabled` mode values, CSS, or JS on its own dedicated pages -- this is a cross-pillar display-layer vocabulary only.

### Fixed

- `test_overview_pillar_rows_sort_alphabetically_by_label` was itself out of sync with the pillar list it was meant to guard -- it was missing "Internal Script Integrity". Now asserts against `Pillar_Registry::pillars()` directly instead of a second hand-maintained label list.

## [2.9.30] - 2026-09-01

### Changed

- Replaced `.wordpress-org/icon-{128,256}x{128,256}.png` and `banner-{772x250,1544x500}.png`. The 2.9.27 originals used a shield mark and amber accent invented without reference to VCNS's actual brand (the real mark -- a cloud-and-circuit icon in a teal-to-cyan gradient, `#00DAB7` to `#00B4E7` -- lives in the company's BIMI record and was never consulted), and the copy only called out CSP, HSTS, and SSL/TLS, materially underselling the plugin now that it also covers ten header pillars total, ACME/TLS certificate automation, and script/content integrity protections. New artwork reuses the real brand mark and gradient, and the banner copy enumerates the actual current scope.

## [2.9.29] - 2026-09-01

### Added

- A persistent `admin_notices` warning (site-wide, not just on the Certificates page) for as long as the most recent ACME run's status is `failed`, following the same recurring-until-resolved pattern already used for the schema-downgrade warning. `Certificate_Manager::last_run()` already tracked this; nothing previously surfaced it outside the Certificates > Issue/Renew tab, so a failed WP-Cron renewal could go unnoticed until the certificate expired.

### Fixed

- `docs/user-guide.html` and `docs/index.html` referenced seven screenshot filenames (`admin-overview-page.png`, `csp-profiles-tab.png`, `csp-for-review-tab.png`, `csp-policy-changes-tab.png`, `permissions-policy-page.png`, `csp-settings-automation-upgrade.png`, `admin-menu-structure.png`) that were never captured under those names -- the real screenshots that had since been added to `docs/images/` used a different (`sam-*.png`) naming convention, so those seven `<img>` tags rendered as broken images on the live GitHub Pages site since launch. Repointed all seven at the correct real files, and added screenshots to eight more sections that already had descriptive prose for a feature but no illustration of it (X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Strict-Transport-Security, Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy, Reverse Tabnabbing, Scripts External, Scripts Internal). Certificates (ACME/TLS) still has no dedicated section in the help site at all -- ten captured screenshots for it remain unused; see `docs/images/README.md`.
- The "Last run" row on the Certificates page's Issue/Renew tab now colour-codes the status (red for `failed`, green for `success`) instead of plain text, so a failure is obvious even when an administrator is already looking directly at it.

## [2.9.28] - 2026-09-01

### Fixed

- The listing icon/banner added in 2.9.27 deployed to `assets/assets/*` instead of `assets/*` -- the deploy's `ASSETS_DIR` is `.wordpress-org` itself, not a subfolder of it. Moved the four PNGs to the top level of `.wordpress-org/`, updated its README, and added `.gitignore` rules (`.wordpress-org/*.zip`, `wporg-resubmission-reply-draft.md`) after finding both had been accidentally committed in an unrelated commit and were live on the public SVN listing since before approval. `wporg-deploy.yml` now also removes that stale content from the live listing (existence-checked per path, safe to run on every future deploy once nothing's left to remove).
- Referrer-Policy's "unsafe-url" dropdown option carried a full explanatory sentence, stretching the select. Shortened to "unsafe-url (not recommended)"; the full explanation moved to the page's own intro text.
- `scripts-internal.php`'s Hash Inventory table had the same `.widefat.fixed` even-column-width problem as the For Review table (documented in 2.9.27) -- URL and Hash (full URLs, base64 SHA-384 hashes) now get proportionally more room via a new `wp-sam-hash-inventory-table` class.

## [2.9.27] - 2026-09-01

### Added

- Plugin icon (`icon-256x256.png`, `icon-128x128.png`) and header banner (`banner-1544x500.png`, `banner-772x250.png`) for the WordPress.org listing, in `.wordpress-org/assets/`.

### Changed

- Rewrote `readme.txt`'s Description section (and the matching plugin-header tagline) to lead with the actual value proposition -- report-only learning before enforcement -- instead of opening with a dense feature inventory. Full technical detail preserved, moved to a "For the technically curious" subsection.

### Fixed

- `page-csp-dashboard.php`'s For Review (Sources) table used `.widefat.fixed`, which sizes every column evenly from the header row regardless of actual content -- Host (a full domain plus the Known-source badge) was starved down to the same width as ID or State, forcing ugly mid-word wraps. Added explicit `nth-child` column-width percentages via a new `wp-sam-sources-table` class.
- `page-permissions-policy.php`'s per-directive `<select>` dropdowns were stretched wide because the "All" option's label included a full descriptive sentence ("-- any origin, including third-party iframes and embeds (not recommended)"). Shortened every option to a plain label and moved the fuller explanation into the page's existing description paragraph below the table, plus a `max-width` on the select itself.

## [2.9.26] - 2026-08-31

### Fixed

- No plugin functionality change. Release/CI pipeline fix only: `wporg-deploy.yml`'s SVN-repository-existence check assumed the `svn` CLI was preinstalled on `ubuntu-latest` runners; it isn't, so `svn info` failed instantly with "command not found," silently swallowed by `> /dev/null 2>&1`, and every run (including the one right after WordPress.org approved the plugin and provisioned its SVN repo) misreported "repository doesn't exist yet." Added an explicit `apt-get install subversion` step. This version exists solely to produce a properly `vX.Y.Z`-tagged commit for that now-working pipeline to deploy from -- `workflow_dispatch`/tag-triggered runs use the workflow file as committed on that exact ref, so the fix needed a new tag to take effect for a real deploy.

## [2.9.25] - 2026-08-31

### Added

- `Known_Source_Badge`: a display-only "Known" badge on the CSP Sources table for commonly-recognised third-party domains (Google Analytics, Google Tag Manager, Google Fonts, YouTube, Gravatar, jQuery/jsDelivr/cdnjs CDNs, and others), naming the recognised service on hover/focus. Purely informational -- never touches `risk_level`, the Decision Engine, or auto-approval. Extensible via the `wp_sam_known_source_labels` filter.

## [2.9.24] - 2026-08-28

### Fixed

- Made the DNS Made Easy, INWX, and GitHub Pages external-service disclosures in `readme.txt` explicit about why their linked Terms of Service/Privacy Policy documents live on a different domain than the API/service hostname itself: `dnsmadeeasy.com` has no legal pages of its own (its own site defers to DigiCert's, confirmed by direct fetch), `domrobot.com` doesn't resolve to a website at all (confirmed via DNS lookup -- it's an API-only hostname), and GitHub Pages (`*.github.io`) has no separate terms from `github.com`. v2.9.23 added the literal hostnames but an automated domain-matching check still couldn't associate them with their (necessarily different-domain) legal documents without this stated directly.

## [2.9.23] - 2026-08-27

### Fixed

- Added literal API hostnames (`api.dnsmadeeasy.com` for DNS Made Easy, `api.domrobot.com` for INWX) to `readme.txt`'s external-service disclosures, alongside the legal entities that already govern them. Both providers' actual API endpoints run under a different domain than the one already disclosed (DNS Made Easy's legal terms are DigiCert's; INWX's API is branded DomRobot), which an automated domain-disclosure scanner couldn't match without the literal hostname present.
- Added GitHub's Terms of Service and Privacy Statement links to the GitHub-channel update-manifest disclosure, covering GitHub Pages (the hosting infrastructure serving the manifest) itself, distinct from the manifest content being VCNS's own.

### Changed

- Documented `Content_Rewriter::maybe_start_buffer()`'s intentional cross-hook `ob_start()`/close pairing (opened on `template_redirect`, closed on `shutdown` via the shared LIFO stack) with an inline comment pointing to the closing call site and its test coverage, for static analysis that can't trace a buffer closed on a different hook than it was opened on.

## [2.9.22] - 2026-08-26

### Fixed

- A help paragraph on the Scripts page (`page-scripts.php`) literally contained the text `<link rel="stylesheet">` as prose describing what the plugin inventories -- an automated scanner (Plugin Check's `NonEnqueuedStylesheet` sniff) read it as an actual unregistered stylesheet tag. Reworded to describe the same thing without a literal tag-shaped substring, matching the fix already applied to the CORP page's `<script>` mention.

### Changed

- Added `phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped` annotations to ~80 `throw new \RuntimeException(...)`/`\Exception(...)` call sites across `includes/certificates/` (ACME client/crypto, `Certificate_Manager`, `Deployer`, `Dns_Provider`, and all 40 DNS provider drivers), each built from an interpolated domain name or raw API response body. Verified representative call sites: these messages are never echoed to a browser -- they're only passed to `Audit_Log::log()` or stored via `Certificate_Manager::record_run()`, both of which escape at actual display time, matching this codebase's established "escape late" convention. Purely a documented false-positive suppression; no behavioural change.

## [2.9.21] - 2026-08-25

### Fixed

- `_load_textdomain_just_in_time` "called incorrectly" notice (WordPress 6.7+) firing on every request. `Automation_Mode_Registry::register_defaults()` translates each automation mode's label immediately on registration, and `Plugin::bootstrap()` called it directly on `plugins_loaded` -- before `init`, which is what the check flags. Registration (and the `wp_sam_register_automation_modes` extension hook) now runs on `init` instead; every actual consumer of the registry (admin pages, admin-post/AJAX handlers, REST routes) already ran after `init`, so this changes no observable behaviour.
- A stale DigitalOcean Terms of Service URL (`/legal/tos` had gone 404) in the external-service disclosures in `readme.txt`, corrected to `/legal/terms-of-service-agreement`.

### Security

- DNS provider credential fields now sanitize non-secret values (account/zone name, endpoint host) via `sanitize_text_field()`, honoring each field's existing `'secret' => false` metadata, instead of leaving every field unslash-only regardless of whether it actually holds a credential.
- Three `$_SERVER` reads (`class-violation-reporter.php`, `class-challenge-http.php`, `class-request-surface.php`), already individually verified safe (strictly validated before use, never echoed or persisted raw), now also sanitize as defense-in-depth.

## [2.9.20] - 2026-08-21

### Fixed

- Admin notice queue (`Audit_Log::push_admin_notice()`) now de-duplicates by component/event instead of appending every occurrence unconditionally. `display_admin_notices()` only drains the queue when an admin actually visits wp-admin, so a condition that keeps re-logging while unattended (e.g. an hourly rate-limit hit) previously dumped one near-identical banner per occurrence on the next visit -- confirmed in production, 2026-08-21 (staging.alltimetech.co.uk): 15+ `hash_budget_exceeded`/`hash_learning_rate_limited` notices appearing at once after several days without an admin visit. The queue now keeps at most one notice per event type, always reflecting its latest occurrence; the 20-entry cap and the permanent `sam_audit_log` DB record are both unaffected.

## [2.9.19] - 2026-08-20

### Changed

- CSP > Profiles tab's Experimental column (Trusted Types) now matches the Bypass Best Practices column's layout: checkbox, then `require-trusted-types-for: 'script'` in code formatting, then a badge -- instead of a checkbox labelled "Trusted Types" with a separate description paragraph underneath. The badge reads "Report-only" rather than a risk tier, since Trusted Types is a hardening feature rather than a relaxation; a risk-tier label there would misleadingly imply enabling it is itself risky. Adds a neutral `.risk-report-only` badge style alongside the existing risk-tier colours.

## [2.9.18] - 2026-08-20

### Added

- CSP > Profiles tab's "Bypass Best Practices" catalog grows from 3 to 9 entries: `img_src_blob`, `media_src_data`, `media_src_blob` (low risk, same reasoning as the existing data:/blob: entries -- these directives can only ever render non-executable content), `script_src_attr_unsafe_hashes` (medium risk, mirrors the existing `style-src-attr` entry for inline event handler attributes), `script_src_wasm_unsafe_eval` (medium risk, CSP3's `'wasm-unsafe-eval'` permits only WebAssembly instantiation, not `eval()`/`new Function()`), and `worker_src_blob` (the catalog's first **high**-risk entry -- unlike the others, a blob-constructed `Worker` genuinely executes as JavaScript). Full reasoning for each in `docs/threat-model.md`.
- Profiles tab relevance filtering: a Bypass Best Practices entry is now only shown for a surface once that surface has actually triggered it at least once (per `csp_violation_reports`), or the entry is already enabled. Previously every entry in the catalog was shown for every surface regardless of relevance.
- Each Bypass Best Practices checkbox label now shows the literal `<directive>: <expression>` it adds (e.g. `img-src: data:`, `worker-src: blob:`) instead of a paraphrased description; the previous description is preserved as the lead sentence of the risk badge's hover tooltip.

### Changed

- `csp_policy_profiles.bypass_flags` (schema v25) replaces the three legacy per-entry tinyint columns (`bypass_img_src_data`, `bypass_font_src_data`, `bypass_style_attr_unsafe_hashes`) with a single JSON array of enabled `Policy_Builder::BYPASS_CATALOG` keys, so the catalog can keep growing without a schema migration for every addition. `Activator::migrate_consolidate_bypass_flags_into_json()` converts existing profiles once on upgrade; legacy columns are left in place (`dbDelta()` cannot drop columns) but nothing reads them again.

## [2.9.17] - 2026-08-19

### Added

- `Policy_Builder::EMPTY_CONTENT_HASH_TOKEN`: the sha256 hash of the empty string is now always present in `script-src-attr`/`style-src-attr`, regardless of hash inventory or admin approval (still gated by the surface's own `'unsafe-hashes'` opt-in, per CSP3 §6.1.2, same as any other attribute-context hash). An empty attribute value can never execute or style anything. Reported from live enforce-mode testing: a vendored carousel library's routine `jQuery.attr('style', '')` was blocked and reported as a violation purely because that exact empty value had never been individually captured and approved yet.

### Fixed

- Corrected two claims in `docs/threat-model.md`'s "Inline style attributes" section that the above change made inaccurate as written.

## [2.9.16] - 2026-08-19

### Fixed

- `Csp_Header_Formatter` (2.9.13) correctly wrapped each CSP directive name in `<strong>`, but a monospace `<code>` block's default browser bold weight alone wasn't visually distinct enough to read as emphasis at a glance on a standard monitor -- confirmed directly against a live install. Directive names now also carry a `wp-sam-csp-directive` class styled with colour on top of an explicit heavier weight.

## [2.9.15] - 2026-08-19

### Fixed

- Root cause of the unbounded `csp_hash_inventory` growth behind the 2026-08-19 incident (contained since 2.9.9, never previously identified): WordPress core's own Global Styles inline stylesheet -- and any theme/plugin inline `<style>` block added via `wp_add_inline_style()` -- can genuinely differ in content between renders of the exact same page, which no exact-content hash allowlist can ever usefully cover. `Nonce_Manager` had no way to nonce this specific shape of inline style block (its existing `style_loader_tag` hook only covers `<link>` elements); `Hash_Manager::inject_nonce_into_wp_inline_style_blocks()` now nonces any `<style id="{handle}-inline-css">` block (WordPress's stable naming convention) before hash extraction runs, so it's covered by the per-request nonce instead and never reaches `csp_hash_inventory` at all. The safety caps added in 2.9.9-2.9.11 remain as a backstop for anything else that behaves the same way.
- Corrected a stale docblock in `Hash_Manager::extract_and_record_style_attributes()` claiming `Policy_Builder` adds `'unsafe-hashes'` to `style-src-attr` automatically -- that stopped being true at schema v22.

## [2.9.14] - 2026-08-19

### Changed

- `media-src` now defaults to `'self'` instead of `'none'` for newly-seeded profiles (schema v24). `media-src 'none'` blocked WordPress core's own native Video/Audio blocks (self-hosted media) on every fresh install, with no corresponding security benefit -- unlike `object-src`/`frame-src`/`base-uri`/`worker-src`/`child-src` (correctly `'none'`), same-origin video/audio can't execute script. Every other same-origin-safe directive (`img-src`, `font-src`, `connect-src`, `form-action`) already defaulted to `'self'`.
- `Activator::migrate_loosen_media_src_default()`: loosens any existing profile's stored `media-src`, but only when it still exactly matches the old `['none']` default -- an administrator's deliberate customisation is left untouched.

## [2.9.13] - 2026-08-19

### Changed

- CSP > Policy Audit tab: `Csp_Header_Formatter` bolds each directive name in the Effective Header column, leaving its source list in normal weight, so a long header (often a dozen-plus directives on one line) reads as scannable segments instead of one dense run of text.

## [2.9.12] - 2026-08-19

### Changed

- About tab rewritten to describe every pillar this plugin manages -- CSP, the nine other header pillars, the page-rewrite protections (Reverse Tabnabbing, External Scripts/SRI, Internal Script Integrity), and the free-standing Certificates (ACME TLS) manager -- instead of being framed almost entirely around CSP.

### Fixed

- `Admin_UI::display_admin_notices()` showed a CSP hash-safety notice's raw technical detail (`Hash_Manager`, `csp_hash_inventory`, `source_file`/`source_context`, exact-content dedup) verbatim in the wp-admin dashboard -- language written for a developer investigating via the database, reported directly by a site owner who saw it. Adds `Admin_UI::ADMIN_NOTICE_SUMMARIES`, a plain-English summary shown as primary text for the three hash-safety events added in 2.9.9/2.9.10, with the full technical detail preserved behind a collapsed "Technical detail" disclosure (the same pattern already used for certificate key-generation failures). Unlisted events are unaffected.

## [2.9.11] - 2026-08-19

### Fixed

- `Policy_Builder::load_approved_hashes()`'s `ORDER BY last_seen_at DESC` had no tiebreaker. `last_seen_at` is a `datetime` column (one-second resolution) and many hashes commonly get bumped to the same second by the same page render, so ties were left in SQL-unspecified order. Confirmed in production: the same ~1,027-row backlog produced a "Dropped 34" hash-budget cutoff on one request and "Dropped 985" moments later on another, because the arbitrary tie order placed a different mix of cheap vs expensive hash tokens before the byte-budget cutoff each time. Added `id DESC` as a deterministic secondary sort key -- the same underlying data now always produces the same cutoff.

## [2.9.10] - 2026-08-19

### Fixed

- `Policy_Builder`'s `hash_budget_exceeded`/`policy_too_large` audit log entries (added in 2.9.9) now write at most once per rolling hour per surface, instead of once per request. Confirmed in production on staging: a surface still over its hash safety budget was logging a warning on every single pageview. The protective behaviour (dropping hashes / refusing an oversized header) is unaffected -- only the logging was throttled.

## [2.9.9] - 2026-08-19

### Fixed

- Unbounded growth of `csp_hash_inventory`, which could grow the emitted Content-Security-Policy header past common web-server response-header size limits and cause every request on an affected surface to fail with a silent 500 (confirmed in production: a 93,580-byte header from ~1,700 hashes on one surface). Root cause: `Hash_Manager::upsert()`'s dedup is exact-content-match only, so an inline script/style block whose content varies on every render (a value not routed through the plugin's nonce path) is learned as a brand-new row forever, never retired in practice because the existing `retire_stale()` needs in-request capture data that's essentially always empty for a WP-Cron-dispatched scan.

### Added

- `Hash_Manager`: a per-surface, per-hour cap (30, filterable via `wp_sam_max_new_hashes_per_hour`) on brand-new hash rows; reactivating an already-known hash is exempt.
- `Hash_Manager::prune_stale_by_age()`: real, time-based retirement across every surface (30 days by default), run from the daily cron scan, independent of any in-request capture data.
- `Policy_Builder`: a hard byte budget on hashes appended to the header (`wp_sam_max_hash_token_budget_bytes`, drops least-recently-seen hashes first once exhausted) and an absolute ceiling on the fully serialised policy string (`wp_sam_max_policy_string_bytes`) as a last-resort failsafe -- no header for that surface/request rather than one the web server might reject. Both log a warning/error to the audit log when triggered.
- `Hash_Manager` now populates `source_file` (request path) and `source_context` (a content excerpt) on insert -- both columns existed in schema already but had no writer before this.

## [2.9.8] - 2026-08-18

### Added

- `Config_Portability` (`includes/class-config-portability.php`): exports/imports administrator-authored configuration (policy profiles, source/hash approvals, other pillar profiles, dependency classifications, non-secret certificate settings, automation/reporting options) as a downloadable/uploadable JSON file, from the new Recovery tab. Both export and import are allowlist-based on table and option names -- an uploaded file can never write a table or option outside the declared list. Certificate secrets (`dns_credentials`, `cpanel_token`, `custom_key_pem`) are never exported and never written by import. Resolves roadmap issue #185.
- A new Recovery tab (Security Automation Manager -> Overview -> Recovery), holding schema-downgrade status and snapshot restore (moved from Readiness), Reset Plugin Data (moved from Readiness), and the new configuration export/import above.

### Changed

- The Readiness tab now covers plugin/schema/operational health checks only; schema-downgrade status, snapshot restore, and Reset Plugin Data moved to the new Recovery tab.
- Reset Plugin Data's confirmation phrase and description corrected from "RESET CSP DATA" / "start from a blank CSP canvas" to "RESET SAM PLUGIN DATA", accurately describing that reset clears every plugin table and option across all pillars, not just CSP.

## [2.9.7] - 2026-08-18

### Added

- `Rollback_Guard` (`includes/class-rollback-guard.php`): schema-downgrade detection and refusal (an older plugin version installed over a database a newer version already migrated no longer runs `Activator::activate()` against it -- a persistent admin notice and audit-log entry are recorded instead), pre-migration configuration snapshots (`sam_migration_snapshots`, schema v23), and same-schema-version snapshot restore from a new "Rollback and Recovery" section on the Readiness tab. Resolves roadmap issue #160.
- `docs/rollback-and-recovery.md`: the manual code-rollback process the plugin cannot automate, what to back up first, recovering from an unintended downgrade, and the vault-key interaction that can affect certificate/credential decryptability across a rollback.
- `.github/workflows/release-verification.yml`: a `rollback-and-recovery` job validating the full downgrade-detection and snapshot/restore cycle against a real WordPress + MySQL instance.

### Changed

- `WP_SAM_DB_VERSION` bumped to 23 (adds `sam_migration_snapshots`; no changes to any existing table).

## [2.9.6] - 2026-08-18

### Fixed

- The Updates and About tabs (`Security Automation Manager > Overview`) had a leftover inline `max-width: 760px` not present on any other tab on that page (`Overview`, `Readiness` rely on `.widefat`'s natural full width with no such constraint). Removed.
- `page-scripts.php`'s "Start Here" tab, and the `ajax_suggest_dependency_sri()`/`ajax_classify_dependency()` docblocks in `class-admin-ui.php`, claimed the "Suggest" SRI hash helper computes a hash "for you to review" before it's saved. Reading `assets/js/admin.js`'s handler shows the returned hash is written to the field and immediately posted to save it as the pinned value, with no confirmation step in between. Corrected the comments to describe the actual behaviour. Also corrected the same overstated framing in README.md and readme.txt.

### Changed

- The Cross-Origin-Embedder-Policy and Cross-Origin-Opener-Policy tabs' risk warnings now recommend a concrete minimum Report-Only duration (two weeks, covering a full content/traffic cycle), name the specific testing that can shorten it (manually exercising every embed/font/popup-based flow rather than relying on organic traffic alone), and note that the Report-Only Evidence table only reflects Chromium-based visitors, so manual testing in Safari/Firefox is still required regardless of wait time.

No DB schema change; `WP_SAM_DB_VERSION` stays at 22.

## [2.9.5] - 2026-08-18

### Changed

- `Acme_Crypto::generation_capability()` no longer returns the raw OpenSSL exception message as the administrator-facing explanation for why automatic key generation failed. It now returns a fixed, stable message (`Acme_Crypto::GENERATION_FAILURE_MESSAGE`) plus a separate `detail` key carrying the original diagnostic; `page-certificates.php` shows the stable message as the primary explanation and the raw detail inside a collapsed "Technical detail" disclosure.
- Normalizes stray em dashes (`-`) to plain hyphens in comments and translated admin-facing strings across `docs/`, `includes/`, and `test/`. Comment/string content only; no logic or identifiers touched.

### Added

- `docs/credential-vault-assessment.md`: a formal assessment of `Credential_Vault`'s SHA-256-based key derivation against entropy, domain separation, ciphertext compatibility, rotation, and recovery. Conclusion: the derivation is defensible as-is and is not changed by this release; two real gaps (no rotation support, silent data loss on a vault-key change) are documented as follow-up work, not fixed here.
- `.github/workflows/release-verification.yml`: real `wordpress` + MySQL install/upgrade lifecycle tests via WP-CLI -- clean install for both distribution channels, upgrade from the previous release, upgrade from the last pre-certificate release (v2.4.33), data-preservation and upgrade-idempotency checks, and a real-network manifest-rejection test against a mock HTTP server. Addresses the gap `docs/testing-requirements.md` named as the single biggest structural gap: no test previously ran against a real WordPress instance.
- Two regression tests in `test/unit/AcmeCryptoTest.php` covering the OpenSSL-error-message change.

### CI

- `ci.yml`'s PHP matrix expands from a single hardcoded PHP 8.1 to PHP 8.1, 8.2, 8.3, and 8.4 for the `test/unit/` suite (PHPCS still runs once, on 8.1).

No DB schema change; `WP_SAM_DB_VERSION` stays at 22.

## [2.9.4] - 2026-08-18

### Fixed

- Corrected documentation drift catalogued in `docs/consolidation-ledger.md`: the GitHub release package name/install instructions (README.md described the retired pre-2.8.0 two-asset scheme), a self-contradiction on the CSP automation default (README.md line 28 vs 102), and a stale claim across README.md, readme.txt, and the public help site (`docs/faq.html`, `docs/user-guide.html`, `docs/index.html`) that none of the nine non-CSP header pillars have a report-only mode -- Cross-Origin-Opener-Policy and Cross-Origin-Embedder-Policy have had one since the Stage 3 report-only learning workflow shipped.
- Added Certificates as a documented first-class product domain in README.md and readme.txt (previously mentioned only in readme.txt's external-services disclosure).

### Changed

- Replaced `SPECIFICATION.md` (v0.3, CSP-only, declared alignment to DB schema v4 against a live v22) with an authoritative v1.0 covering all product domains: security headers, CSP governance, script/stylesheet integrity, cross-origin policy learning, certificate lifecycle management, audit evidence, automation, distribution, commercial boundaries, privacy, operational resilience, and known limitations.
- Extended `test/unit/VersionConsistencyTest.php` to assert SPECIFICATION.md's declared DB schema alignment matches `WP_SAM_DB_VERSION`, and to regression-check that the corrected false claims don't reappear.

No functional or runtime behaviour changed in this release.

## [2.9.3] - 2026-08-18

### Added

- `docs/consolidation-ledger.md`: a verified repository assessment and roadmap reconciliation for all open roadmap issues at the time of writing, checked directly against code, tests, and CI rather than issue titles or changelog claims. Corrects repository identity (`vcns/csp-automation-manager` is a historical name for `vcns/security-automation-manager`, not a separate repository) and establishes the baseline for the ongoing public-release consolidation work.

No functional or runtime changes in this release.

## [2.9.2] - 2026-08-18

### Added

- `WP_SAM\Admin\Risk_Badge`: a shared helper for rendering the small coloured risk badge used across the CSP dashboard, consolidating three independent hand-rolled implementations (Profiles tab's Bypass Best Practices toggles, the Sources table, and the Policy Changes table) that had drifted into two different, inconsistent ways of showing the explanation -- a permanently-visible paragraph on the Profiles tab, versus a bare HTML `title=""` attribute (unstyled, not keyboard-reachable) on the other two. All three now render identically: the badge itself is the trigger for a hover/focus tooltip, reusing the existing `.wp-sam-meta-popover` accessible-popover mechanism (already used elsewhere in the admin UI) rather than introducing a new one.
- `risk-critical` and `risk-unknown` badge colours in `assets/css/admin.css` -- both are real values `Decision_Engine` assigns (`CSP-SRC-004` unsafe keywords, `CSP-SRC-002`/`CSP-EVID-001` missing-directive-or-evidence cases) that previously rendered as an unstyled badge wherever they reached the Policy Changes table.

## [2.9.1] - 2026-08-18

### Changed

- `Acme_Crypto::generation_capability()`: a live probe (an actual throwaway key generation, not just `extension_loaded('openssl')`) for whether this server can generate certificate keys right now -- the extension can be compiled in and still fail at runtime (the missing-openssl.cnf case `generate_key()` already works around; RANDFILE write restrictions; other host lockdowns). The Certificates Configuration tab now uses this to decide the "bring your own private key" section's visibility: hidden entirely on a working server, shown with the specific failure reason and the matching `openssl genpkey` command when generation fails, and still shown (without the error framing) when a key is already stored so a server that starts working again still has a way to remove it. Corrects 2.8.0's implementation, which rendered the upload box unconditionally as an "optional" field regardless of server capability.

## [2.9.0] - 2026-08-18

### Changed

- `Policy_Builder::build_policy_string()` no longer adds `'unsafe-hashes'` to `style-src-attr` automatically whenever a hash is present for it. A security scanner correctly flagged this as a scanner-worthy posture change on a production site after it shipped as automatic behaviour in v2.4.31 (#213) -- it needed to be a conscious, reversible admin decision, not the plugin's own call. It is now its own `BYPASS_CATALOG` entry (`style_src_attr_unsafe_hashes`), reusing the same per-surface opt-in mechanism as the existing `img-src`/`font-src` `data:` entries; a captured style-attribute hash sits inert until enabled. Schema v22 adds `bypass_style_attr_unsafe_hashes` to `csp_policy_profiles`.
- `BYPASS_CATALOG` entries now carry a `risk_level` (low/medium), rendered as a badge next to each Profiles-tab checkbox. The catalog is no longer implicitly restricted to only low-risk entries -- the safety property was always "nothing is silently automatic," not "nothing risky is ever offered." Documented at length in `Policy_Builder::BYPASS_CATALOG`'s docblock and a new "Bypass Best Practices catalog" section in `docs/threat-model.md`, including why this entry cannot affect `script-src-attr` or script execution (CSP directives don't cross-contaminate).
- The Profiles tab's bypass violation-count query is now built generically from `BYPASS_CATALOG`'s `directive`+`violation_blocked_uri` pairs instead of being hardcoded to `img-src`/`font-src`, so a future catalog entry shows a real count instead of a silent zero.

### Fixed

- The plugin version-history docblock never documented schema v21 (added for ACME certificate storage in 2.5.0) and this change would otherwise have collided with it, reusing "v21" for a second, unrelated schema bump. Rebasing onto current main surfaced the gap: v21 is now documented, and this release's column addition correctly lands as v22 (`WP_SAM_DB_VERSION` bumped accordingly) -- without that bump, a site already upgraded to 2.8.0 (`wp_sam_db_version=21`) would have silently never run the migration that adds `bypass_style_attr_unsafe_hashes`, since `maybe_upgrade_db()`'s version check would already read as satisfied. Verified live: a site pinned at `db_version=21` correctly advances to 22 and gains the column on first boot of this release.

## [2.8.0] - 2026-08-18

### Added

- Bring-your-own private key on the Certificates Configuration tab: a pasted PEM is validated with `openssl_pkey_get_private()` before it is accepted (rejected keys are never saved), sealed by `Credential_Vault`, reused for every order in place of per-order generation, and removable via an explicit clear checkbox (`Certificate_Store::save_config()` gains a null-means-clear sentinel so "blank keeps stored secret" semantics stay intact). The UI shows the exact `openssl genpkey` command for the selected key type.
- Requirements preflight on the Certificates page: missing ext/openssl or ext/sodium now yields a plain-language admin error (including what to ask the host for) instead of a mid-order fatal. Deliberately honest boundary: BYO key removes the key-generation dependency only - ACME JWS signing still requires ext/openssl.
- HSTS/HTTP-01 compatibility documented in the UI and a new docs FAQ: HSTS (and preload) binds browsers, not ACME validators; Let's Encrypt starts at http:// and follows the redirect to HTTPS, so only a closed port 80 breaks HTTP-01.

### Changed

- GitHub releases publish exactly one asset: `security-automation-manager-vX.Y.Z.zip`, now the GITHUB-channel (self-updating) build. The WordPress.org-channel package remains a CI artifact for the SVN pipeline but is no longer a release download (attaching it is how a site silently loses its updater). Naming-semantics flip documented in docs/release-and-publishing.md; v2.7.0's assets were retro-normalised to match.

## [2.7.0] - 2026-08-18

### Added

- Explicit DNS-01 / HTTP-01 validation-method radio on the Certificates Configuration tab. Previously the challenge type was silently derived from whether a DNS provider was configured; now it's a first-class choice, and selecting HTTP-01 hides the 41-provider dropdown and credential fields (stored credentials survive the round trip for switching back). `Certificate_Manager` already honoured `challenge` from config, so no order-flow changes.
- CSR subject (distinguished name) fields: organisation, organisational unit, country (validated ISO alpha-2), state, and locality flow from the Configuration tab through `Acme_Crypto::csr_der()` into the signing request, with blanks omitted. Documented honestly: DV CAs (Let's Encrypt included) issue on domain names only and strip these from the final certificate; they matter for CAs/workflows that consume the CSR itself.

### Changed

- The Certificates page is split into three tabs - Configuration, Issue / Renew, Install - using the same nav-tab conventions as the CSP dashboard, and content now uses the full window width (the old single page constrained everything to 640-860px). Settings save per-tab: each tab's form carries a section marker and the handler only overrides that section's keys, so saving Install settings can never clobber Configuration and vice versa.
- The Domains box pre-fills from the site's own host (plus `www.` for bare registrable domains) when unconfigured.

## [2.6.1] - 2026-08-18

### Changed

- The Export deployment mode's guidance no longer assumes the administrator knows their host's filesystem layout. The Certificates page now spells out the three requirements (absolute path outside the web root -- shown against the site's actual `ABSPATH` -- writable by the PHP user, directory pre-created if the plugin can't), and adds a "not sure / lacking permissions?" paragraph with the exact request to send a hosting provider, including the alternative of asking for a control-panel API token to upgrade to fully automatic installation. `docs/certificates.md`'s export section gains the same expansion.

## [2.6.0] - 2026-08-17

### Added

- 34 additional DNS-01 provider drivers (41 total): AWS Route 53 (full SigV4 request signing), Azure DNS (OAuth2 client-credentials against ARM), Google Cloud DNS (service-account JWT flow, signed with the existing `Acme_Crypto` RS256 path), Akamai Edge DNS (EdgeGrid EG1-HMAC-SHA256), Alibaba Cloud DNS (RPC HMAC-SHA1 signatures), OVH (time-drift-corrected request signatures, EU/CA/US endpoints), DNS Made Easy (HMAC header auth), plus token/basic-auth drivers for Bunny.net, ClouDNS, deSEC, DNSimple, DNSPod, Domeneshop, DreamHost, Dynu, easyDNS, GleSYS, INWX (JSON-RPC session), IONOS, Joker.com (their documented svc TXT-replace ACME mechanism), Mythic Beasts, Namecheap (safe read-modify-write around its replace-everything setHosts, refusing to write when the read fails), Name.com, NameSilo, netcup (CCP session API), Netlify, Njalla, NS1, PowerDNS's built-in HTTP API (self-hosted), Scaleway, Vercel, and Vultr.
- Two universal mechanisms that cover effectively every provider not listed: an **acme-dns** driver (one-time `_acme-challenge` CNAME delegation to an acme-dns instance -- works with any DNS host, including ones with no API) and an **RFC 2136** driver speaking TSIG-signed (RFC 8945, hmac-sha256/sha512/sha1/md5) dynamic updates over raw TCP wire format to BIND, Knot, PowerDNS, Windows Server DNS, and any other standards-compliant authoritative server.
- Provider credential field definitions now carry input-type metadata (`secret`, `textarea`), so the Certificates page renders endpoints/usernames as text, secrets as password fields, and Google's service-account JSON as a textarea. Everything is still sealed by `Credential_Vault` before storage.

## [2.5.0] - 2026-08-17

### Added

- TLS certificate automation over ACME v2 (RFC 8555), implemented entirely in PHP over `wp_remote_*` -- no shell-outs, no certbot, shared-hosting compatible. The new Certificates admin page configures domains (wildcards supported), contact email, key type (ECDSA P-256 default / RSA-2048), a Let's Encrypt staging/production toggle, DNS provider credentials, and deployment mode; "Issue / Renew Now" queues the order through WP-Cron so DNS-propagation waits never block a browser request, and a daily `wp_sam_cert_renewal_check` re-issues production certificates inside the 30-day expiry window.
- DNS-01 challenge support with seven built-in provider drivers (Cloudflare, DigitalOcean, Gandi LiveDNS, GoDaddy, Hetzner DNS, Linode/Akamai, Porkbun), a shared zone-resolution/relative-name base class, and a `wp_sam_dns_providers` filter for third-party drivers. HTTP-01 is the automatic fallback when no provider is configured, served at `parse_request` priority 0 so it works regardless of permalink or `.htaccess` state. (ACME v1 is not implemented: Let's Encrypt retired those endpoints in June 2021; "HTTP fallback" means the http-01 challenge type within v2.)
- Deployment adapters for the privilege boundary that certificate *installation* (unlike issuance) runs into: cPanel UAPI `SSL::install_ssl` (fully automatic where the host exposes it), an export directory (refuses paths under the web root) feeding a root-side install hook, and manual PEM download. Platform-by-platform steps, the install_ssl dependency caveat, and the real-cron renewal recommendation live in `docs/certificates.md`.
- `Credential_Vault`: sodium `crypto_secretbox` encryption at rest for DNS credentials, cPanel tokens, ACME account keys, and certificate private keys (schema v21 adds the `sam_certificates` table). The vault key derives from `WP_SAM_CERT_VAULT_KEY` in wp-config.php when defined (recommended), falling back to `wp_salt('auth')`; either way a database dump alone yields no usable secret. Settings forms treat blank password fields as "keep stored secret", so plaintext never round-trips to the browser.

## [2.4.33] - 2026-08-17

### Fixed

- `Hash_Manager`'s capture buffer opened on the head hooks at default priority 10, but WordPress core prints every enqueued style -- including all `wp_add_inline_style()` blocks, which is how themes and page builders emit their per-page `<style>` CSS -- via `wp_print_styles` at `wp_head` priority 8 (head scripts at 9). Those blocks were already sent before `ob_start()` ran, so they were never hashed, never entered the policy, and were blocked on enforce-mode surfaces (observed in production as repeated `style-src-elem` violations for head styles the policy knew nothing about). The buffer now opens at `PHP_INT_MIN` on `wp_head`, `admin_head`, and `login_head`. Known limitation: `admin_head` fires after `admin_print_styles`, so admin-enqueued styles still escape capture -- acceptable while wp-admin strict CSP remains best-effort (core Trac #59446).

## [2.4.32] - 2026-08-17

### Added

- The CSP dashboard's competing-CSP-header banner gains a "Dismiss these findings" button. Dismissal records `wp_sam_conflict_dismissed_at` and the banner query only surfaces `conflict_detector` audit findings newer than that moment -- the audit log itself is untouched. Because both sources throttle their logging (`Violation_Reporter`'s disposition-mismatch check at most once per surface/directive per hour), a still-live conflict re-opens the banner on its own within about an hour of real traffic, while a stale one (e.g. cached responses from before an enforce promotion) stays dismissed. The option is removed by Reset Data and on uninstall.

### Changed

- Risky dropdown values are now labelled as such instead of reading identically to the safe options around them: Referrer-Policy's `unsafe-url` (always sends the full URL, including query string, even cross-origin and over plain HTTP) and Permissions-Policy's `all` token (grants the feature to any origin, including third-party iframes and embeds).

### Fixed

- Profiles table column widths: the fixed-width `nth-child` rules written for the pre-2.4.31 six-column layout pinned the new "Bypass Best Practices" column to a narrow 140px while leaving the real Last Updated/Actions columns unruled, producing the cramped, oversized layout reported against the live site. (#217)

## [2.4.31] - 2026-08-16

### Fixed

- `Discovery`'s 'admin' surface crawl target was `admin_url()`, fetched anonymously via `wp_remote_get()`. This never saw real admin-only content (a logged-out request redirects to `wp-login.php`, which the 'login' surface already crawls directly), and on at least one production site triggered a fatal error (surfaced as `crawl_http_error: HTTP 500`) when hit by a bot-like anonymous request, interrupting Run Manual Scan entirely. The 'admin' crawl target is removed; real admin-surface inline content is unaffected, since `Hash_Manager` already captures it passively on every genuine logged-in admin page view.
- The violations dashboard's Details popover now notes, for any row whose `blocked_uri` has no host (`inline`, `eval`, `data:`, etc.), that `occurrence_count` aggregates every occurrence of that directive+token combination rather than counting distinct content blocks -- a page with many different inline scripts/styles still shows as one row. Points admins at the Scripts (Internal Script Integrity) tab, where individually captured content hashes actually live.

### Added

- `Hash_Manager` now also captures inline `style="..."` **attribute** values (previously only `<script>`/`<style>` **element** blocks were extracted), recording their hashes under a new `style-src-attr` directive value. `Policy_Builder` adds the CSP3-required `'unsafe-hashes'` keyword to `style-src-attr` automatically, and only, when it has at least one approved hash. Together these close a gap where `style-src-attr` had no discovery or approval path at all -- on one production site this was the single largest source of CSP violations under enforce mode.
- Profiles tab gains a "Bypass Best Practices" column: a small, deliberately curated, per-surface opt-in for `img-src: data:` and `font-src: data:` -- directive+token combinations that `Decision_Engine` correctly excludes from *automatic* approval (`CSP-SCHEME-002`) but which are safe for these two specific directives, since inline image/font data cannot execute as script. Each checkbox shows the surface's actual observed violation count for that directive. Schema v20 adds `bypass_img_src_data`, `bypass_font_src_data` columns to `csp_policy_profiles` (default off).

## [2.4.30] - 2026-08-14

### Added

- Stage 3 of the Cross-Origin-Opener-Policy / Cross-Origin-Embedder-Policy report-only learning workflow: the Cross-Origin Policies page's COOP and COEP tabs replace the plain enabled checkbox with a per-surface Mode selector (Disabled / Report-Only / Enforce), and gain a Report-Only Evidence table below -- same `Table_Query` sort/filter/pagination conventions as the CSP Violations tab -- showing what's been observed in `sam_pillar_violation_reports` for that pillar, plus a simple "N violations in the last 7 days" summary. Cross-Origin-Resource-Policy and X-Permitted-Cross-Domain-Policies, which have no report-only or Reporting API mechanism, are unchanged. Promoting a surface from Report-Only to Enforce is always this manual mode-selector choice -- nothing here is auto-promoted.

### Fixed

- `test/bootstrap.php` never stubbed `wp_kses_post()`, which every admin view's intro/warning HTML passes through -- a pre-existing gap that happened to go unnoticed because no test previously rendered a code path calling it. Caught by, and fixed alongside, the new render-without-fatal tests for the Cross-Origin Policies page's four tabs.

## [2.4.29] - 2026-08-14

### Added

- Stage 2 of the Cross-Origin-Opener-Policy / Cross-Origin-Embedder-Policy report-only learning workflow (see 2.4.24's stage 1 backend plumbing): `Cross_Origin_Opener_Policy_Builder` and `Cross_Origin_Embedder_Policy_Builder` gain a `mode` (`disabled` / `report-only` / `enforce`) alongside their existing `value`, stored in the same `sam_pillar_profiles.payload` JSON. `report-only` emits the `-Report-Only` variant of the header plus the shared `Reporting-Endpoints`/`Report-To` headers (unconditionally -- unlike CSP, COOP/COEP have no `report-uri` fallback, so the Reporting API is the only delivery mechanism); `enforce` emits the real header as before. A profile with no `mode` key (every profile that predates this change) defaults to `enforce`, preserving existing behaviour exactly -- nothing that was already enforcing silently switches to report-only or stops emitting on upgrade.
- The shared `wp_sam_set_pillar_value` AJAX handler accepts an optional `mode` field, validated per-pillar and gated to COOP/COEP only; every other pillar's payload is completely unaffected since the field is simply never sent for them.
- No admin-facing UI yet for setting `mode` -- that ships in stage 3, a dedicated view per pillar with an evidence table (replacing the plain enabled-checkbox picker these two currently share with every other simple pillar).

## [2.4.28] - 2026-08-14

### Fixed

- `Policy_Builder::build_policy_string()` added `'strict-dynamic'` only to `script-src`, never to `script-src-elem`. `script-src-elem` is always explicitly present in every profile's directives (see `default_directives()`), and per CSP3, once an `-elem` directive is explicitly set it has exclusive authority over element-level checks -- the base directive is never consulted as a fallback for those checks. This meant a strict-dynamic profile still blocked same-origin scripts dynamically inserted by already-trusted code, e.g. WordPress core's own `zxcvbn-async.js` password-strength-meter loader on `wp-login.php`, which injects `<script src="zxcvbn.min.js">` via JavaScript with no nonce. `strict-dynamic` (and the accompanying host-allowlist suppression, since browsers ignore host sources once strict-dynamic is present) now applies to both `script-src` and `script-src-elem`.
- Approved inline-script/style hashes from `csp_hash_inventory` were appended only to `script-src`/`style-src` -- the literal directive names `Hash_Manager` stores captured hashes under -- never to `script-src-elem`/`style-src-elem`. Since those `-elem` directives are always explicitly present and take the same CSP3 exclusive-authority precedence described above, an administrator approving an inline script or style block from the violations review queue could see the approval have no actual effect: the hash landed in a directive the browser never consults for `<script>`/`<style>` element checks. Approved hashes now propagate to both the base directive and its `-elem` counterpart, mirroring how nonce injection already handles both.

## [2.4.27] - 2026-08-14

### Fixed

- `Violation_Reporter::learn_source_from_report()` was only ever invoked when a violation report happened to be its fingerprint's very first `INSERT` into `csp_violation_reports` -- every later occurrence of the same violation took the `ON DUPLICATE KEY UPDATE` path and never attempted to propose a source again. `Policy_Change_Manager::propose_source()` is itself idempotent (it looks up any existing `csp_source_inventory` row and refreshes evidence rather than duplicating, and separately respects a prior administrator rejection via `is_suppressed()`), so this one-shot gate was never necessary for correctness -- it just meant a source whose first-ever occurrence landed while the learning window was closed (or for any other transient reason) never got a second chance, and kept violating in production with zero path back into the review queue. Source learning is now attempted on every report, gated instead on whether `csp_source_inventory` already has a row for that `(surface, directive, host)` -- closing the gap while still avoiding redundant queries and, for an already-rejected source, repeated audit-log entries on every duplicate report.

## [2.4.26] - 2026-08-14

### Changed

- Renames the REST API namespace from `security-manager/v1` to `sam/v1`, matching the plugin's internal `wp_sam_`/`WP_SAM` naming convention used everywhere else. The public violation-report endpoint is now `/wp-json/sam/v1/report`; the privileged admin endpoints are now under `/wp-json/sam/v1/admin/*`; the Stripe webhook endpoint (private/commercial build only) is now `/wp-json/sam/v1/webhook/stripe`.
- `security-manager/v1/report` remains registered as a legacy alias against the same handler, since a browser holding a CSP header issued before this release keeps POSTing to that URL until it receives a fresh policy -- the same treatment given to the original `csp-manager/v1` rename. `Conflict_Detector`'s self-recognition check now accepts either URL, so a stale cached response carrying the old alias is not misreported as a competing CSP source.
- The older `csp-manager/v1` alias (from the original CSP Manager -> Security Automation Manager plugin rename) has been fully retired -- its own transition window closed long ago and it no longer reflects any current name.

## [2.4.25] - 2026-08-14

### Fixed

- `Violation_Reporter::store_report()`'s `INSERT ... ON DUPLICATE KEY UPDATE` never refreshed `disposition`, `effective_directive`, `original_policy`, or `status_code` on the UPDATE path -- only `occurrence_count`, timestamps, and a handful of other evidence fields were kept current. Since a violation's fingerprint is stable (surface + host/blocked_uri + directive) but not time-bound, these four fields stayed frozen at whatever the very first report for that fingerprint happened to carry, for as long as that row existed. In practice this meant: promote a surface from report-only to enforce, and every violation fingerprint first recorded *before* that promotion kept showing `disposition: report` on the Violations tab forever afterward, even though the browser was correctly sending `enforce` on every new occurrence -- reading exactly like a competing CSP header, when it was actually just stale display data. Existing rows self-correct on their next occurrence once this ships; no backfill migration needed given how quickly new reports arrive on an active site.

## [2.4.24] - 2026-08-14

### Added

- `sam_dependency_inventory` (schema v19) gains `last_seen_url`: the most recently observed full URL (path and query included) for a governed third-party origin. Deduplication stays at the origin (scheme+host) level -- unchanged -- but the "Suggest" SRI hash helper needs an exact file URL to fetch and hash, which the origin alone can't provide. The Scripts > External inventory's Suggest field is now pre-filled with this URL, and a metadata popover on the Origin column surfaces it for every row regardless of classification.

### Changed

- Documentation (`README.md`, `docs/architecture.md`, `docs/user-guide.html`, `docs/faq.html`) updated to describe the retained last-seen URL and its query-string privacy tradeoff, rather than claiming only the bare origin is ever stored.

## [2.4.23] - 2026-08-14

### Changed

- Moves the Update Channel page into the Overview page as a new "Updates" tab, replacing its own separate submenu entry. `Security Automation Manager > Update Channel` is now `Security Automation Manager > Overview > Updates`. No behavioural change to the content itself -- same diagnostics, same WordPress.org/GitHub-channel branching.

## [2.4.22] - 2026-08-14

### Fixed

- Fatal error on both Scripts tabs (`External` and `Internal`): `page-scripts.php` correctly imports `Table_Query`, `Dependency_Governance_Builder`, and `Internal_Script_Integrity_Builder` via `use` statements, but PHP's `use` imports are per-file, not inherited through `require()` -- the two partial files it includes (`includes/admin/views/partials/scripts-external.php`, `scripts-internal.php`) referenced those classes bare, with no import of their own, and fatalled with "Class not found" on every visit. Both partials now import what they use directly. Added render tests for both tabs (`AdminUITest`) that exercise the actual `page-scripts.php` require() chain, plus `checked()`/`disabled()`/`submit_button()` test stubs that were missing from `test/bootstrap.php` -- the reason no existing test caught this.
- CSP violation report rate limiting was shared across all directives on a surface (500/hour total). A single noisy directive (e.g. hundreds of inline style violations on one page) could exhaust the shared budget and silently drop reports for every other directive on that surface, including a brand-new violation type never seen before. Now scoped per (surface, directive).

### Added

- Quick range buttons (last hour / 6 hours / day / 7 days) on the CSP Violations tab, alongside the existing custom date-range filter.
- `Violation_Reporter` now flags a likely competing Content-Security-Policy header: when a browser-reported disposition doesn't match this plugin's own configured mode for that surface (this plugin only ever emits one policy per surface, so a genuine per-directive split can't originate here), a throttled warning is logged to the same audit trail `Conflict_Detector` already uses, and the CSP dashboard now shows a persistent banner (not just a dismissible admin notice) summarising recent findings from both sources.
- "First seen" added to the Violations tab's metadata popover, and the "Occurrences" column is now explicitly labelled as a lifetime total (it never resets, unlike the seen-range filter which only affects which rows are shown).

## [2.4.21] - 2026-08-14

### Security

- Hardens `Github_Update_Checker::is_allowed_package_url()` to reject any download-URL path containing a `..` segment. `str_starts_with()`/`str_ends_with()` are plain string prefix/suffix checks, not path normalisation -- a path containing `..` could textually satisfy both while an HTTP client resolves it to a different location on the same trusted host before the request is even sent, e.g. escaping the update path into another product's folder. Found via a structural comparison against two sibling VCNS updater implementations (roadmap #157); this plugin's own `is_valid_slug` check in `validate_remote_info()` was confirmed to already be a defense-in-depth layer neither sibling has.

### Changed

- Tightens `auto_update_gate()`'s parameter/return type hint from `mixed` to the actual WordPress-documented `?bool`.

## [2.4.20] - 2026-08-13

### Added

- Update Channel admin page (roadmap #158): installed version, active build channel, update manifest URL, last successful/failed update check, available version, manifest validation status, package checksum verification status, last applied-update result, and whether `WP_SAM_DISABLE_AUTO_UPDATE` is defined. A WordPress.org build shows only its own version/channel summary and never references the GitHub update service or the diagnostics option it writes -- `Github_Update_Checker` isn't even present in that build's ZIP.
- `Github_Update_Checker` now persists check/checksum/applied-update outcomes to a `wp_sam_update_diagnostics` option. The existing manifest cache is a short-lived transient purely to reduce remote requests; once it expired, any record of the last check's outcome disappeared with it, which made a real status page impossible. No secret or credential is ever stored -- every field is a timestamp or a short, fixed-vocabulary status code, and the manifest itself is a public JSON file.

## [2.4.19] - 2026-08-13

### Changed

- Seeds a vetted, enabled-by-default configuration for X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Reverse Tabnabbing, Cross-Origin-Resource-Policy, Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy, and X-Permitted-Cross-Domain-Policies on every surface that doesn't already have a row (schema v18), so a fresh install ships hardened by default instead of requiring nine separate admin pages to be found and enabled individually. Only fills in a missing `(pillar, surface)` row -- a surface already configured, enabled or deliberately left disabled, is never touched by this on upgrade. `X-Frame-Options` is `DENY` on the API surface and `SAMEORIGIN` elsewhere; `Cross-Origin-Resource-Policy` is `same-site` on the API surface and `cross-origin` elsewhere; `Referrer-Policy` is `no-referrer` on the API surface and the existing `strict-origin-when-cross-origin` default elsewhere; `Permissions-Policy` sets every known directive to `none` except `autoplay=self` on the frontend surface; `X-Permitted-Cross-Domain-Policies` is `none` everywhere. `Cross-Origin-Opener-Policy` and `Cross-Origin-Embedder-Policy` ship `unsafe-none` -- the spec's no-op value for both, present only so external scanners see the header rather than adding real cross-origin isolation; a future periodic self-scan (tracked separately) is intended to identify when a site can safely move to a stricter value.
- HSTS is deliberately excluded from the above: unlike everything else in this list, HSTS is extremely hard to undo once a browser (or, worse, a preload list) has cached it, so it stays a per-surface opt-in rather than a blind default.
- Changes the default CSP automation-approval mode from Manual to Automatic (high approvals only) for every surface. A new install now auto-approves proposed CSP sources below the high-risk threshold into the report-only policy on their own evidence, with high-risk sources still requiring a human decision -- this only changes who approves a *proposed* source. CSP itself still starts report-only on every surface, and promotion to enforce still requires a deliberate administrator action through the existing learning window and promotion gate, regardless of automation mode.

## [2.4.18] - 2026-08-13

### Changed

- CSP Profiles page: renamed the "Trusted Types" column to "Experimental" and moved its checkbox inline with the feature's own name rather than a generic "Enabled" label, with a shorter explanation below. The checkbox is still pinned to always-report-only regardless of surface mode -- unlike the other CSP directives on that page, enforcing `require-trusted-types-for 'script'` needs application code (a registered Trusted Types policy) that almost no WordPress site has today, so it isn't safe to let it follow a surface's normal report-only/enforce toggle. The column is named generically so future experimental directives can share it.
- Fixed column widths on the CSP Profiles table and the Scripts page's External-tab inventory table. Both use a fixed table layout that split width evenly across columns regardless of content, so the Automation/Experimental columns (a `<select>`, a checkbox, and explanatory text) and the Classification/Expected SRI columns (a `<select>`, two inputs, and a button) were being crammed into slivers too narrow for their controls, causing visible overlap and text cutoff at normal admin widths.


### Changed

- Tightened the default CSP `img-src` directive from `'self' data:` to `'self'` only. `data:` URIs can't execute active content so the risk was always low, but a site that doesn't need inline/base64 images now gets a stricter default out of the box. Applies to newly seeded profiles; an existing profile whose `img-src` still exactly matches the old default is migrated automatically on upgrade (schema v17), while a profile an administrator has already customised is left untouched.

## [2.4.16] - 2026-08-12

### Added

- `Internal_Script_Integrity_Builder`: automatic Subresource Integrity for first-party (theme/plugin/core) `<script src>`/`<link rel="stylesheet">` tags, per-surface opt-in. Fundamentally different trust model from third-party SRI -- the hash is read from the exact local file this install is about to serve, never from a remote fetch, so there's no compromised-CDN risk. Cached by file size/mtime so an unchanged file is never re-read; a changed file (a plugin/theme update, a manual edit) is picked up on the very next request that serves it. New `sam_internal_asset_inventory` table (schema v16) backs a read-only inventory of what's currently being hashed.
- A "Start Here" tab on the renamed Scripts page, explaining what this plugin does for third-party scripts versus first-party ones before either sub-page.

### Changed

- Renamed the "External Scripts" submenu to "Scripts", now with three tabs: Start Here, External (the former standalone page, unchanged behaviour), and Internal (the new first-party SRI feature). Overview's "External Scripts" row now links to the External tab; a new "Internal Script Integrity" row links to the Internal tab.
- Nonce injection was already automatic and unconditional for every enqueued script/style tag (`Nonce_Manager`, first-party or third-party) -- core CSP plumbing this plugin has always performed, not a new toggle. Internal Script Integrity gets the same opt-in-per-surface treatment as every other pillar since, unlike the nonce, it's purely additive hardening with no downside if left off.

## [2.4.15] - 2026-08-12

### Changed

- Pinned the Overview submenu to the top of the left nav (the plugin's landing page), above the alphabetically-sorted rest of the menu.

## [2.4.14] - 2026-08-11

### Added

- Proactive Subresource Integrity drift detection: a new daily check (`Dependency_Integrity_Monitor`) fetches this site's own frontend homepage -- never third-party content -- and re-verifies that every `immutable_pinned` origin's live `integrity` attribute still matches the administrator-declared `expected_sri`, logging a warning via the audit log on mismatch. Catches drift (a theme update stripping the attribute, an edited embed) before a real visitor triggers `Dependency_Governance_Builder`'s reactive removal in enforce mode.
- A "Suggest" button on the External Scripts page's Expected SRI field: fetches a URL the administrator explicitly supplies (restricted to an origin already observed on this site, to avoid becoming an arbitrary fetch proxy) and computes its SHA-384 hash for them to review and save, saving a trip to an external hash generator. Never fetches automatically or trusts a hash without the administrator both supplying the URL and accepting the result via the normal save action.

### Changed

- Extracted `Dependency_Governance_Builder::extract_governed_resource()`, a small static helper shared by the per-request rewrite pass and the new proactive monitor, so both recognise exactly the same set of `<script>`/`<link rel="stylesheet">` elements.

## [2.4.13] - 2026-08-11

### Changed

- Sorted the Overview page's per-pillar status table alphabetically by pillar label, matching the left-nav ordering. "Content Security Policy" (rendered as its own row above the sorted list) already sorts first on its own.

## [2.4.12] - 2026-08-11

### Fixed

- Widened `sam_pillar_profiles.pillar` from `varchar(32)` to `varchar(48)`. `X_Permitted_Cross_Domain_Policies_Builder::PILLAR_KEY` (`x-permitted-cross-domain-policies`) is 33 characters -- one over the old column length -- so every toggle on that one pillar either failed outright under strict SQL mode, or was silently truncated to a different, unreadable key otherwise. Either way the Overview page's per-pillar status table always showed it as "Off" regardless of what an admin actually saved on the Cross-Origin Policies page.

## [2.4.11] - 2026-08-11

### Fixed

- Fixed a false-positive conflict report: `Conflict_Detector`'s daily probe could misreport this plugin's own live `Content-Security-Policy`/`-Report-Only` header as a "competing" header from another plugin or the web server. On sites sitting behind a full-page cache, CDN, or reverse proxy, that layer can serve a previously-rendered response -- including this plugin's own CSP header from an earlier real visitor request -- for the probe's HEAD request without WordPress re-running, so the outgoing `X-WP-SAM-Probe` suppression header never reaches PHP and the usual self-suppression never fires. The probe now recognises its own output by the `report-uri` it always emits (pointing back at this site's own report endpoint) and excludes it, rather than flagging a false conflict.

## [2.4.10] - 2026-08-11

### Changed

- Commercial-build only, no functional change to the free WordPress.org/GitHub build. Replaced the Cloudflare Worker-based checkout/entitlement backend with a direct integration: `Checkout_Service` now calls `https://api.stripe.com/v1/checkout/sessions` directly from this WordPress install using a locally-configured secret key and Price ID, and `Webhook_Controller` (already a direct Stripe webhook receiver at `/wp-json/security-manager/v1/webhook/stripe`, verifying Stripe's real signature and granting entitlement to the local `sam_entitlements` table) needed no changes at all. Removed `Config_Resolver` and the entire `cloudflare/` directory (worker + wrangler config) -- neither serves a purpose in this architecture. Added a "Stripe Configuration" section to the CSP dashboard's Settings tab (secret keys, Price IDs per mode/interval, webhook signing secret; only rendered on a build where `Checkout_Service` is present) so the whole flow is configurable without leaving wp-admin.
- Removed the now-unused `wp_sam_config_*` and `wp_sam_entitlement_grace_hours` options (`Config_Resolver`-only, never read anywhere else) from `Activator`, `uninstall.php`, and the reset/uninstall option lists.

## [2.4.9] - 2026-08-11

### Changed

- Sorted the left-nav submenu alphabetically by its displayed label. The Overview submenu item (whose slug matches the top-level menu, so it still serves as the top-level click target) now falls wherever "Overview" sorts alphabetically rather than always being first.
- Merged the standalone Readiness page into the Overview page as a tab. Schema/runtime checks and the authenticated data-reset flow are unchanged, only relocated -- the reset form's redirect and the Plugins-list "Reset" action link now point at `security-automation-manager&tab=readiness#wp-sam-reset` instead of the removed `security-automation-manager-readiness` page.
- Added an About tab to the Overview page: who built this plugin (VCNS Tech Ltd), why, the gap it fills in the WordPress security-plugin market, and links to the public help site, user guide, FAQ, and GitHub repository.

### Changed

- Reordered the Cross-Origin Policies page's tabs alphabetically: Cross-Origin-Embedder-Policy, Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy, X-Permitted-Cross-Domain-Policies (previously CORP, XPCDP, COOP, COEP). The default tab (when no `tab` query arg is present) changed accordingly, from `corp` to `coep`.

## [2.4.7] - 2026-08-11

### Changed

- Consolidated the four separate `Cross-Origin-Resource-Policy`, `X-Permitted-Cross-Domain-Policies`, `Cross-Origin-Opener-Policy`, and `Cross-Origin-Embedder-Policy` submenu pages into one "Cross-Origin Policies" page (`security-automation-manager-cross-origin`) with a tab per pillar, matching the tab pattern already used by the CSP dashboard. `X-Frame-Options`, `X-Content-Type-Options`, and `Referrer-Policy` keep their own separate pages -- they aren't part of this "cross-origin" grouping. The Overview page's per-pillar "Manage" links now route to the correct tab on the consolidated page.

## [2.4.6] - 2026-08-11

### Changed

- Commercial-build only, no functional change to the free WordPress.org/GitHub build. Wired up the pieces that make the Fully Automatic checkout flow actually work end-to-end rather than fail with "unable to create a checkout session" on every install:
  - `cloudflare/wrangler.toml` now activates the `wp-sam.vcns.tech` custom domain route (previously commented out, so the worker was only reachable at its default `*.workers.dev` URL, not the URL `Checkout_Service` and `Config_Resolver` actually call).
  - Added `WP_SAM_CONFIG_PUBLIC_KEY` (the public half of a freshly generated Ed25519 keypair) as a hardcoded constant in `security-automation-manager.php` -- safe to publish, since only the matching private key needs to stay secret -- and re-signed `cloudflare/worker.js`'s `CONFIG` payload with it. Previously no public key was wired in anywhere, so `Config_Resolver::verify_signature()` always failed closed and no product config could ever be trusted, regardless of everything else being correctly deployed.
  - Added `WP_SAM_CONFIG_URL`, the one signed-config endpoint every install of this product shares, as `Config_Resolver::get()`'s final fallback -- previously an install had no way to resolve pricing at all unless an administrator manually set a DNS TXT record or the `wp_sam_config_fallback_url` option, which nothing in the admin UI ever surfaced.
  - The Stripe Product ID placeholders in `cloudflare/worker.js` and the KV-stored Price IDs and Stripe API/webhook secrets referenced there still require the account owner's own Stripe/Cloudflare credentials and cannot be filled in by this change -- see the worker's own doc comment for the exact remaining `wrangler` commands.

## [2.4.5] - 2026-08-11

### Fixed

- Fixed every header pillar (CSP, X-Frame-Options, Permissions-Policy, X-Content-Type-Options, Referrer-Policy, HSTS, Cross-Origin-Resource-Policy, Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy, X-Permitted-Cross-Domain-Policies) being silently skipped on the WordPress login page (`wp-login.php`) regardless of configuration. `Header_Builder::register()` hooked only `send_headers` and the `wp_redirect` filter, but `wp-login.php` is a standalone entry point that never calls `wp()` / `WP::main()`, so `send_headers` -- fired only from `WP::send_headers()` -- never runs there; every pillar's `login` surface profile was loaded, active, and configured, but its header was never actually sent. Confirmed live: a raw fetch of a customer's `wp-login.php` carried none of this plugin's headers (its `Content-Security-Policy` value didn't even match this plugin's output shape), while the same site's frontend response carried the full configured set, including `Permissions-Policy` -- the only symptom the customer's external scanner had flagged, since a host-level LiteSpeed default happened to cover the other, older headers on that surface. `register()` now also hooks `login_init`, the substitute WordPress itself documents for code that must run before any output on that page.

## [2.4.4] - 2026-08-11

### Fixed

- Fixed CSP violation reports being deduplicated by exact `blocked_uri` instead of host, so a CDN or font provider (e.g. `fonts.gstatic.com`) serving each request from a distinct, content-hashed filename under the same host permanently accumulated a separate row per file in the Violations table instead of being recognised as repeat traffic to the same source. `Violation_Reporter::store_report()` now fingerprints on `(profile_surface, blocked_host, violated_directive)` wherever a host is extractable from `blocked_uri` (`Violation_Reporter::extract_blocked_host()`), matching the host-level granularity CSP source-approval already uses; keyword-like values with no host (`inline`, `eval`, `data:`, `blob:`, `about:`) keep their exact-value fingerprint. A new `blocked_host` column (schema v14) is backfilled and existing rows that now collapse under the same fingerprint are merged on upgrade, summing occurrence counts and keeping the earliest first-seen / latest last-seen timestamps. The Violations tab's "Blocked URI" column and its search filter now match against the grouped host first.

## [2.4.3] - 2026-08-11

### Fixed

- Fixed a fatal `TypeError` on every wp-admin page load: `Admin_UI::filter_admin_footer_text()` was typed to require its `admin_footer_text` filter argument be a `string`, but WordPress does not guarantee that -- any other plugin or theme hooked earlier in the same filter chain can pass through a non-string value (observed live: `null`), and this plugin's `strict_types` declaration turned that into an uncaught fatal instead of a type-juggled empty string. The method now accepts `mixed` and coerces defensively, matching how WordPress's own loosely-typed filter contracts should be handled.

## [2.4.2] - 2026-08-11

### Fixed

- Fixed `Conflict_Detector`'s internal self-check probe permanently failing to suppress this plugin's own CSP output, causing every install to misreport its own live CSP/CSP-Report-Only header as a "competing" header from web-server configuration or another plugin. The probe's outgoing header name (`X-WP-CSP-Probe`) was never updated during the WP_CSP -> WP_SAM rename, while the incoming suppression check (`Request_Surface::is_conflict_probe_request()`) was -- the two silently drifted apart, so the suppression never actually triggered on any release since the rename. Both sides now reference one shared constant (`Request_Surface::CONFLICT_PROBE_HEADER`) so they cannot diverge again, with a regression test covering it.

## [2.4.1] - 2026-08-11

No functional changes. Marks the first release actually tagged and published this session -- 2.2.0, 2.3.0, and 2.4.0 were all merged to `main` but never tagged, so no GitHub Release or update-feed entry exists for them. This tag is the first to trigger the publish pipeline.

## [2.4.0] - 2026-08-11

### Added

- Added backend plumbing for a Cross-Origin-Opener-Policy / Cross-Origin-Embedder-Policy report-only learning workflow (no admin-facing UI yet -- this is the first of a multi-stage rollout). COOP and COEP are the only two of this plugin's newer cross-origin pillars with a browser-native report-only + Reporting API delivery mechanism (Chromium only); Cross-Origin-Resource-Policy and X-Permitted-Cross-Domain-Policies have no such mechanism and are not part of this work.
  - `Violation_Reporter`'s REST endpoint (`security-manager/v1/report`) now also accepts Reporting API `coop`/`coep` report types, routed to a new generic `Pillar_Violation_Store` rather than CSP's directive-shaped storage.
  - New `sam_pillar_violation_reports` table (schema v13) stores these reports; an activation-time migration is not needed since this is a new table, not a changed one.
  - Extracted a shared `Reporting_Endpoint` helper (`includes/security/class-reporting-endpoint.php`) from `Policy_Builder` so CSP, COOP, and COEP all resolve the same report endpoint URL and emit identical `Reporting-Endpoints`/`Report-To` header values -- including respecting the existing `wp_sam_report_endpoint_url` override for proxy/CDN deployments.
  - Extended the daily purge job to also clear old pillar violation reports, reusing the existing `wp_sam_violation_retention_days` setting.

## [2.3.0] - 2026-08-10

### Added

- Added a per-surface Trusted Types toggle to the CSP Profiles tab: sends `require-trusted-types-for 'script'` when enabled, always report-only regardless of surface mode, closing off DOM-based XSS injection sinks. The directive was already scaffolded in the policy builder but had no admin control to actually enable it until now.

### Fixed

- Fixed approved CSP source hosts being emitted without a scheme prefix (e.g. `img-src cdn.example.com` instead of `img-src https://cdn.example.com`). `source_scheme` was captured and stored at proposal time but never read back out when building the policy string, so every approved source matched its host on any scheme, including plain HTTP. Flagged by a third-party CSP linter as a "missing protocol" finding across `connect-src`, `frame-src`, `img-src`, and `script-src-elem`.
- Fixed `upgrade-insecure-requests` being emitted in report-only mode, where browsers ignore it entirely (the directive has no effect under `Content-Security-Policy-Report-Only`, same as `sandbox`). Now stripped dynamically in report-only mode instead of always being present.
- Removed `fenced-frame-src` from the default CSP directive set. It's an experimental Privacy Sandbox directive, not part of the CSP living standard, and real-world CSP linters commonly flag it as "should not be used" -- removed after live scan feedback. A new activation-time migration strips it from already-seeded profiles on upgrading sites, not just new installs.
- Fixed a `trusted-types` directive with no configured policy names being able to leak into the header as a bare, valueless token if `require-trusted-types-for` was ever enabled without also configuring `trusted-types`. Now stripped independently whenever empty.
- Fixed the Violations table column widths on the CSP dashboard: Surface, Directive, Occurrences, Last Seen, Disposition, and Details now have fixed widths, and Blocked URI absorbs the remaining space (still auto-wrapping) instead of all seven columns splitting evenly.

## [2.2.0] - 2026-08-10

### Added

- Added Cross-Origin-Resource-Policy, Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy, and X-Permitted-Cross-Domain-Policies as four new simple pillars (per-surface value picker, same shape as X-Frame-Options and Referrer-Policy). Cross-Origin-Opener-Policy and Cross-Origin-Embedder-Policy carry real breakage risk -- COOP's `same-origin` can sever `window.opener` access from popup-based OAuth/SSO flows, and COEP's `require-corp` blocks any cross-origin subresource lacking an explicit CORP/CORS opt-in -- so their admin pages show a prominent warning notice above the picker. Cross-Origin-Resource-Policy and X-Permitted-Cross-Domain-Policies are low-risk by comparison. None of the four have a report-only mode, discovery workflow, or automation, matching every other simple pillar.

## [2.1.2] - 2026-08-10

### Fixed

- Fixed silent AJAX save failures across the per-surface toggle/dropdown autosave controls for X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Strict-Transport-Security, Reverse Tabnabbing, and External Scripts. `postPillarValue()`, `postHstsChange()`, `postDependencyMode()`, and `postPermissionsPolicyChange()` in `assets/js/admin.js` only handled `.fail()` (a network-level failure) and never inspected the response body -- but WordPress returns HTTP 200 for a real success, a `check_ajax_referer()` nonce failure (body `"-1"`), and a `wp_send_json_error()` validation error alike, so all three looked identical to the JS: the control silently re-enabled as if saved, with nothing actually written. A new shared `reportAjaxFailure()` helper now checks `res.success` in `.done()` for all five of these autosave handlers (the sixth, `postDependencyClassification()`, already did this correctly and now reuses the same helper) and surfaces the real error message instead of swallowing it.

## [2.1.1] - 2026-08-10

### Fixed

- Fixed a fatal error on the External Scripts admin page: `Call to undefined method WP_SAM\Admin\Table_Query::equals_where()`. The published 2.1.0 GitHub release was built from a commit where `page-external-scripts.php` (merged as part of the External Scripts pillar) called `equals_where()` before the PR that actually added that method to `Table_Query` had been merged -- an artifact of resolving several long-open, out-of-order pull requests. `main` had carried the fix since the `equals_where()` PR merged; this release exists purely to publish a working build. No other code changes.

## [2.1.0] - 2026-08-10

### Added

- Added Strict-Transport-Security (HSTS) as a sixth pillar: per-surface Max-Age, Include Subdomains, and Preload. Unlike the other simple pillars, this header is only ever emitted over an HTTPS request, and Preload cannot be enabled until Max-Age and Include Subdomains already meet hstspreload.org's submission minimum (Max-Age >= 1 year, Include Subdomains on) -- guardrails against a header that, once cached by a browser, cannot be walked back the way the other pillars can.
- Added Reverse Tabnabbing Protection: per-surface, adds `rel="noopener"` to `target="_blank"` links missing `noopener`/`noreferrer`, closing a `window.opener` phishing gap. A content rewrite rather than a header, built on a new shared `Content_Rewriter` base (`includes/security/class-content-rewriter.php`) alongside the existing header-pillar envelope.
- Added External Scripts: passively inventories third-party `<script>`/`<link rel="stylesheet">` origins from real page loads (no dedicated crawl, origin only -- never a path or query string), lets an administrator classify each one, and supports Subresource Integrity. A freshly discovered origin is always `unclassified`, never `prohibited` -- report mode (the default) never removes anything, and even enforce mode only ever removes an origin explicitly marked Blocked or an "immutable" origin whose administrator-declared SRI hash no longer matches. SRI hashes are never fetched or computed by the plugin, only compared against what the administrator already trusts and typed in.

### Changed

- Set Fully Automatic subscription pricing at £1.99/month or £19.99/year. Checkout now creates a recurring Stripe subscription (previously a one-time payment) and the Upgrade control lets the administrator choose the billing interval before starting checkout.
- Moved Policy Audit from a standalone top-level admin page into a tab on the CSP dashboard (it was always CSP-specific content). The pending review queue and full decision ledger it used to duplicate now live only on the adjacent For Review and Policy Changes tabs; Policy Audit itself keeps just the at-a-glance current-policy summary.

## [2.0.0] - 2026-08-10

### Added

- Added full-dataset sorting and per-column filtering (multi-select, free-text, numeric, date-range) to the Violations, For Review, and Policy Changes tables, replacing plain unsortable pagination.
- Added a per-row metadata popover on the Violations table showing document URI, source file, line/column, referrer, user agent, and any captured data-URI payload for a violation.
- Added a "Start Here" tab explaining the report-only, learning-window, and manual enforce-promotion workflow; it is now the default landing tab on the CSP dashboard.
- Renamed the plugin to Security Automation Manager: CSP becomes the first of several HTTP security-header pillars, with X-Frame-Options, X-Content-Type-Options, and Referrer-Policy joining it as simpler per-surface pillars (no report-only mode, discovery workflow, or automation for these three).
- Added a top-level "Security Automation Manager" admin menu with a new Overview page summarizing every pillar's per-surface status, plus dedicated X-Frame-Options, X-Content-Type-Options, and Referrer-Policy pages. The CSP dashboard moves to a "CSP" submenu at its existing URL.
- Added a shared `Header_Builder` envelope (hook registration, header-emission guard, conflict-probe suppression, surface detection) and a `sam_pillar_profiles` table so future pillars can reuse the same plumbing as CSP without duplicating it.
- Added Permissions-Policy as a fourth pillar: per-surface, per-directive control (`none`/`self`/`all`) over a starter set of seven browser features (geolocation, camera, microphone, fullscreen, payment, usb, autoplay). No report-only mode, discovery workflow, or automation, matching the other simple pillars.

### Changed

- Merged the standalone Settings page into the CSP dashboard as a tab, alongside Start Here, Profiles, For Review, Policy Changes, Violations, and Scan Log.
- Fully Automatic mode (zero-review auto-apply of deterministic policy changes) now requires a paid subscription. Sites without an active entitlement have Fully Automatic selections downgraded to "Automatic (with high approvals only)"; the free/local WordPress.org and GitHub-channel builds are unaffected otherwise. An "Upgrade" action is shown on the CSP Settings tab where a Checkout flow is available.

### Removed

- Removed the "Allow eligible auto-approvals" checkbox and its underlying `emergency_disabled` field. Automation Mode alone now governs whether a surface's proposals can be auto-approved; the field could previously be silently reset by an unrelated settings save due to how defaults were merged, which is no longer possible now that it no longer exists.

## [1.0.16] - 2026-08-04

### Added

- Added a separate GitHub-channel release ZIP with native WordPress update integration, plugin-information support, stale-offer suppression, package host validation, checksum verification, cache busting, and a `WP_CSP_DISABLE_AUTO_UPDATE` kill switch.
- Added release workflow generation of `vcns/wp-updates` metadata for GitHub-channel installs when `WP_UPDATES_TOKEN` is configured.
- Added administrator-selectable automation postures for manual approval, low-risk automation, low-plus-medium automation, and fully automatic deterministic approval within hard safety exclusions.

### Changed

- Split release artifacts so the plain ZIP remains WordPress.org-safe while the GitHub-channel ZIP contains the updater and generated `Update URI` metadata.
- Updated installed-plugin row messaging and release documentation to identify the active update channel.
- Replaced the dashboard Strict-Dynamic display column with an Automation dropdown so each surface can be switched between manual and automatic postures directly from Profiles.

## [1.0.15] - 2026-08-04

### Changed

- Renamed the dashboard Source Inventory tab to For Review so the operator queue matches the approval workflow.
- Expanded the Policy Changes tab into a policy activity timeline that includes discovered proposals, decisions, actors, suppression state, and policy version snapshots.
- Added per-surface deterministic automation settings and automatic low-risk approval records with actor `automation_engine`.

## [1.0.14] - 2026-08-04

### Changed

- CSP reporting now defaults to direct `report-uri` delivery so browser violations reach the local report endpoint promptly during learning.
- Added an administrator setting to opt into Reporting API headers and the `report-to` directive when required.

## [1.0.13] - 2026-08-04

### Fixed

- Policy version table creation now avoids the reserved `trigger` index name, fixing MariaDB activation failures.
- Activation now skips initial policy version seeding when the policy version table could not be created, preventing missing-table follow-on errors.
- Activation-time policy snapshots now use a safe local report endpoint fallback until WordPress REST routing has initialised.

## [1.0.12] - 2026-08-03

### Fixed

- CSP directives now remove `'none'` when approved sources are merged into the same directive, avoiding browser warnings and ignored `'none'` values such as `frame-src 'none' example.com`.
- CSP report ingestion now accepts document hosts that match the configured public reporting endpoint host or forwarded request host, so proxied deployments do not silently discard valid browser reports.
- The Violations empty state now reflects that browser reports can be collected from either report-only or enforce CSP headers.

## [1.0.11] - 2026-08-03

### Fixed

- CSP surface detection is now path-aware so `wp-admin` URLs that produce redirects or 404 responses still use the admin surface configuration.

## [1.0.10] - 2026-08-03

### Changed

- Destructive CSP data reset now leaves all policy surfaces disabled so the plugin stops emitting CSP headers until rollout is deliberately restarted.
- CSP headers are emitted before WordPress redirects so unauthenticated `wp-admin` redirects are easier to diagnose.

## [1.0.9] - 2026-08-03

### Added

- Configurable origin policy header name for Cloudflare, CDN, and reverse-proxy deployments that copy an origin header back to the browser-facing CSP header.

### Fixed

- Schema self-healing now recreates missing plugin tables even when the stored database schema version already matches the current code schema.

## [1.0.8] - 2026-08-03

### Changed

- Clarified the Violations empty state so administrators understand that manual scans do not create browser violation reports and can see the expected reporting endpoint.

## [1.0.7] - 2026-08-03

### Added

- Readiness admin page with plugin-version, database-schema, table-row, reporting-endpoint, scheduled-scan, and default automation posture checks.
- Installed Plugins Reset action linking to a destructive reset panel that requires current administrator password re-authentication and a typed confirmation before clearing CSP Automation Manager data.

## [1.0.6] - 2026-08-03

### Added

- CSP conflict detection now scans `.htaccess` Header directives and treats any CSP still present during the internal probe as a likely web-server or security-header-plugin conflict.
- Source approval, rejection, reversion, and undo decisions now require administrator reasons, and approved/rejected source decisions can be undone without rewriting history.
- Dashboard tabs now include operator guidance through hover titles, screen-reader descriptions, and an active-tab help note.
- Reporting server URL override for sites whose public HTTPS endpoint differs from the WordPress-detected REST URL, with a settings button to use the current site endpoint.
- Installed Plugins now shows a Settings action and an explicit WordPress.org-only update posture note.

## [1.0.5] - 2026-07-16

### Changed

- Renamed the repository, package slug, text domain, main plugin file, GitHub Pages links, WordPress.org deployment slug, and release ZIP naming to `csp-automation-manager`.
- Updated release packaging checks so tagged releases build `csp-automation-manager-vX.Y.Z.zip` with the `csp-automation-manager/` plugin root.

## [1.0.4] - 2026-07-15

### Changed

- Made all shipped CSP capabilities available locally without payment, remote entitlement checks, or trialware-style feature locking.
- Updated readme, package metadata, and public copy to reflect the WordPress.org build's local-only runtime behaviour.

### Removed

- Removed the custom runtime update checker and third-party update manifest polling from the WordPress.org plugin package.
- Removed licensing, checkout, and remote product configuration admin surfaces from the WordPress.org plugin package.
- Removed legacy production defaults for remote configuration, licensing, and custom update endpoints from the plugin bootstrap.

## [1.0.3] - 2026-07-15

### Changed

- Renamed the public plugin display name to `CSP Automation Manager` to comply with WordPress.org plugin naming requirements.

## [1.0.2] - 2026-07-15

### Changed

- Tightened the release package so development-only files, internal policy notes, and local cache files are excluded from distributed ZIP builds.
- Moved default configuration and licensing endpoints to VCNS-owned service hostnames while preserving `wp-config.php` overrides.
- Added explicit external-services disclosure for VCNS configuration, licensing, checkout, and GitHub update metadata requests.
- Added release workflow checks that fail if submission-only or development-only files are present in the packaged ZIP.

## [1.0.1] - 2026-07-15

This release includes database migrations through schema version 7. Existing installations can migrate directly from earlier schema versions through the normal `dbDelta()` activation path. CSP runtime behaviour remains local and does not depend on remote billing, licensing, or update services during normal page rendering.

### Added

- `Reporting-Endpoints` header emission alongside CSP headers, with legacy `Report-To` fallback.
- Forbidden directive denylist for removed or deprecated CSP directives.
- `strict-dynamic` host-source suppression when licensed and enabled.
- `upgrade-insecure-requests`, `child-src`, `fenced-frame-src`, sandbox handling, and Trusted Types defaults in policy profiles.
- `'report-sample'` defaults for script and style directives.
- `sample` column in `csp_violation_reports` for violation snippets. DB version 3.
- `csp_audit_log` append-only table. DB version 4.
- Violation retention purge with `wp_csp_violation_retention_days`.
- Content-Type validation, cross-origin `document-uri` rejection, and sample-field normalisation for violation reports.
- wp-admin enforce-mode limitation notice.
- CSP policy change proposals, risk classification, administrator approve/reject/revert decisions, and rejected/reverted fingerprint suppression.
- `csp_policy_change_decisions` append-only decision ledger. DB version 5.
- Violation report rollups with `first_reported_at`, `last_reported_at`, unique fingerprint upsert support, and occurrence counts. DB version 6.
- Policy audit foundation with policy version snapshots, deterministic rule-evaluation provenance, manual automation configuration defaults, privileged admin REST endpoints, and a Policy Audit admin page.
- `csp_policy_versions` append-oriented surface policy snapshots. DB version 7.
- `csp_decision_rule_evaluations` deterministic rule findings linked to proposals and decisions. DB version 7.
- GitHub-distributed update checking. This runtime updater was removed from the WordPress.org plugin package in 1.0.4.
### Changed

- Plugin version metadata now targets `1.0.1` for the initial GitHub release package.
- `WP_CSP_DB_VERSION` bumped from `'2'` to `'7'` (v3 = sample column; v4 = audit log table; v5 = policy change decision ledger and proposal metadata; v6 = violation rollups; v7 = provenance and policy history foundation).
- Policy builder emits `Reporting-Endpoints` and `Report-To` headers immediately before the CSP header - any code that expects the CSP to be the first header will need updating.
- Product copy no longer describes all premium access as a one-time payment; entitlement-gated capabilities are compatible with future VCNS Portal account management.

### Fixed

- Fixed silent Reporting API delivery failure where the CSP string referenced `report-to csp-endpoint` without declaring the endpoint through `Reporting-Endpoints`.

## [0.2.0] - 2026-06-03

### Added

- Initial public plugin implementation for WordPress 6.4+ and PHP 8.1+.
- Bootstrap file with plugin headers, constants, autoloader, activation, deactivation, and uninstall hooks.
- Database installer for seven custom tables covering policy profiles, source inventory, hash inventory, violation reports, scan logs, entitlements, and processed Stripe webhook events.
- Per-surface CSP engine for frontend, admin, login, and REST API requests.
- Strict defaults for all CSP directives.
- Nonce generation and injection through native WordPress 6.4+ script attribute hooks with legacy tag-filter fallback.
- Policy builder capable of emitting strict `Content-Security-Policy` and `Content-Security-Policy-Report-Only` headers.
- Crawl-based discovery workflow for external sources with approval and deny actions.
- Inline block hash recording and retirement support.
- Violation reporting REST endpoint with deduplication and transient-based rate limiting.
- Daily scheduler for rescans and policy-change notifications.
- Conflict detector for duplicate CSP headers from other plugins or server layers.
- Stripe checkout session creation without the Stripe PHP SDK, using the WordPress HTTP API.
- Webhook verification with HMAC-SHA256 signing, replay-window tolerance, and idempotent event recording.
- Local entitlement store bound to a stable hash of the site URL, including configurable grace periods.
- Feature gate with explicit free-tier capabilities and local tier checks.
- Remote product configuration fetched from DNS-discovered HTTPS JSON with Ed25519 signature verification.
- Transient-cached remote configuration with configurable TTL and grace-window handling.
- Admin UI covering dashboard, settings, entitlement display, checkout initiation, and manual rescans.
- Full uninstall routine that drops all custom tables and removes plugin-owned `wp_csp_*` options.

### Security

- Enforced prepared SQL access for parameterised queries and consistent escaping in admin output.
- Added promotion gate so enforce mode is blocked until at least one approved source or hash exists.
- Restricted admin actions to `manage_options` users with nonce verification.
- Kept Stripe secret material out of browser-delivered code and remote DNS configuration.

## Release policy

- `main` is the shipping branch for tagged releases.
- WordPress.org release artifacts are built from a clean tag only.
- Database schema changes must increment `WP_CSP_DB_VERSION` and include upgrade logic.
