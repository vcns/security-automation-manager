# Security Controls Inventory

## Purpose

Resolves roadmap issue #162 (Phase 4D, `.roadmap/phase4_plan.md`; source: SPECIFICATION.md §2.3, "Security controls inventory"). Security Automation Manager implements a wide set of HTTP security and content-protection controls, but until this document there was no single place that described each one's actual behaviour and limitations consistently. This inventory exists so an administrator or auditor can look up exactly one control and learn what it does, what it does not guarantee, what happens if it breaks something, and how to recover -- without reading the implementing PHP.

**Audience:** WordPress administrators operating this plugin, and auditors/security reviewers assessing what it does and does not provide.

**Grounding:** every field below is drawn directly from the current codebase (each control's own builder class under `includes/security/` or `includes/csp/`, `includes/admin/class-pillar-registry.php`, `includes/class-activator.php`'s seeding logic, `includes/modules/class-audit-log.php` and every `->log()` call in the controls' own files, `includes/class-rollback-guard.php`, and `docs/threat-model.md`/`docs/architecture.md`/`docs/rollback-and-recovery.md`), not from general knowledge of what a header with this name "usually" does. Where the code's actual behaviour is narrower, stricter, or otherwise different from what the header name might suggest, that is called out explicitly rather than smoothed over.

**Covers 19 controls**: the 17 named in issue #162's acceptance criteria, plus Information Masking and Cache-Control -- two controls that shipped after the issue was written but before this document, and which are exactly the kind of implemented control this inventory exists to cover.

## How to read this document

- **Surfaces.** This plugin evaluates every header/content-rewrite pillar independently per request "surface": `frontend` (public site), `admin` (wp-admin), `login` (wp-login.php), and `api` (REST API requests, `REST_REQUEST` defined true). Detection is centralised in `WP_SAM\Intelligence\Surface_Classifier::detect()`. Most controls below store one configuration row per surface in the shared `sam_pillar_profiles` table; CSP uses its own `csp_policy_profiles` table with the same four surfaces.
- **Approval mechanics common to nearly every control.** Unless a control's own section says otherwise: changing its configuration requires an authenticated user with the WordPress `manage_options` capability, and every AJAX save handler in `includes/admin/class-admin-ui.php` additionally verifies the `wp_sam_admin_nonce` nonce via `check_ajax_referer()`. There is no multi-person or peer-review approval step for these simple toggles -- one `manage_options` administrator's action takes effect immediately. CSP is the deliberate exception: it has its own richer discovery/risk-scoring/approval workflow, described in its own section.
- **A finding worth flagging up front:** across every "simple" pillar (X-Frame-Options through Cache-Control, plus External/Internal Script Integrity), saving a configuration change through the admin UI does **not** itself write an audit-log entry. Grepping every file under `includes/security/` and the relevant handlers in `class-admin-ui.php` for `Audit_Log`/`->log(` calls turns up exactly one: `Dependency_Integrity_Monitor`'s reactive SRI-mismatch detector. Everything else that reaches the audit log is either CSP's own automation/safety-net machinery, the generic rollback/migration subsystem, or certificate/evidence-export actions -- not a plain "administrator enabled/disabled/reconfigured pillar X" event. Each control's own "Audit events" field below states this precisely rather than repeating a blanket disclaimer.
- **Rollback is a shared, generic mechanism**, not a per-control "undo" button, for everything except CSP's own automated-proposal bookkeeping. See the "Rollback behaviour" field on each control and `docs/rollback-and-recovery.md` for the full picture.

---

## Content-Security-Policy

**Implementation:** `includes/csp/class-policy-builder.php` (`WP_SAM\CSP\Policy_Builder`), reading through `Policy_Data_Loader`/`Wpdb_Policy_Data_Loader`, storage in the `csp_policy_profiles`, `csp_source_inventory`, and `csp_hash_inventory` tables.

The plugin's primary content-injection defense and by far its most complex control. Builds and emits a `Content-Security-Policy` or `Content-Security-Policy-Report-Only` header per surface from a base directive set, admin overrides, approved source hosts, approved inline-content hashes, and a per-request nonce.

- **Purpose:** restrict which script, style, image, font, connect, frame, media, and other resource origins a page may load or execute, and which contexts may embed it, to mitigate XSS and related content-injection attacks.
- **Supported WordPress surfaces:** frontend, admin, login, api -- each with its own independently configured `csp_policy_profiles` row. The admin surface carries a documented caveat: WordPress core Trac #59446 is unresolved, and some core admin screens and bundled themes emit inline scripts outside the WordPress script API, so strict nonce-based enforcement on the admin surface is best-effort. The plugin surfaces a persistent admin notice whenever the admin profile's mode is `enforce`.
- **Default state:** every surface is seeded at activation with `mode = 'report-only'`, `strict_dynamic = 0`, `trusted_types = 0`, and a fairly restrictive baseline directive set (`default-src 'none'`; `img-src`/`font-src`/`connect-src`/`media-src`/`manifest-src`/`form-action` `'self'`; `frame-src`/`frame-ancestors`/`base-uri`/`object-src`/`worker-src`/`child-src` `'none'`; `script-src-attr`/`style-src-attr` `'none'`). Nothing is ever seeded in enforce mode.
- **Report-only capability:** yes, natively -- `mode = 'report-only'` emits `Content-Security-Policy-Report-Only`, which browsers evaluate and report against without blocking anything.
- **Enforcement capability:** yes -- `mode = 'enforce'` emits the real, blocking `Content-Security-Policy` header. Gated by a security-critical invariant (`docs/threat-model.md` #3): the plugin blocks enforce mode on a surface until at least one source or hash has been explicitly approved by a `manage_options` administrator, specifically to reduce the risk of an enforce-mode policy locking an admin out of wp-admin.
- **Discovery capability:** yes -- `Discovery` (`includes/csp/class-discovery.php`) crawls frontend/admin/login/api URLs via the WordPress HTTP API, parses the HTML for script/style/img/font/frame/media/manifest resource references (and linked CSS for `@font-face` sources), classifies each into the correct directive, and proposes new sources through `Policy_Change_Manager` with `approval_state = 'pending'`. `connect-src` (fetch/XHR/WebSocket) and `worker-src` cannot be reliably discovered from static HTML at all -- the code's own docblock states these must come from real CSP violation reports collected in report-only mode on an actual browser session.
- **Approval requirements:** every discovered or admin-added source starts `pending`. `Decision_Engine` risk-scores each candidate and hard-excludes several categories from ever being auto-approved regardless of scoring: wildcard sources (`CSP-SRC-003`), cleartext HTTP sources (`CSP-SCHEME-001`), `data:`/`blob:` schemes in executable/worker-capable contexts (`CSP-SCHEME-002`), and any `'unsafe-*'` CSP keyword (`CSP-SRC-004`) -- all four require explicit human review regardless of automation mode. Every "Bypass Best Practices" catalog entry (`Policy_Builder::BYPASS_CATALOG` -- e.g. allowing `data:`/`blob:` in `img-src`/`font-src`/`media-src`, `'unsafe-hashes'` for style/script attributes, `'wasm-unsafe-eval'`, `blob:` workers) is off by default and requires an explicit, individually-labelled per-surface admin toggle (`manage_options`, nonce-checked) -- see `docs/threat-model.md`'s "Bypass Best Practices catalog" section for the full risk reasoning behind each entry.
- **Risk of breakage:** high if enforce mode is turned on with an incomplete allowlist -- a missing source or hash blocks the corresponding script, style, image, font, or embed outright, and a wrong `frame-ancestors`/admin-surface policy can lock an administrator out of wp-admin (see the approved-source gate above, which exists specifically to reduce this). Two hard safety ceilings exist because an oversized header can break the entire response rather than just one resource: a 4096-byte (filterable) budget on appended approved-hash tokens, oldest-dropped-first, and a 7500-byte (filterable) ceiling on the fully serialised policy string, past which the plugin emits no CSP header at all for that request rather than risk the web server rejecting the response. Both limits exist because of a real production incident referenced in the code: a runaway hash-learning bug produced a 93,580-byte header (~1,700 hashes) on one surface.
- **Rollback behaviour:** `csp_policy_profiles`, `csp_source_inventory`, and `csp_hash_inventory` are all snapshotted by `Rollback_Guard` immediately before every forward schema migration and restorable from **Security Automation Manager → Recovery → Rollback and Recovery**, but only while the running code's schema still matches exactly what the snapshot was taken for (see `docs/rollback-and-recovery.md`). Separately, and narrower in scope, `Policy_Change_Manager` remembers a rejected or reverted automated source proposal so it is never silently re-proposed on a later discovery/decision-engine pass (`proposal_suppressed` audit event) -- but there is no one-click "undo my last manual directive edit"; that is a manual re-edit.
- **Audit events:** `policy_builder`/`hash_budget_exceeded` and `policy_builder`/`policy_too_large` (both rate-limited to at most once per rolling hour per surface, via a transient, specifically so a surface stuck over budget doesn't flood the log on every pageview); `policy_change`/`source_proposed`, `source_approved`, `source_rejected`, `source_reverted`, `proposal_suppressed` (component `policy_change`); `discovery`/`crawl_failed`, `crawl_http_error`, `css_fetch_failed`. Notably, the Profiles-tab admin actions that set a surface's mode, `strict_dynamic`, `trusted_types`, or a Bypass Best Practices flag (`ajax_set_trusted_types`, `ajax_set_bypass_flag` in `class-admin-ui.php`) do **not** themselves write an audit-log entry -- audit coverage is concentrated on the automated engine's own proposals/decisions and the byte-budget safety nets, not on every manual Profiles-tab toggle.
- **Limitations:** `connect-src`/`worker-src` are not statically discoverable; wp-admin enforcement is best-effort due to WordPress core's own unresolved inline-script issue (Trac #59446); the byte-budget safety net can silently withhold the header entirely for a request under sustained hash growth rather than truncate it; unbounded hash/host inventory growth degrades the header until `Hash_Manager`'s age-based pruning runs.
- **Relevant standards:** Content Security Policy Level 3 (W3C, cited in the code as "CSP3 WD-20260505"); the Reporting API (W3C); RFC 9651 (Structured Field Values, for the `Reporting-Endpoints` header format).

## CSP Reporting

**Implementation:** `includes/csp/class-violation-reporter.php` (`WP_SAM\CSP\Violation_Reporter`), `includes/security/class-reporting-endpoint.php` (`WP_SAM\Security\Reporting_Endpoint`), REST endpoint `POST /sam/v1/report` (legacy alias `/security-manager/v1/report`).

- **Purpose:** collect browser-generated CSP violation reports so an administrator can see what a report-only policy would have blocked, before committing to enforce mode, and so real breakage from an already-enforcing policy is visible.
- **Supported WordPress surfaces:** all four (frontend, admin, login, api) -- reports are attributed to a surface derived from the reporting page's own `document-uri`.
- **Default state:** always active whenever CSP is active on a surface (report-only or enforce); direct `report-uri` delivery is the default transport, added automatically to every emitted policy. The Reporting API transport (`report-to`) is opt-in via `wp_sam_reporting_transport` (`report-uri` / `report-to` / `both`) because some browsers ignore `report-uri` once `report-to` is present, which would delay learning if it were the default.
- **Report-only capability:** this control exists specifically to support the report-only workflow -- it is the delivery/collection half of CSP's report-only mode.
- **Enforcement capability:** not applicable to this control itself; it ingests reports regardless of whether the reporting surface's own CSP is in report-only or enforce mode, and flags a mismatch (see Limitations).
- **Discovery capability:** indirectly -- violation reports are one of the two inputs (alongside crawl-based `Discovery`) that surface candidate sources for CSP's approval workflow, and are the *only* practical way to discover `connect-src`/`worker-src` values.
- **Approval requirements:** the endpoint itself is unauthenticated by necessity (browsers, not logged-in admins, POST to it); it is not a source of automatic policy changes -- `docs/threat-model.md` states explicitly that discovered `blocked-uri` values are stored `pending` and only an explicit, capability-checked, nonce-validated admin REST action can move them to `approved`.
- **Risk of breakage:** low for the reporting mechanism itself. Reports are accepted only for `application/csp-report`, `application/reports+json`, or `application/json` Content-Types (anything else gets HTTP 400); a report whose `document-uri` hostname doesn't match this site's own origin is silently discarded (RFC 6454 origin comparison) without revealing the rejection, specifically so the check itself isn't advertised to a probing attacker. Storage is rate-limited to 500 reports/hour per (surface, directive) and deduplicated by a SHA-256 fingerprint of surface + blocked-uri + violated-directive, so a noisy or hostile reporter cannot grow the table unbounded.
- **Rollback behaviour:** violation reports are explicitly excluded from the config-state snapshot/restore mechanism -- `docs/rollback-and-recovery.md` lists CSP violation reports among the tables "never touched, and so never need restoring," because they are an append-only history, not admin-decided configuration.
- **Audit events:** `conflict_detector`/`csp_disposition_mismatch` -- logged (with a cooldown) when a browser reports a disposition (`enforce`/`report`) that doesn't match the surface's own configured CSP mode, which usually indicates another source (server config or a different plugin) is also emitting a competing CSP header for that surface. Ordinary report ingestion and storage is not itself audit-logged (it is high-volume, client-generated, and already visible on the Violations admin tab).
- **Limitations:** reports are client-generated and trivially spoofable in content -- `docs/threat-model.md` states explicitly that report payload content is used for discovery only, never for policy decisions or auto-approval. A cross-origin (spoofed) report is discarded without a distinguishable error response, by design.
- **Relevant standards:** CSP Level 3's `report-uri`/`report-to` reporting directives; the Reporting API (W3C); RFC 6454 (Origin comparison, used for the `document-uri` validity check).

## Trusted Types support

**Implementation:** within `includes/csp/class-policy-builder.php`'s directive assembly (the `require-trusted-types-for` / `trusted-types` directives), toggle stored as the `trusted_types` column on `csp_policy_profiles`.

- **Purpose:** DOM-XSS mitigation via the Trusted Types API -- restricts dangerous DOM sink APIs (`innerHTML` and similar) to only accept values produced by an explicitly registered, reviewed policy, rather than arbitrary strings.
- **Supported WordPress surfaces:** frontend, admin, login, api, following the same per-surface `csp_policy_profiles` row as the rest of CSP.
- **Default state:** disabled (`trusted_types = 0`) on every surface at activation; the underlying directives (`require-trusted-types-for`, `trusted-types`) default to empty arrays, which are stripped from the emitted policy entirely rather than sent as empty/valueless tokens.
- **Report-only capability:** the plugin's own code comments (both in `Policy_Builder` and `docs/architecture.md`) describe this as "always emitted as report-only regardless of surface mode," with a note that Trusted Types is "Chromium-strong; Baseline widely available ~2028." Reading the executable code directly, however, `require-trusted-types-for`/`trusted-types` are ordinary entries in the same `$directives` array as everything else in `build_policy_string()` -- there is no separate branch that forces them into a `Content-Security-Policy-Report-Only` header when the surface's own `mode` is `enforce`. In practice, on a surface configured for `enforce`, these directives are serialised into the real, blocking `Content-Security-Policy` header along with everything else. Administrators relying on the "always report-only" comment for a rollout plan should verify this directly against a live response header on their own enforce-mode surface rather than assume the comment is accurate.
- **Enforcement capability:** yes, in the sense described above -- toggling it on for an `enforce`-mode surface adds `require-trusted-types-for 'script'` to that surface's real, enforcing CSP header (the admin UI only offers the `'script'` value; an admin wanting named policies or `'default'`/`'*'` needs a directive override).
- **Discovery capability:** none -- this is a binary per-surface toggle, not something the plugin learns or proposes automatically.
- **Approval requirements:** `manage_options` + nonce via `ajax_set_trusted_types`; same mechanics as every other CSP Profiles-tab toggle.
- **Risk of breakage:** meaningful on a site whose theme/plugins assign untrusted strings to DOM sinks without going through a Trusted Types policy -- those assignments will throw in a browser that enforces Trusted Types once `require-trusted-types-for 'script'` is present in an enforcing header. Browser support is Chromium-only today, which limits (but does not eliminate) real-world breakage risk on other engines.
- **Rollback behaviour:** covered only by the same `csp_policy_profiles` schema-migration snapshot as the rest of CSP (see the CSP section above); no dedicated undo for this one toggle.
- **Audit events:** none -- `ajax_set_trusted_types()` writes directly to `csp_policy_profiles` with no `Audit_Log::log()` call.
- **Limitations:** the admin UI only exposes the `'script'` sink-restriction value, not named policy allowlisting via `trusted-types`, without going through a manual directive override; the "always report-only" documentation comment does not match the code's actual emission behaviour on an enforce-mode surface (see Report-only capability above).
- **Relevant standards:** Trusted Types (W3C).

## Conflict Detection

**Implementation:** `includes/csp/class-conflict-detector.php` (`WP_SAM\CSP\Conflict_Detector`). (Cache-Control has its own, differently-designed conflict check -- see the Cache-Control section below.)

- **Purpose:** detect another plugin, theme, or web-server configuration emitting a competing `Content-Security-Policy`/`Content-Security-Policy-Report-Only`/`X-Content-Security-Policy` header, so an administrator knows before enabling enforce mode that another source might interfere or that browsers will apply multiple overlapping policies.
- **Supported WordPress surfaces:** effectively site-wide -- detection runs via the `wp_headers` filter (whatever the current request's queued headers are) and a background probe against the site's home URL, plus a static scan of `.htaccess` `Header` directives, rather than per-surface.
- **Default state:** always active; no configuration toggle exists to disable it. The `wp_headers` filter check runs on every relevant request; the HEAD-probe and `.htaccess` scan are throttled to once per 24 hours via a transient gate, triggered from `admin_init`.
- **Report-only capability:** not applicable -- this is a detection-only mechanism, it never itself emits or blocks a header.
- **Enforcement capability:** not applicable -- it only records and surfaces findings; per its own docblock it "never removes" a detected competing header.
- **Discovery capability:** yes, in the sense of actively probing for competing emitters: an internal HEAD request (carrying `X-WP-SAM-Probe: 1` so the plugin's own header emission suppresses itself and doesn't produce a false positive against its own output) against the home URL, plus a line-by-line scan of `ABSPATH/.htaccess` (skipped if unreadable or over 256 KB) for Apache/LiteSpeed `Header set/add/append/merge/edit` directives naming a CSP header.
- **Approval requirements:** not applicable -- there is nothing to approve; findings are informational.
- **Risk of breakage:** none from this control itself -- it is read-only against live headers and the filesystem.
- **Rollback behaviour:** not applicable -- there is no stored configuration state for this control to snapshot or restore.
- **Audit events:** `conflict_detector`/`csp_conflict`, one per detected competing header, logged with the detection source (`header_filter`, `htaccess`, `probe_existing`, or `probe_duplicate`) and a short guidance string tailored to that source (e.g. "Review Apache or LiteSpeed .htaccess Header directives before enabling enforcement here").
- **Limitations:** the probe recognises and excludes its own output specifically by checking whether the detected header's value contains this site's own report endpoint URL -- a full-page cache, CDN, or reverse proxy that serves a stale cached response to the probe's own HEAD request could, in principle, still misreport a genuinely stale-but-own header as external if the cached copy predates the current report-endpoint URL. The `.htaccess` scan only covers Apache/LiteSpeed-style `Header` directives; it does not inspect Nginx configuration (not filesystem-readable from PHP in the general case) or CDN/edge-level header injection.
- **Relevant standards:** not applicable -- this is an internal safety/QA mechanism, not an implementation of an external protocol or header standard.

---

## X-Frame-Options

**Implementation:** `includes/security/class-x-frame-options-builder.php` (`WP_SAM\Security\X_Frame_Options_Builder`).

- **Purpose:** clickjacking mitigation -- prevents the page from being rendered inside a `<frame>`/`<iframe>`/`<object>` on another origin (or on any origin at all, for `DENY`).
- **Supported WordPress surfaces:** frontend, admin, login, api.
- **Default state:** enabled on all four surfaces at activation. Value is `SAMEORIGIN` on frontend/admin/login, and `DENY` on api (API responses have no legitimate reason to be framed at all).
- **Report-only capability:** none -- no browser ever supported a report-only variant of this header; it is binary on/off with a fixed enforced value.
- **Enforcement capability:** yes, the only mode -- whenever enabled, the emitted header is always the real, enforcing value.
- **Discovery capability:** none -- a static admin-configured value, never learned or proposed.
- **Approval requirements:** standard (`manage_options` + nonce; see "How to read this document").
- **Risk of breakage:** low to moderate -- breaks only site features that intentionally frame this site's own pages from another origin (rare) or, under `DENY`, that frame the site from itself (some page builders/preview tooling). `SAMEORIGIN`, the frontend/admin/login default, does not affect same-site framing.
- **Rollback behaviour:** generic only -- `sam_pillar_profiles` is one of the tables `Rollback_Guard` snapshots before a forward migration; no per-toggle undo (see "How to read this document").
- **Audit events:** none -- the save action itself is not logged (see "How to read this document").
- **Limitations:** only `DENY` and `SAMEORIGIN` are offered; `ALLOW-FROM` is deliberately excluded because it is deprecated and unsupported by modern browsers. CSP's `frame-ancestors` directive supersedes this header in any browser that honours it; this header remains a fallback for browsers that don't.
- **Relevant standards:** never became a formal W3C/IETF standard; commonly referenced as RFC 7034 (Informational). Effectively superseded by CSP3's `frame-ancestors`.

## X-Content-Type-Options

**Implementation:** `includes/security/class-x-content-type-options-builder.php`.

- **Purpose:** disables browser MIME-type sniffing, so a resource served with an unexpected `Content-Type` is not reinterpreted (e.g. executed as script) based on its content.
- **Supported WordPress surfaces:** frontend, admin, login, api.
- **Default state:** enabled on all four surfaces at activation.
- **Report-only capability:** none -- `nosniff` is the only value the header ever takes; there is no report-only concept for it.
- **Enforcement capability:** yes, the only mode -- on or off, always the enforcing `nosniff` value.
- **Discovery capability:** none.
- **Approval requirements:** standard.
- **Risk of breakage:** very low -- there is no configurable value to get wrong (no `sanitize_value()`/options list exists for this pillar at all), and `nosniff` breaking a legitimate response almost always indicates the response's own `Content-Type` header was already wrong.
- **Rollback behaviour:** generic only.
- **Audit events:** none.
- **Limitations:** no configurable value or partial mode; a site that genuinely needs MIME sniffing for some legacy resource has no way to exempt just that resource from this pillar.
- **Relevant standards:** originally a Microsoft/IE extension, now standardised behaviour within the WHATWG Fetch specification.

## Referrer-Policy

**Implementation:** `includes/security/class-referrer-policy-builder.php`.

- **Purpose:** controls how much of this site's own URL is sent in the `Referer` header (and the `Referrer` meta-equivalent) when a user navigates away to another origin, limiting information leakage about the page they were on.
- **Supported WordPress surfaces:** frontend, admin, login, api.
- **Default state:** enabled on all four surfaces at activation. Value is `strict-origin-when-cross-origin` (`Referrer_Policy_Builder::DEFAULT_VALUE`) on frontend/admin/login, and the stricter `no-referrer` on the api surface.
- **Report-only capability:** none -- no report-only variant exists for this header.
- **Enforcement capability:** yes, the only mode.
- **Discovery capability:** none -- a static admin-configured value from a fixed enum of 8 standard values.
- **Approval requirements:** standard.
- **Risk of breakage:** low -- can break analytics/referrer-dependent third-party integrations that rely on receiving this site's full URL as the referrer, but does not break the site's own functionality.
- **Rollback behaviour:** generic only.
- **Audit events:** none.
- **Limitations:** HTTP header only -- the plugin deliberately does not also inject a `<meta name="referrer">` tag, to stay consistent with its header-only architecture and avoid opening a body-content-modification attack surface for this pillar.
- **Relevant standards:** Referrer Policy (W3C).

## Permissions-Policy

**Implementation:** `includes/security/class-permissions-policy-builder.php`.

- **Purpose:** restricts which browser features/APIs (geolocation, camera, microphone, fullscreen, payment, USB, autoplay) this page and any documents it embeds may use.
- **Supported WordPress surfaces:** frontend, admin, login, api.
- **Default state:** enabled on all four surfaces at activation, with every one of the seven supported directives set to `none` except: on the frontend surface only, `autoplay` defaults to `self` (audio/video autoplay is permitted for same-origin embeds, everything else stays `none`).
- **Report-only capability:** none -- the code's own docblock notes `Permissions-Policy-Report-Only` "exists only in draft form with minimal real browser support," so it is deliberately not offered.
- **Enforcement capability:** yes, the only mode.
- **Discovery capability:** none -- and by design, per the code's own docblock: "No discovery workflow or Decision Engine wiring either -- deferred until a pillar genuinely needs it."
- **Approval requirements:** standard, via a dedicated `ajax_set_permissions_policy_directive` handler (read-modify-write against the surface's directive map, since this pillar has multiple independently-configurable directives rather than one scalar value).
- **Risk of breakage:** low to moderate -- can break a legitimate embed or first-party feature that needs one of the governed browser APIs (e.g. a payment iframe needing the `payment` feature, or a self-hosted video needing `autoplay`) if left at `none`.
- **Rollback behaviour:** generic only.
- **Audit events:** none.
- **Limitations:** deliberately offers only a small, fixed set of 7 security/privacy-relevant directives out of the ~30-directive registry, and only a 3-token allowlist (`none`/`self`/`all`) rather than free-text origin lists, specifically to avoid reopening the header-injection sanitisation surface CSP already solves for source hosts. A directive absent from the stored map is simply not emitted (the browser's own default applies), which is standard Permissions-Policy behaviour rather than a plugin limitation.
- **Relevant standards:** Permissions Policy (W3C; successor to the earlier Feature-Policy header).

## Strict-Transport-Security

**Implementation:** `includes/security/class-strict-transport-security-builder.php`.

- **Purpose:** instructs browsers to only ever connect to this site over HTTPS for the given `max-age` window, preventing protocol-downgrade and SSL-stripping attacks after the first secure connection.
- **Supported WordPress surfaces:** frontend, admin, login, api.
- **Default state:** the only "simple" pillar with **no row seeded at all on activation** -- `Activator::seed_default_pillar_profiles()`'s own docblock states this is deliberate: "HSTS is deliberately NOT included here... It stays a deliberate, informed, per-surface opt-in rather than a blind default a fresh install could get burned by." A fresh install shows this pillar as "Not configured," not merely "Disabled," until an administrator explicitly turns it on. When an admin does enable it, the code's own default `max_age` is a deliberately short 86,400 seconds (1 day), specifically because HSTS has no report-only mode to rehearse a rollout with.
- **Report-only capability:** none, and none exists in the HSTS specification at all -- this is why the pillar's own docblock treats it as uniquely risky among the simple pillars.
- **Enforcement capability:** yes, the only mode -- but with two guardrails the admin UI cannot be trusted to skip on its own: the header is only ever sent over an already-HTTPS connection (`is_ssl()`), since sending it over plain HTTP would misrepresent the site as HTTPS-only before it actually is; and the `preload` flag is silently dropped unless the stored `max-age`/`includeSubDomains` combination actually meets hstspreload.org's real submission requirements (`max-age >= 31536000` and `includeSubDomains` present).
- **Discovery capability:** none.
- **Approval requirements:** standard.
- **Risk of breakage:** the highest of any simple pillar, and unlike every other header here, **not easily reversible**. Browsers cache `max-age` and refuse plain-HTTP connections for that duration regardless of what a later response says; a domain submitted to the HSTS preload list can take months to be removed even after the header itself is fixed. If any part of the site (a subdomain, in particular, under `includeSubDomains`) is not actually reachable over valid HTTPS, enabling this can make that content completely unreachable in affected browsers for the full `max-age` window.
- **Rollback behaviour:** generic only (`sam_pillar_profiles` snapshot/restore) -- and this is the one control on this list where that generic rollback genuinely cannot undo the real-world effect: restoring the database row does not un-cache the policy in a visitor's browser, nor remove a domain from the HSTS preload list.
- **Audit events:** none.
- **Limitations:** no report-only mode exists in the specification itself, so there is no way to rehearse a rollout risk-free; browser-side caching means a misconfiguration is not remediated the moment the plugin's own setting is fixed.
- **Relevant standards:** RFC 6797 (HTTP Strict Transport Security).

## Cross-Origin-Resource-Policy

**Implementation:** `includes/security/class-cross-origin-resource-policy-builder.php`.

- **Purpose:** controls whether other origins may load this site's own resources (scripts, images, fonts, etc.) via `<img>`, `<script>`, `fetch()`, and similar cross-origin loading paths.
- **Supported WordPress surfaces:** frontend, admin, login, api.
- **Default state:** enabled on all four surfaces at activation. Value is `cross-origin` (most permissive) on frontend/admin/login, and `same-site` on the api surface.
- **Report-only capability:** none -- no report-only variant of this header exists.
- **Enforcement capability:** yes, the only mode.
- **Discovery capability:** none -- a static admin-configured value from a fixed 3-value enum (`same-site`/`same-origin`/`cross-origin`).
- **Approval requirements:** standard.
- **Risk of breakage:** the lowest of the plugin's cross-origin headers, per the code's own docblock: a misconfiguration can stop a legitimate third party (a CDN, a partner embedding one of this site's assets) from loading this site's own resource, but it never breaks a resource this site itself loads from elsewhere.
- **Rollback behaviour:** generic only.
- **Audit events:** none.
- **Limitations:** governs only resources this site serves being loaded by others -- it has no effect on what this site itself is permitted to load (that is Cross-Origin-Embedder-Policy's domain).
- **Relevant standards:** part of the Fetch standard (WHATWG); one of the "post-Spectre" cross-origin isolation headers alongside COOP/COEP.

## Cross-Origin-Opener-Policy

**Implementation:** `includes/security/class-cross-origin-opener-policy-builder.php`.

- **Purpose:** isolates this site's browsing-context group from cross-origin windows it opens or is opened by, closing off cross-window/Spectre-style information leaks.
- **Supported WordPress surfaces:** frontend, admin, login, api.
- **Default state:** enabled on all four surfaces at activation -- but seeded with `unsafe-none`, the specification's explicit no-op value, and with no `mode` key in the payload, which `extract_mode()` treats as `enforce` (see below). The code's own migration docblock is explicit about why: "This adds no real cross-origin isolation; it exists purely so the header is present for scanners (securityheaders.com, Mozilla Observatory) that check for it." In other words: **out of the box this header is present and in enforce mode, but configured to a value that provides no actual isolation** -- a genuinely tighter value is left as a deliberate future opt-in once there is real evidence the site's own scripts/embeds tolerate isolation.
- **Report-only capability:** yes -- unlike most simple pillars, COOP supports a three-state `mode` (`disabled`/`report-only`/`enforce`), because Chromium supports a native `Cross-Origin-Opener-Policy-Report-Only` header plus Reporting API delivery, so real breakage signal can be gathered before enforcing. `extract_mode()` defaults to `enforce` when the stored payload has no `mode` key at all, specifically so a profile that predates the mode field (or the seeded default, above) is never silently downgraded to report-only.
- **Enforcement capability:** yes -- `mode = 'enforce'` sends the real `Cross-Origin-Opener-Policy` header. Real breakage risk exists here: `same-origin` severs `window.opener` access from any cross-origin popup this site opens or is opened by, including popup-based OAuth/SSO flows many login and payment integrations rely on; `same-origin-allow-popups` preserves isolation for this site's own top-level navigation while still letting popups hold a restricted opener reference, which is what most sites that need popups actually want.
- **Discovery capability:** none for policy value selection itself, but see COOP/COEP Reporting below for how enforcement risk is observed.
- **Approval requirements:** standard, via `ajax_set_pillar_value` with an additional mode-validity check.
- **Risk of breakage:** high if set to `same-origin` on a surface with popup-based OAuth/SSO/payment flows (see Enforcement capability); low/no-op at the seeded default value.
- **Rollback behaviour:** generic only.
- **Audit events:** none for the configuration change itself; see COOP/COEP Reporting below for what *is* captured once report-only mode is active.
- **Limitations:** the report-only delivery mechanism (Reporting API) is Chromium-only; other engines get no rehearsal path before an admin manually switches to enforce.
- **Relevant standards:** defined in the HTML Living Standard (WHATWG), as part of the same cross-origin-isolation family as COEP.

## Cross-Origin-Embedder-Policy

**Implementation:** `includes/security/class-cross-origin-embedder-policy-builder.php`.

- **Purpose:** blocks this page from loading cross-origin subresources that do not explicitly opt in (via a matching CORP header or CORS), closing off another Spectre-class information-leak vector; required for cross-origin isolation APIs (`SharedArrayBuffer`, high-resolution timers).
- **Supported WordPress surfaces:** frontend, admin, login, api.
- **Default state:** enabled on all four surfaces at activation, seeded to `unsafe-none` (no-op) with no `mode` key, defaulting to `enforce` -- the exact same "present for scanners, but a no-op value" pattern as COOP above, and for the same documented reason.
- **Report-only capability:** yes -- the same three-state `mode` (`disabled`/`report-only`/`enforce`) as COOP, for the same reason (Chromium `Cross-Origin-Embedder-Policy-Report-Only` + Reporting API).
- **Enforcement capability:** yes -- and the code's own docblock calls this "the highest-risk header this plugin manages." `require-corp` blocks every cross-origin subresource that doesn't explicitly opt in -- most third-party embeds, ad tags, and CDN-hosted fonts (including Google Fonts, unless self-hosted or already CORS-enabled) do not opt in by default, so enabling this carelessly silently breaks unrelated page content rather than producing an obvious error. `credentialless` is described as usually the safer of the two enforcing values (cross-origin resources load without credentials rather than being blocked outright), at the cost of breaking anything that genuinely needs a credentialed cross-origin request. Per the same docblock: "most WordPress sites do not need it at all."
- **Discovery capability:** none for policy value selection; see COOP/COEP Reporting below.
- **Approval requirements:** standard, via `ajax_set_pillar_value` with a mode-validity check.
- **Risk of breakage:** the highest of any control in this inventory when set to `require-corp` on a site with unreviewed third-party embeds -- breakage is silent (content simply fails to load) rather than an obvious error page.
- **Rollback behaviour:** generic only.
- **Audit events:** none for the configuration change itself; see COOP/COEP Reporting below.
- **Limitations:** same Chromium-only report-only delivery limitation as COOP; genuinely needed only by sites requiring cross-origin isolation APIs, which is not most WordPress sites per the code's own assessment.
- **Relevant standards:** defined in the HTML Living Standard (WHATWG).

## COOP and COEP Reporting

**Implementation:** `includes/security/class-pillar-violation-store.php` (`WP_SAM\Security\Pillar_Violation_Store`), routed from `includes/csp/class-violation-reporter.php::store_pillar_reports()` (same REST endpoint as CSP reporting, `POST /sam/v1/report`).

- **Purpose:** captures Reporting API violation reports for COOP and COEP -- the only two non-CSP pillars this plugin manages with a browser-native report-only + Reporting API delivery mechanism -- so an administrator can review real breakage signal from report-only mode before enforcing.
- **Supported WordPress surfaces:** frontend, admin, login, api (surface derived from the report envelope's own `url` field, same `document-uri`-based classification as CSP reports).
- **Default state:** active automatically whenever a surface's COOP or COEP mode is `report-only` (`Reporting_Endpoint::emit_headers()` is called unconditionally in that branch -- unlike CSP's Reporting API transport, this is **not** gated by the `wp_sam_reporting_transport` site option). No configuration exists to disable report collection independently of the pillar's own mode.
- **Report-only capability:** this control is the delivery/collection mechanism for COOP/COEP's report-only mode.
- **Enforcement capability:** not applicable to this control -- it only stores reports; it never blocks anything.
- **Discovery capability:** yes, in the same sense CSP reporting is -- reports are the only real-world signal for whether a tighter COOP/COEP value than the seeded `unsafe-none` would break something.
- **Approval requirements:** not applicable -- there is no approval step; reports are simply stored for admin review.
- **Risk of breakage:** none from this control itself (storage only). Rate-limited to 500 reports/hour per (pillar, surface) via a transient counter, and a spoofed cross-origin report (page `url` hostname not matching an allowed document host) is silently discarded, mirroring the CSP reporting path's own cross-origin defence.
- **Rollback behaviour:** not applicable -- `sam_pillar_violation_reports` is a log-shaped table, not part of the config-state snapshot/restore mechanism.
- **Audit events:** none. Unlike CSP's `csp_disposition_mismatch` check, there is currently no equivalent audit-log correlation for a COOP/COEP disposition mismatch -- reports land only in the `sam_pillar_violation_reports` table for manual review, not the audit log.
- **Limitations:** the code's own docblock explains why fingerprinting here is coarser than CSP's: COOP and COEP report bodies "carry meaningfully different fields from each other and from a CSP violation report, and (unlike CSP's report format) their exact field names are less stable across browser versions." Reports are therefore deduplicated only on `(pillar, surface, report_type, disposition)`, with the pillar-specific fields kept as an opaque, size-capped (8 KB) `detail` JSON blob rather than structured columns -- coarser evidence than CSP's stable `blocked_uri`-based fingerprint. Reporting API delivery itself is Chromium-only.
- **Relevant standards:** the Reporting API (W3C); the report-only mechanism is defined per-header in the HTML Living Standard alongside COOP/COEP themselves.

---

## X-Permitted-Cross-Domain-Policies

**Implementation:** `includes/security/class-x-permitted-cross-domain-policies-builder.php`.

- **Purpose:** controls whether legacy Adobe Flash/Acrobat plugins may load a cross-domain policy file (`crossdomain.xml`) from this site.
- **Supported WordPress surfaces:** frontend, admin, login, api.
- **Default state:** enabled on all four surfaces at activation, value `none`.
- **Report-only capability:** none.
- **Enforcement capability:** yes, the only mode.
- **Discovery capability:** none -- static value from a fixed 4-value enum (`none`/`master-only`/`by-content-type`/`all`).
- **Approval requirements:** standard.
- **Risk of breakage:** effectively none on a modern site -- the code's own docblock notes "Flash is dead and PDF.js doesn't consult this header, so 'none' is almost always the correct value for a modern site."
- **Rollback behaviour:** generic only.
- **Audit events:** none.
- **Limitations:** addresses a legacy (Flash/Acrobat-era) attack surface that is largely irrelevant to current browsers; kept mainly to explicitly close what would otherwise sit at a permissive browser default.
- **Relevant standards:** not a formal W3C/IETF standard -- originally defined by Adobe as part of the Flash Player cross-domain policy file specification.

## Reverse Tabnabbing Protection

**Implementation:** `includes/security/class-reverse-tabnabbing-builder.php` (`WP_SAM\Security\Reverse_Tabnabbing_Builder`, extends `Content_Rewriter`, not `Header_Builder`).

- **Purpose:** mitigates reverse tabnabbing -- a `target="_blank"` link opening a new tab that then uses `window.opener` to redirect the original tab to a phishing page while looking untouched -- by adding `rel="noopener"` to qualifying anchors.
- **Supported WordPress surfaces:** configuration exists per surface (frontend, admin, login, api) in `sam_pillar_profiles`, matching every other simple pillar's storage shape. **In actual live-request behaviour, however, this control can only ever fire on the frontend surface.** It is the only body-content-rewriting control alongside External Script Integrity, and both share `Content_Rewriter`'s `request_exclusion_reason()` gate, which unconditionally excludes any `is_admin()` request, `wp-login.php`, AJAX, REST, XML-RPC, cron, and CLI requests from ever reaching the rewrite step at all -- before the surface-specific `is_active()` check is even consulted. Since those are exactly the requests that would otherwise classify as the `admin`/`login`/`api` surfaces, the `admin`/`login`/`api` rows in this pillar's own configuration are, in practice, never live: only the `frontend` row's setting has an observable effect. This is not documented anywhere the admin UI would surface it, and is exactly the kind of non-obvious limitation an inventory like this exists to catch.
- **Default state:** enabled at activation (the `frontend` row is what matters per the above).
- **Report-only capability:** none -- this is a binary content rewrite (noopener added or not), with no learning/observation mode.
- **Enforcement capability:** yes, the only mode -- and it is inherently non-blocking by nature: it only ever adds an attribute, never removes content or breaks a link.
- **Discovery capability:** none.
- **Approval requirements:** standard.
- **Risk of breakage:** very low -- `rel="noopener"` is additive and near-universally safe; the implementation preserves surrounding markup, attribute order, and encoding byte-for-byte via `WP_HTML_Tag_Processor`, skips anchors that already carry `noopener`/`noreferrer`, and fails open (returns the original, unmodified HTML) on any parser exception.
- **Rollback behaviour:** generic only.
- **Audit events:** none.
- **Limitations:** only ever effectively active on the frontend surface regardless of the admin/login/api toggle state (see above); like every `Content_Rewriter`-based control, it only processes a successful (2xx), non-streamed, `text/html`/`application/xhtml+xml` response for a `GET`/`HEAD` request with a real main query -- feeds, trackbacks, robots.txt, sitemaps, and streamed responses are all skipped by design.
- **Relevant standards:** not a formal header standard; `rel="noopener"` is a standard HTML link-type keyword (HTML Living Standard, WHATWG). The mitigation itself is commonly documented in OWASP guidance rather than a numbered spec.

## External Script Integrity

**Implementation:** `includes/security/class-dependency-governance-builder.php` (`WP_SAM\Security\Dependency_Governance_Builder`, admin-UI label "External Scripts"; extends `Content_Rewriter`), reactive check in `includes/security/class-dependency-integrity-monitor.php`.

- **Purpose:** passively inventories third-party `<script src>`/`<link rel="stylesheet">` origins from real page loads, lets an administrator classify each one, and -- only once a surface is explicitly switched to enforce mode -- removes elements from origins the administrator has explicitly classified `prohibited`, or `immutable_pinned` origins whose declared Subresource Integrity hash no longer matches what the page actually serves.
- **Supported WordPress surfaces:** same caveat as Reverse Tabnabbing above -- `Content_Rewriter`'s shared exclusion gate means this control can, in practice, only ever rewrite the `frontend` surface; the `admin`/`login`/`api` rows in `sam_pillar_profiles` exist but have no observable live effect.
- **Default state:** **no row is seeded at all on activation** -- unlike the header pillars, `Dependency_Governance_Builder::PILLAR_KEY` never appears in `Activator::seed_default_pillar_profiles()`'s row list. A fresh install shows this as "Not configured" and it is fully inactive until an administrator explicitly enables it per surface. When first enabled, every newly discovered origin is stored as `unclassified`, never `prohibited` -- the code's own docblock is explicit that this deliberately diverges from a naive default-deny design.
- **Report-only capability:** yes, and it is the default whenever the pillar is enabled -- `mode = 'report'` (the default) never removes anything; only `mode = 'enforce'`, an explicit further opt-in per surface, does.
- **Enforcement capability:** yes, per surface -- and even in enforce mode, an `unclassified` origin is never silently blocked; only an origin an administrator explicitly marked `prohibited`, or an `immutable_pinned` origin whose live `integrity` attribute no longer matches the admin-declared `expected_sri`, is removed.
- **Discovery capability:** yes, passive (not an active crawl like CSP's `Discovery`) -- every non-first-party `<script>`/`<link rel="stylesheet">` origin encountered during a real, eligible frontend page render is recorded (or has its evidence count/last-seen URL updated) in `sam_dependency_inventory`, keyed by `resource_type:origin`.
- **Approval requirements:** standard (`manage_options` + nonce) for both the mode toggle (`ajax_set_dependency_mode`) and, notably, classification changes themselves (`ajax_classify_dependency`) -- including marking an origin `prohibited` or pinning an `immutable_pinned` SRI hash, which is arguably the single most security-consequential action this pillar offers. There is no separate confirmation step, and (see Audit events) no audit-log entry for it either.
- **Risk of breakage:** moderate in enforce mode -- a `prohibited` classification, or a stale pinned SRI hash on a legitimately-updated third-party asset, removes that `<script>`/`<link>` element from the page outright. SRI is never fabricated by the plugin itself: `expected_sri` only ever comes from an administrator typing or pasting a hash they already trust; the plugin never computes a hash from a live remote fetch, which would defeat the point of SRI if the remote origin were compromised.
- **Rollback behaviour:** the `sam_pillar_profiles` (mode/enabled) row is covered by the generic schema-migration snapshot; `sam_dependency_inventory` (the actual per-origin classifications) is **not** in `Rollback_Guard::SNAPSHOT_TABLE_SUFFIXES` and so is not restorable via the snapshot mechanism at all -- a classification change (including marking something `prohibited`) has no automated undo of any kind.
- **Audit events:** none for enabling the pillar, changing its mode, or classifying an origin. The one and only audit event anywhere in this control's family is reactive: `Dependency_Integrity_Monitor`'s daily proactive scan (throttled once/day via `admin_init`) logs `dependency_integrity_monitor`/`sri_mismatch` when a pinned SRI hash no longer matches what the site's own homepage actually serves -- catching drift before a real visitor's enforce-mode page load would silently strip the element.
- **Limitations:** same `Content_Rewriter` surface restriction as Reverse Tabnabbing (frontend-effective only); `Dependency_Integrity_Monitor`'s proactive check is scoped to the frontend homepage only ("admin/login/api don't have a single representative URL that can be fetched anonymously the way the homepage can," per its own docblock); classification/pinning changes are not covered by any rollback mechanism.
- **Relevant standards:** Subresource Integrity (W3C).

## Internal Script Integrity

**Implementation:** `includes/security/class-internal-script-integrity-builder.php` (`WP_SAM\Security\Internal_Script_Integrity_Builder`, extends `Request_Surface` directly -- **not** `Content_Rewriter` or `Header_Builder`).

- **Purpose:** adds Subresource Integrity (`integrity="sha384-…"`) to first-party (theme/plugin/core) `<script src>` and `<link rel="stylesheet">` tags, protecting against tampering between this server and the browser (e.g. a compromised caching layer or CDN sitting in front of an otherwise-untouched origin file) -- fundamentally different from the third-party trust model External Script Integrity addresses, because the hash is always computed by reading the exact local file this install is about to serve, never by trusting a fetched remote response.
- **Supported WordPress surfaces:** frontend, admin, login, api -- and unlike the two `Content_Rewriter`-based controls above, **this one genuinely is live on all four**, because it hooks the `script_loader_tag`/`style_loader_tag` filters directly rather than going through `Content_Rewriter`'s admin/login/AJAX/REST exclusion gate.
- **Default state:** **no row is seeded at all on activation**, same as External Script Integrity -- inactive ("Not configured") on every surface until an administrator explicitly enables it. The code's own docblock explains why this one, unlike the always-on nonce injection CSP performs unconditionally, gets the same opt-in treatment as the rest of the optional pillars: "integrity hashing here is purely additive hardening with no downside if left off."
- **Report-only capability:** not applicable -- there is no blocking/removal behaviour in this control at all (see Enforcement capability), so a report-only/enforce distinction doesn't apply.
- **Enforcement capability:** in a narrower sense than every other control in this inventory -- this pillar never removes or blocks anything itself. It only ever *adds* an `integrity`/`crossorigin="anonymous"` attribute pair to a tag WordPress is already about to output; the browser is what enforces the hash match. If the hash doesn't match what the browser actually receives, the browser silently refuses to execute/apply that resource -- this plugin has no visibility into that outcome and does not detect or log it.
- **Discovery capability:** not a classification/proposal workflow like External Script Integrity's, but the pillar does maintain its own live inventory (`sam_internal_asset_inventory`) of every first-party asset it has hashed, keyed by resource type + local path, reusing a cached hash (by matching file size and mtime) rather than re-reading and re-hashing an unchanged file on every request.
- **Approval requirements:** standard.
- **Risk of breakage:** low under normal operation -- hashes are computed fresh from whatever file is actually about to be served, so a routine plugin/theme/core update simply produces a new hash on the next request rather than a mismatch. The realistic failure mode is a caching/CDN layer serving a stale asset body against a freshly-computed hash for the *current* file, which would cause the browser to refuse that specific resource.
- **Rollback behaviour:** `sam_internal_asset_inventory` is not part of the `Rollback_Guard` snapshot table list -- but this is low-consequence, since the table is described as fully recomputed from files, not admin-decided configuration (`docs/rollback-and-recovery.md` groups it with tables that don't need restoring for that reason). The `sam_pillar_profiles` enabled/disabled row is covered by the generic snapshot.
- **Audit events:** none.
- **Limitations:** the plugin has no way to observe whether a browser actually rejected a resource due to an integrity mismatch (that failure happens entirely client-side); path resolution is deliberately conservative -- only URLs that resolve to a real, containment-checked path under this install's own known content/includes/admin/site-root directories are hashed, so any first-party asset served through an unrecognised path mapping (an unusual rewrite rule, a symlinked directory outside `ABSPATH`) is silently skipped rather than hashed incorrectly.
- **Relevant standards:** Subresource Integrity (W3C).

---

## Information Masking

**Implementation:** `includes/security/class-information-masking-builder.php` (`WP_SAM\Security\Information_Masking_Builder`), live self-probe in `includes/security/class-information-masking-diagnostic.php`.

- **Purpose:** removes HTTP response headers that disclose the server technology stack, PHP version, or this site's own hostname to a passive observer -- specifically `X-Powered-By`, `Server`, and `X-Pingback` (GitHub issue #220).
- **Supported WordPress surfaces:** frontend, admin, login, api.
- **Default state:** enabled on all four surfaces at activation (part of the same `seed_default_pillar_profiles()` batch as the other always-on header pillars).
- **Report-only capability:** none -- binary on/off, no configurable value (same shape as X-Content-Type-Options).
- **Enforcement capability:** yes, the only mode -- calls `header_remove()` for all three header names whenever active.
- **Discovery capability:** none as configuration, but see Limitations -- a live diagnostic exists to check whether removal actually took effect.
- **Approval requirements:** standard.
- **Risk of breakage:** effectively none -- removing these three headers has no functional effect on the site; they exist purely for disclosure.
- **Rollback behaviour:** generic only.
- **Audit events:** none.
- **Limitations:** removal reliability differs sharply by header. `X-Powered-By` and `X-Pingback` are set by PHP/WordPress itself, so `header_remove()` reliably removes them. `Server`, on most hosting configurations, is set by the web server (Apache/Nginx/LiteSpeed) *before* PHP ever runs, at a layer `header_remove('Server')` cannot reach or override -- the plugin still attempts the call (harmless, and it does work on some hosts/SAPIs), but whether it actually took effect on a given install is never assumed; that is exactly what `Information_Masking_Diagnostic`'s live self-probe exists to check, with host-level configuration (Apache `ServerTokens`/`ServerSignature`, Nginx `server_tokens off;`) as the documented remedy when it doesn't. `X-Generator` (WordPress core's own version tag) is deliberately out of scope: confirmed to be emitted as a `<generator>` element in RSS/Atom feed *body* content via the `the_generator` filter, never as an actual HTTP header -- masking it would be body-content modification, a different mechanism this header-only pillar deliberately doesn't take on.
- **Relevant standards:** not a formal standard -- general information-disclosure hardening commonly recommended by guides such as the OWASP Secure Headers Project, not an implementation of a numbered spec.

## Cache-Control

**Implementation:** `includes/security/class-cache-control-builder.php` (`WP_SAM\Security\Cache_Control_Builder`), conflict check in `includes/security/class-cache-control-conflict-detector.php` (`WP_SAM\Security\Cache_Control_Conflict_Detector`) (GitHub issue #221).

- **Purpose:** emits a `Cache-Control` header from a small set of named, internally-consistent presets, so caching-sensitive responses (e.g. authenticated/session-bearing pages) are not cached inappropriately by shared caches or the browser.
- **Supported WordPress surfaces:** frontend, admin, login, api.
- **Default state:** unlike every other simple pillar, **a row is seeded for every surface but with `enabled = 0`** -- disabled by default everywhere, not merely "Not configured." The code's own docblock is explicit about why this pillar alone gets this treatment: "Cache-Control is a performance/behaviour decision, not a universal security hardening default the way X-Content-Type-Options or X-Frame-Options are... shipping this pillar pre-enabled would risk silently changing a site's frontend caching behaviour on upgrade." The stored default value, for whenever an admin does enable it, is still the safest preset (`no-store`), so enabling starts from a safe choice rather than an empty one.
- **Report-only capability:** none -- one of a fixed 4-preset enum (`no-store`, `private-no-cache`, `public-short`, `public-long`), each mapping to a specific, internally-non-contradictory `Cache-Control` value (e.g. `no-store` maps to `no-store, no-cache, must-revalidate`) rather than a free-form directive builder, specifically because raw Cache-Control directives can be mutually contradictory (`public` and `private` are exclusive; `max-age` is meaningless alongside `no-store`) in a way a preset can never express.
- **Enforcement capability:** yes, the only mode, and gated by its own conflict check (see below) even when the stored row says `enabled = 1`.
- **Discovery capability:** none.
- **Approval requirements:** standard for the pillar's own toggle. Separately, whether a CDN/edge cache is "acknowledged" as already managing caching is a plain site-wide option (`wp_sam_cache_control_cdn_acknowledged`) an administrator sets manually on the Cache Control admin page -- the code's own docblock notes this is deliberately manual, since a reverse proxy or CDN's caching behaviour "isn't observable from inside a single PHP request on the origin server," per issue #221's own admission.
- **Risk of breakage:** moderate if enabled carelessly on the frontend surface with a `public-*` preset for pages that shouldn't be publicly cached (e.g. anything session-sensitive). Mitigated by `is_profile_active()` additionally consulting `Cache_Control_Conflict_Detector::detect()['blocked']` before ever emitting the header -- a stored `enabled = 1` row is not sufficient on its own.
- **Rollback behaviour:** generic only.
- **Audit events:** none -- neither the pillar toggle/value change nor a conflict-blocked emission is logged to the audit log; `Cache_Control_Conflict_Detector::detect()` simply returns a `blocked`/`reason`/`detail` array consumed by `is_profile_active()` and the admin UI, with no `Audit_Log::log()` call anywhere in either class.
- **Limitations:** the conflict detector is deliberately narrower than CSP's `Conflict_Detector` and works completely differently -- it does **not** treat "a Cache-Control header already exists" as a conflict at all, because WordPress core's own `nocache_headers()` already sends one on nearly every dynamic admin/login/preview request; treating that as a conflict would gray this pillar out on every WordPress site unconditionally. Instead it only checks two things: whether a known caching plugin is active (a fixed, code-maintained list of 9 plugins -- WP Rocket, W3 Total Cache, WP Super Cache, LiteSpeed Cache, WP Fastest Cache, Cache Enabler, SiteGround Speed Optimizer, WP-Optimize, Breeze -- detected via each plugin's own stable bootstrap-time constant/class marker, confirmed live against each plugin's current WordPress.org SVN trunk or GitHub repository on 2026-09-03), or whether a CDN has been manually acknowledged. A caching plugin or CDN not on that list, or one that changes its own bootstrap marker in a future release, is not detected, and this pillar would then emit a header alongside whatever that other mechanism sends -- the exact "competing header" scenario issue #221 asks to avoid, just for an unlisted plugin.
- **Relevant standards:** RFC 9111 (HTTP Caching, obsoletes RFC 7234).
