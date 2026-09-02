# VCNS Security Automation Manager
## Phase 3 Development Roadmap and Requirements Specification

**Product:** VCNS Security Automation Manager  
**Repository:** `vcns/security-automation-manager`  
**Phase:** 3  
**Baseline:** v2.9.24  
**Status:** Substantially delivered as of v2.9.44 (2 September 2026) -- pruned to reflect that; see the delivery-status table below before reading any individual section  
**Date:** 29 August 2026 (original); pruned 2 September 2026

---

## Delivery status (added 2 September 2026)

This document was written as a forward-looking spec. Most of it has since shipped. Rather than delete what's done, every section below now carries a one-line status: **Delivered** sections are trimmed to a pointer at what implements them (full requirement text was carried into the code's own docblocks and `SPECIFICATION.md`, so keeping a second full copy here just invited drift -- exactly the failure mode `docs/consolidation-ledger.md` and this session's GitHub issue audit both found in other documents). Sections with **real remaining work** keep their full original text unchanged -- that text is the active specification for whoever picks it up. Sections marked **Deferred** were explicitly, deliberately not built by product decision, not oversight.

| § | Title | Status |
|---|---|---|
| 1-3 | Purpose, Product Model, Operational Lifecycle | Living architecture principles -- kept in full, not a delivery target |
| 4 | WordPress Surfaces | Delivered |
| 5 | Technology Pillars | Delivered (definitional, kept in full) |
| 6 | Administration IA | Delivered, one stale line to fix |
| 7 | Visitor and Request Intelligence | Delivered |
| 8 | Identity Verification | Delivered, one field (ASN) blocked on §13.5 |
| 9 | Commercial Scanner Intelligence | Delivered (mechanism); vendor data is a sourcing decision, not a code gap |
| 10 | Bot, Crawler and Scraper Detection | **Real remaining work** -- kept in full |
| 11 | Pattern Recognition and Detector Families | **Real remaining work** (3 of 13 families) -- kept in full |
| 12 | HTTP Method Intelligence | **Real remaining work** -- kept in full |
| 13 | Traffic Protection Controls | **Real remaining work** (13.4-13.6 zero) -- kept in full |
| 14 | Campaign Detection | Delivered |
| 15 | Deception and Honey Paths | Delivered |
| 16 | Integrity Monitoring | Delivered, partial (2 of 9 signals) -- kept in full |
| 17 | Change Attribution | Delivered |
| 18 | Security Change Window | Delivered |
| 19 | Baseline and Drift | Delivered |
| 20 | External Verification | **Deferred by explicit decision**, 2 September 2026 -- kept in full |
| 21 | Site Security Health | Delivered |
| 22 | Recommendations | **Real remaining work**, not started -- kept in full |
| 23 | Federated Intelligence Service | **Deferred by explicit decision**, 2 September 2026 -- kept in full |
| 24 | Managed Intelligence Updates | **Deferred by explicit decision**, 2 September 2026 -- kept in full |
| 25 | Commercial Product Boundary | **Real remaining work** (packaging design undone) -- kept in full |
| 26 | Evidence and Assurance | Delivered |
| 27 | Fleet Management | **Deferred by explicit decision** (unchanged since original write) -- kept in full |
| 28-34 | UX, Explainability, Default-Safety, Architecture, Testing, Performance, Privacy | Living cross-cutting requirements -- kept in full |
| 35 | Development Roadmap (3A-3J) | Updated inline with delivery status per sub-phase |
| 36-38 | Non-Goals, Definition of Done, Strategic Outcome | Living principles / status-checked -- kept in full |

Everything marked "real remaining work" or "deferred" above is the raw material for the next phase plan -- see `.roadmap/phase4_plan.md`.

---

# 1. Purpose

Phase 3 extends VCNS Security Automation Manager from a strong WordPress security-control plugin into a broader site security and assurance platform.

The existing product already provides substantial local protection and security-policy automation. Phase 3 must preserve that foundation while adding:

- clearer product architecture and navigation;
- behavioural and request intelligence;
- bot, crawler and scanner identification;
- traffic controls;
- security-event classification;
- pattern recognition;
- baseline and drift detection;
- external verification;
- centralised intelligence services;
- evidence and assurance reporting;
- controlled automation;
- optional future commercial and managed-service capability.

The product must remain locally authoritative. A central VCNS service may provide intelligence, aggregation, recommendations and signed updates, but it must not become an unrestricted remote-control channel into customer WordPress installations.

---

# 2. Product Model

Phase 3 formalises three separate concepts which must not be conflated.

## 2.1 Protection Layers

The protection layers describe the architectural capability stack.

### Layer 1: Governance and Operations

This layer provides the control framework around every other capability.

It includes:

- audit evidence;
- capability controls;
- diagnostics;
- readiness checks;
- controlled updates;
- rollback and recovery;
- configuration portability;
- decision provenance;
- exception handling;
- security-event history;
- administrator accountability;
- evidence retention.

### Layer 2: Controlled Automation

This layer governs how the product progresses from human-controlled decisions to automated operation.

Supported maturity states should include:

1. Manual
2. Assisted
3. Controlled automatic
4. Fully automatic, where explicitly permitted

Automation must always use safe fallback mechanisms.

A failed automation decision must not weaken an existing security control.

Higher-risk actions must remain approval-gated unless the administrator has explicitly authorised an automation posture that permits them.

### Layer 3: Continuous Intelligence

This layer observes the site and its inbound traffic, derives security context and produces evidence-backed recommendations.

It includes:

- source discovery;
- request-pattern recognition;
- change detection;
- behavioural analysis;
- scanner recognition;
- crawler and bot recognition;
- confidence scoring;
- threat and security-event classification;
- recommendations;
- known-service intelligence;
- change attribution;
- drift detection.

### Layer 4: Browser Security Policies

This layer contains browser-facing controls and browser security policy management.

It includes, but is not limited to:

- Content Security Policy;
- Cross-Origin Opener Policy;
- Cross-Origin Embedder Policy;
- Cross-Origin Resource Policy;
- X-Permitted-Cross-Domain-Policies;
- X-Frame-Options;
- Referrer-Policy;
- Permissions-Policy;
- X-Content-Type-Options;
- HSTS where appropriate to browser-facing transport policy;
- reverse tabnabbing protection;
- external script governance;
- Subresource Integrity;
- internal script integrity.

### Layer 5: Transport and Certificate Trust

This layer covers transport identity, certificate management and network trust.

It includes:

- HTTPS;
- host and transport checks;
- certificate state;
- ACME;
- DNS-01;
- HTTP-01;
- certificate issuance;
- certificate deployment;
- renewal;
- provider capability checks;
- external certificate verification;
- DNS-provider validation;
- certificate trust evidence.

---

# 3. Operational Lifecycle

The operating lifecycle must be presented consistently across the product:

**Observe → Decide → Control → Verify**

The previous term "Enforce" must be replaced with **Control**.

"Control" is preferred because the correct security action is not always enforcement. A decision may result in:

- observation only;
- notification;
- recommendation;
- throttling;
- challenge;
- temporary blocking;
- permanent blocking;
- allowlisting;
- policy adjustment;
- escalation;
- explicit no-action.

Every significant Phase 3 feature should identify where it sits in this lifecycle.

## 3.1 Observe

Collect evidence without making an enforcement decision.

Examples:

- request behaviour;
- source IP;
- ASN;
- Geo-IP;
- user-agent;
- request path;
- HTTP method;
- known scanner range;
- known crawler identity;
- CSP violations;
- script changes;
- certificate changes;
- policy drift.

## 3.2 Decide

Evaluate evidence using deterministic rules, confidence, policy and administrator configuration.

Examples:

- known scanner versus unknown scanner;
- authorised scanner versus merely recognised scanner;
- genuine Googlebot versus claimed Googlebot;
- likely SQL injection;
- likely reconnaissance;
- likely crawler;
- likely credential attack;
- likely campaign;
- known change versus unexplained drift.

## 3.3 Control

Apply an explicitly permitted response.

Examples:

- observe only;
- log;
- alert;
- rate-limit;
- temporarily block;
- block;
- allow;
- challenge;
- restrict by surface;
- restrict by geography;
- restrict by ASN;
- apply a policy;
- suppress a known false positive.

## 3.4 Verify

Confirm whether the control had the intended effect.

Examples:

- confirm policy is externally visible;
- confirm blocked traffic no longer reaches the protected surface;
- confirm a CSP policy change is present;
- confirm a certificate is correctly deployed;
- confirm a crawler identity;
- confirm a previously detected drift condition has been resolved.

---

# 4. WordPress Surfaces

The product must continue to manage WordPress surfaces independently.

The minimum supported surfaces are:

- Frontend
- Admin
- Login
- API

A capability may apply to one, several or all surfaces.

Controls must be independently configurable per surface where technically meaningful.

Examples:

- public crawler controls may apply only to Frontend;
- `/wp-admin/` protections apply to Admin;
- credential-stuffing controls primarily apply to Login;
- abusive API clients may be controlled specifically on API.

The product must not assume that a control suitable for one surface is appropriate for every surface.

---

# 5. Technology Pillars

Technology pillars are the individual technical control families currently represented in the WordPress administration navigation.

Examples include:

- Certificates
- Cross-Origin Policies
- CSP
- HSTS
- Permissions-Policy
- Referrer-Policy
- Reverse Tabnabbing
- Scripts
- X-Content-Type-Options
- X-Frame-Options

These pillars are not the same as the five protection layers.

The pillars remain useful for technical users and as drill-down destinations.

Phase 3 must preserve direct access to them while introducing a simpler lifecycle-oriented primary experience.

---

# 6. Administration Information Architecture

**Status: Delivered.** Primary navigation (§6.1) is Observe/Decide/Control/Verify/Settings, live in `includes/admin/views/page-observe.php`, `page-decide.php`, `page-control.php`, `page-verify.php`, `page-overview.php` -- the original technology-standard pages remain as CSS-hidden-but-reachable drill-downs (`class-admin-ui.php`'s `print_hidden_menu_css()`), exactly per §6.1's intent. Settings is the default landing page (§6.2), grouped by protection layer (§6.3, `page-overview.php`). Status vocabulary (§6.4) shipped as a narrower 4-state set (`not-configured`/`disabled`/`report-only`/`active` -- `class-status-badge.php:25-28`) than the ~15 candidates originally listed; the roadmap itself said labels should be "normalised during implementation," so this is an accepted narrowing, not a gap.

**One stale line to fix:** `page-observe.php:101-103` still says an ongoing baseline/drift feed is "not yet available... planned for a future phase" -- it shipped in Phase 3F. Small copy fix, tracked in `.roadmap/phase4_plan.md`.

---

# 7. Visitor and Request Intelligence

**Status: Delivered.** `includes/intelligence/class-request-observer.php` builds per-request context (IP, method, path, surface, user-agent) on every request across all four surfaces, consumed by `Detector_Engine` and `Identity_Resolver`. Predates this document (Phase 3B) but intact and unchanged.

---

# 8. Identity Verification

**Status: Delivered**, one field short. `includes/intelligence/class-identity-resolver.php` (`resolve()`, `verify_fcrdns()`) implements the full identity-record model this section specifies: claimed identity, user-agent match, published-network match, rDNS/forward-confirmed-rDNS, verification result, confidence -- see `class-scanner-identity-store.php` for the persisted state shape ("verified / probable / claimed only / false claim / unknown", matching this section's example almost verbatim). Architecture is generic across identity types, not scanner-specific.

**Missing:** the "source ASN" field from the candidate record list above -- no ASN resolver exists anywhere in the codebase. Blocked on the same missing verified data source as §13.5; not a separate piece of work.

---

# 9. Commercial Scanner Intelligence

**Status: Delivered (mechanism).** `includes/intelligence/class-scanner-vendor-store.php` implements the exact §9.2 authoritative-source schema (vendor, category, CIDR ranges, rDNS suffixes, source URL, verification method), and `class-scanner-identity-store.php` implements all seven §9.1 trust states verbatim (unknown, known commercial scanner, known research scanner, customer-authorised, explicitly denied, previously-authorised-expired, identity conflict). The load-bearing rule, unchanged and enforced throughout:

> **Recognition is not authorisation.** A source IP matching a published vendor range only identifies likely ownership or service association -- it does not by itself authorise, allowlist, or bypass anything. Customer-specific authorisation is a separate, explicit administrator decision.

**Not delivered, and not a code gap:** none of the initial known categories (Qualys, Tenable, Rapid7, Detectify, Intruder, StackHawk, Burp Suite DAST, Acunetix, ImmuniWeb, BitSight, Censys) are pre-seeded -- only Googlebot/Bingbot are, deliberately, because their network ranges are forward-confirmed-reverse-DNS-verifiable without fabricating commercial vendor data VCNS hasn't independently verified (`class-activator.php`'s `seed_default_scanner_vendors()` docblock). Administrators can already add vendors themselves via the UI; shipping pre-verified commercial-vendor data is a data-sourcing decision, not an engineering task, and is out of scope for a plan document.

---

# 10. Bot, Crawler and Scraper Detection

**Status: real remaining work.** The identity-matching substrate this depends on (§8, §9) is delivered, but the multi-signal classification model below is not -- no robots.txt-behaviour tracking, no session/cookie-behaviour analysis, no header-consistency scoring, no AI-crawler identities seeded (zero matches for `GPTBot`/`ClaudeBot`/`CCBot`/`PerplexityBot` anywhere in the codebase). Rate/timing signals exist only generically via `Rate_Limiter`, not attributed to "crawler behaviour" as its own classification. Full text below is the active spec.

Phase 3 should support classification of:

- legitimate search-engine crawlers;
- AI crawlers;
- commercial crawlers;
- scraper services;
- unidentified automation;
- likely botnets;
- browser automation;
- aggressive crawlers;
- impersonated crawlers.

The system should avoid a binary "bot/not bot" model.

Suggested classification should consider:

- user-agent identity;
- IP ownership;
- ASN;
- vendor-published ranges;
- reverse DNS;
- request rate;
- request distribution;
- URI patterns;
- robots.txt behaviour;
- session/cookie behaviour;
- header consistency;
- method use;
- timing;
- repeated errors;
- cross-site intelligence where centrally available.

---

# 11. Pattern Recognition and Detector Families

**Status: real remaining work, 10 of 13 families delivered.** `class-detector-registry.php`'s `register_defaults()` registers exactly 10: 11.1 Technology Mismatch, 11.2 Command Injection, 11.3 SQL Injection, 11.5 Script/Web-Shell Probes, 11.7 Protocol Injection, 11.8 Sensitive Directory Probing, 11.9 Sensitive File Probing, 11.10 Setup/Install Probes, 11.11 Version-Control Artefacts, 11.12 Vulnerability Probes -- each with full test fixtures per §32. **Not built:** §11.4 HTML Injection, §11.6 PHP/PHPUnit Probes, §11.13 Legacy WordPress Endpoints (XML-RPC) -- three genuinely new detector families, kept in full below. Also missing: no detector carries an "allowed control actions" / "default action" field (per the shared metadata contract below) -- `Traffic_Guard` blocking is generic rate/IP-based, not keyed to which detector family matched, so §13.3's "firewalling by detector family" depends on this too.

Phase 3 should not implement an unstructured collection of independent regular expressions.

It should introduce detector families.

Each detector should declare:

- detector ID;
- detector family;
- description;
- evidence inputs;
- pattern version;
- confidence;
- severity;
- applicable surfaces;
- false-positive considerations;
- allowed control actions;
- default action;
- source/provenance;
- last update;
- test fixtures.

Initial detector families should include the following.

## 11.1 Technology Mismatch

Detect attempts to access technologies or platforms not used by the site.

Examples:

- Magento probes against a WordPress-only site;
- Joomla paths;
- Drupal paths;
- unrelated administrative endpoints.

Technology mismatch alone should generally be a reconnaissance signal rather than an automatic permanent-block signal.

## 11.2 Command Injection

Detect common command-injection attempts.

Signals may include:

- shell separators;
- command chaining;
- encoded shell constructs;
- suspicious command substitution;
- known shell utility invocation;
- payloads intended to execute server commands.

## 11.3 SQL Injection

Support deterministic SQL-injection pattern recognition across relevant request data.

The system should distinguish:

- low-confidence keyword matches;
- structural SQL injection;
- encoded patterns;
- repeated exploitation attempts.

## 11.4 HTML Injection

Detect suspicious attempts to inject HTML.

This detector must be treated carefully because legitimate application requests may submit HTML.

Default posture should therefore be observation unless the protected endpoint is known not to accept HTML.

## 11.5 Script and Web-Shell Probes

Detect probing for script-execution files and web shells.

Candidate extensions include:

- `.php`
- `.cgi`
- `.pl`
- `.py`
- `.sh`
- `.asp`
- `.aspx`
- `.jsp`
- `.jsf`
- `.shtm`
- `.shtml`

The system must use context and path semantics rather than assuming every request for one of these extensions is malicious.

## 11.6 PHP and PHPUnit Probes

Detect common probes for:

- PHPUnit;
- exposed PHP development utilities;
- known historical vulnerable test endpoints;
- common web-shell paths.

These should be maintained as versioned intelligence rather than fixed assumptions embedded permanently in code.

## 11.7 Protocol Injection

Detect attempts to inject alternate protocols into parameters or URLs.

Examples may include:

- `file://`
- `ftp://`
- unexpected URI schemes;
- suspicious PHP wrappers;
- unexpected protocol handlers.

The detector must distinguish legitimate application behaviour from exploit attempts.

## 11.8 Sensitive Directory Probing

Detect attempts to access paths associated with host filesystem structure.

Examples:

- `/etc/`
- `/usr/`
- `/var/`

This includes encoded traversal attempts that resolve towards such paths.

## 11.9 Sensitive File Probing

Detect likely attempts to retrieve secrets, credentials or sensitive configuration.

Examples include:

- private keys;
- `id_rsa`;
- `id_dsa`;
- credential files;
- `.secret`;
- `.env`;
- `.aws/credentials`;
- configuration files;
- package lock files;
- composer metadata;
- version-control metadata.

Detection should be path-aware and should not blindly classify every `.json`, `.yaml`, `.conf` or similar file as malicious.

## 11.10 Setup and Installation Probes

Detect requests for:

- setup pages;
- installers;
- test pages;
- obsolete configuration scripts;
- known product installation paths;
- common forgotten deployment artefacts.

## 11.11 Version-Control and Build Artefacts

Detect access attempts involving:

- `.git`;
- `.svn` where appropriate;
- `.env`;
- lock files;
- package metadata;
- Composer artefacts;
- build scripts;
- shell scripts.

## 11.12 Vulnerability Probes

Detect requests for common exposed administrative and vulnerable services.

Examples:

- phpMyAdmin;
- cPanel;
- known database interfaces;
- known management tools;
- known vulnerable plugin paths.

## 11.13 Legacy WordPress Endpoints

Support explicit controls for old or commonly abused WordPress endpoints where applicable.

RPC/XML-RPC controls must be configurable rather than assumed universally safe to block.

---

# 12. HTTP Method Intelligence

**Status: real remaining work, small-to-moderate.** Method is already captured as raw evidence (`class-request-observer.php`, `REQUEST_METHOD` -> context -> `Event_Store`), but no classification logic exists on top of it -- `Rate_Limiter` keys only on `(ip, surface)`, no method dimension anywhere. Since the data is already recorded, building the classification below is additive, not architectural.

The product should classify HTTP methods in context.

Methods such as GET, POST and HEAD are expected.

OPTIONS must not be considered malicious merely because it is OPTIONS.

OPTIONS may be:

- legitimate CORS preflight;
- application/API discovery;
- scanner reconnaissance;
- unusual traffic.

Method classification must therefore combine:

- target surface;
- target URI;
- request rate;
- accompanying headers;
- origin;
- subsequent behaviour.

---

# 13. Traffic Protection Controls

**Status: real remaining work.** 13.1/13.2/13.3 are partially delivered (see per-subsection notes); **13.4 Geo-IP, 13.5 ASN, and 13.6 Tor Awareness are genuinely zero-implementation** -- no matches for `geoip`/`asn`/`tor` anywhere in `includes/` beyond forward-looking docblock comments explicitly noting they're not yet built. This is correctly blocked on sourcing a verified, licensable data provider, not an oversight -- confirmed no partial scaffolding exists to build on. 13.7 Progressive Response is fully delivered.

Phase 3 should introduce a coherent traffic-protection capability.

## 13.1 Rate Limiting

**Delivered, by `(ip, surface)` only** (`class-rate-limiter.php`, `class-traffic-guard.php`). Missing dimensions from the list below: subnet, ASN, identity, endpoint, HTTP method, request classification, authenticated state.

Support rate limits based on combinations of:

- source IP;
- subnet;
- ASN;
- identity;
- endpoint;
- surface;
- HTTP method;
- request classification;
- authenticated/unauthenticated state.

Controls should support:

- observation;
- threshold warnings;
- progressive throttling;
- temporary blocks;
- escalating temporary blocks.

## 13.2 Excessive Request Detection

**Partial.** Generic rate-limit exceed/escalation exists (`class-traffic-guard.php`), but doesn't yet distinguish the categories below as separate classifications -- it's one undifferentiated "rate_limit" reason.

The product should distinguish between:

- high legitimate traffic;
- crawler behaviour;
- brute force;
- scraping;
- scanning;
- endpoint abuse;
- distributed activity.

## 13.3 Firewalling

**Partial.** IP/CIDR block/allow rules implemented (`class-ip-rule-store.php`, `class-cidr-matcher.php`). Missing: ASN, country, identity, detector-family, request-rate-as-firewall-dimension.

Phase 3 may introduce application-level request blocking.

This must not be represented as equivalent to a network firewall.

Controls may include:

- source IP;
- CIDR;
- ASN;
- country;
- identity;
- detector family;
- target surface;
- request rate.

## 13.4 Geo-IP Controls

Optional Geo-IP controls may support:

- observe;
- alert;
- allow;
- deny;
- rate limit;
- challenge where technically feasible.

Geo-IP data must be treated as probabilistic location intelligence, not proof of a person's physical location.

Geo-IP blocking should not be enabled by default.

## 13.5 ASN Controls

Support classification and optional policy by ASN.

This may be particularly useful for:

- hosting providers;
- cloud platforms;
- VPN providers;
- scanning infrastructure;
- known bot networks.

## 13.6 Tor Awareness

Phase 3 may identify known Tor exit nodes.

Tor identity must not imply malicious intent.

Default treatment should be observation only.

## 13.7 Progressive Response

**Delivered.** `class-traffic-guard.php`'s stage model matches the 6-stage list below almost exactly, with the final stage requiring explicit admin action (`Traffic_Block_Store::set_persistent()`).

Where appropriate, controls may escalate through stages:

1. observe;
2. warn;
3. throttle;
4. temporary block;
5. longer temporary block;
6. administrator-reviewed persistent block.

---

# 14. Campaign Detection

**Status: Delivered**, one signal of the eight listed. `includes/intelligence/class-campaign-detector.php` + `class-campaign-store.php` implement distinct-source-IP correlation per detector+surface within a time window -- the roadmap's own worked example (many IPs, one unusual request sequence). Observe/correlate/notify only, exactly as required; blocking participants is a separate, explicit admin action with a required reason, never automatic. **Not implemented:** payload-fingerprint clustering, common-UA/timing correlation, multi-cloud-provider awareness, path sequencing -- each would need infrastructure (payload fingerprint storage, ASN/provider lookup) this build doesn't have; not faked.

---

# 15. Deception and Honey Paths

**Status: Delivered.** `includes/intelligence/class-honeypath-store.php` + `detectors/class-honeypath-detector.php`. Disabled by default because a fresh install has zero configured paths (structural, not a flag). A hit is recorded through the same `Event_Store` path as every other detector; the actual HTTP response is never altered, satisfying "no active exploitation of the requester" by construction.

---

# 16. Integrity Monitoring

**Status: Delivered, 2 of 9 signals.** `includes/intelligence/class-account-integrity-recorder.php` covers new administrator accounts and role escalations to administrator, correlating with the existing plugin/theme/core change log. **Not implemented:** unexpected PHP/executable files, unusual cron entries, unexpected plugin/theme file changes, new third-party script origins, critical-configuration changes -- each needs filesystem/cron-scanning infrastructure this build doesn't have. Explicit gap, not partial/faked coverage.

Candidate signals not yet covered:

- unexpected PHP files;
- unexpected executable files;
- unexpected scheduled tasks;
- unusual WordPress cron entries;
- unexpected plugin/theme file changes;
- new third-party script origins;
- changes to critical configuration.

---

# 17. Change Attribution

**Status: Delivered.** `includes/admin/class-change-timeline-builder.php` merges site changes (`Change_Log_Store`), security drift (`Drift_Store`), and campaigns (`Campaign_Store`) into one chronological view, modeled on the existing `Policy_Events_Builder` pattern. Every row is worded as correlation only ("Correlates with...") -- the causation rule below is enforced in the UI copy itself, not just aspirationally.

---

# 18. Security Change Window

**Status: Delivered, 5 of 8 steps.** `includes/intelligence/class-change-window-store.php` covers: (1) snapshot reference -- records whatever baseline is current, doesn't force a fresh capture; (3)+(4) application changes and new behaviour -- already run continuously via existing infrastructure, nothing new needed; (6) delta presentation on close; (8) retained rollback reference via baseline history (`Baseline_Store::approve()` never deletes prior versions). **Not implemented:** (2) "increase observation" has no concrete lever anywhere in the codebase to hook (detector sensitivity isn't currently tunable); (5) "run external verification" depends on §20, deferred. (7) accepting the new baseline stays a separate, explicit "Capture Baseline" action -- never automatic, by design.

---

# 19. Baseline and Drift

**Status: Delivered.** `includes/intelligence/class-baseline-state-builder.php` + `class-baseline-store.php` + `class-drift-store.php` + `class-drift-scanner.php` implement this section close to verbatim: baseline snapshots (CSP headers, pillar toggles, dependency/asset-integrity inventories, certificate expiry, WordPress/theme/plugin versions), drift records with old/new value, risk classification, correlated-change text, and a four-state disposition (`unexplained`/`expected`/`approved`/`resolved`) matching the four states below exactly. Disposition changes only via an explicit administrator action with a required note.

**Not covered:** externally-observed sources (redirects, selected DNS records, externally visible technology) -- those depend on §20, deferred.

---

# 20. External Verification

**Status: deferred by explicit product decision, 2 September 2026** (this is what "Phase 3G" in §35 refers to). Requires a central, VCNS-operated verification service that does not exist yet -- the product owner chose to skip building that infrastructure for now rather than build it prematurely. `Security_Health`'s `external_verification` row (§21) honestly reports "not available yet" rather than faking a status. Kept in full below as the active spec for whenever this is picked back up.

Local configuration alone cannot prove what an external client receives.

Phase 3 should therefore build towards optional VCNS external verification.

Candidate verification targets include:

- public home page;
- representative public pages;
- WordPress login;
- REST API;
- redirects;
- error responses;
- cached responses;
- uncached responses where technically possible;
- selected public application endpoints.

Verification may inspect:

- expected security headers;
- duplicate headers;
- proxy or CDN replacement;
- report-only versus enforced CSP;
- external scripts;
- external styles;
- SRI;
- certificate state;
- HTTP to HTTPS redirection;
- cross-origin controls;
- reporting endpoints;
- unexpected externally observable technology;
- drift from baseline.

Authenticated administration pages must not be externally crawled unless a separate secure design is approved.

---

# 21. Site Security Health

**Status: Delivered**, as an 8-category cross-pillar summary rather than a numeric score, matching this section's own preference. `includes/intelligence/class-security-health.php`'s `get_report()` returns enforcement, drift, certificates, dependencies, exceptions, automation, evidence freshness, and external verification, each with a `{label, value, status, detail}` shape (`pass`/`warning`/`fail`/`info` -- `info` used specifically so external verification can honestly say "not available yet" instead of faking a status). No numeric score exists, per this section's own guidance not to introduce one without a defensible methodology.

---

# 22. Recommendations

**Status: real remaining work, not started.** No matches for `recommendation`/`Recommendation_Engine`/`recommended_action` anywhere in the codebase -- confirmed absent, consistent with GitHub #190's deferral. Nothing to build on beyond the general evidence infrastructure (`Evidence_Exporter`, `Security_Health`) this would need to draw from. Kept in full below.

Recommendations must be evidence-backed.

Each recommendation should, where relevant, state:

- what was observed;
- why it matters;
- affected layer;
- affected pillar;
- affected surface;
- confidence;
- risk;
- evidence;
- recommended action;
- alternative action;
- automation eligibility;
- rollback position.

Deterministic rules remain authoritative for:

- risk classification;
- source validation;
- approval requirements;
- enforcement decisions;
- hard exclusions;
- automation limits.

AI-generated content may assist with explanation, summarisation or recommendation wording.

AI must not independently bypass deterministic controls or directly alter enforced security policy.

---

# 23. Federated Intelligence Service

**Status: deferred by explicit product decision, 2 September 2026** (this is "Phase 3H" in §35 -- deferred together with §20/Phase 3G since it depends on the same central-service infrastructure not existing yet). Kept in full below.

Phase 3 should define a central VCNS intelligence architecture.

The central service may:

- receive limited site observations where explicitly enabled;
- aggregate patterns;
- maintain scanner/vendor network intelligence;
- maintain crawler intelligence;
- maintain detector patterns;
- maintain known exploit signatures;
- maintain compatibility intelligence;
- identify emerging campaigns;
- provide recommendations;
- provide external verification;
- return signed intelligence updates.

The central service must amplify local decision-making rather than replace it.

## 23.1 Local Authority

The WordPress plugin remains locally authoritative.

A central service must not:

- execute arbitrary PHP;
- deliver executable code through an intelligence channel;
- silently override local high-risk decisions;
- disable existing local protections because the service is unavailable;
- act as an unrestricted remote shell.

## 23.2 Data Sent Centrally

Data collection must be minimised.

Candidate telemetry may include:

- pseudonymous site identifier;
- event type;
- detector ID;
- timestamp;
- source network data where permitted;
- request fingerprint;
- target class;
- surface;
- confidence;
- action;
- outcome.

Sensitive request bodies, credentials and customer content should not be transmitted unless explicitly required, justified and approved.

## 23.3 Signed Intelligence

Central intelligence delivered to sites should be:

- versioned;
- signed;
- authenticated;
- provenance-aware;
- replay-resistant;
- locally validated;
- auditable.

## 23.4 Offline Behaviour

Loss of the VCNS service must not remove locally enforceable protection.

Existing controls must continue operating using the last valid local configuration and intelligence cache.

---

# 24. Managed Intelligence Updates

**Status: deferred by explicit product decision, 2 September 2026** -- same reason as §23, part of Phase 3H.

A future managed update service may distribute:

- vendor IP ranges;
- crawler definitions;
- AI crawler identities;
- scanner identities;
- detector signatures;
- known exploit probes;
- compatibility intelligence;
- known infrastructure metadata;
- risk-rule updates.

The value proposition should centre on maintained security intelligence and assurance rather than merely unlocking local interface options.

---

# 25. Commercial Product Boundary

**Status: real remaining work.** Only legacy, single-tier entitlement plumbing exists (`includes/extensions/commercial-services.php`'s `sam_entitlements` table, `tier varchar(32) DEFAULT 'free'` -- one free/paid distinction, not the Community/Professional/Managed taxonomy below). `Detector_Registry::is_available()` and each `Detector::is_available()` are a real, reusable per-detector entitlement gate extension point, ready to wire up once tiers are actually defined. **Not done:** mapping any specific capability below to a tier -- largely moot until the capabilities themselves exist (most of Professional/Managed's list is still §10/§13.4-13.6/§22/§23/§27, all elsewhere marked as remaining work). See `docs/sam-portal-requirements-spec.md` for the checkout/entitlement-delivery infrastructure question, which is related but distinct from the tier-packaging design this section is about.

Phase 3 should allow for future product tiers without requiring the entire architecture to be duplicated.

Potential packaging:

## Community

- local baseline security controls;
- local observation;
- local deterministic detection;
- manual/assisted workflows;
- core certificate management;
- core browser-security controls.

## Professional

Potential future capabilities:

- advanced detector packs;
- richer automated controls;
- advanced request intelligence;
- extended Geo-IP/ASN policy;
- deeper integrity monitoring;
- advanced baseline/drift workflows.

## Managed

Potential future capabilities:

- federated intelligence;
- external verification;
- central reporting;
- fleet posture;
- cross-site pattern intelligence;
- managed detector updates;
- evidence aggregation;
- managed recommendations.

Exact commercial boundaries remain a packaging decision and must be reconciled with WordPress.org distribution requirements.

---

# 26. Evidence and Assurance

**Status: Delivered.** `includes/intelligence/class-evidence-exporter.php`'s `build()` returns a JSON bundle (health summary, per-pillar controls, exceptions, certificates, current baseline, open drift count, recent change log, audit-log excerpt) with an explicit "not a certification" disclaimer and named-framework context (ISO/IEC 27001, PCI DSS, and others) stated as informational only -- never claiming the technical control alone satisfies a requirement, per this section's own rule. **Not covered:** CSV/HTML export formats (JSON only) and signing/checksumming for tamper detection -- see GitHub #178.

---

# 27. Fleet Management

**Status: deferred, unchanged since original write.** No matches for `fleet` anywhere in the codebase -- consistent with GitHub #186-190, all confirmed still deferred.

Fleet management is explicitly later-phase capability.

The central architecture should not be overbuilt before sufficient operational evidence exists.

Future fleet views may show:

- sites;
- version;
- update state;
- protection posture;
- drift;
- outstanding approvals;
- certificate risk;
- active exceptions;
- failed verification;
- scanner/crawler activity;
- intelligence freshness;
- entitlement state.

Example estate view:

- 83 sites
- 76 healthy
- 4 security drift events
- 2 certificate risks
- 1 CSP enforcement regression
- 7 outstanding administrator decisions

Fleet management must be built after real-world independent deployments establish the actual support and operational requirements.

---

# 28. UX Principles

Phase 3 administration must support both technical and non-technical users.

Requirements:

- plain-language lifecycle navigation;
- standards remain visible for technical users;
- technical terms are explained in context;
- no unexplained acronym-only primary navigation;
- evidence is available behind decisions;
- direct technology drill-down remains fast;
- status is understandable without opening every control;
- automation posture is visible;
- surface scope is visible;
- confidence is visible;
- central versus local evidence is distinguishable.

---

# 29. Explainability

Every significant automated action should be explainable.

An action record should answer:

- What happened?
- What evidence was observed?
- Which detector matched?
- How confident was the classification?
- Which policy authorised the action?
- What action was taken?
- Which surface was affected?
- Was the identity independently verified?
- Was the source merely recognised or explicitly authorised?
- How can the action be reversed?
- Was the outcome verified?

This is mandatory for security automation and future MSP/assurance use.

---

# 30. Default-Safety Requirements

Phase 3 must maintain conservative defaults.

The following should not automatically block by default:

- Geo-IP;
- ASN;
- Tor;
- campaign correlation;
- crawler classification;
- commercial scanner recognition;
- technology mismatch;
- HTML injection where legitimate HTML input may exist;
- generic OPTIONS requests;
- uncertain behavioural classifications.

New detector families should normally begin in Observe mode.

Automation may increase only when:

- confidence is sufficient;
- false-positive risk is understood;
- explicit administrator policy permits it;
- rollback or recovery is available where applicable.

---

# 31. Technical Architecture Requirements

**Status: satisfied, differently factored.** Request Observer, Surface Classifier, Identity Resolver, Detector Registry, Detector Engine, and Audit/Evidence Store all exist as named classes. Confidence/policy/control logic lives inside `Traffic_Guard`/`Traffic_Policy_Store` directly rather than as separately-named engines -- a naming/factoring difference, not a missing capability. **Genuinely absent:** `Network_Intelligence_Resolver` and `Intelligence_Update_Client` -- both tied to the same missing ASN/Geo-IP (§13.4-13.6) and federated-intelligence (§23-24, deferred) work, not a separate gap.

The detector subsystem should use reusable interfaces rather than embedding isolated regular expressions throughout request hooks.

Suggested logical components:

- Request Observer
- Surface Classifier
- Identity Resolver
- Network Intelligence Resolver
- Detector Registry
- Detector Engine
- Confidence Engine
- Policy Engine
- Control Engine
- Verification Engine
- Audit/Evidence Store
- Intelligence Update Client

Detector data should be versionable independently from the core detection engine where practical.

---

# 32. Detector Test Requirements

Every detector should have regression fixtures.

Testing should include:

- positive match;
- negative match;
- encoded variant;
- benign lookalike;
- surface applicability;
- action eligibility;
- confidence outcome;
- false-positive regression cases.

Changes to managed detector data should be testable before release.

---

# 33. Performance Requirements

Request inspection must not impose uncontrolled overhead on normal WordPress traffic.

Requirements:

- fast-path rejection of irrelevant detectors;
- avoid repeated external lookups during requests;
- cache network intelligence;
- perform heavy correlation asynchronously;
- bound event storage;
- bound queues;
- configurable retention;
- avoid blocking page delivery on central-service availability.

---

# 34. Privacy Requirements

**Status: satisfied, one nuance.** Retention is documented and enforced (`class-scheduler.php`'s `purge_old_request_events()`, default 90 days via `wp_sam_violation_retention_days`); detail payloads are size-capped. **Missing:** no WordPress core Personal-Data Eraser/Exporter hook integration -- deletion is time-based retention only, not an on-demand per-subject erase tool. Mechanical addition once prioritised; the retention cron already does the heavy lifting.

Security telemetry can contain personal data.

Phase 3 must:

- minimise stored request data;
- avoid storing credentials;
- avoid storing full sensitive request bodies by default;
- document retention;
- support deletion;
- distinguish local and central data;
- document third-party intelligence services;
- provide administrator controls over telemetry sharing.

---

# 35. Development Roadmap

**All sub-phases below are delivered except 3G and 3H, which were explicitly deferred by product decision on 2 September 2026 -- not skipped by oversight.** 3D through 3J shipped as v2.9.40 through v2.9.44 across five same-day releases; 3A-3C predate this plan document (already implemented at its v2.9.24 baseline). See `.roadmap/phase4_plan.md` for what comes next.

## Phase 3A: Information Architecture and Product Model

**Delivered** (predates this document's v2.9.24 baseline).

Deliver:

- formal protection-layer model;
- operational lifecycle;
- navigation redesign;
- Settings overview grouped by layer;
- consistent status model;
- surface visibility;
- preserved technology-pillar drill-down.

Exit criteria:

- a non-technical administrator can understand the product structure without knowing individual HTTP security-header names;
- technical users retain direct access to individual pillars.

## Phase 3B: Request Observation Framework

**Delivered** (predates this document's v2.9.24 baseline).

Deliver:

- request observer;
- surface classifier;
- event schema;
- detector registry;
- confidence model;
- audit/evidence integration;
- Observe-only initial mode.

Exit criteria:

- detectors can be added without rewriting core request-flow architecture.

## Phase 3C: Initial Detector Families

**Delivered** (predates this document's v2.9.24 baseline) -- 10 of the 10 listed here; see §11 for the 3 additional families (11.4/11.6/11.13) identified after this document was written, which are real remaining work.

Deliver initial deterministic detectors for:

- technology mismatch;
- command injection;
- SQL injection;
- sensitive directories;
- sensitive files;
- setup/install probes;
- script/web-shell probes;
- protocol injection;
- version-control artefacts;
- vulnerability probes.

Exit criteria:

- all detectors have regression tests and explainable evidence.

## Phase 3D: Identity and Scanner Intelligence

**Delivered, v2.9.40.**

Deliver:

- user-agent extraction;
- known crawler identities;
- scanner vendor registry;
- CIDR matching;
- authoritative source URLs;
- customer-specific authorisation state;
- verified-versus-claimed identity model;
- reverse-DNS verification framework.

Exit criteria:

- recognised vendor traffic is never automatically treated as authorised.

## Phase 3E: Traffic Controls

**Delivered, v2.9.41 -- except ASN/Geo-IP, blocked on a verified data source (see §13.4-13.5), and per-surface policy, which is delivered.**

Deliver:

- rate limiting;
- excessive-request detection;
- IP/CIDR control;
- ASN observation/control;
- Geo-IP observation/control;
- progressive temporary blocking;
- per-surface policy.

Exit criteria:

- all new controls default safely;
- administrators can independently configure Frontend, Admin, Login and API behaviour.

## Phase 3F: Baseline and Drift

**Delivered, v2.9.42.**

Deliver:

- approved baseline;
- change capture;
- drift records;
- risk classification;
- administrator disposition;
- correlation with WordPress updates;
- evidence history.

Exit criteria:

- administrators can answer "what changed?" rather than only "what is configured?"

## Phase 3G: External Verification

**Deferred by explicit product decision, 2 September 2026** -- requires central VCNS-operated infrastructure that doesn't exist yet; the product owner chose not to build it prematurely. Not started, not partially built.

Deliver:

- external verification service design;
- ownership/authentication model;
- representative target management;
- external header verification;
- certificate verification;
- redirect verification;
- script/SRI observation;
- drift comparison.

Exit criteria:

- local intended state can be compared with externally observed state.

## Phase 3H: Federated Intelligence

**Deferred by explicit product decision, 2 September 2026** -- depends on Phase 3G's infrastructure, deferred together with it.

Deliver:

- central intelligence data model;
- signed intelligence bundles;
- local validation;
- scanner/crawler updates;
- managed detector updates;
- privacy controls;
- offline caching;
- service failure handling.

Exit criteria:

- central service enhances intelligence without becoming a remote-control dependency.

## Phase 3I: Assurance and Reporting

**Delivered, v2.9.43.**

Deliver:

- site security health;
- evidence exports;
- control-to-evidence mapping;
- exception state;
- evidence freshness;
- assurance reporting.

Exit criteria:

- output is useful to administrators, MSPs and assurance reviewers without making unsupported compliance claims.

## Phase 3J: Advanced Optional Intelligence

**Delivered in full, v2.9.44** -- built ahead of the "should follow operational validation" guidance below, at the product owner's explicit request. See §14-19 for what shipped and what didn't (each section notes its own gaps individually).

Consider:

- campaign detection;
- deception/honey paths;
- advanced integrity monitoring;
- adaptive controls;
- security change windows;
- richer change attribution.

These capabilities should follow operational validation of the core Phase 3 detection model.

---

# 36. Phase 3 Non-Goals

Phase 3 is not intended to:

- replace a dedicated network firewall;
- claim equivalence with a full enterprise WAF;
- become an unrestricted remote administration agent;
- treat known commercial scanners as inherently trusted;
- automatically block all bot traffic;
- automatically block by geography by default;
- infer malicious intent solely from Tor use;
- treat every unusual HTTP method as malicious;
- claim compliance certification;
- rely on AI as the authority for enforcement;
- build full fleet management before operational requirements are validated.

---

# 37. Definition of Done for Phase 3 Core

**Status, checked against v2.9.44, 2 September 2026:**

- [x] the product architecture clearly separates layers, lifecycle, surfaces and technology pillars;
- [x] the primary administration experience uses Observe, Decide, Control, Verify and Settings;
- [x] the Settings overview is grouped by protection layer;
- [x] request observation is implemented through a reusable detector architecture;
- [x] key attack/reconnaissance detector families are available (10 of 13 -- see §11 for the 3 remaining);
- [x] crawler/scanner identities can be recognised and evidence-backed;
- [x] recognition and authorisation are explicitly distinct ("Recognition is not authorisation" enforced throughout §9, §14);
- [x] traffic controls are surface-aware;
- [x] controlled automation applies to detection and traffic controls;
- [x] baselines and drift records are supported;
- [ ] external verification can compare intended and observed state -- **deferred (§20/Phase 3G)**;
- [ ] central intelligence updates are signed and locally validated -- **deferred (§23-24/Phase 3H)**;
- [x] loss of the central service does not remove local protections (vacuously true -- no central service exists yet to lose);
- [x] actions and recommendations are explainable and auditable (for what's built -- §22's actual recommendation *engine* is separate, unbuilt work);
- [x] evidence can be exported for security assurance purposes.

**13 of 15 done.** The 2 unchecked items are exactly the 2 explicitly deferred phases (3G, 3H) -- this was a known, accepted trade-off when that decision was made, not a surprise gap found now.

---

# 38. Strategic Outcome

Phase 1 establishes the protection core.

Phase 3 changes the product from:

> A WordPress plugin that configures and automates security controls.

Into:

> A WordPress site security platform that observes, decides, controls and verifies security state across multiple protection layers.

The longer-term managed-service direction becomes:

> A federated security assurance platform in which each WordPress installation remains locally authoritative while VCNS provides shared threat intelligence, external verification, aggregated pattern recognition and managed security knowledge.

The design principle remains:

**Local autonomy first. Central intelligence as an amplifier.**
