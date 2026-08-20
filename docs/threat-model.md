# Threat Model

## Scope

This document captures the trust boundaries, threat actors, and security-critical invariants for Security Automation Manager. The runtime flow is described in `docs/architecture.md`; this document focuses on adversarial framing.

Resolves roadmap issue #154 ("Threat model for updates, entitlements, and remote management") -- see "Update pipeline", "Entitlements and commercial control plane", and "Remote fleet management" below for the three areas that issue's single acceptance criterion asks for.

## Trust boundaries

### Fully trusted

| Asset | Trust basis |
|---|---|
| Plugin PHP code | Installed by a WordPress admin with filesystem access |
| WordPress options and custom tables | Protected by WordPress authentication and capability checks |
| Server filesystem | Assumed uncompromised for normal plugin operation |

### Conditionally trusted (validated before use)

| Input | Validation applied |
|---|---|
| GitHub-channel update manifest and package | Manifest fetched only from a hardcoded host (`vcns.github.io`); package download URL must exactly match the manifest's `download_url`; SHA-256 checksum verified with `hash_equals()` after download, before the file is handed to WordPress's installer (`Github_Update_Checker::verify_package_download()`) |
| Stripe webhooks | HMAC-SHA256 signature verified against `wp_sam_webhook_secret`; 5-minute timestamp replay window enforced |
| Browser CSP violation reports | Content-Type enforced; `document-uri` hostname checked against `home_url()`; rate-limited at 500/hour per surface; deduplicated by SHA-256 fingerprint |
| Crawled HTML (discovery scan) | External origins extracted from resource tags; never executed or auto-approved |

**Design stage, not yet implemented:** a DNS-discovered, Ed25519-signed remote
config JSON (`docs/remote-config-and-signing.md`) and a VCNS-hosted
checkout/entitlement proxy (`docs/checkout-proxy-design.md`) are designed but
their implementing code (`Config_Resolver`, the Cloudflare Worker) was removed
in PR #143 and does not currently exist. Do not treat the "Compromised
delivery infrastructure" mitigation below, or invariant #5, as descriptions of
current code - they describe the target design once #172 is implemented.

### Explicitly untrusted

| Input | Rationale |
|---|---|
| Stripe redirect query parameters | Entitlement granted only from verified webhook events; redirect parameters are ignored entirely |
| Violation report payload content | Reports are client-generated and trivially spoofable; used for discovery only, never for policy decisions or auto-approval |
| Remote config values | Must contain only public product metadata; a secret appearing in remote config would be a critical defect |

## Threat actors

**Unauthenticated external attacker** - can POST to the violation report endpoint. Mitigated by Content-Type enforcement, cross-origin `document-uri` rejection, rate limiting, and parameterised DB writes. Spoofed reports cannot trigger auto-approval; discovered sources remain `pending` until an admin reviews them.

**Compromised delivery infrastructure (target design, see above)** - DNS hijacking, TLS interception, or CDN compromise of the remote config origin. To be mitigated by Ed25519 signature verification: a compromised delivery channel cannot forge a valid signature without the private key. Not implemented today.

**Malicious co-installed plugin (target design, see above)** - a plugin could intercept `apply_filters()` calls. The design calls for infrastructure constants (e.g. `WP_SAM_CONFIG_PUBLIC_KEY`) rather than WordPress options or filterable values, so a plugin cannot redirect config fetches or alter the verification key at runtime. These constants do not exist in the current codebase.

**Stripe webhook replay** - a captured valid webhook event replayed later. Mitigated by the 5-minute timestamp window in `verify_signature()`.

**Privilege-escalation via CSP lockout** - an enforce-mode policy that blocks admin JS could lock an admin out of wp-admin. Mitigated by requiring at least one approved source or hash before enforce mode is permitted, and by surfacing a persistent admin notice when the admin surface is in enforce mode (see `docs/architecture.md` §wp-admin constraint).

## Security-critical invariants

The following must never be changed without a full security review:

1. **Entitlements from webhooks only.** Premium features are granted only when a Stripe webhook with a valid HMAC-SHA256 signature and an in-tolerance timestamp is received. Redirect parameters, admin REST actions, and remote config values must never grant entitlements.

2. **No secrets in remote config.** The signed JSON payload must contain only public product metadata. If any key or credential appeared in remote config, every site that fetched it would be compromised.

3. **Enforce mode requires an approved source or hash.** The plugin blocks CSP enforce mode on a surface until at least one source or hash has been explicitly approved by an admin with the `manage_options` capability.

4. **Cross-origin violation reports are discarded silently.** Reports whose `document-uri` hostname does not match `home_url()` are dropped without revealing a rejection response, to avoid advertising the check to an attacker probing the endpoint.

5. **Infrastructure constants must be PHP constants, not filters (target design).** Any future config-verification public key or control-plane URL must use `defined() || define()` so it can be overridden only in `wp-config.php` (server-level), never through `apply_filters()`. Making such a value filterable would allow any co-installed plugin to redirect signature verification or config fetches to an attacker-controlled endpoint. No such constant exists in the codebase today; this is a requirement for when one is introduced, not a description of current code.

6. **Violation report fields are never auto-approved.** Discovered `blocked-uri` values are stored with `approval_state = 'pending'`. Only an explicit admin action via the REST API (capability-checked, nonce-validated) can change the state to `approved`.

7. **Bypass Best Practices entries are never auto-enabled.** Every `Policy_Builder::BYPASS_CATALOG` entry is off by default (`0` in `csp_policy_profiles`) and only takes effect after an explicit per-surface admin toggle via `Admin_UI::ajax_set_bypass_flag()` (capability-checked, nonce-validated). No entry may be derived generically from a risk-classifier finding or added automatically because approved content exists elsewhere (e.g. `style-src-attr`'s `'unsafe-hashes'` entry does not turn on just because a hash was captured) - see "Bypass Best Practices catalog" below.

## Bypass Best Practices catalog

`Policy_Builder::BYPASS_CATALOG` (Profiles tab, "Bypass Best Practices" column) is a hardcoded, individually-reasoned set of directive+token relaxations for cases where a specific site's real design goes against CSP best practice in a way `Decision_Engine` or an external scanner would flag. Every entry carries a `risk_level` (`low`/`medium`/`high`) shown to the admin before they opt in - this catalog is not restricted to only low-risk entries; the safety property is that nothing is ever silently or automatically enabled, not that nothing risky is ever offered (invariant #7 above). Stored as a single `bypass_flags` JSON array per surface (schema v25) rather than one column per entry, so the catalog can keep growing without a schema migration for every addition -- see `docs/database-schema.md`.

The Profiles tab only shows an entry for a surface once that surface has actually triggered it at least once (per `csp_violation_reports`), or the entry is already enabled -- not every entry in the catalog is relevant to every site, and showing dozens of unrelated toggles is noise, not a real choice.

### Data/blob URI schemes for non-executable content (`img-src`, `font-src`, `media-src`)

`img_src_data`, `img_src_blob`, `font_src_data`, `media_src_data`, `media_src_blob` (all `low` risk) each append a single scheme token (`data:` or `blob:`) to one directive. `Decision_Engine` classifies `data:`/`blob:` schemes as high-risk for *automation* purposes (CSP-SCHEME-002, hard-excluded from auto-approval) -- but in these five directives specifically, the referenced content can only ever be rendered as pixel/glyph/audio/video data; none of these contexts can execute script. That's the entire reasoning for every entry in this group, and why they're grouped together rather than each getting their own subsection. This reasoning does not extend to `script-src`, `object-src`, `frame-src`, `worker-src`, or `base-uri`, where the same schemes are genuinely dangerous -- those directives must never gain a `data:`/`blob:` catalog entry of this shape; `worker_src_blob` below is a deliberately different, higher-risk case, not an extension of this group.

### Inline event handler and style attributes (`script-src-attr`/`style-src-attr` + `'unsafe-hashes'`)

**Threat actors and mitigations:**

- **The keyword itself.** `'unsafe-hashes'` (CSP3 §6.1.2) allows hash-source matching to apply in attribute contexts - inline event handlers, `javascript:` URLs, and style attributes - which CSP does not cover by default. Security scanners correctly flag it as a keyword worth reviewing.
- **Two separate catalog entries, one per directive.** `style_src_attr_unsafe_hashes` (`medium` risk) covers `style-src-attr`; `script_src_attr_unsafe_hashes` (`medium` risk) covers `script-src-attr` -- inline event handler attributes such as `onclick="…"`. CSP directives don't cross-contaminate: enabling one never affects the other, `script-src`, or any other script-execution path. Whichever of the two isn't enabled stays `'none'` plus the one hardcoded exception below; content with any actual value stays fully blocked regardless of the other entry's state.
- **Near-no-op without a paired hash.** Each entry only adds the keyword to its own directive; beyond the one hardcoded exception (below), that directive still needs an actual approved hash (from `Hash_Manager`'s attribute capture, `docs/database-schema.md`'s `csp_hash_inventory` rows) before anything else can match. Enabling either flag with zero approved hashes for that directive permits only that one exception, nothing else.
- **The one hardcoded exception: an empty attribute value.** `Policy_Builder::EMPTY_CONTENT_HASH_TOKEN` (the sha256 hash of the empty string) is always present in both `script-src-attr` and `style-src-attr`, unconditionally -- not gated by either bypass toggle or by any capture/approval workflow. An empty attribute value can never execute or style anything: there is no content for it to be an attack vector for, in any context, regardless of what else the page does. Added after a real false-positive: a vendored carousel library's routine `jQuery.attr('style', '')` (clearing inline styles as part of its own destroy/refresh cycle) was reported as a CSP violation purely because that specific empty value had never happened to go through the hash-learning workflow yet -- noise with no security value on either side. Like any other attribute-context hash, it still only takes effect once `'unsafe-hashes'` is present on that directive, so this doesn't weaken the "nothing auto-enables" invariant above; it just means this one specific, provably harmless value never needs individual capture and approval.
- **Residual risk: CSS/JS-based data exfiltration.** If an attacker separately achieves HTML injection elsewhere on the page, and the injected attribute content happens to byte-for-byte match a hash already approved for a different, legitimate purpose, it would be permitted. This is real but low-probability - it requires an independent injection primitive plus a hash collision with existing legitimate content. For `style-src-attr` this is meaningfully narrower than "arbitrary code execution": CSS cannot execute code in any current browser, so the realistic abuse case is attribute-selector-based data exfiltration (e.g. leaking input values via `input[value^="a"] { background: url(...) }`), not script execution. `script-src-attr` is genuinely narrower still to exploit in practice -- an attacker would need their injected content to collide with a hash approved for a *legitimate* event handler, not just any script content, since `script-src-attr` only ever matches attribute-context execution, never `<script>` elements (that's `script-src`/`script-src-elem`, unaffected by either entry here).
- **Why this mechanism over the alternatives.** The other options CSP provides are `'unsafe-inline'` on the directive (approves *any* attribute content, a materially broader bypass) or leaving the directive permanently blocked (breaks any page whose template legitimately uses inline style attributes or event handlers). Hash-plus-`unsafe-hashes` is the narrowest mechanism CSP3 offers for this case.

### WebAssembly compilation (`script-src` + `'wasm-unsafe-eval'`)

`script_src_wasm_unsafe_eval` (`medium` risk). CSP3's `'wasm-unsafe-eval'` keyword permits only `WebAssembly.instantiate()`/`WebAssembly.compile()` -- unlike `'unsafe-eval'`, it does **not** permit `eval()`, `new Function()`, `setTimeout(string)`, or any other string-to-JS execution path; a page with `'wasm-unsafe-eval'` but not `'unsafe-eval'` still fully blocks those. The residual risk is scoped to whatever the site's own already-approved WASM modules do once instantiated -- this keyword doesn't let an attacker supply arbitrary WASM bytecode, only relaxes the restriction on running WASM the page's own script already references. Needed by some image/video-processing, PDF-rendering, or cryptography libraries compiled to WebAssembly, which fail to initialise at all without it.

### Blob-constructed workers (`worker-src` + `blob:`)

`worker_src_blob` (`high` risk -- the highest in this catalog). Unlike every other entry above, this one is a genuine, unrestricted code-execution relaxation, not a narrowly-scoped one.

**Threat actors and mitigations:**

- **Why this is categorically different from the data:/blob: group above.** `img-src`/`font-src`/`media-src` blob content is rendered, never executed. A `Worker` (or `SharedWorker`) constructed from a `blob:` URL runs that blob's content **as JavaScript**, with full Worker-context capabilities (network requests via `fetch`, `importScripts()`, message-passing back to the main thread). If an attacker can get arbitrary content into a blob a page then constructs a worker from, `worker-src blob:` lets that content execute.
- **Why sites need it anyway.** Several legitimate, common libraries construct their worker this way rather than shipping a separate worker script file -- notably PDF.js (PDF rendering), some video/audio encoders, and some bundler output patterns that inline a worker's source and construct it via `URL.createObjectURL(new Blob([...]))`. Without this entry, `worker-src` stays `'none'` and those libraries fail outright; the only CSP-native alternative is `worker-src blob:` (this entry) or dropping `worker-src` back to inheriting `script-src`/`default-src`'s own allowlist, which is a broader, less auditable relaxation than this narrowly-directive-scoped one.
- **The mitigating factor: the blob's content must already be same-origin script.** Enabling this does not let an attacker's cross-origin content become a worker -- the blob itself has to be constructed by same-origin JavaScript already running on the page (from `script-src`'s own already-approved sources). This entry doesn't grant new content injection capability; it removes a restriction on what *already-trusted, already-running* script may do with content it itself assembles.
- **Explicit recommendation, not a default-safe toggle.** Unlike the `low`-risk entries above, this one should only be enabled after identifying the *specific* library or code path on the site that needs it (check the CSP violation report's `document-uri`/`blocked-uri` and, ideally, the referring script). Enabling it speculatively "just in case" widens the attack surface for no observed benefit -- the Profiles tab's relevance filter (only showing an entry once a surface has actually triggered it) is a meaningful guard here specifically because this entry should never be enabled without a real, observed trigger.

## Update pipeline

Scope: the GitHub-channel updater (`Github_Update_Checker`). The
WordPress.org-channel build ships no custom updater at all and inherits
WordPress.org's own update infrastructure and threat model instead
(mechanically enforced by `release-package.yml`'s package-content check - see
#171).

**Assets:** the plugin code running with the site's own privileges after an
update is applied; the update manifest; the package ZIP.

**Threat actors and mitigations:**

- **Manifest host compromise or substitution.** The manifest is fetched only
  from a hardcoded host (`vcns.github.io`) over HTTPS; there is no filter or
  option that can redirect this. An attacker would need to compromise that
  GitHub Pages deployment itself (see #171/#40's hardening of the Pages
  deployment workflow) or perform a CA-level TLS interception.
- **Package substitution / manifest–package mismatch.** The download URL used
  is the manifest's own `download_url` field, compared for an exact string
  match before use; nothing else can be substituted in.
- **Manifest tampering (version/checksum fields).** SHA-256 checksum,
  verified with `hash_equals()` against the actual downloaded file, is
  required before the file is ever handed to WordPress's installer. A missing
  or malformed checksum field fails closed (`wp_sam_update_checksum_missing`).
  There is currently no signature over the manifest itself, only the checksum
  of the package it points to - an attacker who fully compromises the
  manifest host controls both the checksum and the package it validates
  against, so checksum verification defends against a corrupted-in-transit
  package, not a compromised manifest origin. Manifest-origin compromise is
  currently mitigated only by host allowlisting and Pages-deployment
  hardening, not by a signature.
- **Checksum bypass.** Verification uses `hash_equals()` (constant-time) and
  fails the update (rather than silently proceeding) on mismatch or missing
  checksum; there is no code path that installs an unverified package.
- **Downgrade / rollback abuse.** No in-plugin downgrade mechanism exists
  (see #160) - an attacker cannot use the updater itself to push a known
  vulnerable older version, because the updater only ever offers versions
  newer than the currently-installed one (`inject_update()`).

**Known gap:** only 2 of the 18 release-verification scenarios described in
spec §1.4 have automated test coverage today (manifest-host rejection,
checksum-mismatch rejection) - see `docs/testing-requirements.md` and #159.
Untested does not mean broken, but every install/upgrade-via-WP-core,
interrupted-update, and rollback scenario is currently unverified by CI.

## Entitlements and commercial control plane

Scope: the commercial-build billing/entitlement flow (`Feature_Gate`,
Stripe checkout and webhook handling) and its planned successor, the
VCNS-hosted checkout/entitlement proxy (`docs/checkout-proxy-design.md`, #172).

**Assets:** VCNS's Stripe account (create charges, issue refunds, read
account-wide data); individual customers' entitlement state; the integrity of
the free/commercial feature boundary.

**Current-state threat actors and mitigations:**

- **Entitlement forgery via redirect parameters.** Mitigated - entitlements
  are granted only from a verified Stripe webhook event, never from a
  browser-redirect query parameter (invariant #1 below).
- **Webhook replay.** Mitigated - 5-minute timestamp tolerance window in
  webhook signature verification.
- **Stripe secret exposure on customer installs.** **Not mitigated - live
  finding.** The commercial build's checkout flow requires VCNS's own
  account-wide Stripe API secret key to be entered into the CSP dashboard's
  Settings tab and stored as a plaintext WordPress option
  (`wp_sam_stripe_secret_key_live`) on whichever site runs checkout. This key
  can create charges and issue refunds against VCNS's entire Stripe account,
  not just that one site's entitlement - it is not a per-customer or
  scoped credential. Any attacker who obtains database access to that one
  site (a separate plugin vulnerability, a leaked backup, a malicious
  co-admin, a compromised host) obtains the key. This is a regression from an
  earlier architecture (a Cloudflare Worker holding the same key as a Worker
  secret, never transmitted to the WordPress install - see `SECURITY.md` and
  PR #143's removal of it). Remediation is designed in
  `docs/checkout-proxy-design.md` and tracked as #172; until implemented,
  this is the single highest-severity open item in this threat model and the
  primary blocker on the public-hosting readiness gate (#156).
- **Webhook secret exposure.** Lower severity than the API secret key (a
  webhook secret can only be used to forge a *verification* of a fake event
  toward the one endpoint it's configured for, not to call the Stripe API
  directly), but it has the same storage-location problem - plaintext
  WordPress option, no rotation tooling. Also addressed by the checkout-proxy
  design, which moves webhook receipt to VCNS-controlled infrastructure
  entirely.
- **Site-identity spoofing.** The entitlement's site-identity binding is a
  truncated SHA-256 hash of the site URL (`docs/stripe-operations.md`), not a
  secret - it is a low-assurance binding intended to catch accidental
  cross-site reuse, not a security boundary. This should not be treated as
  authentication.

**Forward-looking (once #172 lands):**

- **Signature forgery on the "entitlement granted" callback.** Mitigated by
  design - the proxy signs the callback with a private key held only on
  VCNS infrastructure; the plugin verifies against an embedded public key
  (reusing the pattern already specified in
  `docs/remote-config-and-signing.md`).
- **Compromise of the VCNS-hosted proxy itself.** Becomes the new highest-value
  target once implemented - it holds the live Stripe secret key that no
  longer exists anywhere else. See `docs/checkout-proxy-design.md` for its own
  dedicated threat model; that document's threat model is a required input to
  #172 implementation review, not a formality.
- **Key compromise (proxy's Stripe secret or signing private key).** No
  rotation/revocation/incident-response procedure exists yet for either - see
  the "Follow-up" checklist in `docs/security-privacy-checklist.md`. This
  must be written before #172 ships, not after.

## Remote fleet management (forward-looking - Phase 6, greenfield)

Scope: the estate/fleet-management capability described in spec §13 (#186-190)
and any future remote change-application channel. Nothing in this section
describes existing code - `SPECIFICATION.md` explicitly flags multisite and
fleet management as unsupported today. This section exists so implementation
work on #188-190 starts from an agreed set of attacker assumptions rather than
inventing them mid-implementation.

**Assets:** every managed site's security configuration, potentially across an
entire fleet at once - the blast radius of a compromise here is
multiplicative in a way nothing else in this plugin is.

**Threat actors to design against:**

- **Unauthorised remote configuration change.** A fleet-management channel
  that can push policy/config changes to managed sites is, by construction, a
  remote-write primitive. It must be authenticated at least as strongly as
  the entitlement signing scheme above, must be scoped (a compromised
  credential for one site must not grant write access to the whole fleet),
  and every applied change must be recorded in that site's own audit log as
  if an admin had made it locally.
- **Remote code execution via the update or config channel.** A
  fleet-management channel is a more attractive RCE target than the existing
  per-site updater, because a single compromise could affect every managed
  site simultaneously. It must not introduce any new deserialization of
  remote data into executable PHP, and should reuse the existing
  checksum/signature verification patterns rather than inventing a new one.
- **Fleet-wide credential compromise.** If a single shared secret authenticates
  fleet-wide remote changes, its compromise compromises every managed site at
  once. Prefer per-site credentials issued by the control plane over one
  shared fleet-wide secret, even if that's operationally more complex.
- **Remote change bypassing local admin review.** The existing invariant that
  enforce-mode CSP requires local admin approval (invariant #3 below) must
  not be overridable by a remote fleet-management action - a compromised
  control plane must not be able to force a site into a lockout-risk state
  without a local human in the loop, or must at minimum be constrained by the
  same safety gates a local admin would go through.

## Out of scope

The following do not qualify as security issues by themselves:

- Missing best-practice HTTP headers unrelated to this plugin's execution path
- Attacks that require direct admin (filesystem or database) access to the target install
- Issues caused by unsupported PHP, WordPress, or host configurations
- Requests to support end-of-life PHP versions
