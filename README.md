# Security Automation Manager

Security Automation Manager is a WordPress plugin covering three product areas: strict HTTP security header rollout, third-party script/stylesheet integrity governance, and TLS certificate lifecycle management. Content Security Policy (CSP) is the most capable header pillar -- per-surface profiles, nonce injection, source discovery, violation reporting, and audit-first policy-change review -- with X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Strict-Transport-Security, Cross-Origin-Resource-Policy, Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy, and X-Permitted-Cross-Domain-Policies as simpler per-surface pillars alongside it. Certificates is a separate, self-contained ACME v2 (Let's Encrypt) certificate manager -- see the Certificates section below.

## Features

**Content Security Policy**

- Per-surface CSP profiles for `frontend`, `admin`, `login`, and `api`
- Strict defaults across CSP directives, including `upgrade-insecure-requests`, `child-src`, and the `sandbox` document directive
- `report-sample` support in fetch directives so inline snippets can appear in violation reports
- Direct `report-uri` browser reporting by default, with optional Reporting API headers
- Configurable origin policy header name for Cloudflare, CDN, and reverse-proxy deployments
- Per-request nonce injection for compatible WordPress script output
- Report-only rollout mode
- CSP violation reporting endpoint with content-type and origin checks
- Automatic purge of old violation reports
- Append-only audit log for significant plugin events
- Source discovery and administrator approval workflow
- "Start Here" tab covering the report-only, learning-window, and manual-promotion workflow; the default landing tab on the CSP dashboard
- Full-dataset sorting and per-column filtering (multi-select, free-text, numeric, date-range) on the Violations, For Review, and Policy Changes tables
- Per-row metadata popover on the Violations table showing document URI, source file, line/column, referrer, user agent, and any captured data-URI payload
- Risk-ranked CSP change proposals with reason-required approve, reject, revert, and undo decisions
- Revert-and-suppress workflow so a reversed source is not proposed again automatically
- Policy version snapshots, policy diffs, decision provenance, and deterministic rule findings
- Policy Audit tab (on the CSP page) and privileged admin REST endpoints for current policy, pending reviews, decisions, history, and manual automation configuration
- Readiness admin view for plugin-specific schema and runtime checks; a separate Recovery admin view covers schema-downgrade status, pre-migration snapshot restore, configuration export/import, and an authenticated reset flow that clears all plugin data (every pillar, not just CSP) and disables header emission until rollout is restarted
- Automation configuration scaffold that defaults a *fresh install's* every surface to `automatic_high_approval` -- every proposed CSP source below the high-risk threshold is auto-approved into the report-only policy on its own evidence, high-risk sources still require a human decision. An *upgraded* install is not retroactively changed: the default only ever fills in a surface that has no automation setting yet, so an administrator's existing choice -- including an explicit Manual selection -- is always left alone. This governs approval only, never enforcement: CSP still starts report-only on every surface, and promotion to enforce still requires a deliberate administrator action through the learning window and promotion gate, regardless of automation posture
- Multi-surface scan support
- `strict-dynamic` with automatic host-source suppression
- Per-surface Trusted Types toggle (Profiles tab): sends `require-trusted-types-for 'script'`, always report-only regardless of surface mode
- Conflict detection for competing CSP headers from `.htaccess`, server config, or other security-header plugins
- Scheduled rescans with audit logging

**Other header pillars**

- X-Frame-Options: per-surface `DENY` or `SAMEORIGIN` (a fallback for browsers that don't honor CSP's `frame-ancestors`)
- X-Content-Type-Options: per-surface on/off (`nosniff`)
- Referrer-Policy: per-surface value from the eight standard tokens, defaulting to `strict-origin-when-cross-origin`
- Permissions-Policy: per-surface, per-directive picker (`none` / `self` / `all`) across a starter set of seven browser features (geolocation, camera, microphone, fullscreen, payment, usb, autoplay)
- Strict-Transport-Security: per-surface `max-age`, `includeSubDomains`, and `preload`. Only ever sent over HTTPS, and `preload` stays off until `max-age` and `includeSubDomains` already meet hstspreload.org's submission minimum -- this header is sticky (browsers cache it), so it warrants more care than the other four
- Cross-Origin-Resource-Policy: per-surface `same-site` / `same-origin` / `cross-origin`, controlling which sites may load this site's own resources cross-origin. Low risk -- it only restricts who can embed this site's content, not what this site can embed
- Cross-Origin-Opener-Policy: per-surface `unsafe-none` / `same-origin` / `same-origin-allow-popups`, isolating this site's browsing context from cross-origin windows it opens or is opened by. `same-origin` severs `window.opener` access from any cross-origin popup, including popup-based OAuth/SSO flows -- `same-origin-allow-popups` is the safer choice for sites that rely on those
- Cross-Origin-Embedder-Policy: per-surface `unsafe-none` / `require-corp` / `credentialless`, the highest-risk pillar this plugin manages. `require-corp` blocks any cross-origin subresource (fonts, embeds, ad tags) that doesn't explicitly opt in via CORP or CORS -- most third-party embeds don't, so enabling this carelessly can silently break unrelated page content. Only actually needed for sites that require cross-origin isolation (`SharedArrayBuffer`, high-resolution timers); most WordPress sites do not
- X-Permitted-Cross-Domain-Policies: per-surface `none` / `master-only` / `by-content-type` / `all`, a legacy Flash/Acrobat-era header controlling cross-domain policy file loading. `none` is almost always correct for a modern site

Seven of these nine pillars are simple by design: no report-only mode, discovery workflow, or automation -- each header is either sent exactly as configured, or not sent at all. Cross-Origin-Opener-Policy and Cross-Origin-Embedder-Policy are the two exceptions: each has its own Disabled / Report-Only / Enforce mode selector and a Report-Only Evidence table showing violations the browser's Reporting API has actually observed over the last 7 days, so a risky isolation policy can be rehearsed before it's enforced -- narrower than CSP's discovery-and-approval workflow, but a real report-only learning step, not a blunt on/off toggle. See "Cross-Origin Policy Learning" below for browser-support caveats.

**Cross-Origin Policy Learning**

The Report-Only Evidence table's data only reflects violations from browsers that actually send Reporting API delivery -- Chromium-based browsers (Chrome, Edge, Opera, Brave, and others built on the same engine) only, as of this writing. Report-Only mode itself is respected by every modern browser regardless -- the *header* is universally honoured -- but a visitor on a non-Chromium browser generates no evidence row even if their session would have tripped the isolation policy. Treat an empty or sparse evidence table as inconclusive on a site with meaningful non-Chromium traffic, not as proof the policy is safe to enforce.

**Content rewrite protections**

Two further protections rewrite the rendered HTML body itself rather than emit a header, sharing a `Content_Rewriter` envelope (request/response eligibility, buffering, fail-open on any uncertainty) alongside the header pillars' own `Header_Builder` envelope:

- Reverse Tabnabbing Protection: per-surface, adds `rel="noopener"` to `target="_blank"` links missing `noopener`/`noreferrer`, closing off `window.opener` access a new tab could otherwise use to redirect the original tab to a phishing page. Purely additive -- it never blocks or breaks a link.
- External Scripts: passively inventories third-party `<script>`/`<link rel="stylesheet">` origins observed on real page loads (no dedicated crawl; deduplicated at the origin level, but the most recently observed full URL is retained too), lets an administrator classify each one (Unclassified / Approved-immutable with SRI / Approved-mutable provider / Exception / Blocked), and supports Subresource Integrity. A freshly discovered origin is always `unclassified`, matching this plugin's report-first philosophy -- report mode (the default) never removes anything, and even enforce mode only ever removes an origin explicitly marked Blocked or an "immutable" origin whose SRI hash no longer matches what the page served. SRI hashes are never fetched from a third party in the background -- the plugin only ever compares against a hash typed in directly, or computed by fetching a URL the administrator themselves supplied and immediately pinned ("Suggest" button, pre-filled with the last observed URL for that origin; the fetched hash is saved as the pinned value as soon as it's computed, with no separate confirmation step, so only point it at a URL already trusted to be correct). A daily check proactively re-verifies pinned hashes against this site's own homepage (never third-party content) so drift is caught before a real visitor triggers a removal.

A third pillar, Internal Script Integrity (`Internal_Script_Integrity_Builder`), is architecturally distinct from the two above: rather than the `Content_Rewriter` body-buffering envelope, it hooks the same `script_loader_tag`/`style_loader_tag` filters `Nonce_Manager` already uses. Per-surface opt-in; when enabled, it reads a first-party script/stylesheet's local file directly (never a network fetch -- this server already has the exact file it's about to serve), computes its SHA-384 hash, and adds it as the tag's `integrity` attribute automatically. Cached by file size/mtime, so an unchanged file is never re-read, and a changed one (a plugin/theme update, a manual edit) is picked up on the next request that serves it -- nothing to remember to update by hand, and nothing to classify or approve, since the hash can never legitimately drift from what's on disk the way an admin-declared third-party hash can. External Scripts and Internal Script Integrity share one admin page (Scripts), each its own tab, alongside a Start Here tab explaining the distinction.

**Certificates**

A separate, self-contained TLS certificate lifecycle manager, unrelated to the header pillars above beyond sharing the same admin/audit plumbing:

- ACME v2 (RFC 8555) client -- account registration, order/authorization polling, nonce handling with bad-nonce retry, and a Let's Encrypt staging/production environment switch
- DNS-01 validation with 41 built-in DNS-provider drivers (Cloudflare, Route53, DigitalOcean, Gandi, Hetzner, and more; extensible via the `wp_sam_dns_providers` filter), and HTTP-01 validation
- Wildcard certificate support (DNS-01 only, as required by the ACME protocol)
- EC-P256 (default) or RSA-2048 key generation, with a "bring your own private key" option when this server can't reliably generate one itself -- the Configuration tab runs a live capability probe (an actual throwaway key generation, not just an extension check) to decide whether to show it
- Credentials (DNS-provider API tokens, cPanel tokens) and private keys encrypted at rest before they reach the database
- Deployment: automatic install via cPanel's `SSL::install_ssl` UAPI where available, export to a configured filesystem path (rejected if it resolves inside the web root), or manual PEM download
- WP-Cron renewal on a 30-day-before-expiry threshold, with duplicate-schedule guards and an audit-logged failure path that never silently drops a certificate
- Every certificate issuance, renewal, and deployment attempt -- success or failure -- is recorded in the same append-only audit log CSP uses

See `docs/certificates.md` for the full setup walkthrough, DNS-provider list, and hosting-platform notes.

Every pillar, all rewrite protections, certificate management, and three of the four CSP automation modes are available locally without payment, remote entitlement checks, or third-party licensing calls. The exception is Fully Automatic CSP mode, which requires an active subscription -- see Automation Posture below.

## Requirements

- WordPress 6.4+
- PHP 8.1+
- Certificates additionally require the `openssl` PHP extension (key generation, CSR/JWS signing) and `sodium` (credential/key encryption at rest) -- the Certificates page checks for both up front and explains what to ask your host for if either is missing

## Installation

### From the WordPress plugin directory

Once published to WordPress.org:

1. Go to **Plugins -> Add New Plugin**.
2. Search for `Security Automation Manager`.
3. Click **Install**, then **Activate**.

### Install from GitHub Releases

Tagged releases publish ready-to-install ZIPs to the
[Releases page](https://github.com/vcns/security-automation-manager/releases).

1. Download `security-automation-manager-vX.Y.Z.zip` from the release assets -- this is the only asset a GitHub Release publishes, and it *is* the GitHub-channel (self-updating) build.
2. In WordPress go to **Plugins -> Add New Plugin -> Upload Plugin**.
3. Choose the downloaded ZIP and click **Install Now**.
4. Activate the plugin.

The GitHub-channel ZIP includes a checksum-verified updater that uses WordPress' native plugin update screen and the `https://vcns.github.io/wp-updates/security-automation-manager/update.json` manifest. The separate WordPress.org-safe package (without the GitHub updater) is never published as a GitHub Release asset -- it's built and deployed straight to the WordPress.org SVN repository by the same release pipeline, for administrators installing from the WordPress plugin directory instead.

## Getting Started

1. Install and activate the plugin.
2. Open **Security Automation Manager -> CSP**; the Start Here tab explains the workflow below.
3. Run an initial scan from the Profiles tab.
4. Review and approve only the external sources your site actually requires from the For Review tab.
5. Reject or revert unwanted sources so the same fingerprint is suppressed from future proposals.
6. Use the Policy Audit tab to inspect why a proposal exists and what policy version resulted from decisions.
7. Use the Readiness page to validate schema health, and the Recovery page when deliberately resetting all plugin data for a clean rollout attempt.
8. After a reset, re-enable the required surfaces in report-only mode when you are ready to restart rollout.
9. Stay in report-only mode until violations are understood.
10. Promote one surface at a time into enforce mode.

## Automation Posture

A fresh install defaults every surface to `Automatic (with high approvals only)` -- see the Content Security Policy feature list above for exactly what that does and does not automate. An upgraded install keeps whatever each surface was already set to, including an explicit `Manual` choice; the default only ever fills in a surface with no automation setting yet. Administrators may explicitly select each surface posture from the Profiles tab or the Settings tab:

- `Manual` -- free
- `Automatic (with medium+high approvals)` -- free
- `Automatic (with high approvals only)` -- free
- `Fully Automatic` -- requires an active subscription (£1.99/month or £19.99/year, billed via Stripe Checkout); without one, a surface selecting it is kept on `Automatic (with high approvals only)` instead

Automatic approvals are bounded by deterministic risk rules, hard exclusions, configured directive/scheme limits, evidence requirements, and per-run caps. Automatic decisions record `automation_engine` provenance and can be undone without rewriting history.

Future AI-assisted recommendation work must keep deterministic product rules as the authority. AI output must not directly modify an enforced CSP policy.

## External Services

The WordPress.org plugin package does not contact third-party services for plugin updates, licensing, checkout, telemetry, or remote product configuration.

The GitHub-channel ZIP checks `https://vcns.github.io/wp-updates/security-automation-manager/update.json` from administrator update contexts only, validates the advertised package host and SHA-256 checksum, and then lets WordPress perform the update. Define `WP_SAM_DISABLE_AUTO_UPDATE` as `true` in `wp-config.php` to prevent background auto-updates for the GitHub-channel package.

By default, the plugin emits CSP reporting headers that point browsers back to this WordPress site's own REST endpoint:

- `/wp-json/sam/v1/report`

Administrators may override the reporting server URL when the public HTTPS endpoint differs from the WordPress-detected site URL, such as behind a proxy, CDN, or load balancer. If the override points to another host, browsers will send CSP reports to that configured endpoint; local report learning only works when the URL routes back to this plugin's report endpoint.

Administrators may also configure an origin-only policy header name, such as `X-Origin-CSP-Policy`, when a proxy needs to copy the WordPress-generated policy into the browser-facing `Content-Security-Policy-Report-Only` or `Content-Security-Policy` header. Leaving the setting blank preserves the normal mode-aware CSP header names. Custom names are validated as HTTP header field names and unsafe hop-by-hop or cookie headers are rejected.

Browser-submitted CSP violation reports received by this plugin are validated and stored in the local WordPress database. They are not sent to any external provider by default.

The Certificates page, only when an administrator explicitly configures it, contacts the ACME v2 API of the configured certificate authority (Let's Encrypt production or staging) to request certificates, and -- when DNS-01 validation is selected -- the chosen DNS provider's API (for example, Cloudflare's) using credentials the administrator supplies. Nothing under Certificates is contacted until an administrator configures it; there is no background or automatic certificate activity beyond the WP-Cron renewal check for certificates that already exist.

## Privacy

The plugin keeps operational data local to WordPress.

- Browser CSP violation reports and COOP/COEP Reporting API violation reports are stored in the local database.
- Source inventory, hashes, scan logs, policy versions, and decision records are stored locally.
- Certificate DNS-provider and cPanel credentials, ACME account keys, and issued certificates' private keys are stored locally, encrypted at rest -- never transmitted anywhere except the ACME/DNS-provider APIs required to issue or renew a certificate an administrator configured.
- No telemetry or background tracking is intended as part of the normal plugin runtime.

## Repository Guides

- Product specification: [SPECIFICATION.md](SPECIFICATION.md)
- Architecture: [docs/architecture.md](docs/architecture.md)
- Certificates: [docs/certificates.md](docs/certificates.md)
- Threat model: [docs/threat-model.md](docs/threat-model.md)
- Testing and quality: [docs/testing-and-quality.md](docs/testing-and-quality.md)
- Release and publishing: [docs/release-and-publishing.md](docs/release-and-publishing.md)
- Security policy: [SECURITY.md](SECURITY.md)
- Repository assessment and roadmap reconciliation: [docs/consolidation-ledger.md](docs/consolidation-ledger.md)

## GitHub Pages Help Site

The repository also publishes a public help site from the `docs/` directory:

- https://vcns.github.io/security-automation-manager/

## Development And Release Flow

Two-stage flow, formalised as the product moves from MVP into a real commercial release cadence -- see `.github/workflows/pr-branch-policy.yml` for the enforced rules:

- `chore/*`, `docs/*`, `feature/*`, `fix/*`, and `hotfix/*` branches target `development`
- `release/*` branches (cut from `development` once it holds what you want to ship) are the normal path into `main`; `development` itself may also open a PR directly into `main`
- `hotfix/*` may additionally go straight into `main`, bypassing `development`, for a genuine emergency fix that can't wait for the normal cycle -- back-merge it into `development` afterwards so the fix isn't lost on the next release cut
- `codex/*` is not an allowed source branch for either target
- `main` is the release and publishing branch; every release is a merged `release/*` (or emergency `hotfix/*`) PR, tagged `vX.Y.Z`
- Pushing a `vX.Y.Z` tag on `main` triggers the release pipeline: it builds and publishes the single GitHub Release asset (the GitHub-channel ZIP) and separately deploys the WordPress.org-safe package to the WordPress.org SVN repository -- both from the same tagged commit, in the same run

## Notes For Maintainers

- Keep `README.md` GitHub-friendly and concise.
- Keep `readme.txt` aligned with actual shipped behaviour for WordPress.org.
- Update both when installation, features, external services, or release flow changes.
