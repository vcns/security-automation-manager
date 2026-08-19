=== Security Automation Manager ===
Contributors: vcns
Tags: security, csp, content security policy, headers, ssl certificates
Requires at least: 6.4
Tested up to: 7.0
Requires PHP: 8.1
Stable tag: 2.9.16
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Automates strict HTTP security header rollout -- Content Security Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Strict-Transport-Security, Cross-Origin-Resource-Policy, Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy, and X-Permitted-Cross-Domain-Policies -- plus Reverse Tabnabbing Protection, third-party script/stylesheet governance with Subresource Integrity, and free-standing ACME (Let's Encrypt) TLS certificate lifecycle management, with violation reporting, source discovery, and policy-change review for WordPress.

== Description ==

Security Automation Manager helps site owners roll out strict HTTP security headers safely and incrementally. Content Security Policy (CSP) is its most capable pillar; X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Strict-Transport-Security, Cross-Origin-Resource-Policy, Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy, and X-Permitted-Cross-Domain-Policies are simpler per-surface pillars alongside it. Reverse Tabnabbing Protection, External Scripts, and Internal Script Integrity round it out as further protections that rewrite the rendered page itself rather than emit a header. Certificates is a separate, self-contained ACME v2 (Let's Encrypt) TLS certificate manager, unrelated to the header pillars beyond sharing the same admin and audit plumbing.

The CSP pillar provides per-surface profiles, nonce injection, source discovery, violation reporting, policy-change review, reason-required append-only audit records, policy history, readiness checks, and conflict detection for existing CSP emitters. Seven of the other pillars (X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Strict-Transport-Security, Cross-Origin-Resource-Policy, X-Permitted-Cross-Domain-Policies) are simple per-surface toggles/value pickers with no report-only mode, discovery workflow, or automation. The remaining two, Cross-Origin-Opener-Policy and Cross-Origin-Embedder-Policy, have a narrower report-only learning workflow of their own: a per-surface Disabled / Report-Only / Enforce mode and a Report-Only Evidence table populated by the browser Reporting API (Chromium-based browsers only, as of this writing). External Scripts follows the same report-first philosophy as CSP: a freshly discovered third-party origin is always unclassified, never blocked, until an administrator decides. Internal Script Integrity is unconditional once enabled for a surface -- there is nothing to classify, since the hash is always freshly computed from the exact file being served. Certificates issues and renews TLS certificates via ACME DNS-01 (41 built-in DNS-provider drivers) or HTTP-01 validation, with encrypted-at-rest credentials and private keys, and deploys them via cPanel, filesystem export, or manual download.

Every pillar, all rewrite protections, certificate management, and three of the four CSP automation modes are free. The exception is Fully Automatic mode (zero-review auto-apply of deterministic policy changes), which requires an active subscription: £1.99/month or £19.99/year.

== External services ==

This WordPress.org build does not contact third-party services for plugin updates, licensing, checkout, telemetry, or remote product configuration.

GitHub release builds are published separately for administrators who install from GitHub rather than WordPress.org. The GitHub-channel ZIP checks https://vcns.github.io/wp-updates/security-automation-manager/update.json from administrator update contexts only, validates the advertised package host and SHA-256 checksum, and then lets WordPress perform the update. Define WP_SAM_DISABLE_AUTO_UPDATE as true in wp-config.php to prevent background auto-updates for the GitHub-channel package.

By default, the plugin emits CSP reporting headers that point browsers back to this WordPress site's own REST endpoint:

* `/wp-json/sam/v1/report`

Administrators may override the reporting server URL when the public HTTPS endpoint differs from the WordPress-detected site URL, such as behind a proxy, CDN, or load balancer. If the override points to another host, browsers will send CSP reports to that configured endpoint; local report learning only works when the URL routes back to this plugin's report endpoint.

Purpose:
* receive browser-generated CSP violation reports for this site;
* store reports locally so administrators can review and refine policy safely.

Data handled:
* browser CSP violation report fields such as blocked URL, document URL, violated directive, referrer, user agent, line/column where provided, and an optional script sample where the active policy requests `report-sample`.

Reports received by this plugin are validated and stored in this site's WordPress database. They are not sent to any external provider by default.

For Cloudflare, CDN, and reverse-proxy deployments, administrators can configure an origin-only policy header name such as X-Origin-CSP-Policy. The proxy can then copy that origin header into the browser-facing Content-Security-Policy-Report-Only or Content-Security-Policy header.

The Scripts page's External tab has a "Suggest" button, only triggered by an administrator explicitly clicking it, that fetches a URL the administrator themselves supplies (restricted to a third-party origin already observed on this site) and computes a Subresource Integrity hash from it, saving that hash immediately as the pinned value with no separate confirmation step. No content from that fetch is stored or sent anywhere else; only the computed hash is written to this site's own database. Nothing is fetched automatically or in the background as part of this feature.

The Scripts page's Internal tab, when enabled for a surface, reads this site's own theme/plugin/core files directly from local disk to compute their Subresource Integrity hash -- never a network fetch of any kind, since the file being hashed is the exact file this server is about to serve.

The Certificates page, only when an administrator configures it, requests TLS certificates over the ACME v2 protocol. This contacts the Let's Encrypt API (acme-v02.api.letsencrypt.org, or the staging equivalent) and, when a DNS provider is selected for DNS-01 validation, that provider's API (for example api.cloudflare.com) using credentials the administrator supplies. Credentials and private keys are encrypted at rest. Nothing is contacted until certificates are explicitly configured. Issuing a certificate happens inside WordPress; installing it into the web server depends on your hosting platform -- automatic installation uses cPanel's install_ssl API where available, and the bundled docs/certificates.md explains the basic steps for other platforms.

== Changelog ==

= 2.9.16 =

* CSP > Policy Audit tab: bolded directive names in the Effective Header column (2.9.13) now also use colour, since font-weight alone wasn't visually distinct enough in a monospace code block on a standard monitor.

= 2.9.15 =

* Fixes the root cause behind the CSP hash-safety notices introduced in 2.9.9: WordPress core's own Global Styles inline stylesheet (and any theme/plugin inline style block added the same standard way) is now covered by the per-request nonce instead of needing an approved hash, since its content can genuinely differ between renders of the exact same page -- something no hash allowlist could ever keep up with. The earlier safety caps remain in place as a backstop, but this should mean far fewer -- ideally none -- of those notices going forward.

= 2.9.14 =

* Database schema updated to v24: media-src now defaults to 'self' instead of 'none'. Previously, media-src 'none' blocked WordPress core's own native Video/Audio blocks (self-hosted media) out of the box, with no corresponding security benefit -- same-origin video/audio can't execute script. Every profile still at the untouched 'none' default is automatically updated; a deliberately customised media-src is left as-is.

= 2.9.13 =

* CSP > Policy Audit tab: each directive name in the Effective Header column is now bold, so a long header (often a dozen-plus directives on one line) is easier to scan.

= 2.9.12 =

* Rewrites the About tab to describe every pillar this plugin manages, not just Content Security Policy -- the nine other header pillars, the page-rewrite protections, and the free-standing Certificates (ACME TLS) manager now each get their own explanation.
* Shows a plain-English summary for the CSP hash-safety admin notices introduced in 2.9.9/2.9.10 instead of raw technical detail (database table names, internal class names) in the wp-admin dashboard. The full technical detail is still available for a developer, now behind a "Technical detail" disclosure.

= 2.9.11 =

* Fixes an inconsistency in the 2.9.9 CSP hash safety cap: on a surface with more approved hashes than fit the safety byte budget, which specific hashes got dropped could vary unpredictably between requests instead of consistently favouring the most recently seen ones. The emitted policy is now deterministic for the same underlying data.

= 2.9.10 =

* Fixes audit-log noise introduced in 2.9.9: a surface still over its CSP hash safety budget was logging a warning on every single pageview instead of at most once per hour.

= 2.9.9 =

* Fixes unbounded growth of the inline-script/style hash inventory that could grow the emitted Content-Security-Policy header past common web-server response-header size limits, causing every page on an affected surface to fail with a silent 500. Adds a per-surface hourly cap on newly-learned hashes, real time-based retirement of stale hashes (previously only worked in narrow conditions), and a hard byte-budget safety cap when building the header, so this can no longer take a site down even if the same root cause recurs.
* Inline-script/style hash records now capture the request path and a content excerpt when first seen, so a future occurrence is traceable from the database instead of requiring a manual investigation.

= 2.9.8 =

* Splits the Readiness tab in two: Readiness now covers plugin/schema/operational health checks only, and a new Recovery tab holds schema-downgrade status, configuration snapshot restore, Reset Plugin Data, and configuration export/import.
* Corrects the Reset Plugin Data confirmation phrase and description, which previously said "RESET CSP DATA" / "blank CSP canvas" even though reset has always cleared every plugin table across all pillars, not just CSP. Now reads "RESET SAM PLUGIN DATA" and describes the actual scope.
* Adds configuration export/import: administrator-authored policy profiles, source/hash approvals, other pillar profiles, dependency classifications, non-secret certificate settings, and automation/reporting options as a downloadable/uploadable JSON file, from the new Recovery tab. Never includes secrets, credentials, private key material, the audit log, or violation history.

= 2.9.7 =

* Adds automatic protection against an unsafe plugin downgrade: if an older plugin version is ever installed over a site whose database a newer version already upgraded, the plugin now refuses to touch the database and shows a clear warning instead of risking silent data corruption.
* Adds automatic configuration snapshots taken before every database upgrade, with a way to restore one from Security Automation Manager > Overview > Readiness if an upgrade's data changes turn out to be unwanted -- while staying on the current plugin version.
* Database schema updated to v23 (adds a new internal table for the snapshots above; no changes to any existing table).

= 2.9.6 =

* The Updates and About tabs (Security Automation Manager > Overview) now use the full available width, matching every other tab on that page.
* Added concrete guidance to the Cross-Origin-Embedder-Policy and Cross-Origin-Opener-Policy tabs on how long to run Report-Only before enforcing, and what testing can shorten that wait.
* Corrected the Scripts > Start Here explanation of the "Suggest" SRI hash helper -- it saves the fetched hash as the pinned value immediately, with no separate review step, not "for you to review" as previously described.

= 2.9.5 =

* Certificates: the "This server could not generate a certificate key automatically" message on the Configuration tab now shows a stable, plain-English reason up front, with the raw technical detail (for your host's support team) moved into a collapsed disclosure instead of being shown as the primary explanation.
* Formally assessed the certificate credential vault's key derivation (entropy, domain separation, ciphertext compatibility, rotation, recovery) and documented the findings; the derivation itself is unchanged.
* Adds a real WordPress + MySQL release-verification test suite (CI-only, no user-facing change): clean install for both distribution channels, upgrade from the previous release and from the last pre-certificate release, data-preservation checks, and a real-network manifest-rejection test.
* Expands automated testing to PHP 8.1 through 8.4 (previously PHP 8.1 only).
* Normalizes stray em dashes to plain hyphens in a number of admin-facing help strings and code comments. No functional or runtime changes from this item.

= 2.9.4 =

* Documentation correction release: fixes several places where the description text had drifted from actual behaviour -- the GitHub release package name/install instructions, a self-contradiction about the CSP automation default, and an out-of-date claim that Cross-Origin-Opener-Policy and Cross-Origin-Embedder-Policy have no report-only mode (they've had one since the Stage 3 report-only learning workflow shipped). Certificates is now documented as a first-class feature rather than only mentioned in the external-services disclosure. No functional or runtime changes.

= 2.9.3 =

* No functional or runtime changes. Repository governance release: adds `docs/consolidation-ledger.md`, a verified repository assessment and roadmap reconciliation used to plan the ongoing public-release consolidation work.

= 2.9.2 =

* Risk badges (Profiles tab's Bypass Best Practices toggles, the Sources table, and the Policy Changes table) now show their explanation as a proper hover/focus tooltip on the badge itself, instead of a permanently-visible paragraph on the Profiles tab or a plain, unstyled browser tooltip on the other two. All three now render identically and consistently.
* Added colours for the "Critical" and "Unknown" risk levels, which previously rendered as unstyled badges.

= 2.9.1 =

* Certificates > Configuration now checks whether this server can actually generate a certificate key -- by attempting one, not just checking that the openssl extension is present, since the extension can be loaded and still fail (a missing openssl.cnf, for example). The "bring your own private key" upload box is only shown when generation genuinely fails, with the specific reason and the OpenSSL command to make one yourself, or when a key is already stored. Servers that work correctly no longer see the upload box at all.

= 2.9.0 =

* `style-src-attr`'s `'unsafe-hashes'` keyword is no longer added automatically whenever an inline style attribute hash exists -- a security scanner correctly flags this keyword, so it is now its own explicit, off-by-default "Bypass Best Practices" toggle on the Profiles tab (schema v22), labelled with its risk level. A captured hash sits inert until an admin opts in per surface, same as before inline-style-attribute hash capture existed.
* The "Bypass Best Practices" catalog now shows a risk-level badge (Low/Medium) next to each toggle, and its violation-count display is built generically from the catalog instead of being hardcoded to two entries, so future entries show a real count automatically.

= 2.8.0 =

* Bring your own private key: optionally paste a PEM private key on the Certificates Configuration tab (validated before saving, encrypted at rest, reused for every order), with the matching OpenSSL command line shown for whichever key type is selected. Useful when your organisation must control key material or key generation misbehaves on your host.
* The Certificates page now checks its PHP requirements up front: if the openssl or sodium extension is missing it explains exactly what to ask your host for, instead of failing mid-order. Note that ACME request signing requires ext/openssl regardless of who generates the key.
* Documented that HSTS (including hstspreload.org) does not conflict with HTTP-01 validation: HSTS is a browser-only policy; ACME validators start at http:// and follow the redirect to HTTPS. Only a closed port 80 breaks HTTP-01.
* GitHub releases now publish a single ZIP asset (security-automation-manager-vX.Y.Z.zip, the self-updating GitHub-channel build) instead of three.

= 2.7.0 =

* The Certificates page is reorganised into three full-width tabs: Configuration (domains, validation method, DNS provider, key type, environment), Issue / Renew (status and the manual trigger), and Install (deployment mode, downloads, platform guidance).
* The Domains box pre-fills with this site's own address (plus its www variant where sensible) so the common case needs no typing.
* New explicit DNS-01 / HTTP-01 validation-method choice: pick HTTP-01 and the DNS provider fields disappear; stored DNS credentials are kept for switching back.
* Certificate signing requests can now carry organisation details (company name, department, country, state, city). Note that domain-validated CAs such as Let's Encrypt issue on the domain names only and omit these from the final certificate; they are included in the CSR for CAs and workflows that use them.

= 2.6.1 =

* The Certificates page's Export deployment mode now explains exactly what the export path needs to be (outside the web root, writable by the PHP user, usually a sibling of the web root), how to create it, and what to ask your hosting provider for if you lack a suitable path or the permissions to make one -- including the wording for the request and the upgrade path to fully automatic installation via a control-panel API token.

= 2.6.0 =

* DNS-01 provider support expanded from 7 to 41 built-in providers, now covering AWS Route 53, Azure DNS, Google Cloud DNS, Akamai Edge DNS, Alibaba Cloud DNS, Bunny.net, ClouDNS, deSEC, DNSimple, DNS Made Easy, DNSPod, Domeneshop, DreamHost, Dynu, easyDNS, GleSYS, INWX, IONOS, Joker.com, Mythic Beasts, Namecheap, Name.com, NameSilo, netcup, Netlify, Njalla, NS1, OVH, PowerDNS (self-hosted), Scaleway, Vercel, and Vultr alongside the original seven -- plus two universal mechanisms that cover effectively every remaining provider: acme-dns (one-time CNAME delegation; works with any DNS host, even ones without an API) and RFC 2136 TSIG-signed dynamic updates (BIND, Knot, Windows Server DNS, and other self-hosted servers).
* Provider credential forms now render appropriate field types (text for endpoints/usernames, password for secrets, textarea for service-account JSON); all values remain encrypted at rest.

= 2.5.0 =

* New: TLS certificate automation (ACME v2 / Let's Encrypt). Request and auto-renew certificates -- including wildcards -- directly from WordPress, with DNS-01 validation through Cloudflare, DigitalOcean, Gandi, GoDaddy, Hetzner, Linode, or Porkbun APIs (extensible via filter), automatic HTTP-01 fallback, a Let's Encrypt staging toggle for safe testing, and daily renewal via WP-Cron. Deployment adapters cover cPanel (automatic via the install_ssl API), an export directory for host-side install scripts, and manual download; which applies depends entirely on your hosting platform -- see docs/certificates.md for per-platform steps. All DNS credentials and private keys are encrypted at rest.

= 2.4.33 =

* Fixed a bug where inline `<style>` blocks printed by WordPress core's style queue -- including the per-page CSS emitted by themes and page builders -- were never captured for hashing, so they were blocked on enforce-mode surfaces. The capture buffer now opens before core prints enqueued styles. After updating, load an affected page once (with any page cache bypassed) so its styles are captured; the policy then includes them automatically.

= 2.4.32 =

* Added a Dismiss button to the "Possible competing Content-Security-Policy source detected" banner on the CSP dashboard. Dismissing hides the current findings without deleting anything from the audit log, and the banner returns automatically if a new competing-header signal is detected afterwards.
* Dropdown values that weaken security are now labelled as such instead of reading identically to the safe options around them: Referrer-Policy's `unsafe-url` and Permissions-Policy's `all` token.
* Fixed the cramped Profiles table layout introduced alongside the new Bypass Best Practices column.

= 2.4.31 =

* Fixed a bug where running Manual Scan could fail with an HTTP 500 error, caused by the admin-surface scan anonymously requesting wp-admin. That crawl target has been removed; it never discovered real admin content anyway, since a logged-out request just redirects to the login page.
* Added automatic hash capture and approval support for inline `style="..."` attributes, closing a gap where this content had no path to approval under an enforce-mode policy.
* Added a "Bypass Best Practices" option on the Profiles tab, letting you explicitly allow `data:` image and font URIs per surface when your site's design legitimately needs them -- shown alongside how many times each has actually been blocked.
* Clarified the Violations tab's occurrence counts for inline content so it's clear when a single row represents many different blocked items, not just one.

= 2.4.30 =

* Stage 3 of the Cross-Origin-Opener-Policy / Cross-Origin-Embedder-Policy report-only learning workflow: the Cross-Origin Policies page's COOP and COEP tabs now show a per-surface Mode selector (Disabled / Report-Only / Enforce) in place of the plain enabled checkbox, plus a Report-Only Evidence table below showing what's actually been observed for that pillar, with a simple "N violations in the last 7 days" summary. Promoting a surface to Enforce is always a deliberate, manual choice.

= 2.4.29 =

* Stage 2 of the Cross-Origin-Opener-Policy / Cross-Origin-Embedder-Policy report-only learning workflow: both pillars gain a mode (Disabled / Report-Only / Enforce) alongside their existing value. Report-Only emits the `-Report-Only` variant of the header plus the Reporting API endpoint so violations are observable without breaking anything; Enforce emits the real header as before. Every existing profile defaults to Enforce, so nothing that's already active changes behaviour on upgrade. No admin-facing UI yet for choosing a mode -- that ships next.

= 2.4.28 =

* Fixes two bugs that could leave `script-src-elem` and `style-src-elem` weaker than intended even though `script-src`/`style-src` looked correctly configured: `strict-dynamic` was only ever added to `script-src`, and approved inline-script/style hashes were only ever added to `script-src`/`style-src` -- never to their `-elem` counterparts. Per the CSP spec, once a policy explicitly sets `script-src-elem`/`style-src-elem` (this plugin always does), browsers use it exclusively for `<script>`/`<style>` element checks and never fall back to the base directive. In practice this meant a same-origin script inserted dynamically by trusted code (e.g. WordPress core's own password-strength-meter loader on the login page) could still be blocked despite strict-dynamic being enabled, and an administrator approving an inline script/style hash from the violations review queue could see it have no effect at all. Both now propagate to the matching `-elem` directive alongside the base one.

= 2.4.27 =

* Fixes a bug where a genuinely new violation only ever got one chance to become a reviewable source proposal -- the exact moment its violation-report fingerprint was first ever recorded. If the learning window happened to be closed at that one moment, the source never surfaced in For Review again, even though it kept violating on every subsequent visit. Every report now gets a fresh chance, without re-proposing (or re-logging) a source that already has an inventory entry.

= 2.4.26 =

* Renames the REST API namespace from `security-manager/v1` to `sam/v1`, matching the plugin's internal `wp_sam_`/`WP_SAM` naming everywhere else. The report endpoint is now `/wp-json/sam/v1/report`. Browsers holding a CSP header issued before this release keep POSTing to `/wp-json/security-manager/v1/report`, which remains registered as a legacy alias. The older `csp-manager/v1` alias, from the original CSP Manager plugin rename, has been fully retired.

= 2.4.25 =

* Fixes a bug where a CSP violation's stored disposition (report vs enforce), effective directive, original policy, and status code were only ever written on the first time that violation was seen, and never refreshed afterward. A surface promoted from report-only to enforce would keep showing "report" indefinitely for any violation first recorded before the promotion, even though the browser was correctly sending "enforce" on every new occurrence.

= 2.4.24 =

* Scripts > External now retains the most recently observed full URL (not just the origin) for each third-party script/stylesheet, so the "Suggest" SRI hash helper is pre-filled with an exact file to fetch instead of requiring you to find that URL yourself first.

= 2.4.23 =

* Moves the Update Channel page into the Overview page as a new "Updates" tab (Security Automation Manager > Overview > Updates), replacing its own separate left-nav entry.

= 2.4.22 =

* Fixes a fatal error on both Scripts tabs (External and Internal): the tab content files were missing PHP class imports of their own, since imports declared in the parent page do not carry over to a file it requires. Both tabs are now covered by an automated test that renders them end to end, closing the gap that let this ship unnoticed.
* Adds quick range buttons (last hour / 6 hours / day / 7 days) to the CSP Violations tab.
* Scopes the CSP violation report rate limit per directive instead of per surface, so one noisy directive can no longer crowd out visibility into every other directive on the same surface.
* Flags a likely competing Content-Security-Policy header: if a browser reports a disposition that doesn't match this plugin's own configured mode for that surface, a warning now appears on every CSP dashboard tab.

= 2.4.21 =

* Hardens the GitHub-channel update checker's download-URL validation to reject any path containing a ".." segment, closing a theoretical path-traversal gap the prefix/suffix string checks alone couldn't catch.
* Adds a kill-switch regression test and tightens the auto-update gate filter's type hint from mixed to the actual WordPress-documented `?bool`.

= 2.4.20 =

* Adds an Update Channel admin page: installed version, active build channel, manifest URL, last successful/failed check, available version, manifest validation status, package checksum verification status, last applied-update result, and whether WP_SAM_DISABLE_AUTO_UPDATE is defined. A WordPress.org build shows only its own version/channel summary and never references the GitHub update service.

= 2.4.19 =

* Ships a vetted, enabled-by-default configuration for X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Reverse Tabnabbing, Cross-Origin-Resource-Policy, Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy, and X-Permitted-Cross-Domain-Policies on every surface that doesn't already have a row, so a fresh install ships hardened out of the box instead of requiring nine separate admin pages to be found and enabled individually. Only ever fills in a missing (pillar, surface) row -- a surface you've already configured, enabled or deliberately left disabled, is never touched. HSTS is deliberately not included: it stays a per-surface opt-in given how hard it is to undo once a browser caches it.
* Changes the default CSP automation-approval mode from Manual to Automatic (high approvals only): a new install now auto-approves proposed CSP sources below the high-risk threshold into the report-only policy on their own evidence, with high-risk sources still requiring a human decision. This only governs who approves a proposed source -- CSP still starts report-only on every surface, and promotion to enforce still requires a deliberate administrator action through the existing learning window and promotion gate.

= 2.4.18 =

* Renames the CSP Profiles page's "Trusted Types" column to "Experimental", tightens its checkbox/label layout, and explains why it's pinned to report-only instead of just asserting it.
* Fixes column widths on the CSP Profiles and Scripts (External tab) inventory tables so dropdowns, inputs, and their labels no longer overlap or get cut off at normal admin widths.

= 2.4.17 =

* Tightens the default CSP img-src directive from 'self' data: to 'self' only. An existing profile whose img-src still exactly matches the old default is migrated automatically on upgrade; a profile you've already customised is left untouched.

= 2.4.16 =

* Renames the External Scripts page to Scripts, adding a Start Here tab and a new Internal tab.
* Adds Internal Script Integrity: automatic Subresource Integrity for your own theme/plugin/core scripts and stylesheets, per-surface opt-in, recalculated whenever a file changes. Reads the local file directly -- never a network fetch.

= 2.4.15 =

* Pins the Overview page to the top of the left nav, above the alphabetically-sorted rest of the menu.

= 2.4.14 =

* Adds proactive Subresource Integrity drift detection: a daily check re-verifies pinned SRI hashes against this site's own homepage and warns before a visitor triggers a removal.
* Adds a "Suggest" button on the External Scripts page to compute an SRI hash for a URL you supply, instead of using an external tool.

= 2.4.13 =

* Sorts the Overview page's per-pillar status table alphabetically, matching the left-nav ordering.

= 2.4.12 =

* Fixes X-Permitted-Cross-Domain-Policies settings not taking effect: a database column was one character too narrow for that pillar's internal key, so toggles on that page could silently fail to save (or save under an unreadable key), leaving the Overview page always showing it as "Off".

= 2.4.11 =

* Fixes a false-positive conflict warning: on sites behind a full-page cache, CDN, or reverse proxy, the daily conflict probe could misreport this plugin's own cached CSP header as a competing header from another plugin or the web server. The probe now recognises and excludes its own output.

= 2.4.10 =

* Commercial-build only, no functional change to the free WordPress.org/GitHub build: Fully Automatic checkout now calls the Stripe API directly from this WordPress install instead of through an external Cloudflare Worker, which has been removed entirely. Configure your Stripe secret keys, Price IDs, and webhook signing secret in Settings ("Stripe Configuration").

= 2.4.9 =

* Sorts the left-nav submenu alphabetically.
* Merges the Readiness page into the Overview page as a tab (schema/runtime checks and the data-reset flow are unchanged, just relocated).
* Adds an About tab to the Overview page: who built this plugin, why, the gap it fills, and links to the public help site.

= 2.4.8 =

* Reorders the Cross-Origin Policies tabs alphabetically: Cross-Origin-Embedder-Policy, Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy, X-Permitted-Cross-Domain-Policies.

= 2.4.7 =

* Consolidates the four separate Cross-Origin-Resource-Policy, X-Permitted-Cross-Domain-Policies, Cross-Origin-Opener-Policy, and Cross-Origin-Embedder-Policy submenu pages into one "Cross-Origin Policies" page with a tab per pillar.

= 2.4.6 =

* Commercial-build only, no functional change to the free WordPress.org/GitHub build: wires up the signed product-config endpoint (Cloudflare Worker's custom domain route, the Ed25519 keypair used to verify it, and a shared default config URL) so the Fully Automatic checkout flow no longer requires per-site manual configuration.

= 2.4.5 =

* Fixes every header pillar (Content Security Policy, X-Frame-Options, Permissions-Policy, HSTS, and all others) being silently skipped on the WordPress login page (wp-login.php), even when explicitly enabled and configured for the login surface. wp-login.php never fires the `send_headers` action this plugin relied on exclusively; it now also emits headers on `login_init`, the hook WordPress itself documents as the substitute for code that must run early on that page.

= 2.4.4 =

* Fixes CSP violation reports being logged as a permanent, separate row per exact file URL instead of grouping by host -- a CDN or font provider (e.g. Google Fonts) serving each request from a distinct, content-hashed filename under the same host no longer floods the Violations table with one row per file. Deduplication now groups on the blocked host wherever one is extractable, matching how CSP source-approval already treats hosts as the unit of approval. Existing rows are merged automatically on upgrade.

= 2.4.3 =

* Fixes a fatal error on every wp-admin page load. admin_footer_text filter callbacks can receive a non-string value from another plugin or theme hooked earlier in the chain; this plugin's own callback required a string and fataled instead of tolerating it.

= 2.4.2 =

* Fixes the conflict-detector self-check probe permanently failing to suppress this plugin's own CSP output, causing every install to misreport its own live CSP header as a "competing" header from web-server config or another plugin. The bug has been present since the WP_CSP -> WP_SAM rename.

= 2.4.1 =

* No functional changes. First release actually tagged and published this session.

= 2.4.0 =

* Adds backend plumbing for a Cross-Origin-Opener-Policy / Cross-Origin-Embedder-Policy report-only learning workflow (no admin-facing UI in this release -- the first stage of a multi-stage rollout). Covers report ingestion, storage, and a shared reporting-endpoint helper reused by CSP, COOP, and COEP.

= 2.3.0 =

* Adds a per-surface Trusted Types toggle to the CSP Profiles tab: sends require-trusted-types-for 'script' when enabled, always report-only regardless of surface mode.
* Fixes approved CSP source hosts being emitted without a scheme prefix (e.g. img-src cdn.example.com instead of img-src https://cdn.example.com). Flagged by a third-party CSP linter as a "missing protocol" finding.
* Fixes upgrade-insecure-requests being emitted in report-only mode, where browsers ignore it entirely.
* Removes fenced-frame-src from the default CSP directive set (experimental, not part of the CSP living standard, commonly flagged by CSP linters). Existing profiles are migrated automatically on upgrade.
* Fixes a possible bare, valueless trusted-types token leaking into the header.
* Fixes Violations table column widths on the CSP dashboard so Blocked URI fills the available space instead of all columns splitting evenly.

= 2.2.0 =

* Adds Cross-Origin-Resource-Policy, Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy, and X-Permitted-Cross-Domain-Policies as four new simple pillars (per-surface value picker, same shape as X-Frame-Options and Referrer-Policy). Cross-Origin-Opener-Policy and Cross-Origin-Embedder-Policy carry real breakage risk -- COOP's same-origin can sever window.opener access from popup-based OAuth/SSO flows, and COEP's require-corp blocks any cross-origin subresource lacking an explicit CORP/CORS opt-in -- so their admin pages show a prominent warning notice above the picker. None of the four have a report-only mode, discovery workflow, or automation.

= 2.1.2 =

* Fixes silent AJAX save failures: the per-surface toggle/dropdown autosave handlers for X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Strict-Transport-Security, Reverse Tabnabbing, and External Scripts did not check the AJAX response body, so a nonce failure or server-side validation error looked identical to success -- the control silently re-enabled with nothing actually saved. Failures now surface a clear error message instead of being swallowed.

= 2.1.1 =

* Fixes a fatal error on the External Scripts admin page (Call to undefined method Table_Query::equals_where()). The 2.1.0 release ZIP was built from a commit where that page's filters referenced a helper method that hadn't actually merged yet. No other functional changes.

= 2.1.0 =

* Adds Strict-Transport-Security (HSTS) as a sixth pillar: per-surface Max-Age, Include Subdomains, and Preload. Only ever sent over HTTPS; Preload cannot be enabled until Max-Age and Include Subdomains already meet hstspreload.org's submission minimum.
* Adds Reverse Tabnabbing Protection: per-surface, adds rel="noopener" to target="_blank" links missing noopener/noreferrer.
* Adds External Scripts: passively inventories third-party script/stylesheet origins from real page loads, lets an administrator classify each one, and supports Subresource Integrity. Report mode (the default) never removes anything; a freshly discovered origin is always unclassified, never blocked by default.
* Reworks the Violations and For Review filter panels to match Policy Changes' collapsible layout; Surface is now a single-select combobox and Directive is free-text search.
* Moves Policy Audit from a standalone top-level admin page into a tab on the CSP dashboard.
* Makes the Fully Automatic upgrade call-to-action more prominent on the CSP Settings tab.
* Sets Fully Automatic subscription pricing at £1.99/month or £19.99/year with a recurring Stripe subscription and a billing-interval choice.

= 2.0.0 =

* Renames the plugin to Security Automation Manager. Content Security Policy becomes the first of five HTTP security-header pillars, joined by X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy as simpler per-surface pillars with no report-only mode, discovery workflow, or automation.
* Adds a top-level "Security Automation Manager" admin menu with an Overview page summarizing every pillar's per-surface status.
* Adds full-dataset sorting and per-column filtering to the Violations, For Review, and Policy Changes tables, and a per-row metadata popover on Violations.
* Adds a "Start Here" tab and merges the standalone Settings page into the CSP dashboard as a tab.
* Fully Automatic mode (zero-review auto-apply of deterministic policy changes) now requires a paid subscription; sites without an active entitlement are kept on "Automatic (with high approvals only)" instead. Every other feature remains free, with no remote licensing calls in the WordPress.org build.
* Removes the "Allow eligible auto-approvals" checkbox and its underlying field; Automation Mode alone now governs automatic approval eligibility.

= 1.0.16 =

* Adds a separate GitHub-channel release ZIP with checksum-verified native WordPress update integration.
* Keeps the plain release ZIP WordPress.org-safe by excluding the GitHub updater and Update URI header.
* Publishes GitHub-channel update metadata for vcns/wp-updates when the release pipeline has a WP_UPDATES_TOKEN.
* Adds selectable automation postures on Profiles and Settings: Manual, Automatic with medium+high approvals, Automatic with high approvals only, and Fully Automatic within deterministic hard safety exclusions.
* Replaces the dashboard Strict-Dynamic display column with a per-surface Automation dropdown.

= 1.0.15 =

* Renames the dashboard source review queue to "For Review".
* Expands Policy Changes into a policy activity timeline showing source proposals, decisions, actors, suppression state, and policy snapshots.
* Adds per-surface deterministic automation settings and records eligible automatic approvals as `automation_engine` decisions.

= 1.0.14 =

* Changes the default CSP reporting transport to direct `report-uri` so browser violations reach the local endpoint promptly during learning.
* Adds a Reporting transport setting for opting into Reporting API headers when required.

= 1.0.13 =

* Fixes policy version table creation on MariaDB by avoiding a reserved index name.
* Prevents activation from querying policy version snapshots when the snapshot table could not be created.
* Avoids calling WordPress REST routing too early while activation-time policy snapshots are being built.

= 1.0.12 =

* Normalizes CSP directives so `'none'` is removed when approved sources are merged into the same directive.
* Accepts CSP reports from configured public reporting endpoint and forwarded hostnames so proxied deployments do not silently discard valid browser reports.
* Clarifies that browser violation reports can be collected from either report-only or enforce CSP headers.

= 1.0.11 =

* Makes CSP surface detection path-aware so wp-admin URLs that produce redirects or 404 responses still use the admin surface configuration.

= 1.0.10 =

* Makes the destructive CSP data reset return all surfaces to disabled mode so the plugin stops emitting CSP headers until rollout is deliberately restarted.
* Emits CSP headers before WordPress redirects, making unauthenticated wp-admin redirects easier to diagnose.

= 1.0.9 =

* Adds a configurable origin policy header name for Cloudflare, CDN, and reverse-proxy deployments that copy an origin header back to the browser-facing CSP header.
* Adds schema self-healing so missing CSP tables are recreated even when the stored database version already matches the current schema version.

= 1.0.8 =

* Clarifies the Violations empty state so administrators know manual scans do not create browser violation reports and can see the expected reporting endpoint.

= 1.0.7 =

* Adds a CSP Manager Readiness page for plugin-specific schema, database, reporting endpoint, scan schedule, and automation posture checks.
* Adds a Reset action in the Installed Plugins row that links to a destructive reset panel requiring current administrator password re-authentication and typed confirmation.

= 1.0.6 =

* Adds CSP conflict detection for existing `.htaccess`, server, and security-header-plugin CSP emitters.
* Requires administrator reasons for source approval, rejection, reversion, and undo decisions.
* Adds undo support for approved and rejected source decisions without rewriting history.
* Adds dashboard tab guidance, configurable reporting server URL support, and an Installed Plugins Settings link.

= 1.0.5 =

* Renames the package slug, text domain, main plugin file, release ZIP, and WordPress.org deployment slug to `csp-automation-manager`.
* Updates WordPress.org scanner metadata and includes the declared `languages` directory.

= 1.0.4 =

* Removes the custom runtime update checker and all third-party update manifest polling from the WordPress.org plugin package.
* Removes legacy external-service admin surfaces from the WordPress.org plugin package.
* Makes all shipped CSP capabilities available locally without payment, remote entitlement checks, or trialware-style feature locking.
* Updates package copy and disclosures for WordPress.org guideline alignment.

= 1.0.3 =

* Renames the public plugin display name to `CSP Automation Manager` to comply with WordPress.org plugin naming requirements.

= 1.0.2 =

* Tightens the release package so development-only files, internal policy notes, and local cache files are excluded from distributed ZIP builds.
* Adds release workflow checks that fail if submission-only or development-only files are present in the packaged ZIP.

= 1.0.1 =
* Adds Reporting API headers, forbidden-directive filtering, violation sample persistence, audit logging, policy-change proposals, decision suppression, revert behaviour, violation rollups, policy history, and review APIs.

= 0.2.0 =
* Initial public plugin implementation.
