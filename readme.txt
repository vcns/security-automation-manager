=== Security Automation Manager ===
Contributors: vcns
Tags: security, csp, content security policy, hsts, ssl certificates
Requires at least: 6.4
Tested up to: 7.1
Requires PHP: 8.1
Stable tag: 2.9.20
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Roll out and enforce CSP, HSTS, X-Frame-Options, Referrer-Policy, and other security headers safely, with violation reports plus free ACME (Let's Encrypt) SSL/TLS certificate automation for WordPress.

== Description ==

Security Automation Manager helps site owners roll out strict HTTP security headers safely and incrementally, instead of flipping them on and risking a broken, unusable site. Content Security Policy (CSP) is its most capable pillar: it discovers the scripts, styles, fonts, and other sources your site actually uses, proposes a policy from what it observes, runs that policy in report-only mode so violations surface without blocking anything, and only enforces once an administrator reviews and approves it. X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Strict-Transport-Security (HSTS), Cross-Origin-Resource-Policy (CORP), Cross-Origin-Opener-Policy (COOP), Cross-Origin-Embedder-Policy (COEP), and X-Permitted-Cross-Domain-Policies are simpler per-surface pillars alongside it. Reverse Tabnabbing Protection, External Scripts, and Internal Script Integrity (Subresource Integrity / SRI hashing) round it out as further protections that rewrite the rendered page itself rather than emit a header. Certificates is a separate, self-contained ACME v2 (Let's Encrypt) SSL/TLS certificate manager, unrelated to the header pillars beyond sharing the same admin and audit plumbing -- it issues and renews certificates automatically via HTTP-01 or DNS-01 domain validation (41 built-in DNS provider integrations, including Cloudflare, AWS Route 53, and Google Cloud DNS) and deploys them for you.

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

= 2.9.20 =

* Fixed: a recurring warning (e.g. CSP hash-budget trimming) that occurred while nobody visited wp-admin for several days could dump a wall of near-identical banners on the next visit. Admin notices for the same underlying condition now replace each other in the queue, showing only the latest occurrence.

= 2.9.19 =

* CSP > Profiles tab's Experimental column (Trusted Types) now shows the same layout as Bypass Best Practices: checkbox, then `require-trusted-types-for: 'script'`, then a badge -- instead of a checkbox labelled "Trusted Types" with a separate description paragraph underneath.

= 2.9.18 =

* Database schema updated to v25: CSP > Profiles tab's "Bypass Best Practices" catalog grows from 3 to 9 entries (new: blob: URIs for images/audio/video, data: URIs for audio/video, inline event handler attributes via hash approval, WebAssembly compilation, blob: URIs for workers), and now only shows an entry once the surface has actually triggered it at least once (or the entry is already enabled). Storage moves from one column per entry to a single JSON list, so the catalog can keep growing without a schema change each time; existing selections are carried over automatically.
* Each Bypass Best Practices checkbox now shows the exact directive and expression it adds (e.g. `worker-src: blob:`) followed by its risk badge, instead of a paraphrased description.

= 2.9.17 =

* Always allows an empty inline style/event-handler attribute value (e.g. a script library clearing `style=""`) in enforcing surfaces with the "Allow inline style attributes via hash approval" toggle enabled, instead of blocking and reporting it as a violation. An empty attribute can never execute or style anything, so this was noise, not a real risk.

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

Full changelog history: https://github.com/vcns/security-automation-manager/blob/main/CHANGELOG.md
