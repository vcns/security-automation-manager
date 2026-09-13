=== VCNS Security Automation Manager ===
Contributors: vcnstech
Tags: security, csp, content security policy, hsts, ssl certificates
Requires at least: 6.4
Tested up to: 7.1
Requires PHP: 8.1
Stable tag: 2.9.106
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Self-learning security headers, built-in attack detection and rate limiting, file-integrity monitoring, and free TLS certificates. No paywall.

== Description ==

Turning on strict security headers usually means picking between two bad options: leave Content-Security-Policy off and stay exposed, or turn it on and watch it silently break your checkout page, your embedded videos, or your analytics -- with no warning before it happens.

Security Automation Manager takes a third option. It watches your site quietly first, in report-only mode, learning exactly which scripts, styles, and fonts your site actually loads -- nothing gets blocked while it learns. Once you can see the whole picture, you approve a policy built from your real site, not a guess. Only then does it start enforcing.

= Everything below is free, with nothing held back =

* **Content Security Policy** that proposes itself from real traffic, runs report-only until you approve it, and keeps learning as your site changes.
* **HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy**, and five more security headers, each shipped with sane, hardened defaults.
* **Reverse tabnabbing protection, a third-party script inventory, and Subresource Integrity (SRI) hashing** for everything your site pulls in from elsewhere.
* **Free SSL/TLS certificates** via Let's Encrypt, issued and renewed automatically, with 41 built-in DNS providers for wildcard domains -- Cloudflare, AWS Route 53, and Google Cloud DNS among them.

The WordPress.org edition is a complete free plugin with no subscription-locked functionality. VCNS also distributes a separate commercial edition that includes Fully Automatic mode and associated commercial services.

= Built for the moment things go wrong, not just the moment you install it =

Every policy change is written to an append-only audit log, with a reason recorded. Conflict detection catches another plugin or your host quietly emitting a competing security header before it confuses you. Nothing enforces without a report-only learning period first, on every pillar that supports one.

= For the technically curious =

CSP ships per-surface profiles, nonce injection, source discovery, violation reporting, policy-change review, and readiness checks, alongside conflict detection for any CSP header already being emitted elsewhere. Seven more pillars (X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Strict-Transport-Security, Cross-Origin-Resource-Policy, X-Permitted-Cross-Domain-Policies) are straightforward per-surface toggles. Cross-Origin-Opener-Policy and Cross-Origin-Embedder-Policy get their own lighter report-only workflow via the browser Reporting API (Chromium-based browsers only, as of this writing). Certificates issues and renews via ACME DNS-01 or HTTP-01 domain validation, with credentials and private keys encrypted at rest, deploying via cPanel, filesystem export, or manual download.

== External services ==

This WordPress.org build does not contact third-party services for plugin updates, licensing, checkout, telemetry, or remote product configuration.

GitHub release builds are published separately for administrators who install from GitHub rather than WordPress.org; this update check is never present in the WordPress.org-channel package (this code is physically absent from it, not merely inactive). The GitHub-channel ZIP checks https://vcns.github.io/wp-updates/security-automation-manager/update.json from administrator update contexts only, validates the advertised package host and SHA-256 checksum, and then lets WordPress perform the update. This manifest is VCNS's own infrastructure, not a third party; the request sends no personal or site-identifying data, only a plain HTTPS GET for a static, publicly-readable JSON file. The file is served from vcns.github.io, a GitHub Pages subdomain -- GitHub Pages has no separate terms or privacy documents of its own; the whole *.github.io domain is governed entirely by GitHub's own Terms of Service (https://docs.github.com/en/site-policy/github-terms/github-terms-of-service) and Privacy Statement (https://docs.github.com/en/site-policy/privacy-policies/github-privacy-statement), the same as github.com itself. Define WP_SAM_DISABLE_AUTO_UPDATE as true in wp-config.php to prevent background auto-updates for the GitHub-channel package.

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

The Certificates page, only when an administrator configures it, requests TLS certificates over the ACME v2 protocol. Nothing is contacted until certificates are explicitly configured. Credentials and private keys are encrypted at rest. Issuing a certificate happens inside WordPress; installing it into the web server depends on your hosting platform -- automatic installation uses cPanel's install_ssl API where available, and https://vcns.github.io/security-automation-manager/certificates.html explains the basic steps for other platforms.

Every certificate request or renewal contacts the certificate authority:

* Let's Encrypt (acme-v02.api.letsencrypt.org, or the staging equivalent), operated by the Internet Security Research Group (ISRG). Subscriber Agreement: https://letsencrypt.org/repository/ -- Privacy Policy: https://letsencrypt.org/privacy/

Data sent to Let's Encrypt: the domain name(s) being requested; the ACME account's public-key material (used to sign every request and identify the account, never a private key); an optional contact email address, only if the administrator supplies one; the certificate signing request (CSR) at finalization; and challenge-response/validation data as the ACME protocol's issuance flow requires.

When a DNS provider is selected for DNS-01 domain validation, that provider's API is also contacted at certificate request and renewal time, using credentials the administrator supplies. Data sent depends on the specific request: API credentials/tokens on every call; the domain and DNS zone name; requests to discover which zone matches the domain; the DNS record name being created or deleted (always of the form `_acme-challenge.<domain>`); the ACME TXT challenge value; and, for providers that require it, an account, project, or zone identifier. This plugin includes 41 built-in DNS provider drivers; below is each one's operating company and legal links, where the provider is a third-party service:

* Akamai (Edge DNS) -- Akamai Technologies, Inc. -- Terms: https://www.akamai.com/legal/portal-terms -- Privacy: https://www.akamai.com/legal/privacy-statement
* Alibaba Cloud DNS -- Alibaba Cloud -- Terms: https://www.alibabacloud.com/help/en/legal/latest/alibaba-cloud-international-website-product-terms-of-service -- Privacy: https://www.alibabacloud.com/help/en/legal/latest/alibaba-cloud-international-website-privacy-policy
* Microsoft Azure DNS -- Microsoft Corporation -- Terms and Privacy (agreement depends on purchase channel): https://azure.microsoft.com/en-us/support/legal/
* Bunny.net DNS -- BunnyWay d.o.o. -- Terms: https://bunny.net/tos/ -- Privacy: https://bunny.net/privacy/
* Cloudflare DNS -- Cloudflare, Inc. -- Terms: https://www.cloudflare.com/terms/ -- Privacy: https://www.cloudflare.com/privacypolicy/
* ClouDNS -- Cloud DNS Ltd -- Terms: https://www.cloudns.net/tos/ -- Privacy: https://www.cloudns.net/privacy-policy/
* deSEC -- deSEC e.V. -- Terms: https://desec.io/terms/ -- Privacy: https://desec.io/privacy-policy/
* DigitalOcean DNS -- DigitalOcean, LLC -- Terms: https://www.digitalocean.com/legal/terms-of-service-agreement -- Privacy: https://www.digitalocean.com/legal/privacy-policy
* DNSimple -- DNSimple Corporation -- Terms: https://dnsimple.com/terms -- Privacy: https://dnsimple.com/privacy
* DNS Made Easy (API: api.dnsmadeeasy.com -- dnsmadeeasy.com itself has no separate legal pages of its own; its own site directs to DigiCert's) -- DigiCert, Inc. -- Terms: https://www.digicert.com/legal-repository -- Privacy: https://privacy.digicert.com/policies/en/?name=dns-network-security-products-privacy-notice
* DNSPod -- Tencent Cloud -- Terms: https://docs.dnspod.cn/account/terms-of-service/ -- Privacy: https://docs.dnspod.cn/account/privacy-policy/ (Chinese-language)
* Domeneshop -- Domeneshop AS -- Terms and Privacy (single combined document, Norwegian-language): https://domene.shop/terms
* DreamHost DNS -- DreamHost, LLC -- Terms: https://www.dreamhost.com/legal/terms-of-service/ -- Privacy: https://www.dreamhost.com/legal/privacy-policy/
* Dynu -- Dynu Systems, Inc. -- Terms: https://www.dynu.com/en-US/Legal/TermsOfUse -- Privacy: https://www.dynu.com/en-US/Legal/PrivacyPolicy
* easyDNS -- easyDNS Technologies Inc. -- Terms: https://easydns.com/legal/terms-of-service/ -- Privacy: https://easydns.com/legal/privacy-policy/
* Gandi DNS -- Gandi SAS -- Terms: https://www.gandi.net/en/contracts/terms-of-service -- Privacy: https://www.gandi.net/en/contracts/privacy-policy
* GleSYS -- Glesys AB -- Terms: https://glesys.com/legal/general-terms-and-conditions/ -- Privacy: https://glesys.com/legal/privacy-policy/
* GoDaddy DNS -- GoDaddy.com, LLC -- Terms: https://www.godaddy.com/legal/agreements/universal-terms-of-service-agreement -- Privacy: https://www.godaddy.com/agreements/privacy
* Google Cloud DNS -- Google LLC -- Terms: https://cloud.google.com/terms -- Privacy: https://cloud.google.com/terms/cloud-privacy-notice
* Hetzner DNS -- Hetzner Online GmbH -- Terms: https://www.hetzner.com/legal/terms-and-conditions/ -- Privacy: https://www.hetzner.com/legal/privacy-policy/
* INWX (API: api.domrobot.com, DomRobot, INWX's own API product -- domrobot.com is an API-only hostname and does not resolve to a website of its own) -- INWX GmbH -- Terms: https://www.inwx.com/en/aboutus/terms -- Privacy: https://www.inwx.com/en/aboutus/dataprotection
* IONOS DNS -- IONOS Inc. -- Terms: https://www.ionos.com/terms-gtc/general-terms-and-conditions/ -- Privacy: https://www.ionos.com/terms-gtc/privacy-policy/
* Joker.com DNS -- CSL Computer Service Langenbach GmbH -- Terms: https://joker.com/terms/general -- Privacy: https://joker.com/index.joker?mode=page&page=impressum
* Linode DNS -- operated by Akamai Technologies since Linode's acquisition -- Terms: https://www.akamai.com/legal/msa -- Privacy: https://www.akamai.com/legal/privacy-statement
* Mythic Beasts -- Mythic Beasts Ltd -- Terms: https://www.mythic-beasts.com/terms/overview -- Privacy: https://www.mythic-beasts.com/terms/privacy
* Namecheap DNS -- Namecheap, Inc. -- Terms: https://www.namecheap.com/legal/universal/universal-tos/ -- Privacy: https://www.namecheap.com/legal/general/privacy-policy/
* Name.com DNS -- Name.com, Inc. -- Terms: https://www.name.com/policies/registration-agreement -- Privacy: https://www.name.com/privacy-policy
* NameSilo DNS -- NameSilo, LLC -- Terms: https://www.namesilo.com/support/v2/articles/general-terms/terms-and-conditions -- Privacy: https://www.namesilo.com/support/v2/articles/general-terms/privacy-policy
* netcup DNS -- netcup GmbH -- Terms: https://www.netcup.com/en/terms-and-conditions -- Privacy: https://www.netcup.com/en/contact/data-privacy
* Netlify DNS -- Netlify, Inc. -- Terms: https://www.netlify.com/legal/terms-of-use/ -- Privacy: https://www.netlify.com/privacy/
* Njalla -- operating entity not published -- Terms (also covers data collection; no separate privacy policy is published): https://njal.la/tos/
* NS1 -- operated by IBM since NS1's acquisition -- Terms: https://www.ibm.com/legal/terms -- Privacy: https://www.ibm.com/us-en/privacy
* OVH DNS -- OVH Groupe SA (OVHcloud) -- Terms: https://www.ovhcloud.com/en/terms-and-conditions/ -- Privacy: https://www.ovhcloud.com/en/terms-and-conditions/privacy-policy/
* Porkbun DNS -- Porkbun LLC -- Terms: https://porkbun.com/legal/agreement/product_terms_of_service -- Privacy: https://porkbun.com/legal/agreement/privacy_policy
* AWS Route 53 -- Amazon Web Services, Inc. -- Terms: https://aws.amazon.com/agreement/ -- Privacy: https://aws.amazon.com/privacy/
* Scaleway DNS -- Scaleway S.A.S. -- Terms: https://www.scaleway.com/en/contracts/ -- Privacy: https://www.scaleway.com/en/privacy-policy/
* Vercel DNS -- Vercel Inc. -- Terms: https://vercel.com/legal/terms -- Privacy: https://vercel.com/legal/privacy-policy
* Vultr DNS -- The Constant Company, LLC -- Terms: https://www.vultr.com/legal/tos/ -- Privacy: https://www.vultr.com/legal/privacy/

The remaining three DNS-01 drivers (acme-dns, PowerDNS, and RFC 2136 dynamic DNS updates) are not third-party services: they contact infrastructure the administrator operates or points at themselves (a self-hosted acme-dns instance, a self-hosted PowerDNS Authoritative Server, or any DNS server speaking the RFC 2136 standard), so no external terms or privacy policy apply.

When an administrator configures automatic cPanel deployment, once a certificate is successfully issued the plugin sends an HTTPS request to the cPanel host the administrator specifies (cPanel's UAPI SSL::install_ssl endpoint), containing: the cPanel account username and API token supplied by the administrator (as an Authorization header); the domain name; the issued certificate; the certificate chain; and the certificate's private key. This is the one automatic-deployment method that transmits the private key itself, since installing a certificate requires it. Nothing is sent unless cPanel deployment is explicitly configured, and it happens once per issuance or renewal, immediately after the certificate is issued. Because the endpoint is the administrator's own hosting provider, not a service this plugin operates or has a relationship with, no single Terms of Service or Privacy Policy governs it -- those are whatever the administrator's own hosting provider publishes for their account and API access.

== Changelog ==

= 2.9.106 =

* Added: Recommendations Engine (Phase 4F) gains a fifth and final rule for this phase -- a detector an administrator has disabled that had real matches recorded in the week before (or up to) being switched off now surfaces a suggestion to confirm that was deliberate, since a disabled detector is never evaluated at all going forward.

= 2.9.105 =

* Added: Recommendations Engine (Phase 4F) gains the same enforce-readiness suggestion for Cross-Origin-Opener-Policy and Cross-Origin-Embedder-Policy -- the two other header pillars with their own report-only learning mode -- as CSP already had: report-only, no violations for 30 days, and no deliberate exception recorded, now suggests promoting that surface to Enforce.

= 2.9.104 =

* Added: Recommendations Engine (Phase 4F) gains a fourth rule -- a report-only Content Security Policy surface that's stayed quiet (no violations) for 30 days, with no deliberate exception recorded against it, now suggests promoting that surface to Enforce.

= 2.9.103 =

* Added: Recommendations Engine (Phase 4F) gains its first three rules -- certificate renewal due, unexplained high/critical-risk configuration drift, and exceptions expiring soon. Each reuses evidence this plugin already collects (no new data source), links straight to where to act on it, and explains why it matters and what to do instead if the suggestion doesn't fit.

= 2.9.102 =

* Added: Recommendations Engine (Phase 4F) -- foundation increment. A new "Recommendations" tab on Settings/Overview, right after Security Health, for prioritised, evidence-backed suggestions drawn from what this plugin already observes. Nothing is ever applied automatically; every suggestion links to where to act on it, and can be dismissed with a reason until the underlying evidence actually changes. This increment ships the engine and admin UI with no rules registered yet -- concrete rules (certificate renewal, unexplained drift, expiring exceptions, and more) land in the following increments.

= 2.9.101 =

* Added: Continuous Intelligence's bot/crawler classification gains a "repeated errors" signal (Phase 4C carried-forward item, the second and last of the two named alongside "timing") -- an unrecognised source whose recent requests were disproportionately HTTP errors (most often 404) is now classified as "Error probing (repeated 4xx/5xx)" on the Identities tab, the classic signature of a scanner probing for paths that don't exist or aren't allowed. Independent of enumeration and timing -- a source can be flagged for any of the three without the others.

= 2.9.100 =

* Added: Continuous Intelligence's bot/crawler classification gains a "timing" signal (Phase 4C carried-forward item) -- an unrecognised source whose last several requests arrived at a suspiciously uniform interval (a script sleeping a fixed duration between requests, rather than a person's naturally irregular browsing) is now classified as "Scripted timing (uniform request interval)" on the Identities tab. Independent of the existing sequential-path-enumeration signal -- a source can be flagged for one without needing the other.

= 2.9.99 =

* Added: Continuous Intelligence's Identities table now persists ASN and Geo-IP (country/region/city) directly on the identity record, not just as per-event evidence. This was a known gap: ASN/Geo-IP were already resolved and recorded against individual detector findings, but never merged onto the identity itself. Populated only when that resolution was already happening anyway (a detector already found something on that request), so this adds no extra cost to ordinary traffic -- a repeat source's identity fills in the network details over time as it keeps triggering findings.
* Fixed: a real bug found in live testing, not shipped before release -- WordPress's own `wpdb::prepare()` doesn't preserve a blank value as a true database NULL for number/text placeholders, so the first version of this feature's "don't overwrite what we already know" logic could have reset a source's ASN back to blank on a later request with no new data. Fixed before release.

= 2.9.98 =

* Added: a new "Getting Started" tab on Settings/Overview -- a short, suggested-order checklist for a new install (Configure CSP, turn on the other header pillars, review Traffic Controls, capture a security baseline, issue a free TLS certificate). Each step shows a live status pulled straight from the actual configuration, not a static list, and nothing here is required or enforced -- skipping a step or doing them in a different order doesn't break anything. Completes the Phase 4G UI documentation retrofit.

= 2.9.97 =

* Added: the public GitHub Pages help site's user guide and FAQ now explain what Content Security Policy actually defends against -- cross-site scripting -- rather than only describing configuration mechanics. The FAQ's most-read general answers (what the plugin does, why enforce mode can break a site, whether wp-admin is safe to enforce, what "high risk" means, whether reports can be spoofed, caching-plugin compatibility, and more) each gained a concrete consequence, not just a restated fact. Completes the Phase 4G UI documentation retrofit's public-docs track.

= 2.9.96 =

* Added: the Phase 4G UI documentation retrofit now covers every remaining admin page -- all 14 pillar pages (X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Information Masking, Cache-Control, Permissions-Policy, HSTS, Reverse Tabnabbing, External Scripts, Internal Script Integrity, Cross-Origin-Resource-Policy, X-Permitted-Cross-Domain-Policies, Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy) plus Continuous Intelligence and Baseline & Drift. Certificates was reviewed and already met the bar, so it's unchanged.
* Two real, previously-undocumented gaps were surfaced while researching this: (1) Reverse Tabnabbing Protection and External Script Integrity share an exclusion gate that means their Admin/Login/Api toggles can be switched on but never actually take effect -- only Frontend is live for either; both pages now say so plainly. (2) Cross-Origin-Opener-Policy and Cross-Origin-Embedder-Policy ship pre-enabled in Enforce mode on every surface, but at the specification's no-op `unsafe-none` value -- enough to satisfy a scanner checking for the header's presence, but genuinely isolating anything requires deliberately choosing a stronger value; both pages now explain this rather than leaving an administrator to wonder why "enabled" seems to do nothing.
* No behaviour change anywhere in this release -- explainer copy only.

= 2.9.95 =

* Fixed: `.roadmap/phase4_plan.md`'s note on the Traffic Controls retrofit (v2.9.94) described this page's other recent growth (Network Intelligence's new ASN/Geo-IP/Well-Known-Files/Network-Rules sub-tabs) as "unrelated work" -- user-corrected: that work was explicitly requested, not unrelated, just not something this document's own increment list happened to track. Reworded to attribute it correctly. Documentation only, no behaviour change.

= 2.9.94 =

* Added: Traffic Controls (Policy, IP Rules, and Blocks tabs) gained the same guided explainer text already shipped for Settings/Overview and the CSP Dashboard -- what a surface's rate limit and Observe/Enforce mode actually do, what the Warn/Throttle/Temporary-block/Extended-block ladder means, what a CIDR range is and when to use Allow vs. Block, and what Release and Make Permanent actually change. The Network Intelligence, Detectors, and Custom Rules tabs already had this level of detail from when those features were built. No behaviour change.

= 2.9.93 =

* Added: a "Development Build" GitHub Actions workflow that publishes a rolling pre-release (tag `development-latest`, always overwritten) containing the same self-updating GitHub-channel ZIP a real release ships, rebuilt automatically on every merge to the `development` branch -- a stable, bookmarkable download for testing what's currently on `development` without a numbered release.

= 2.9.92 =

* Fixed: Baseline & Drift's Drift table had unsuitable column widths for its content -- Item and Actions are now pinned (140px/200px) and the rest size dynamically, with long item keys now wrapping at natural word boundaries instead of overflowing.
* Fixed: Advanced Intelligence's Campaigns tab asked for a reason twice (one box for Acknowledge/Dismiss, a second for Block Participants) -- now a single Reason field feeds whichever action you take. Added an info icon showing the actual currently-live participant IPs, and explanatory text stating the real detection criteria (10+ distinct IPs on the same detector/surface within 24 hours) so a block decision isn't made blind.
* Fixed: Continuous Intelligence's Events table still wrapped text unnecessarily in narrow viewports; widened the Detector column and collapsed the Family column to an em-dash whenever it's identical to the Detector (the case for the large majority of built-in detectors), which is what was crowding the table in the first place.

= 2.9.91 =

* Fixed: Traffic Controls' Network Intelligence sub-tabs (Tor Exit List, ASN Lookup, Geo-IP, Well-Known Files) displayed each summary as a tall, narrow, single-fact-per-row table capped at 600px wide. These now render as a compact row of stat boxes using the page's actual width, and the two remaining 600px caps on the Geo-IP sub-tab were removed to match. The Policy and Blocks tables' column widths and the Network Intelligence sub-tab navigation itself were already correct in this branch; only the still-narrow stat displays needed fixing.

= 2.9.90 =

* Added: 10 more built-in crawlers to the Continuous Intelligence vendor catalogue -- YandexBot, Baiduspider, DuckDuckBot, Applebot, Sogou web spider, SeznamBot, OAI-SearchBot, Amazonbot, DuckAssistBot, and Meta-ExternalAgent -- each verified against the vendor's own current documentation (published IP range or reverse-DNS suffix; Meta-ExternalAgent recognition-only, since Meta publishes neither). New `docs/scanner-vendor-research.md`, linked from the Vendors tab, also catalogues researched commercial scanners (Qualys, Tenable, Detectify, and others) and monitoring/SEO bots (Ahrefs, UptimeRobot, and others) for administrators to add manually -- these are deliberately not seeded as built-ins, matching this catalogue's existing policy against hardcoding data that changes over time or vendors with no distinctive user agent.

= 2.9.89 =

* Fixed: the Continuous Intelligence Events, Identities, and Vendors tables (Settings/Overview) borrowed the CSP Violations table's column widths, which didn't match their own column layouts and caused severe text wrapping (detector/classification labels, dates, vendor names). Each table now has its own tuned column widths. The Identities "Reason" field is wider, the table now sorts by Occurrences descending by default, and a loopback identity (the server calling itself) is now auto-authorised rather than requiring a manual click -- an explicit Deny is still available if a site's reverse proxy makes that recognition wrong. The Vendors "Add a vendor" form is now a collapsible disclosure instead of always being shown in full.

= 2.9.88 =

* Added: the Security Health summary (Settings/Overview > Security Health, GitHub issue #175) now shows a per-surface CSP enforcement breakdown and distinguishes a surface not enforcing because of an active, administrator-recorded exception from one that simply hasn't been promoted yet, using the real Exceptions feature. The Exceptions row now also counts formal, time-bound exceptions alongside the existing signals it already tracked. The health model is now explicitly versioned (currently v2), shown on the Health tab.

= 2.9.87 =

* Added: a per-provider DNS-01 setup guide covering all 41 built-in DNS providers (GitHub issue #291) -- credential-creation links, minimum permission scopes, zone-scoping guidance, field-by-field mapping, rotation/revocation steps, and common errors for each, researched directly against each provider's own current documentation with any unconfirmed detail explicitly flagged rather than guessed. New "View setup instructions" link on the Certificates page next to the provider picker.

= 2.9.86 =

* Added: the Evidence Export (Settings/Overview, GitHub issue #178) now includes a SHA-256 checksum so later alteration can be detected, an optional reporting-period date range narrowing the recent-audit-history section, and a new "formal exceptions" section reading the Exceptions feature's own records. Framework mappings (Cyber Essentials, ISO/IEC 27001, PCI DSS, OWASP ASVS, CIS Controls) were already complete.

= 2.9.85 =

* Added: configuration snapshots (Settings/Overview > Recovery, GitHub issue #180) now also cover time-bound exceptions and the automation-posture setting, alongside the policy/source/pillar/dependency/certificate tables they already covered. Each restorable snapshot now has a "Preview what this would overwrite" disclosure showing row counts and included options before you confirm, and a restore that can't fully complete (a table in the snapshot missing from the live database) is now reported as a partial restore rather than an unqualified success.

= 2.9.84 =

* Added: promoting a CSP surface to enforce mode now requires a written reason (GitHub issue #179), and passes three more automated checks before it's allowed: no active exception covering that surface (see the new Exceptions tab), no source candidates still awaiting an approve/reject decision, and no competing Content-Security-Policy header detected in the last 48 hours. Existing checks (approved sources/hashes present, no recent violations) are unchanged.

= 2.9.83 =

* Added: Exceptions (Settings/Overview > Exceptions, GitHub issue #177) -- record a controlled, time-bound weakening of a control or surface (a legacy integration, a third-party embed) as an auditable exception instead of a silent override. Requires a business justification and an owner; requires an expiry date unless a privileged override is used. A daily check automatically returns an exception to review once it expires, and emails the configured admin address as one approaches expiry. Every creation, extension, and revocation is written to the audit log.

= 2.9.82 =

* Fixed: three release-verification test gaps closed (GitHub issue #159) -- a dedicated test now covers the update checker's HTTPS-only package URL rule (previously only exercised indirectly by a path-traversal test), a missing or expired manifest cache entry correctly falls through to a fresh check instead of being treated as a result, and a cached manifest is honoured without an unnecessary re-fetch.

= 2.9.81 =

* Fixed: `code-review-findings.json`'s 10 retained findings had no disposition metadata even though most had already been resolved by later issues (GitHub issue #164) -- each entry now records whether it's resolved (and by which issue) or was fixed directly in this release. Also closed the two findings that were still genuinely open: the test bootstrap's autoloader is now registered immediately before the stubs that need it, closing the window where a stub could be silently bypassed, and an unresolvable test class now throws immediately instead of only logging a notice PHPUnit doesn't fail on by default.

= 2.9.80 =

* Fixed: the CSP dashboard queried the policy-profiles, last-50-violations, and scan-log tables unconditionally on every page load regardless of which tab was open (GitHub issue #166) -- viewing e.g. Settings or Start Here still fired three unneeded queries. Profiles and violations queries are now scoped to only the tabs that actually use them; the scan-log query is scoped to the Scan Log tab.

= 2.9.79 =

* Fixed: a customer's WP Engine site suffered PHP-FPM worker pool exhaustion (two outages in one morning) because the CSP violation-report endpoint had no request-level throttle and the default reporting transport (report-uri) fires one immediate, unbatched HTTP request per browser-side violation. The default reporting transport is now "both" (report-uri retained as a fallback, report-to added so supporting browsers batch delivery instead); existing installs still on the untouched report-uri-only default are migrated automatically. The report endpoint also now rejects a flooding sender with a 429 before any request body is parsed or written to the database, separate from and tighter than the existing hourly per-surface storage cap.

= 2.9.78 =

* Fixed: WordPress.org's SVN import warned (author/committer-only banner) that this section was truncated past its 5,000-word budget -- readme.txt had accumulated 69 version entries back to 2.9.9 (~6,300 words). Trimmed to the most recent 15 releases; the "Full changelog history" link below them already covers everything older via CHANGELOG.md. Added an automated test so this section approaching the word budget again is caught in CI, not by another SVN warning.

= 2.9.77 =

* Added: Traffic Controls tracks five more well-known files alongside robots.txt -- agents.txt, security.txt, humans.txt, ads.txt, and app-ads.txt -- each with its own daily-refreshed cache and a "Refresh Now" action; agents.txt also gets a Disallow-rule compliance detector, the same as robots.txt already had.
* Added: a Geo-IP country block/allow grid (Network Intelligence > Geo-IP) -- every country defaults to Allow, nothing changes until you click Save, and saving a change that would block the requesting administrator's own resolved country (with no covering IP-allow rule) is held behind an explicit "save anyway" confirmation instead of silently locking them out.
* Added: a Description column on the Detectors tab, and a tooltip explaining what "(fixed)" means next to an observe-only control action.
* Changed: the Policy tab is now a single compact table instead of four stacked forms; Network Intelligence is split into Tor/ASN/Geo-IP/Well-Known Files/Network Rules sub-tabs; several tabs no longer cap their own width unnecessarily.
* Changed: the About tab's "What this plugin covers" now mentions Traffic Controls & Network Intelligence and Advanced Intelligence, both previously missing entirely, and its built-in-detector count is computed live instead of a hardcoded number.
* Fixed: automatic rate-limit escalation could block a loopback address (127.0.0.1/::1) -- wp-cron's and Site Health's own loopback requests were landing in the Blocks list as if they were an attacker. An explicit administrator IP-block rule for a loopback address still applies.
* Fixed: the Geo-IP self-lockout check silently proceeded (no warning) whenever the Geo-IP lookup for the administrator's own IP failed, and only checked for an admin-surface IP-allow rule rather than the actual surface a block would apply to.
* Fixed: the short "tagline" description WordPress.org shows in plugin-directory search results and the "Add Plugins" install screen said nothing about file-integrity monitoring (Baseline & Drift) and described rate limiting as "traffic filtering". Updated to "Self-learning security headers, built-in attack detection and rate limiting, file-integrity monitoring, and free TLS certificates. No paywall." (142 characters).

= 2.9.76 =

* Fixed: the short "tagline" description WordPress.org shows in plugin-directory search results and the "Add Plugins" install screen (user-flagged from a live install) still said "Ten security headers that learn your site before enforcing" with no mention of Continuous Intelligence, traffic filtering, or Baseline & Drift -- all shipped since that line was written. Updated to "Security headers that learn before enforcing so nothing breaks, plus attack detection, traffic filtering, and free TLS certs. No paywall." (137 characters, within WordPress.org's ~150-character directory-tagline budget). Added an automated test so this line and the plugin header's own Description: field can't silently drift apart again.

= 2.9.75 =

* Fixed: `.github/workflows/wporg-deploy.yml`'s 24-hour "one submission per day" gate was documented as a WordPress.org platform requirement -- it isn't. An already-approved plugin's SVN commits go live immediately with no human review queue (that queue is specific to the initial plugin submission). Corrected the misleading comments and added an explicit `bypass_cadence_convention` manual-dispatch option so this team's own cadence convention can be skipped for one run when needed, without weakening the standing default. No plugin behaviour change.

= 2.9.74 =

* Added: real traffic-control filtering by Tor exit-node status, ASN, and country -- the missing half of Geo-IP/ASN/Tor awareness (previously evidence-only). Tor exit-node filtering is a new detector (works alongside the existing 19, enable/observe/enforce from the Detectors tab). ASN and country blocking are a new "Network Rules" list on Traffic Controls > Network Intelligence -- enter an ASN (e.g. AS15169) or a two-letter country code to block, and it's checked on every request alongside IP Rules. ASN/Geo-IP lookups stay off (zero added cost) until you add at least one rule; only Tor's exit-node check runs unconditionally, since it's a cheap local table lookup rather than a live query.

= 2.9.73 =

* Fixed: the Settings/Overview page's About tab had drifted badly behind the actual feature set -- it still described "nine further HTTP security headers" (now eleven -- Information Masking and Cache-Control shipped since that text was written) and never mentioned Continuous Intelligence (request observation, nineteen built-in attack detectors, bot/crawler recognition, custom fail2ban-style rules, traffic controls) or Baseline & Drift (file/theme/plugin change detection) at all, despite both being fully shipped features with their own admin pages. Rewrote the "What this plugin covers" and "The gap this fills" sections to reflect the current product.

Full changelog history: https://github.com/vcns/security-automation-manager/blob/main/CHANGELOG.md
