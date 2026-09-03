=== VCNS Security Automation Manager ===
Contributors: vcnstech
Tags: security, csp, content security policy, hsts, ssl certificates
Requires at least: 6.4
Tested up to: 7.1
Requires PHP: 8.1
Stable tag: 2.9.63
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Ten security headers that learn your site before enforcing -- nothing breaks. Plus free automatic TLS certificates and script integrity. No paywall.

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

= 2.9.63 =

* Fixed: the External Scripts admin table's pagination never capped an out-of-range page number at the real last page (e.g. requesting page 9999 of a 3-page list rendered "Page 9999 of 3" instead of the last real page) -- every other paginated admin table in this plugin already clamped correctly; this was the one that didn't. Also added regression test coverage across all seven of this plugin's paginated admin tables (GitHub issue #167) confirming each one correctly caps out-of-range pages, preserves filters across a page change, and handles an empty result set without error.

= 2.9.62 =

* Internal: replaced Content-Security-Policy's protected, subclass-overridable database-loading methods with an explicit, constructor-injected `Policy_Data_Loader` collaborator (GitHub issue #170). No behaviour change for real WordPress sites -- confirmed live that CSP headers (nonces, approved hashes, approved sources, all directives) are still emitted exactly as before. This only affects internal architecture and the plugin's own test suite.

= 2.9.61 =

* Internal: improved the PHPUnit test suite's `wpdb::prepare()` stub (GitHub issue #169) to mirror real WordPress behaviour more closely -- `%f`/`%i` placeholder support, an argument-count mismatch now correctly returning null instead of silently mismatching, and confirmed LIKE-expression wildcard handling. No user-facing change; this only affects the plugin's own test suite.

= 2.9.60 =

* Added: Cache-Control, a new pillar (GitHub issue #221) with a named-preset Cache-Control value per surface (no-store; private, no-cache; public with a 5-minute or 1-hour max-age). Unlike every other pillar, this one is not enabled by default on any surface -- Cache-Control is a caching/performance decision, not a universal security default, and shipping it pre-enabled would risk silently changing a site's frontend caching behaviour on upgrade.
* Added: automatic conflict detection so this pillar never competes with an existing caching mechanism, per the issue's own explicit safety requirement. It disables itself (with a clear on-screen explanation) when a known caching plugin is detected (WP Rocket, W3 Total Cache, WP Super Cache, LiteSpeed Cache, WP Fastest Cache, Cache Enabler, SiteGround Speed Optimizer, WP-Optimize, or Breeze -- more can be added over time) or when an admin has acknowledged a CDN/edge cache is in front of the site (a manual acknowledgement, since a reverse proxy's own caching isn't observable from inside a single PHP request).

= 2.9.59 =

* Added: Information Masking, a new pillar (GitHub issue #220) removing headers that disclose the server stack, PHP version, or this site's own hostname -- X-Powered-By (PHP version), Server (web-server signature), and X-Pingback (this site's own xmlrpc.php URL). Per-surface enable toggle, same shape as X-Content-Type-Options; enabled on every surface by default, matching every other simple pillar. X-Powered-By and X-Pingback removal is always reliable; Server is best-effort -- many hosts set it at the web-server layer before PHP ever runs, a layer no WordPress plugin can reach. A new live readiness check (Information Masking admin page) probes this site's own front page and reports whether each header is actually absent, so that host-dependent limitation is visible rather than silently assumed to work.

= 2.9.58 =

* Added: robots.txt disallow-rule compliance, completing the robots.txt behaviour signal started in an earlier release. This site's own robots.txt is now fetched and cached daily (the same way a real crawler would read it), and a source already recognised as a known crawler or scanner vendor requesting a path it disallows is now recorded as evidence. An ordinary, unrecognised visitor is never evaluated against these rules -- robots.txt is a voluntary convention for automated crawlers, not something that applies to people. Like the other bot-classification signals, this can optionally be switched to Enforce on the Detectors tab; defaults to observation only.

= 2.9.57 =

* Added: Phase 4C of the roadmap, fifth increment -- URI-pattern recognition, closing the last of the three signals (identity, request-rate, URI-pattern) the roadmap calls for combining into bot classification. Every recognised source now has its last 10 request paths logged (visible as a hover tooltip on the Identities tab's Classification column -- directly answering "log the fact they're hitting the endpoint"). An unrecognised source whose recent paths show a consistent sequential-ID pattern (e.g. /product/101, /product/102, /product/103, /product/104) is now classified as "Enumerating" -- checked ahead of the existing rate-based signal, since a script walking IDs is worth flagging whether or not it has tripped a rate limit yet. A known crawler's own path history is never checked this way, since systematically walking a site's posts is normal, expected crawler behaviour.

= 2.9.56 =

* Added: Phase 4C of the roadmap, fourth increment -- session/cookie behaviour and header-consistency signals. A login attempt (POST to wp-login.php) that never carries back the wordpress_test_cookie WordPress itself sets when rendering the login form is now recorded as evidence -- consistent with scripted credential-stuffing that posts straight to the login handler rather than a real browser that loaded the form first. Separately, a request whose User-Agent claims a specific, versioned browser (Chrome, Firefox, Edge, or Safari) but sends no Accept-Language header at all -- something every mainstream browser always sends -- is also now recorded, since that's a stronger signal of a copy-pasted User-Agent than an actual browser. Both default to observation only, like every other detector.

= 2.9.55 =

* Added: Phase 4C of the roadmap, third increment -- robots.txt visit recognition, the first piece of robots.txt-behaviour tracking. A source examining robots.txt is now recorded as its own low-severity, observation-only evidence, correlatable by IP against everything else this plugin already knows about that source (its identity, its bot classification). Checking whether a source goes on to actually respect what robots.txt disallows is a bigger piece not yet built.

= 2.9.54 =

* Added: Phase 4C of the roadmap, second increment -- bot/crawler classification that avoids a binary "bot or not" model. The Identities tab now shows a Classification column combining what's already known about each source: an explicit admin decision always wins if one exists; otherwise a recognised vendor is split into "Verified crawler" (matches the vendor's own published network data) versus "Claimed crawler (unverified)" -- a real impersonation signal, since claiming to be Googlebot without matching Google's network is worth noticing; an unrecognised source is split into "Aggressive / rate-escalated" versus plain "Unclassified" depending on whether it's actually triggered progressive rate-limiting. Nothing new is written to the database -- purely a read-time view over evidence this plugin already records.

= 2.9.53 =

* Added: HTTP Method Intelligence -- OPTIONS requests are now classified instead of treated as reconnaissance by default. A genuine browser CORS preflight (carrying both an Origin header and an Access-Control-Request-Method header, exactly as the Fetch/CORS spec defines) is recorded as low-severity, confirmed-expected evidence; an OPTIONS request missing that pair is recorded separately at medium severity, since it could be legitimate API-discovery tooling or reconnaissance -- headers alone can't tell those apart. Like HTML Injection and Legacy WordPress Endpoints, this can optionally be switched to Enforce on the Detectors tab; defaults to observation only.

= 2.9.52 =

* Added: Phase 4C of the roadmap, first increment -- AI crawler recognition. The built-in scanner/crawler catalogue now also includes GPTBot (OpenAI), ClaudeBot (Anthropic), CCBot (Common Crawl), and PerplexityBot, verified against each vendor's own current published documentation the same way Googlebot/Bingbot already are: CCBot by forward-confirmed reverse DNS, the other three by their vendor's published IP-range list (no IP ranges are hardcoded -- add current ones from the linked source via the existing Scanner Vendors admin page if you want IP-match verification too).

= 2.9.51 =

* Added: Phase 4B of the roadmap, fourth and final increment -- a thirteenth detector family, Legacy WordPress Endpoints, recognising requests to xmlrpc.php (still legitimate in some setups, but also a common pingback-SSRF and credential-stuffing target), wp-trackback.php, and the long-removed wp-app.php. Per the roadmap's own requirement that "RPC/XML-RPC controls must be configurable rather than assumed universally safe to block," this is the second detector (after HTML Injection) that can be switched to Enforce on the Detectors tab -- still defaults to observation only. This completes Phase 4B: all 13 detector families are now registered, and the control-action framework is fully wired.
* Fixed: request observation now also runs on WordPress's `init` hook, alongside the existing send_headers/login_init/wp_redirect coverage. xmlrpc.php (and wp-cron.php) bootstrap WordPress directly and never fire send_headers, so without this fix they were invisible to every detector -- found while verifying the new Legacy Endpoints detector against a real site, not merely in the test suite.

= 2.9.50 =

* Added: Phase 4B of the roadmap, third increment -- a twelfth detector family, PHP and PHPUnit Probes. Recognises specific, well-known vulnerability signatures: the PHPUnit eval-stdin.php remote code execution path (CVE-2017-9841), an exposed phpinfo()-style diagnostic script, the Laravel Ignition debug RCE path (CVE-2021-3129), the old php-cgi argument-injection query string (CVE-2012-1823), and a Symfony profiler path -- none of which are ever legitimate on a WordPress install. Defaults to observation only, same as every detector not explicitly opted into blocking.

= 2.9.49 =

* Added: Phase 4B of the roadmap, second increment -- an eleventh detector family, HTML Injection. Recognises suspicious markup in a request (script tags, image/SVG/body tags carrying an onerror/onload/onclick handler, an iframe, a javascript: link, and similar), while staying deliberately careful not to flag ordinary text containing "<" or the word "on...". Like every other detector, it defaults to observation only -- but unlike most, it can optionally be switched to Enforce on the new Detectors tab, since a legitimate endpoint that's known not to accept HTML can safely treat a match more strictly.

= 2.9.48 =

* Added: Phase 4B of the roadmap, first increment -- the control-action framework. Every detector family can now be individually enabled or disabled, and (where the family allows it) switched from pure observation to also feeding the same progressive-response blocking ladder rate limiting and login-brute-force protection already use, still gated behind that surface's own Observe/Enforce mode. New "Detectors" tab on the Traffic Controls page. Nothing changes for any existing install unless you explicitly opt a detector into enforcement -- every detector still defaults to observation only.

= 2.9.47 =

* Added: Phase 4A of the roadmap, third and final increment (Geo-IP Controls) -- an opt-in feature using your own IPinfo (ipinfo.io) account, never a shared VCNS credential. Disabled until you add a token on the Network Intelligence tab; the token is encrypted at rest using the same mechanism already protecting certificate and DNS-provider credentials. Once enabled, evidence a detector already produced now also notes the source's country, region, and city. A "Look Up" tool lets you check any IP directly. MaxMind support was deliberately not built in this pass -- its free tier is a downloaded database, not a live lookup service, and adding it would mean this plugin's first external code dependency; that stays a separate future decision. This completes Phase 4A (Tor Awareness, ASN Controls, Geo-IP Controls).

= 2.9.46 =

* Added: Phase 4A of the roadmap, second increment (ASN Controls) -- the plugin can now resolve which network/organisation a source IP belongs to, using Team Cymru's free, unauthenticated ASN lookup service (no account needed). Results are cached for 30 days so the cost is only paid once per IP. Like Tor awareness, this is observation only -- when another detector already produces evidence for a request, that evidence now also notes the source's ASN and organisation name. The Network Intelligence tab gains a "Look Up" tool so you can check any IP's ASN directly; Geo-IP remains noted there as planned next.

= 2.9.45 =

* Added: Phase 4A of the roadmap (Tor Awareness) -- the plugin now recognises requests originating from a known Tor exit node, using the Tor Project's own public exit-node list (no account or API key needed, refreshed daily). This is observation only: Tor identity never implies malicious intent and nothing is blocked because of it. When another detector already produces evidence for a request, that evidence now also notes whether the source was a Tor exit node. A new "Network Intelligence" tab on the Traffic Controls page shows the current list status and a manual refresh option; ASN and Geo-IP are noted there as planned next.

= 2.9.44 =

* Added: Phase 3J of the roadmap -- Advanced Optional Intelligence, a new "Advanced Intelligence" page with four tabs. Campaigns correlates request-observation events into a possible coordinated campaign when many distinct source IPs trigger the same detector on the same surface -- observe/correlate/notify only; blocking every participant is a separate, explicit action requiring a reason. Honey Paths lets you configure decoy paths no legitimate visitor ever requests; disabled until you add one, and a hit is recorded exactly like any other detector finding, never served special content. Change Windows lets you declare an intentional change (an upgrade, a deployment) in progress, recording the current baseline as a rollback reference, then shows exactly what drifted while the window was open. Timeline merges site changes, security drift, and campaigns into one chronological, correlation-only view. Two new administrator-account signals (new admin account created, existing user granted the administrator role) now feed the same change history this correlates against.
* Added: an indexed `ip` column on the request-observation events table, needed for Campaign correlation to count distinct sources cheaply.

= 2.9.43 =

* Added: Phase 3I of the roadmap -- Assurance and Reporting. A new "Security Health" tab on the Settings page gives a plain-language, non-gamified summary of security outcomes -- enforcement posture, open drift, certificate expiry, unclassified third-party dependencies, active exceptions, automation posture, and evidence freshness -- so you can see "what's the state of my security controls?" without opening every individual page. An "Evidence Export" downloads a JSON snapshot of currently-configured controls, open exceptions, certificate state, baseline/drift status, and recent audit history, useful for a security review, an MSP report, or audit preparation -- it explicitly documents this as evidence to support a review, never a compliance certification.

= 2.9.42 =

* Added: Phase 3F of the roadmap -- Baseline and Drift. Capture an approved snapshot of this site's locally-known configuration (CSP headers, security header toggles, external dependency and internal-asset-integrity inventories, certificate state, and WordPress/theme/plugin versions) from the new Baseline & Drift page, then run scans to see exactly what changed since. Each difference is risk-classified, checked for a plausible (never claimed-causal) correlation with a recent plugin/theme/core change, and can be reviewed as expected, approved, or left open for investigation -- items that revert to match the baseline are marked resolved automatically. A real Change Log now tracks plugin/theme/core update history for this correlation, separate from the plugin's existing CSP-learning-window signal.

= 2.9.41 =

* Added: Phase 3E of the roadmap -- Traffic Controls. This plugin's first active request-blocking capability: per-surface rate limiting, a manual IP allow/block list, and progressive automatic escalation (warn -> throttle -> temporary block -> extended block), viewable and manageable from the new Traffic Controls page. Every surface starts in Observe mode -- nothing is ever blocked until you explicitly switch a surface to Enforce -- and an already-authenticated administrator is never blocked by automatic detection, only by an explicit IP block rule you add yourself. ASN and Geo-IP controls from the roadmap are deliberately deferred: this plugin has no verified network-intelligence data source for them yet.

= 2.9.40 =

* Added: Phase 3D of the roadmap -- Identity and Scanner Intelligence. A new Continuous Intelligence "Identities" tab shows every claimed identity resolved from real traffic (crawler/scanner recognition via User-Agent + optional published IP ranges), always kept structurally distinct from authorisation: a recognised source is never automatically treated as authorised, and only an explicit administrator decision (with a required reason) changes that. A new "Vendors" tab manages the known-identity catalogue, seeded with two built-in search crawlers (Googlebot, Bingbot) verified by forward-confirmed reverse DNS rather than a hardcoded IP range; administrators can add their own verified commercial scanner vendors, each requiring a source URL.

= 2.9.39 =

* Fixed: the CSP learning window (the bounded period after a "material change" during which newly-discovered hosts from real browser traffic get re-evaluated) only re-opened for plugin activations/deactivations/updates and post/page saves -- a theme update or a WordPress core update never reopened it, even though either can change the exact bytes of inline scripts/styles and the third-party hosts a page depends on just as much as a plugin update can. `Learning_Window::mark_upgrader_change()` (renamed from `mark_plugin_upgrader_change()`) now also recognises `'theme'` and `'core'` from `upgrader_process_complete`.

= 2.9.38 =

* Changed: the Settings Overview table now shows CSP's per-surface automation posture on the Layer 2 (Controlled Automation) row, where it belongs, instead of a placeholder pointing down at Layer 4. Layer 4's "Automation" column is removed -- CSP was the only pillar that ever populated it, every other row showed a blank dash.

= 2.9.37 =

* Added: Phase 3A of the roadmap's primary-navigation redesign -- four new plain-language lifecycle pages (Observe, Decide, Control, Verify) under Security Automation Manager, each linking to the relevant existing pages/tabs with an explanation of what that stage means, honest about what's not built yet (no traffic-blocking capability exists; no external verification service exists yet).
* Changed: the left-hand admin menu now shows Observe, Decide, Control, Verify, and Settings (renamed from Overview) as the primary entries. Certificates, Continuous Intelligence, Cross-Origin Policies, CSP, HSTS, Permissions-Policy, Referrer-Policy, Reverse Tabnabbing, Scripts, X-Content-Type-Options, and X-Frame-Options remain fully accessible at their existing URLs as drill-down pages; only their left-nav entries moved.

= 2.9.36 =

* Added: Phase 3C of `.roadmap/phase3_early_plan.md` -- ten deterministic detector families for the Continuous Intelligence framework introduced in 2.9.35: technology mismatch, command injection, SQL injection, sensitive-directory probing, sensitive-file probing, setup/install probes, script/web-shell probes, protocol injection, version-control artefacts, and vulnerability probes. Every rule is Observe-only (nothing is blocked), reconnaissance-scoped, and specifically designed to stay quiet on ordinary WordPress traffic -- pattern matching was reviewed against real false-positive cases (a legitimate site search, a plugin's own changelog file, ordinary `?cat=`/`?id=` query variables) before shipping. Findings now populate the "Continuous Intelligence" admin page introduced in 2.9.35.

= 2.9.35 =

* Added: Phase 3B of `.roadmap/phase3_early_plan.md` -- the Request Observation Framework. Every request (frontend, admin, login, and REST API) is now observed and classified by surface, laying the foundation for future traffic intelligence. This release ships the observation skeleton only: no detector is registered yet, so the new "Continuous Intelligence" admin page and its underlying event table stay empty, and nothing is written to them, until a detector exists in a future release to evaluate what's observed.

= 2.9.34 =

* Changed: the Overview tab's status table now shows all five protection layers (Governance and Operations, Controlled Automation, Continuous Intelligence, Browser Security Policies, Transport & Certificate Trust) as consistent tables with real links, instead of reducing three of them to a single sentence. Layer 1 now links directly to the Readiness/Recovery/Updates tabs with a real computed status for each; Layer 2 links to the CSP automation settings; Layer 3 is an honest placeholder, since it has no pillars until a future phase.

= 2.9.33 =

* No plugin functionality change -- release/CI pipeline change only (the WordPress.org SVN deploy now runs from its own separate `wporg-vX.Y.Z` tag instead of every version tag, so a routine GitHub release no longer implies a WordPress.org submission). This version exists only to produce a properly-tagged commit for that pipeline change to take effect from.

= 2.9.32 =

* Changed: rewrote the plugin's one-line description (plugin header and the top of this readme) to actually cover what the plugin does, its breadth, and the free/no-paywall promise -- the previous line only mentioned CSP and TLS certificates and left out the other eight headers and script integrity entirely.

= 2.9.31 =

* Added: the Overview tab's pillar status table is now grouped by protection layer -- "Layer 4: Browser Security Policies" (CSP and the other twelve header/content-rewrite pillars) and "Layer 5: Transport & Certificate Trust" (Certificates, which previously had no row in this table at all). Each pillar now shows one of four consistent states per surface -- Not configured, Disabled, Report-only, or Active -- instead of a plain On/Off that couldn't tell "never touched" apart from "deliberately turned off". CSP's own automation posture (Manual / Automatic...) is now shown alongside its status.
* Changed: internal only -- the pillar list this table renders from is now a single registry class (`Pillar_Registry`) instead of a hand-maintained array that had already drifted out of sync with the plugin's actual install-time defaults.

= 2.9.30 =

* Changed: replaced the WordPress.org listing icon and banner. The previous design used an invented shield mark and an amber accent colour with no connection to VCNS's actual brand, and only mentioned CSP/HSTS/SSL-TLS -- a fraction of what the plugin actually does. The new artwork uses VCNS's real cloud-and-circuit mark and brand gradient (teal to cyan), and calls out the full scope: 10 security headers, automatic TLS via ACME, and script/content integrity protections.

= 2.9.29 =

* Added: a persistent admin notice on every wp-admin page (not just the Certificates page) when the most recent ACME certificate issuance or renewal failed -- a failed WP-Cron renewal could previously go unnoticed until the certificate actually expired. The existing "Last run" row on Certificates > Issue/Renew is now colour-coded (red for failed, green for success) so it's unmistakable when you're already looking at it.
* Fixed: the public help site (docs/) referenced seven screenshot filenames that never existed, showing as broken images since the site first went live. Replaced them with the real screenshots, and added several more to sections that already describe a feature but never illustrated it (X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Strict-Transport-Security, Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy, Reverse Tabnabbing, and both Scripts tabs).

= 2.9.28 =

* Fixed: the WordPress.org listing icon/banner from 2.9.27 deployed one directory too deep and never actually showed up -- corrected the path, and removed two stray files (an old build zip and an internal draft) that had been live on the public listing since before this plugin's approval.
* Fixed: same dropdown-width issue as 2.9.27's Permissions-Policy fix, on Referrer-Policy's "unsafe-url" option -- shortened the label, moved the full explanation to the page's own description text.
* Fixed: the Scripts > Internal Hash Inventory table had the same uneven column-width problem as the For Review table -- URL and Hash now get proportionally more room.

= 2.9.27 =

* Added: a plugin icon and header banner for the WordPress.org listing.
* Changed: rewrote the plugin description to lead with what the plugin actually does for you, instead of a feature inventory -- the full technical detail is still there, just further down.
* Fixed: the For Review table's columns were sized evenly regardless of content, forcing long hostnames to wrap mid-word; Host now gets proportionally more room.
* Fixed: Permissions-Policy directive dropdowns were stretched wide by one long option's description text ("All -- any origin, including third-party iframes and embeds (not recommended)"). Options are now short labels; the fuller explanation moved to the page's existing description text below the table.

= 2.9.26 =

* No plugin functionality change -- release/CI pipeline fix only (the WordPress.org SVN deploy workflow was missing the `svn` CLI on its runner). This version exists only to produce a properly-tagged commit for that pipeline to deploy from.

= 2.9.25 =

* Added: commonly-recognised third-party domains (Google Analytics, Google Tag Manager, Google Fonts, YouTube, Gravatar, jQuery/jsDelivr/cdnjs CDNs, and others) now show a "Known" badge on the CSP Sources table, with the recognised service named on hover -- display only, extensible via the wp_sam_known_source_labels filter, never affects risk scoring or auto-approval.

= 2.9.24 =

* Fixed: made the DNS Made Easy, INWX, and GitHub Pages external-service disclosures below explicit about why their linked Terms/Privacy documents are hosted on a different domain than the API/service hostname itself (dnsmadeeasy.com and domrobot.com have no legal pages of their own; github.io has none separate from github.com) -- an automated domain-matching check couldn't associate the two without this stated directly.

= 2.9.23 =

* Fixed: added the literal API hostnames (`api.dnsmadeeasy.com`, `api.domrobot.com`) to the DNS Made Easy and INWX external-service disclosures below, alongside the entities that already govern them, so automated domain-disclosure checks can match them directly.
* Fixed: added GitHub's own Terms of Service and Privacy Statement links to the GitHub-channel update-manifest disclosure below, covering the hosting infrastructure (GitHub Pages) itself.
* Hardening: documented the intentional cross-hook output-buffer lifecycle in `Content_Rewriter::maybe_start_buffer()` with an inline comment, for reviewers checking that every `ob_start()` is paired with a closing call.

= 2.9.22 =

* Fixed: reworded a help paragraph on the Scripts page that literally contained the text `<link rel="stylesheet">` as prose, which an automated scanner misread as an actual unregistered stylesheet tag.
* Hardening: added explicit `phpcs:ignore` annotations to ~80 ACME/DNS-provider exception messages built from interpolated values (domain names, API response bodies) that an automated scanner flags as unescaped output. These messages are never echoed -- only logged via the audit log or stored on the certificate record -- so this is a documented false positive, not a behavior change.

= 2.9.21 =

* Fixed: `_load_textdomain_just_in_time` "called incorrectly" notice appearing on WordPress 6.7+ on every request -- CSP automation mode registration (which translates each mode's label) now happens on `init` instead of earlier, on `plugins_loaded`.
* Hardening: DNS provider credential fields now sanitize non-secret values (account/zone name, endpoint host) rather than leaving them unslash-only; three `$_SERVER` reads already validated safe before use now also sanitize as defense-in-depth.
* Fixed: a stale DigitalOcean Terms of Service URL in the external-service disclosures section below.

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
