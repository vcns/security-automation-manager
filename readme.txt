=== VCNS Security Automation Manager ===
Contributors: vcnstech
Tags: security, csp, content security policy, hsts, ssl certificates
Requires at least: 6.4
Tested up to: 7.1
Requires PHP: 8.1
Stable tag: 2.9.22
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Roll out and enforce CSP, HSTS, X-Frame-Options headers with violation reports; free ACME/Let's Encrypt SSL/TLS certificate automation.

== Description ==

Security Automation Manager helps site owners roll out strict HTTP security headers safely and incrementally, instead of flipping them on and risking a broken, unusable site. Content Security Policy (CSP) is its most capable pillar: it discovers the scripts, styles, fonts, and other sources your site actually uses, proposes a policy from what it observes, runs that policy in report-only mode so violations surface without blocking anything, and only enforces once an administrator reviews and approves it. X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Strict-Transport-Security (HSTS), Cross-Origin-Resource-Policy (CORP), Cross-Origin-Opener-Policy (COOP), Cross-Origin-Embedder-Policy (COEP), and X-Permitted-Cross-Domain-Policies are simpler per-surface pillars alongside it. Reverse Tabnabbing Protection, External Scripts, and Internal Script Integrity (Subresource Integrity / SRI hashing) round it out as further protections that rewrite the rendered page itself rather than emit a header. Certificates is a separate, self-contained ACME v2 (Let's Encrypt) SSL/TLS certificate manager, unrelated to the header pillars beyond sharing the same admin and audit plumbing -- it issues and renews certificates automatically via HTTP-01 or DNS-01 domain validation (41 built-in DNS provider integrations, including Cloudflare, AWS Route 53, and Google Cloud DNS) and deploys them for you.

The CSP pillar provides per-surface profiles, nonce injection, source discovery, violation reporting, policy-change review, reason-required append-only audit records, policy history, readiness checks, and conflict detection for existing CSP emitters. Seven of the other pillars (X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Strict-Transport-Security, Cross-Origin-Resource-Policy, X-Permitted-Cross-Domain-Policies) are simple per-surface toggles/value pickers with no report-only mode, discovery workflow, or automation. The remaining two, Cross-Origin-Opener-Policy and Cross-Origin-Embedder-Policy, have a narrower report-only learning workflow of their own: a per-surface Disabled / Report-Only / Enforce mode and a Report-Only Evidence table populated by the browser Reporting API (Chromium-based browsers only, as of this writing). External Scripts follows the same report-first philosophy as CSP: a freshly discovered third-party origin is always unclassified, never blocked, until an administrator decides. Internal Script Integrity is unconditional once enabled for a surface -- there is nothing to classify, since the hash is always freshly computed from the exact file being served. Certificates issues and renews TLS certificates via ACME DNS-01 (41 built-in DNS-provider drivers) or HTTP-01 validation, with encrypted-at-rest credentials and private keys, and deploys them via cPanel, filesystem export, or manual download.

Every pillar, all rewrite protections, certificate management, and all CSP automation modes included in this package are free.

The WordPress.org edition is a complete free plugin with no subscription-locked functionality. VCNS also distributes a separate commercial edition that includes Fully Automatic mode and associated commercial services.

== External services ==

This WordPress.org build does not contact third-party services for plugin updates, licensing, checkout, telemetry, or remote product configuration.

GitHub release builds are published separately for administrators who install from GitHub rather than WordPress.org; this update check is never present in the WordPress.org-channel package (this code is physically absent from it, not merely inactive). The GitHub-channel ZIP checks https://vcns.github.io/wp-updates/security-automation-manager/update.json from administrator update contexts only, validates the advertised package host and SHA-256 checksum, and then lets WordPress perform the update. This manifest is VCNS's own infrastructure, not a third party; the request sends no personal or site-identifying data, only a plain HTTPS GET for a static, publicly-readable JSON file. Define WP_SAM_DISABLE_AUTO_UPDATE as true in wp-config.php to prevent background auto-updates for the GitHub-channel package.

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
* DNS Made Easy -- DigiCert, Inc. -- Terms: https://www.digicert.com/legal-repository -- Privacy: https://privacy.digicert.com/policies/en/?name=dns-network-security-products-privacy-notice
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
* INWX -- INWX GmbH -- Terms: https://www.inwx.com/en/aboutus/terms -- Privacy: https://www.inwx.com/en/aboutus/dataprotection
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
