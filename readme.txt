=== VCNS Security Automation Manager ===
Contributors: vcnstech
Tags: security, csp, content security policy, hsts, ssl certificates
Requires at least: 6.4
Tested up to: 7.1
Requires PHP: 8.1
Stable tag: 2.12.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Self-learning security headers, built-in attack detection and rate limiting, file-integrity monitoring, and free TLS certificates. No paywall.

== Description ==

Turning on strict security headers usually means picking between two bad options: leave Content-Security-Policy off and stay exposed, or turn it on and watch it silently break your checkout page, your embedded videos, or your analytics -- with no warning before it happens.

Security Automation Manager takes a third option. It watches your site quietly first, in report-only mode, learning exactly which scripts, styles, and fonts your site actually loads -- nothing gets blocked while it learns. Once you can see the whole picture, you approve a policy built from your real site, not a guess. Only then does it start enforcing.

= You don't need to know what CSP means to use this =

The first time you open the plugin, a short, skippable Welcome page asks how you'd like security information explained to you -- nothing more. Answer it or skip it: either way, your Settings page then leads with a plain-language scorecard (how many controls are Protected, still Learning, or Needs your attention), a Protection Status table using six consistent words instead of protocol names, and a consolidated Action Centre for anything worth reviewing. Prefer the technical names and raw evidence instead? Choose Technical presentation and every detail is expanded by default. These are personal display preferences, stored per WordPress user -- they never change how your site is actually protected, and the full technical dashboards this plugin has always had remain exactly where they were.

= Everything below is free, with nothing held back =

* **Content Security Policy** that proposes itself from real traffic, runs report-only until you approve it, and keeps learning as your site changes.
* **HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy**, and five more security headers, each shipped with sane, hardened defaults.
* **Reverse tabnabbing protection, a third-party script inventory, and Subresource Integrity (SRI) hashing** for everything your site pulls in from elsewhere.
* **Free SSL/TLS certificates** via Let's Encrypt, issued and renewed automatically, with 41 built-in DNS providers for wildcard domains -- Cloudflare, AWS Route 53, and Google Cloud DNS among them.

The WordPress.org edition is a complete free plugin with no subscription-locked functionality. VCNS also distributes a separate commercial edition that includes Fully Automatic mode and associated commercial services.

= Built for the moment things go wrong, not just the moment you install it =

Every policy change is written to an append-only audit log, with a reason recorded. Conflict detection catches another plugin or your host quietly emitting a competing security header before it confuses you. Nothing enforces without a report-only learning period first, on every pillar that supports one.

= For the technically curious =

CSP ships per-surface profiles, nonce injection, source discovery, violation reporting, policy-change review, and readiness checks, alongside conflict detection for any CSP header already being emitted elsewhere. Nine more pillars (X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Information Masking, Cache-Control, Permissions-Policy, Strict-Transport-Security, Cross-Origin-Resource-Policy, X-Permitted-Cross-Domain-Policies) are straightforward per-surface toggles. Cross-Origin-Opener-Policy and Cross-Origin-Embedder-Policy get their own lighter report-only workflow via the browser Reporting API (Chromium-based browsers only, as of this writing). Certificates issues and renews via ACME DNS-01 or HTTP-01 domain validation, with credentials and private keys encrypted at rest, deploying via cPanel, filesystem export, or manual download.

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

The Scripts page's External tab has a "Suggest" button, only triggered by an administrator explicitly clicking it, that fetches a URL the administrator themselves supplies (restricted to a third-party origin already observed on this site) and computes a Subresource Integrity hash from it, saving that hash immediately as the pinned value with no separate confirmation step. No content from that fetch is stored or sent anywhere else; only the computed hash is written to this site's own database. Once an administrator has pinned a third-party file by hash, the plugin also fetches that same file once a day from the origin it was pinned on (https only, a plain GET with no site data sent, at most 25 files per day) to check that its content still matches the pinned hash. Only the computed hash is kept; nothing is fetched for origins that have not been pinned.

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

= 2.12.0 =

* Fixed: Content Security Policy violation reports from your WordPress dashboard (the admin surface) were being turned away. The report endpoint's flood guard gave each IP address one shared allowance for every part of the site, and dashboard pages still being learned send many reports per visit, so staff browsing from one office address used it up. Admin and login reports now have their own allowance, and the Violations tab shows each surface separately: how many violations, when it last reported, when its policy was last sent, and whether any reports were turned away.
* Fixed: a slow, steady source of requests -- your own scheduled tasks, an uptime monitor, an office behind one address -- could be rate-limited for exceeding a per-minute limit it never reached in any single minute. Each limit's count now starts afresh when its time window ends. Logged-in administrators no longer use up their address's allowance, and a source that has gone quiet steps back down one block stage per quiet hour. A persistent block you set stays until you release it.
* Fixed: hashes learned from JSON-LD and other JSON data blocks before 2.11.3 are retired automatically on the next scan, freeing room in the policy for the hashes your real inline scripts need.
* Fixed: the Geo-IP Country Block List shows every country at once, instead of hiding most of them behind a sideways scrollbar.
* Fixed: when something outside the plugin, such as an IP allow-list in .htaccess, sends your site's own requests to itself elsewhere, the daily pinned-script check no longer checks the wrong page. SAM now says it couldn't check, explains what to allow so these requests get through, and never records where they were sent.
* Fixed: help text on Control → Traffic Controls uses the page's full width.
* Added: SAM now notices when a vendor changes a script you pinned by hash. A daily check re-fetches each pinned file and compares it with the approved hash. A change raises an Action Centre item and a notice, and Decide → Dependency Classification offers "Re-approve new hash" or "Allow by host instead" in one click.
* Added: Google Tag Manager, Google Analytics, HubSpot, Cloudflare Turnstile and reCAPTCHA are recognised as frequently-updated vendors, shown as "allowed by host, not hash" with the reason.
* Added: Control → Traffic Controls → Network Intelligence → Geo-IP: the Country Block List can tick or untick countries by group -- UN M49 continents and regions, the EU and EEA, and UK and US (OFAC) sanctions snapshots, each with its source and date. Every country stays individually editable, and nothing changes until you save.
* Added: Control → Traffic Controls → IP Rules → This site's own addresses. List the public addresses your own servers use to reach the site, and they're treated like your private network: never rate-limited, escalated or counted into campaigns. SAM suggests addresses it has seen calling wp-cron.php for you to check, and never adds them itself.
* Added: the Geo-IP country groups now include sanctions lists from the UN, the EU, Switzerland, Liechtenstein, Norway, Iceland, Canada, Australia, New Zealand, Japan, South Korea, Singapore, Taiwan and Ukraine, plus every country with a US OFAC program. A new "Where does this website operate?" choice shows only the lists that apply there.
* Changed: the Settings home page now shows only the summary (scorecard, recent activity, protection status and Action Centre). The per-layer status tables have moved, unchanged, to a new Settings → All tab.
* Changed: the Plugins screen in wp-admin lists the plugin as "Security Automation Manager".

= 2.11.6 =

* Fixed: requests from your own hosting network -- this server reaching itself through an internal address, a sibling container, a load balancer or a health check (private addresses such as 10.x, 172.16-31.x and 192.168.x) -- are no longer rate-limited, escalated or blocked automatically, and no longer count toward campaigns. Previously the plugin could block your own site's scheduled tasks. An IP block rule you add yourself still applies.
* Improved: on Observe → Continuous Intelligence → Identities, a source's recent requests now group repeated paths with a count (for example "/wp-cron.php ×9") instead of listing the same path again and again.

= 2.11.5 =

* Security: closed a way for a visitor to slip past Traffic Controls (rate limits and IP blocks) and go unrecorded by the attack detectors by sending a particular request header. Updating is recommended.
* Fixed: the Advanced Intelligence page loaded without the plugin's styles and scripts. Its info pop-ups all showed at once, stacked down the page, and the Campaigns Acknowledge, Dismiss and Block buttons did nothing.
* Fixed: info pop-ups across the plugin's screens could show their text in the wrong font or be cut off at the bottom of a table.
* Changed: Advanced Intelligence is no longer a separate menu item. Each of its sections now sits with the step it belongs to: Timeline under Observe, Campaigns under Decide, Honey Paths under Control, and Change Windows under Verify.
* Improved: plugin notices now include a link to the place where you can act on them, and messages that point you somewhere now name the menu route (for example "Decide → Dependency Classification").

= 2.11.4 =

* Fixed: the Content Security Policy for your WordPress dashboard (the admin surface) is now actually sent. Earlier versions never delivered it on ordinary dashboard pages, so "no violations reported" there meant nothing. If your admin policy was set to Enforce, it has been moved back to Report-only once, so you can review its real reports before promoting it again.
* Fixed: "Promote this surface to Enforce" is now only suggested when the plugin has evidence that the policy was actually being sent for the whole 30 days, and wasn't having to drop learned approvals to stay within its size limit. Expect no such suggestions for the first 30 days after updating while that evidence builds up.
* Changed: the REST API is no longer treated as a Content Security Policy surface you review and promote. API responses (JSON) never load scripts, styles or images, so there was nothing to learn there; they now get a fixed, locked-down policy instead, and the API surface no longer appears on the CSP screens.

= 2.11.3 =

* Fixed: the daily checks of this site's own robots.txt, agents.txt, security.txt, humans.txt, ads.txt and app-ads.txt, and the security-header discovery scan, no longer follow a redirect to a different website. Previously, on a site that redirects some visitors elsewhere (for example a staging site that sends unknown visitors to the live site), the plugin could read the other site's files and pages and report them as this site's own.
* Fixed: a site that simply doesn't have one of those optional files is now recorded as "Absent" instead of raising a daily "refresh failed" warning.
* Fixed: a discovery scan refused by a firewall or login protection is now logged quietly instead of raising an admin warning.
* Fixed: plugin admin notices are now shown only to administrators. Previously any logged-in user who could reach the dashboard could see them, and seeing them cleared them before an administrator did.
* Fixed: Content Security Policy hash learning no longer records JSON-LD structured data (such as SEO schema markup), which browsers never run and CSP doesn't control. On sites with many pages these filled the policy's size budget and could push out the approvals real inline scripts need.
* Fixed: an inline script that directly follows an external script tag is now recognised and approved correctly.
* Fixed: hashes for inline style attributes are no longer sent in the policy unless they can take effect, so they no longer use up the policy's size budget. A manual rescan now also retires approvals unused for 30 days.
* Improved: Advanced Intelligence → Campaigns now shows how many IPs are active in the last 24 hours separately from the count recorded when the campaign was detected, and marks your own IP in the list.
* Fixed: blocking a campaign's participants no longer includes your own IP or the site's own loopback address, so it can't lock you out of your dashboard. The button now says how many IPs it will block.

= 2.11.2 =

* Documentation only, no functional change from 2.11.1. Corrected the pillar count and pillar list on this page and in the bundled documentation: Information Masking and Cache-Control were missing from several lists, which made the counts disagree with each other and with the plugin itself.

= 2.11.1 =

* No functional change from 2.11.0 -- republished under the correct release-branch naming so this version could be published to WordPress.org (2.11.0's release branch was misnamed and didn't satisfy the deploy pipeline's release-provenance check, a deliberate safeguard against publishing from an untracked branch).

= 2.11.0 =

* Rolled out a consistent table layout standard across every admin screen -- CSP dashboard, Overview/Settings, Scripts, Certificates, Cross-Origin Policies, Information Masking, Traffic Controls, Baseline & Drift, and Continuous/Advanced Intelligence -- replacing per-page, hand-tuned column widths (which drifted out of sync whenever a table gained or lost a column) with one shared, self-adjusting layout.
* Purely a presentation change: no security behaviour, stored data, or admin action was altered.

= 2.10.1 =

* Fixed: a first-time WordPress user could be redirected to the new Welcome page before ever seeing a persistent, must-see admin notice (the schema-downgrade warning, or a failed TLS certificate renewal) -- the redirect exited the request before those notices had a chance to render. The redirect now checks for either condition first and skips itself when one is present, so an urgent notice always reaches the administrator immediately.

= 2.10.0 =

* Added: Customer-Centred Administration Experience -- a presentation layer over existing capability, not a change to how the site is protected. A skippable Welcome page collects four personal presentation preferences (relationship to the site, security familiarity, Simple/Balanced/Technical depth, and what to see first) stored per WordPress user; edit them anytime from the new "Personal Preferences" link on Settings/Observe/Decide/Control/Verify. Settings/Overview now leads with a factual Protected/Learning/Needs-attention scorecard and a Recent Activity strip (detections, currently blocked/rate-limited sources, and newly-detected configuration changes in the last 24 hours -- raw request volume is deliberately not shown, since no store in this plugin reliably counts it), followed by an outcome-oriented Protection Status table (Protected/Learning/Monitoring/Needs attention/Not in use/Unavailable, never colour alone) and a new consolidated Action Centre tab gathering everything needing review -- from the existing Recommendations Engine, the CSP source review queue, and unclassified dependencies -- into one What-was-found/Why-it-matters/Recommended-action/What-will-happen list, without duplicating any existing decision logic. Every section keeps a "Technical details" disclosure open by default for Technical-depth users and available (never hidden) for everyone else. No existing tab, page, or security decision changed.

= 2.9.107 =

* Security: removed the direct-Stripe checkout path from the commercial-only Fully Automatic upgrade extension (Stripe secret/price/webhook key storage and the checkout AJAX handler). This path was never functional in either public release channel and has no evidence of real customer use, but its plaintext-secret storage was flagged as an unmitigated finding in this project's own threat model. Any values from a previous private/commercial build are actively removed on upgrade. Fully Automatic mode remains registered as a product concept but is unreachable until a replacement entitlement source is built.

= 2.9.106 =

* Added: Recommendations Engine (Phase 4F) gains a fifth and final rule for this phase -- a detector an administrator has disabled that had real matches recorded in the week before (or up to) being switched off now surfaces a suggestion to confirm that was deliberate, since a disabled detector is never evaluated at all going forward.

= 2.9.105 =

* Added: Recommendations Engine (Phase 4F) gains the same enforce-readiness suggestion for Cross-Origin-Opener-Policy and Cross-Origin-Embedder-Policy -- the two other header pillars with their own report-only learning mode -- as CSP already had: report-only, no violations for 30 days, and no deliberate exception recorded, now suggests promoting that surface to Enforce.

= 2.9.104 =

* Added: Recommendations Engine (Phase 4F) gains a fourth rule -- a report-only Content Security Policy surface that's stayed quiet (no violations) for 30 days, with no deliberate exception recorded against it, now suggests promoting that surface to Enforce.

= 2.9.103 =

* Added: Recommendations Engine (Phase 4F) gains its first three rules -- certificate renewal due, unexplained high/critical-risk configuration drift, and exceptions expiring soon. Each reuses evidence this plugin already collects (no new data source), links straight to where to act on it, and explains why it matters and what to do instead if the suggestion doesn't fit.

Full changelog history: https://github.com/vcns/security-automation-manager/blob/main/CHANGELOG.md
