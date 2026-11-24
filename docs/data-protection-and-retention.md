# Data Protection and Retention Model

## Purpose

Deliverable #7 in the roadmap specification (§23) calls for a data-protection
and retention model. The specification's actual data-handling requirements are
scattered across §4.4 (entitlement data minimisation), §7.4 (external
verification privacy), §8.1 (evidence-pack disclosure), §14.3 (webhook/SIEM
data), §16.3 (config-as-code export), and §20 (general security/privacy
requirements). This document consolidates those into one place: what data this
plugin collects, why, how long it's kept, and how it's deleted.

Resolves roadmap issue #155.

## What data this plugin collects today

All data below is stored in the site's own WordPress database (custom tables,
prefixed per the site's table prefix) or as WordPress options. What is sent
off-site, and when, is listed under "Data transmitted off-site" below and in
the External services section of `readme.txt`. The commercial build
additionally transmits data to Stripe as described below.

| Table / option | What it holds | Personal or site-identifying? | Retention | Deletion |
|---|---|---|---|---|
| `csp_violation_reports` | Browser-submitted CSP violation reports: blocked URI, document URI, referrer, user agent, up to ~40 characters of inline script/style content (`sample`) | Referrer and user-agent are visitor-supplied and client-generated (spoofable); no visitor IP address, cookie, or account identifier is stored | Auto-purged after `wp_sam_violation_retention_days` (default 90 days) by the daily cron scan; **can be set to `0`, which disables purging entirely - see gap below** | Deleted on plugin uninstall (table dropped); individually purgeable via the retention-days cron before that |
| `sam_pillar_violation_reports` | COOP/COEP violation reports, grouped per blocked resource | As for `csp_violation_reports` | Rows not seen for `wp_sam_violation_retention_days` days (default 90) are deleted by the daily cron | Deleted by the retention purge, Reset Plugin Data, and uninstall |
| `sam_request_events` | Continuous Intelligence detector matches: visitor IP address, request path and query, user agent, ASN and Geo-IP country/region/city | **Yes** - visitor IP addresses | Rows not seen for `wp_sam_violation_retention_days` days are deleted by the daily cron | Deleted by the retention purge, Reset Plugin Data, and uninstall |
| `sam_scanner_identities` | Claimed bot/scanner identities: visitor IP address, user agent, reverse-DNS hostname, recent paths and timings, ASN and Geo-IP location, and any administrator decision | **Yes** - visitor IP addresses | Rows not seen for `wp_sam_violation_retention_days` days are deleted by the daily cron, **except** identities an administrator authorised or denied, which are kept as decisions | Deleted by the retention purge (undecided rows), Reset Plugin Data, and uninstall |
| `sam_traffic_blocks` | Rate-limit and brute-force escalation state per visitor IP address | **Yes** - visitor IP addresses | Non-persistent rows not seen for 30 days are deleted by the daily cron; persistent blocks are an administrator decision and are kept | Deleted by the 30-day purge, Reset Plugin Data, and uninstall (releasing a block resets it to observe rather than deleting it) |
| `sam_asn_cache`, `sam_geoip_cache` | Per-IP ASN and Geo-IP lookup results | **Yes** - visitor IP addresses | Rows older than `wp_sam_violation_retention_days` days are deleted by the daily cron (lookups older than 30 days are already ignored) | Deleted by the retention purge, Reset Plugin Data, and uninstall |
| `csp_source_inventory`, `csp_hash_inventory` | Discovered external script/style sources and content hashes; owning plugin/theme where detectable | No | Indefinite (these are the plugin's working configuration, not transient logs) | Deleted on uninstall |
| `sam_scan_logs` | Scan execution history, diff summaries, warnings | No | Indefinite | Deleted on uninstall |
| `sam_entitlements` | `site_identity` (truncated SHA-256 hash of the site URL, not the raw URL), product tier, status, `stripe_customer_id`/`stripe_session_id`/`stripe_payment_intent_id` | The Stripe IDs are identifiers into VCNS's Stripe account, not personal data by themselves, but they are the key that lets whoever holds the Stripe secret key look up the associated billing/customer record at Stripe - see the threat-model note on why local storage of that key is the higher-severity problem | Indefinite (license/entitlement state) | Deleted on uninstall |
| `sam_processed_events` | Stripe webhook event IDs, session IDs, outcome | No | Indefinite (idempotency ledger) | Deleted on uninstall |
| `sam_audit_log` | Structured event log: component, event type, human-readable detail, severity, WordPress `user_id` of the admin who triggered the event | `user_id` is a local WordPress user reference | **Indefinite, append-only, no purge mechanism** - this is intentional (it's the permanent audit trail) but should be stated explicitly rather than left implicit | Deleted only on full plugin uninstall |
| `sam_policy_change_decisions`, `sam_policy_versions`, `sam_decision_rule_evaluations` | Policy change history and decision provenance | No | Indefinite | Deleted on uninstall |
| `wp_sam_stripe_secret_key_test`/`_live`, `wp_sam_webhook_secret` | Stripe API credentials (commercial build only) | Not personal data, but a high-value secret - see `docs/threat-model.md` "Entitlements and commercial control plane" and `docs/checkout-proxy-design.md` | Until manually rotated or the plugin is uninstalled | Deleted on uninstall |

**Retention setting.** `wp_sam_violation_retention_days` is set under Control →
Automation Settings → Data Retention (default 90, at most 3650). `0` still
means "never purge"; the settings page and Continuous Intelligence warn while
it is `0`, because visitor IP addresses, user agents and referrers then build
up indefinitely.

Before 2.16.0 the setting had no field, and saving Automation Settings stored
`0`, so on most sites nothing was purged. 2.16.0 puts a stored `0` back to 90
once (`Activator::migrate_repair_zeroed_retention()`, logged as
`retention_repaired`), and the setting's sanitizer now keeps the stored value
when a form posts the settings group without it.

## Data transmitted off-site

| Destination | What's sent | When | Purpose |
|---|---|---|---|
| Stripe (`api.stripe.com`) | Site identity hash, product key, plugin version (as Checkout Session metadata); no page content, no visitor data | Commercial build only, when an admin initiates a purchase | Payment processing |
| `vcns.github.io` (GitHub Pages) | Plugin slug and current version (implicit in the HTTPS request for the update manifest) | Every update check | Update manifest retrieval |
| Tor Project (`check.torproject.org`) | Nothing but the request itself; its User-Agent names WordPress, SAM, their versions and the site's address | Daily, and on Refresh Now | Download the public Tor exit list |
| Team Cymru (`origin.asn.cymru.com`, `asn.cymru.com`, DNS) | One IPv4 address (a visitor's or the administrator's) or one AS number per query | A detector flags a request; every request while an ASN/country rule exists; ASN Lookup; the ASN-rule self-lockout check. Kept 30 days per address | Find an address's network (ASN) |
| IPinfo (`ipinfo.io`) | One IP address and the administrator's own API token; User-Agent as for the Tor Project | Only once a token is saved: a detector flags a request; every request while an ASN/country rule exists; a Geo-IP tab lookup; the country-rule self-lockout check. Kept 30 days per address | Country, region and city for an address |
| Let's Encrypt, the chosen DNS-01 provider, a cPanel host | See `readme.txt` | Only when certificates are configured | Certificate issuance and installation |

Visitor IP addresses are sent off-site: Network Intelligence sends them to
Team Cymru and, once an administrator adds an IPinfo token, to IPinfo (above).
No violation reports, discovered sources or hashes are. That will change once
the external verification service (#182) and webhook/SIEM integrations (#183)
ship - see "Forward-looking requirements" below for what those must satisfy
before they do.

## §4.4 - Entitlement data minimisation

Current state: satisfied. `site_identity` is a truncated hash, not the raw
site URL; no additional site data is sent to Stripe beyond what's listed
above. This should be re-verified once the checkout-proxy (#172) changes what
travels between the WordPress install and VCNS infrastructure -
`docs/checkout-proxy-design.md` covers this explicitly.

## §7.4 - External verification service (not yet built, #182)

Before this ships, it must:

- [ ] Collect only the information required for verification.
- [ ] Avoid collecting page content unless explicitly required.
- [ ] Avoid collecting authentication credentials.
- [ ] Define a retention period for whatever it does collect.
- [ ] Support deletion on request.
- [ ] Authenticate site ownership before accepting a verification request for
      that site.
- [ ] Rate-limit scans per site.
- [ ] Record the scanner's identity in whatever result it returns.
- [ ] Clearly distinguish externally-verified data from locally-observed data
      wherever both are shown together (e.g. don't let an external scan
      result silently merge into the local violation-reports table as if it
      were the same kind of observation).

## §8.1 - Evidence pack export (not yet built, #178)

Before this ships, every export must carry an explicit disclosure that it
supplies technical evidence and does not, by itself, establish regulatory or
contractual compliance. This is a UI/document-content requirement on the
export feature, not a data-minimisation one - track it as an acceptance
criterion on #178 directly.

## §14.3 - Webhook / SIEM integrations (not yet built, #183)

Before this ships, outbound events must avoid sending sensitive page data
unnecessarily. In practice: an outbound security-event notification should
carry directive names, source hosts, and counts - not raw violation `sample`
content or full document URIs with query strings - unless a specific
integration explicitly requires it and that requirement is documented on a
per-integration basis.

## §16.3 - Configuration-as-code export (not yet built, #185)

Before this ships:

- [ ] Exports must exclude secrets by default (Stripe keys, webhook secrets,
      any future signing keys).
- [ ] Source-site identity must be included only where the operator
      explicitly configures the export to include it, not by default.

## §20 - General requirements (cross-cutting)

Covered in full in `docs/security-privacy-checklist.md`. The three items most
specific to this document:

- **Minimise external data transmission** - see "Data transmitted off-site"
  above; re-audit this table every time a new outbound integration ships.
- **Document retention** - this document is that record; every new stored
  data type must get a row added here in the same PR that introduces it (see
  `docs/security-privacy-checklist.md` requirement #9).
- **Support deletion** - `uninstall.php` currently provides full-plugin
  deletion (verified against the current table/option list above). No
  finer-grained deletion exists (e.g. "delete violation reports older than X"
  is retention-driven, not operator-triggered on demand) - acceptable today
  since none of the current data is personal data in the GDPR/CCPA sense, but
  should be revisited once the external verification service or SIEM
  integrations introduce anything closer to personal data.

## Follow-up

- [x] Decide whether `wp_sam_violation_retention_days = 0` should remain a
      supported "never purge" value or be replaced with a maximum cap:
      kept, with a warning in the admin while it is `0` (2.16.0).
- [ ] Re-run this data inventory once #172 (checkout proxy) ships - the
      Stripe secret key rows above should be removed entirely at that point.
- [ ] Re-run this data inventory before #182 (external verification) and
      #183 (webhook/SIEM) ship, converting the checklists above from
      pre-conditions into verified statements.
