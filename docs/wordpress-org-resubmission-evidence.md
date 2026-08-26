# WordPress.org resubmission evidence (PR C onward)

Internal reference backing the readme.txt "External services" disclosure and
the resubmission reply to the WordPress.org review thread. Not shipped in any
built package (excluded via `.distignore`, same as every other file in this
directory) -- this is sourcing/audit evidence, not user-facing documentation.

## External-service legal links: sourcing and caveats

Every Terms of Service / Privacy Policy URL in readme.txt's "External
services" section was researched against official provider sources, as of
2026-08-24. Most were fetched and inspected directly; the documented
exceptions below were corroborated through official-site references or
search results where bot protection or client-side rendering prevented
direct inspection -- not taken from memory in either case. Full caveats,
beyond what fits in readme.txt:

- **Bunny.net**: Privacy Policy URL follows the same site pattern as its
  Terms of Service but was not independently re-fetched to confirm content.
- **Microsoft Azure**: no single fixed Terms/Privacy URL exists -- which
  agreement applies depends on the customer's purchase channel (Microsoft
  Customer Agreement vs. Online Subscription Agreement). The hub page listed
  always resolves to the current correct agreement.
- **DNS Made Easy**: now operated under DigiCert/Vercara; its own site footer
  points to DigiCert's general Master Services Agreement, not a DNS Made
  Easy-specific document.
- **DNSPod**: the plugin's driver contacts `dnsapi.cn`, the mainland-China
  DNSPod API (operated by Tencent Cloud, originally Yantai Despro Network
  Technology Co., Ltd.) -- not Tencent Cloud's international site. The
  China-specific DNSPod terms/privacy pages are the correct link for that
  reason. Both pages are Chinese-language only and show a 2021 last-updated
  date; no newer version was found elsewhere.
- **Domeneshop**: Terms of Service and Privacy Policy are one combined
  Norwegian-language document, not two separate URLs.
- **GoDaddy**: godaddy.com returned HTTP 403 to automated fetches (bot
  protection) on every URL/region variant tried. URLs are corroborated by
  consistent, matching web search results, but the live page content was not
  directly read.
- **INWX**: the Terms of Service names INWX GmbH as provider; the Privacy
  Policy names INWX Inc. (Zurich, Switzerland) as data controller. Both are
  legitimate INWX-brand pages -- likely a corporate restructuring.
- **Joker.com**: Privacy/data-controller content and the Terms of Service
  live on separate pages; the ToS page is JS-rendered and its body content
  could not be directly read (URL confirmed to exist via search).
- **Linode**: no longer has independent legal pages -- both linode.com legal
  URLs 301-redirect permanently to Akamai's corporate legal pages, which are
  what's linked directly.
- **Njalla**: intentionally structured for registrant anonymity; no
  operating entity name is published on its own site, and no separate
  Privacy Policy exists at all (`njal.la/privacy/` 404s) -- the Terms of
  Service page contains the only privacy-relevant language.
- **NS1**: acquired by IBM; ns1.com now hard-redirects site-wide to IBM's
  site. Linked pages are IBM's general Terms of Use and Privacy Statement,
  not an NS1-specific document (the IBM Privacy Statement's body text does
  explicitly mention NS1).
- **Vultr**: vultr.com returned a Cloudflare bot-check challenge to every
  automated fetch attempt. URLs are corroborated by web search results whose
  titles match Vultr's standard legal-page pattern, but live content was not
  directly read.

## Plugin Check investigation (2026-08-24)

Ran the official WordPress.org Plugin Check plugin (v2.1.0) via WP-CLI
(`wp plugin check`) against the actual built WordPress.org-channel package
(root folder renamed to `vcns-security-automation-manager`, same content
`release-package.yml`'s "Verify WordPress.org package contains no paid-mode
identifiers" step already independently confirms), inside a throwaway Docker
WordPress environment (torn down after use). The complete raw output (all
795 rows: file, line, column, severity, rule code, message) is preserved at
`docs/plugin-check-raw-report-2026-08-24.csv` in this repository -- excluded
from every built package via `.distignore`, same as this file -- so every
finding below can be cross-checked against the tool's own output, not just
this summary.

**795 findings total, reconciled exactly against the raw report:**

```
394 + 94 + 82 + 72 + 62 + 32 + 28 + 16 + 7 + 2 + 2 + 1 + 1 + 1 + 1 = 795
```

**98 of the 795 are ERROR severity, all four accounted for by code:**

```
94 (ExceptionNotEscaped) + 2 (OffloadedContent) + 1 (NonEnqueuedStylesheet)
+ 1 (missing_direct_file_access_protection) = 98
```

The remaining 697 are WARNING severity.

Every finding in every category was examined -- not a sample generalized to
the rest of the category. Where a category's pattern could be checked
programmatically against the actual source (e.g. "is `prepare()` present on
this exact line," "does this exact file only ever get `require`d"), every
single occurrence was checked that way, not a subset. Where that wasn't
mechanically checkable, every occurrence was read individually. The method
column below states which.

| Rule code | Count (unique lines) | Method | Disposition |
|---|---:|---|---|
| `WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedVariableFound` | 394 (163 unique lines) | Every one of the 11 distinct files checked. | 388 findings, all 10 `includes/admin/views/*.php` files: false positive. Confirmed by grepping the entire `includes/` tree for each file's own path -- every one has exactly one call site, always `require WP_SAM_DIR . 'includes/admin/views/...'` from a `class-admin-ui.php` render method (two partials are `require`d from `page-scripts.php` itself, same pattern). None has any other entry point. PHPCS statically treats a `require`d file's top-level variables as global scope since it can't see the calling method's context -- same characteristic as WordPress core's own template files (`single.php`, `header.php`). 6 findings, `uninstall.php`: **genuine** -- that file is a real standalone top-level script (not `require`d from anywhere; grepped `test/` and the rest of `includes/` to confirm), so its top-level variables really are global scope. **Fixed**: `$tables`/`$table`/`$options`/`$option` renamed to `$wp_sam_tables`/`$wp_sam_table`/`$wp_sam_options`/`$wp_sam_option`, matching this same file's own existing `$wp_sam_extension_files` naming convention. |
| `WordPress.Security.EscapeOutput.ExceptionNotEscaped` | 94 (83 unique lines) | Every one of the 83 lines checked programmatically (does a `throw` appear within 3 lines above each flagged line) -- 0 exceptions found, all 83 confirmed. Call chain traced from the `Dns_Provider` subclasses' `create_txt_record()`/`delete_txt_record()` (where all 47 provider-file throws originate) up through `Certificate_Manager::satisfy_authorization()` → `run_order()` → the outer `try`/`catch` in the method that calls it, which stores the exception message via `record_run()`/`audit->log()`. Confirmed the actual display point (`page-certificates.php:306`) escapes correctly: `echo esc_html( $wp_sam_cert_run['detail'] )`. | False positive, all 94. Every one is inside a `throw new \RuntimeException(...)` construction; none is a direct-output call. The sniff checks escaping at exception-construction time; the actual output boundary (where escaping is the correct place to enforce it) already escapes correctly. |
| `PluginCheck.Security.DirectDB.UnescapedDBParameter` + `WordPress.DB.PreparedSQL.InterpolatedNotPrepared` | 89 (86 unique lines) | Every one of the 86 lines checked programmatically for the interpolated variable name and whether `prepare()` appears in the statement. 79 lines interpolate only a table-name variable (`$table`, `$snapshot_table`, `$old_table`/`$new_table`, `$int_table`, or `$wpdb->prefix`). 7 lines interpolate something else (`$in_clause`, `$src_where_sql`/`$viol_where_sql`/`$ext_where_sql`/`$evid_where_sql`, `$condition`, `$where`) -- each of these 7 individually traced to its construction and every call site. | False positive, all 89. Table-name interpolations are built from `$wpdb->prefix . 'literal_name'`, never user input. The 7 non-table cases: `$in_clause` is a runtime-built string of bare `%d` placeholders (no data), filled via `$wpdb->prepare(...$other_ids)` immediately after. The four `*_where_sql` variables are built by `Table_Query`'s fragment builders (`equals_where()`, `like_where()`, `multi_select_where()`, etc.), which return SQL structure (hardcoded column names + `%s`/`%d` placeholders) and actual values in a separate `args` array -- confirmed all four call sites pass the combined SQL through `$wpdb->prepare( $sql, ...$args )` before execution. `$condition` (`class-admin-controller.php`) and `$where` (`class-readiness-checker.php`) are private-method parameters; every call site (2 each, grepped) passes a hardcoded string literal, never request input. Not a SQL injection pattern anywhere in this set. **Comment fix**: found 39 locations across 11 files where an existing `// phpcs:ignore ...WordPress.DB.PreparedSQL.NotPrepared` comment was silently not matching Plugin Check's actual code (`InterpolatedNotPrepared` is a distinct, sibling sniff code, not covered by a `NotPrepared` suppression) -- appended the correct code alongside the existing one at all 39 locations. This is a suppression-comment correction, not a new blanket suppression: every location already carried an ignore comment for the same underlying pattern, just missing this specific code. |
| `WordPress.DB.DirectDatabaseQuery.NoCaching` + `.DirectQuery` | 134 | All 22 flagged files checked against `phpcs.xml.dist`'s own `<exclude-pattern>` list for `WordPress.DB.DirectDatabaseQuery`, then confirmed directly: `vendor/bin/phpcs --standard=phpcs.xml.dist --sniffs=WordPress.DB.DirectDatabaseQuery` against a sample including the two files least obviously covered (`includes/admin/views/partials/scripts-external.php`, nested under `views/`) returned zero findings. | Expected/already-reviewed, all 134. Custom tables can't use WP core's post/comment object cache, which is what this sniff assumes is available -- this project's own `phpcs.xml.dist` already excludes exactly this file set for exactly this reason. `PluginCheck.*`'s copy of the same rule doesn't read `phpcs.xml.dist`'s exclusions (a different ruleset instance), which is why this didn't show up in `composer lint:phpcs`. |
| `WordPress.Security.ValidatedSanitizedInput.InputNotSanitized` + `.MissingUnslash` | 48 (32 unique lines) | All 32 unique lines read individually. | False positive, all 48. Breaks down as: safe `(int)`/cast patterns (majority); strict `===`-to-hardcoded-literal comparisons and ternaries that only ever produce a hardcoded literal (e.g. `'rsa-2048' === ($_POST[...] ?? '') ? 'rsa-2048' : 'ec-256'`); already-sanitized via a function the sniff doesn't credit (`esc_url_raw()`, a custom `Strict_Transport_Security_Builder::sanitize_max_age()`); a custom regex allowlist stricter than `sanitize_text_field()` would provide, with an inline comment explaining why (`class-admin-ui.php`'s CSR domain-list validation: "sanitize_text_field alone would wave through things a CSR must never contain"); intentionally-unsanitized credential/secret fields (cPanel token, DNS provider credentials, a custom private key) where `sanitize_text_field()` would corrupt the value before it's used for authentication, never echoed, and encrypted at rest; and PHP's own server-generated `$_FILES[...]['tmp_name']` upload path (not attacker-suppliable text), gated behind `is_uploaded_file()`. |
| `WordPress.Security.NonceVerification.Missing` | 1 | Read directly, traced both call sites. | False positive. `decide_source()` is a private helper called only from `ajax_approve_source()`, `ajax_reject_source()`, and `ajax_undo_source_decision()`, all three of which call `check_ajax_referer( 'wp_sam_admin_nonce', 'nonce' )` before invoking it. PHPCS can't trace a nonce check across the call graph into a private helper. |
| `WordPress.Security.NonceVerification.Recommended` | 28 (17 unique lines) | All 17 unique lines read individually. | Expected, all 28. Two patterns: (1) tab-selection/sort-order `$_GET` reads, each `sanitize_text_field( wp_unslash(...) )`-sanitized and immediately validated against an allowlist (`$allowed_tabs`, `isset($tabs[$tab])`, or `Table_Query::resolve_sort()`'s whitelist-key lookup) -- read-only UI navigation state, matches an existing, already-justified `phpcs:ignore` pattern for the identical case elsewhere in this codebase (`page-certificates.php`). (2) `page-overview.php`'s Recovery-tab status flags (`wp_sam_reset`, `wp_sam_restore`, etc.) -- these display the outcome of an already-nonce-verified POST action after a redirect; the state-changing operation happened in a separate, separately nonce-checked handler. Same pattern as WordPress core's own `?settings-updated=true`. |
| `PluginCheck.CodeAnalysis.Offloading.OffloadedContent` | 2 | Read directly. | False positive, both. AWS Route 53 DNS-management API calls (`class-provider-route53.php`), misclassified as asset/CDN offloading. |
| `WordPress.WP.EnqueuedResources.NonEnqueuedStylesheet` | 1 | Read directly. | False positive. `<link rel="stylesheet">` appears inside a translatable UI description string (`page-scripts.php`) describing the plugin's own script/stylesheet-inventory feature -- not actual markup this plugin outputs. |
| `missing_direct_file_access_protection` (`class-policy-builder.php`) | 1 | Read directly; grepped the file for `ABSPATH`. | False positive. The `if ( ! defined( 'ABSPATH' ) ) { exit; }` guard is present at line 53 of that file -- confirmed directly -- just after a longer docblock than the checker's heuristic apparently expects (it reported line 0). |
| `PluginCheck.CodeAnalysis.DiscouragedFunctions.load_plugin_textdomainFound` | 1 | Read directly. | False positive as flagged. The call (`class-plugin.php`) is already gated behind `if ( 'github' !== WP_SAM_DISTRIBUTION_CHANNEL ) { return; }` and never executes on the WordPress.org build -- the static scan flags the literal text regardless of the runtime guard. |
| `WordPress.DB.DirectDatabaseQuery.SchemaChange` (`class-activator.php`) | 2 | Read directly. | Accurate advisory, not a defect, both. An idempotent, guarded (`if ( null === $index )`) index migration on a custom table with a hardcoded `ALTER TABLE` statement and no user input -- legitimate, necessary version-migration behaviour for a plugin managing its own schema. |

**Genuine findings, both fixed in this PR:**
1. `uninstall.php`'s 6 unprefixed top-level variables -- real, since that
   file genuinely executes standalone (not a false positive like the
   template-file cases above).
2. The 39-location `NotPrepared`/`InterpolatedNotPrepared` suppression-comment
   mismatch -- an existing, already-intended suppression that wasn't
   matching Plugin Check's actual code.

No other genuine security or correctness defect was found. Decision on the
remaining ~789 findings: document them here, with the verification method
disclosed per category, rather than add ~789 new individual
`phpcs:ignore` annotations -- that would be exactly the "hundreds of blanket
suppressions" this investigation was asked to avoid, for findings that are
demonstrated tool limitations, not code that needs to change.

## Round 2 WordPress.org review follow-up (2026-08-24)

A second batch of reviewer/tool findings arrived after the v2.9.20 tag was
cut. Confirmed with Simon: the reviewed package is
`security-automation-manager-v2.9.20.zip` -- the **GitHub Release asset**
filename, not the WordPress.org-specific package
(`vcns-security-automation-manager-v2.9.20.zip`, built and verified
separately by `release-package.yml` and saved to
`.wordpress-org/vcns-security-automation-manager-v2.9.20.zip`). That
explains the majority of this round's findings directly: the `Update URI`
header, the active `class-github-update-checker.php`, and the GitHub-manifest
service appearing "actively used" are all correct, by-design behaviour for
the GitHub-channel build -- and physically absent from the actual
WordPress.org package. No code fix addresses these; re-uploading the correct
file does.

Findings that were genuinely new and independent of which ZIP was reviewed:

- **DigitalOcean Terms of Service URL had gone stale**: `/legal/tos` now
  404s (it resolved when originally researched). Corrected to
  `/legal/terms-of-service-agreement`, confirmed live via direct fetch
  before publishing. Prompted a full re-verification pass of every other
  provider's links in this same round (see below).
- **DNS provider credential fields**: `class-admin-ui.php`'s save handler
  read every field a provider's `fields()` declares with the same
  `wp_unslash()`-only treatment, regardless of whether that specific field
  is secret. Each field already carries a `'secret' => false` flag for
  plain values (account/zone name, endpoint host) versus the default-secret
  treatment for actual API keys/tokens -- the handler just wasn't reading
  it. Now applies `sanitize_text_field()` to fields explicitly marked
  non-secret; fields that default to secret are unchanged (sanitizing an
  API token before it's used for authentication would corrupt it).
- **Three `$_SERVER` reads** (`class-violation-reporter.php`,
  `class-challenge-http.php`, `class-request-surface.php`) were already
  individually verified safe in the Plugin Check investigation above
  (strict regex-validated before use, or used only for routing/
  classification, never echoed or persisted raw) -- added
  `sanitize_text_field()` anyway as defense-in-depth, since it costs
  nothing behaviourally for well-formed values and closes the finding
  outright rather than relying on a written justification a future
  automated pass won't read.
- **`class-hash-manager.php:252`'s `echo $html`**: a genuine false
  positive, same class as others already documented -- `$html` is this
  request's own captured output buffer (the complete page WordPress core,
  the theme, and every other plugin already rendered), re-emitted after
  nonce injection. `esc_html()` would HTML-entity-encode the entire
  document instead of rendering it. Existing `phpcs:ignore` lacked the
  explanatory comment its sibling citations already had; added one.
- **`Table_Query::sort_header()` / `Risk_Badge::render()` escaping
  citations** (45 incidences cited): Plugin Check's sniff flags every
  location carrying an existing `phpcs:ignore
  WordPress.Security.EscapeOutput.OutputNotEscaped` annotation for
  re-verification, not necessarily a confirmed defect. Both helpers were
  already read in full during the Plugin Check investigation above and
  confirmed to escape internally (`esc_url()`/`esc_html()` inside
  `sort_header()`; `esc_attr()`/`esc_html()` inside `Risk_Badge::render()`).
  No change made.
- **`class-admin-ui.php:816`'s `$domains_raw` array-sanitization
  citation**: already covered above -- the CSR domain-list validator uses a
  stricter custom regex allowlist than `sanitize_text_field()` would
  provide, with an inline comment explaining why. No change made.

## v2.9.21: premature textdomain-loading notice (2026-08-25)

Independent of the review thread: production debug logs (staging and live)
showed `_load_textdomain_just_in_time called incorrectly` firing on every
request. Root cause: `Automation_Mode_Registry::register_defaults()`
translates each mode's label with `__()` at registration time, and
`Plugin::bootstrap()` called it directly from the `plugins_loaded` callback
-- before `init`, which is exactly what the check requires. Fixed by
deferring registration (and the `wp_sam_register_automation_modes` extension
hook) to `init` via `Plugin::register_automation_modes()`; every actual
consumer of the registry already runs after `init`, so no behaviour changed.
Shipped as v2.9.21.

## Round 3: same file, never actually replaced (2026-08-25)

A further round of reviewer feedback arrived, identical in substance to
Round 2 (same DigitalOcean URL, Update URI, update-checker, and
sanitization/escaping citations). Pulled the actual Gmail thread
(`1a02eff8ea3237da`) rather than assume staleness: the message's own header
read "review of the file `security-automation-manager-v2.9.20.zip`
submitted 1 day and 5 hours ago" -- the same GitHub-channel filename and
submission window as Round 2, not a fresh upload. Simon's own reply in
between said "I've now attached the correct... package," but that message
carries no attachment at all (confirmed via the Gmail API's own
`attachments`/`attachmentIds` fields), and its body text linked to the
GitHub Release asset, not the WordPress.org-specific file. Simon
subsequently confirmed the correct file *was* uploaded via "Add your
plugin" (not email, which the platform doesn't allow attachments for) --
the discrepancy was not resolved in this session; the working assumption
going forward is that whichever file WordPress.org's reviewer is looking at
next will settle it, since v2.9.22 (below) is unambiguous either way.

## v2.9.22: self-discovered Plugin Check false positives (2026-08-26)

Simon ran the official Plugin Check tool independently, via WordPress
Playground, against the plugin under test. Two genuinely new categories
(not present in the 2026-08-24 investigation) surfaced:

- **`WordPress.WP.EnqueuedResources.NonEnqueuedStylesheet`**
  (`page-scripts.php:76`): a help paragraph's prose literally contained the
  substring `<link rel="stylesheet">`, describing what the plugin
  inventories -- misread as a real, unregistered tag. Reworded to avoid the
  literal tag-shaped substring, same fix class as the CORP page's `<script>`
  wording from Round 2.
- **`missing_direct_file_access_protection` / `PluginCheck.CodeAnalysis.Offloading.OffloadedContent`**: reconfirmed exactly as already documented above (the ABSPATH guard exists at `class-policy-builder.php:53`; the Route 53 hostname is a DNS API endpoint, not offloaded content) -- no new finding, no code change.

Everything else in that scan (`plugin_updater_detected`, the active
`class-github-update-checker.php`, hundreds of `DirectDB`/
`UnescapedDBParameter` and `PrefixAllGlobals` findings) matched the
already-documented dispositions above almost exactly -- this Playground
test was against an unstripped/GitHub-channel build (the updater code was
present), the same root cause as every prior review round.

**Policy change for `WordPress.Security.EscapeOutput.ExceptionNotEscaped`
specifically**: the 2026-08-24 decision (above) was to document this
category rather than add ~94 individual `phpcs:ignore` annotations, to
avoid "hundreds of blanket suppressions" for a demonstrated tool
limitation. That decision is superseded for this one category only: it
kept resurfacing, identically, on every subsequent Plugin Check run
(reviewer rounds and this independent one), which meant "document once" was
not actually preventing re-litigation. The underlying analysis is
unchanged (verified representative call sites: messages are only ever
passed to `Audit_Log::log()` or `Certificate_Manager::record_run()`, never
echoed) -- but since the fix is mechanical and carries zero behavioural
risk, ~83 call sites across `includes/certificates/` (ACME client/crypto,
`Certificate_Manager`, `Deployer`, `Dns_Provider`, all 40 DNS provider
drivers) now carry an explicit `phpcs:ignore
WordPress.Security.EscapeOutput.ExceptionNotEscaped` with the same
justification inline, rather than relying on this document alone. All
other high-volume categories (`DirectDB`/`UnescapedDBParameter`,
`PrefixAllGlobals`) remain under the original "document, don't suppress"
policy -- unchanged, since they haven't shown the same "keeps resurfacing
in reviewer-visible scans" pattern.

Shipped as v2.9.22, verified against the actual built package (extracted
and re-run through `verify-wporg-package.sh`; confirmed the fix and the
version string are both present in the shipped `.php` files).

## Confirmation scan against the real v2.9.22 package (2026-08-26)

A follow-up Plugin Check run (Playground, filtered to the "Security"
category) against the corrected build showed: no `plugin_updater_detected`/
Update URI findings (first scan in this whole saga against a correctly-
stripped wp.org package), no `ExceptionNotEscaped` findings (v2.9.22's fix
held), and every remaining line was either the already-documented
`DirectDB`/`UnescapedDBParameter` pattern (spot-checked one representative
line against current source -- unchanged, still hardcoded table names plus
`$wpdb->prepare()` on every bound value) or the same `class-policy-builder.php`
ABSPATH-guard false positive. No new findings, no further code changes.
