# WordPress.org resubmission evidence (PR C)

Internal reference backing the readme.txt "External services" disclosure and
the resubmission reply to the WordPress.org review thread. Not shipped in any
built package (excluded via `.distignore`, same as every other file in this
directory) -- this is sourcing/audit evidence, not user-facing documentation.

## External-service legal links: sourcing and caveats

Every Terms of Service / Privacy Policy URL in readme.txt's "External
services" section was independently researched and fetched live (not taken
from memory) as of 2026-08-24. Full caveats, beyond what fits in readme.txt:

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
WordPress environment (torn down after use).

**795 findings (98 errors, 697 warnings) across 84 files.** Investigated
every finding category (not a sample of one or two) by cross-referencing the
actual flagged code, not just the tool's message text:

| Finding | Count | Disposition |
|---|---:|---|
| `PrefixAllGlobals.NonPrefixedVariableFound` | 394 | False positive. 388 (98.5%) are in `includes/admin/views/*.php`, files `require`d from render methods -- PHPCS statically treats every top-level variable in an included file as "global scope" since it can't see the calling method's context. Same characteristic as WordPress core's own template files (`single.php`, `header.php`). |
| `Security.EscapeOutput.ExceptionNotEscaped` | 94 | False positive. Traced 3 samples end-to-end (`class-acme-crypto.php`, `class-certificate-manager.php`, `class-scheduler.php`): caught exception messages are stored via `record_run()`/`audit->log()`, never echoed directly. Confirmed the actual display point (`page-certificates.php:306`) escapes correctly: `echo esc_html( $wp_sam_cert_run['detail'] )`. The sniff checks escaping at exception-construction time, not at the actual output boundary. |
| `PluginCheck.Security.DirectDB.UnescapedDBParameter` | 82 | False positive. Sampled 8 occurrences across 8 different files: every one interpolates only `$table` (built from `$wpdb->prefix . 'literal_name'`, never user input); every bound value goes through `$wpdb->prepare()` with `%s`/`%d` placeholders. Not a SQL injection pattern. |
| `DirectDatabaseQuery.{NoCaching,DirectQuery}` | 134 | Expected/already-reviewed. File list matches this project's own `phpcs.xml.dist` `<exclude-pattern>` list for `WordPress.DB.DirectDatabaseQuery` almost exactly (custom tables can't use WP core's post/comment object cache). `PluginCheck.*` is a separate rule namespace our own exclusions don't reach, which is why this didn't show up in `composer lint:phpcs`. |
| `ValidatedSanitizedInput.{InputNotSanitized,MissingUnslash}` | 48 | False positive (sampled). `(int)` casts are valid sanitization the sniff doesn't credit; one flagged case is an intentionally-unsanitized password field (`sanitize_text_field()` would alter the value before a password comparison, which would be wrong). |
| `NonceVerification.Missing` | 1 | False positive. `decide_source()` is a private helper called only from `ajax_approve_source()`/`ajax_undo_source_decision()`, both of which call `check_ajax_referer()` before invoking it -- PHPCS can't trace across the call graph to the caller's nonce check. |
| `NonceVerification.Recommended` | 28 | Expected. All in `includes/admin/views/*.php`: read-only `$_GET` reads for table filters/tab state, no state-changing action. Matches an existing, already-justified `phpcs:ignore` pattern for the identical case elsewhere in this codebase (`page-certificates.php`). |
| `Offloading.OffloadedContent` (Route 53 provider) | 2 | False positive. AWS Route 53 DNS-management API calls, misclassified as asset/CDN offloading. |
| `EnqueuedResources.NonEnqueuedStylesheet` | 1 | False positive. `<link rel="stylesheet">` appears inside a translatable UI description string about the plugin's own script-inventory feature -- not actual markup this plugin outputs. |
| `missing_direct_file_access_protection` (`class-policy-builder.php`) | 1 | False positive. The `if ( ! defined( 'ABSPATH' ) ) { exit; }` guard is present at line 53 of that file (confirmed directly) -- just after a longer docblock than the checker's heuristic apparently expects. |
| `DiscouragedFunctions.load_plugin_textdomainFound` | 1 | False positive as flagged. The call is already gated behind `if ( 'github' !== WP_SAM_DISTRIBUTION_CHANNEL ) { return; }` and never executes on the WordPress.org build -- the static scan flags the literal text regardless of the runtime guard. |
| `DirectDatabaseQuery.SchemaChange` (`class-activator.php`) | 2 | Accurate advisory, not a defect. An idempotent, guarded (`if ( null === $index )`) index migration on a custom table with a hardcoded statement and no user input -- legitimate, necessary version-migration behaviour for a plugin managing its own schema. |

No genuine security or correctness defect was found. Decision: document this
investigation as resubmission evidence rather than add `PluginCheck.*`-scoped
`phpcs:ignore` annotations at all ~795 locations, since none represent an
actual finding to suppress.
