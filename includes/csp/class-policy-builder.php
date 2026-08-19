<?php
/**
 * Builds and emits the Content-Security-Policy (or CSP-Report-Only) header.
 *
 * Implements §4.3, §4.4, §4.8 of the directive:
 *   - Per-surface profiles loaded from DB (frontend, admin, login, api).
 *   - All 18 directives emitted; empty directives still included to close
 *     implicit fallback to default-src.
 *   - Nonce injected from Nonce_Manager at request time.
 *   - Approved hashes from csp_hash_inventory appended to script-src / style-src
 *     AND their -elem counterpart, since script-src-elem / style-src-elem are
 *     always explicitly present and take exclusive authority over element-level
 *     checks once set (CSP3) -- a hash added only to the base directive would
 *     never actually apply. style-src-attr hashes apply only to themselves
 *     (there is no -elem counterpart for an attribute-scoped directive).
 *     'unsafe-hashes' is NOT added automatically -- it's its own
 *     BYPASS_CATALOG entry, since it's a scanner-flaggable keyword an admin
 *     must explicitly opt into per surface, same as any other entry -- CSP3
 *     §6.1.2 requires it before any approved hash takes effect in an
 *     attribute context.
 *   - Approved hosts from csp_source_inventory appended per directive.
 *   - report-uri appended automatically for direct browser reporting.
 *   - Reporting API headers and the report-to directive are optional because direct
 *     report-uri delivery gives administrators faster learning feedback.
 *   - 'strict-dynamic' added to both script-src and script-src-elem when the
 *     profile enables it (same exclusive-authority reasoning as above -- script-src
 *     alone never reaches element-level enforcement once script-src-elem is set).
 *     When active, approved host sources are suppressed from both -- browsers
 *     silently ignore host allowlists when strict-dynamic is present (CSP3 §8.2),
 *     so including them is misleading noise.
 *   - FORBIDDEN_DIRECTIVES (deprecated/removed by W3C) are stripped from any
 *     admin override before serialisation; a warning is written to the audit log.
 *   - BYPASS_CATALOG: a small, hardcoded set of per-surface "Bypass Best
 *     Practices" toggles (Profiles tab) for specific, individually-reasoned
 *     directive+token relaxations that go against CSP best practice -- some
 *     safe despite being high-risk for automation (e.g. img-src/font-src
 *     data:), some a deliberate, labelled, opt-in risk acceptance (e.g.
 *     style-src-attr unsafe-hashes) -- see the constant's docblock.
 *
 * FIX: source host values are sanitised with sanitize_text_field() rather than
 * esc_attr(). esc_attr() HTML-encodes characters such as & which are invalid
 * in HTTP header values and would produce a malformed CSP directive.
 *
 * Extends Header_Builder, which owns the pillar-agnostic envelope: hook
 * registration, the header_emitted/headers_sent() guard, and surface
 * detection. See includes/security/class-header-builder.php.
 */

declare( strict_types=1 );

namespace WP_SAM\CSP;

use WP_SAM\Modules\Audit_Log;
use WP_SAM\Modules\Feature_Gate;
use WP_SAM\Security\Header_Builder;
use WP_SAM\Security\Reporting_Endpoint;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Policy_Builder extends Header_Builder {

	public const DEFAULT_ENFORCE_HEADER     = 'Content-Security-Policy';
	public const DEFAULT_REPORT_ONLY_HEADER = 'Content-Security-Policy-Report-Only';
	public const REPORTING_TRANSPORT_DIRECT = 'report-uri';
	public const REPORTING_TRANSPORT_API    = 'report-to';
	public const REPORTING_TRANSPORT_BOTH   = 'both';

	/**
	 * sha256 hash of the empty string, base64-encoded -- always allowed in
	 * script-src-attr/style-src-attr regardless of any admin approval, hash
	 * inventory, or the unsafe-hashes bypass toggle's own hashes. An empty
	 * attribute value can never execute or style anything: there is no
	 * content for it to be an attack vector for. Confirmed in production,
	 * 2026-08-19: a vendored carousel library's own destroy/refresh cycle
	 * (jQuery .attr('style', '') to clear inline styles, a common,
	 * unremarkable DOM-manipulation pattern in third-party JS) was reported
	 * as a CSP violation because that exact empty value had never happened
	 * to go through the hash-learning/approval workflow yet -- noise with
	 * no security value on either side: blocking it protects nothing, and
	 * it would never have been worth an admin's attention to review.
	 * Still only takes effect together with 'unsafe-hashes' (CSP3 §6.1.2,
	 * BYPASS_CATALOG's own per-surface opt-in below) same as every other
	 * attribute-context hash -- this doesn't bypass that gate, it just
	 * means this one specific, provably harmless value never needs to
	 * wait for one to be individually captured and approved.
	 */
	private const EMPTY_CONTENT_HASH_TOKEN = "'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='";

	/**
	 * Directives removed or deprecated by W3C that must never be emitted.
	 * References: CSP3 WD-20260505; MDN; research.md R4.
	 */
	private const FORBIDDEN_DIRECTIVES = array(
		'plugin-types',           // removed; plugins are gone from the web platform
		'block-all-mixed-content', // obsolete; superseded by default browser auto-upgrade
		'navigate-to',            // removed from CSP3 spec (was at-risk)
		'prefetch-src',           // deprecated/non-standard; Chromium intent-to-remove
	);

	/**
	 * Deliberately small, hardcoded catalog of specific directive+token
	 * relaxations an admin can opt into per surface from the Profiles tab's
	 * "Bypass Best Practices" column, for cases where a scanner or
	 * Decision_Engine reasonably flags something as going against best
	 * practice, but a specific site's real, legitimate design needs it.
	 *
	 * Every entry carries a 'risk_level' (low/medium/high) and is shown to
	 * the admin with that label before they opt in -- this catalog does NOT
	 * only contain low-risk entries. The safety property is not "nothing
	 * risky is ever offered here"; it's "nothing is ever silently or
	 * automatically enabled, and every entry is individually reasoned about
	 * and documented, not generated from a raw risk-classifier finding."
	 * Two examples of the two different shapes this takes:
	 *
	 * - img-src/font-src data: (low risk): Decision_Engine classifies
	 *   data:/blob: schemes as high-risk for *automation* purposes
	 *   (CSP-SCHEME-002, hard-excluded from auto-approval), but data: URIs
	 *   in img-src/font-src specifically can only ever render pixel/glyph
	 *   data -- they cannot execute as script, unlike data: in
	 *   script-src/object-src/frame-src/worker-src/base-uri, where the same
	 *   scheme is genuinely dangerous. Those directives must never gain a
	 *   catalog entry; they stay hard-blocked and go through explicit
	 *   hash/source review instead.
	 * - style-src-attr unsafe-hashes (medium risk): a real, if narrower,
	 *   security-scanner-flaggable posture change -- it only ever affects
	 *   style-src-attr, never script-src-attr or script execution of any
	 *   kind (CSP directives don't cross-contaminate), and it's a no-op
	 *   without an approved hash to pair with. See the "Inline style
	 *   attributes" entry in docs/threat-model.md for the full reasoning.
	 *   Kept in this catalog specifically so enabling it is a conscious,
	 *   visible, per-surface admin decision, not something the plugin
	 *   decided unilaterally (see PR #213's history for why it originally
	 *   wasn't).
	 *
	 * Storage: a single bypass_flags JSON array on csp_policy_profiles
	 * (schema v25), holding whichever of this catalog's own keys are
	 * enabled for that surface -- not one tinyint column per entry, which
	 * doesn't scale to a catalog meant to keep growing (every addition
	 * would otherwise need its own schema migration). See
	 * migrate_consolidate_bypass_flags_into_json() for the one-time
	 * conversion from the three legacy per-entry columns this replaced.
	 * A catalog key is validated against array_key_exists( $flag, self::BYPASS_CATALOG )
	 * -- never derived from request input -- in Admin_UI::ajax_set_bypass_flag()
	 * before being written.
	 *
	 * 'violation_blocked_uri' is the csp_violation_reports.blocked_uri value
	 * used to show the surface's real observed count for this entry, and to
	 * hide an entry from the Profiles tab entirely when a surface has never
	 * once triggered it and it isn't already enabled -- not consumed by
	 * build_policy_string() itself.
	 */
	public const BYPASS_CATALOG = array(
		'img_src_data'                  => array(
			'directive'             => 'img-src',
			'token'                 => 'data:',
			'label'                 => 'Allow data: URIs for images',
			'risk_level'            => 'low',
			'risk_note'             => 'Low risk: inline image data cannot execute as script.',
			'violation_blocked_uri' => 'data',
		),
		'img_src_blob'                  => array(
			'directive'             => 'img-src',
			'token'                 => 'blob:',
			'label'                 => 'Allow blob: URIs for images',
			'risk_level'            => 'low',
			'risk_note'             => 'Low risk: like data:, a blob: image source cannot execute as script -- common with canvas exports and client-side file/image previews.',
			'violation_blocked_uri' => 'blob',
		),
		'font_src_data'                 => array(
			'directive'             => 'font-src',
			'token'                 => 'data:',
			'label'                 => 'Allow data: URIs for fonts',
			'risk_level'            => 'low',
			'risk_note'             => 'Low risk: inline font data cannot execute as script.',
			'violation_blocked_uri' => 'data',
		),
		'media_src_data'                => array(
			'directive'             => 'media-src',
			'token'                 => 'data:',
			'label'                 => 'Allow data: URIs for audio/video',
			'risk_level'            => 'low',
			'risk_note'             => 'Low risk: inline audio/video data cannot execute as script.',
			'violation_blocked_uri' => 'data',
		),
		'media_src_blob'                => array(
			'directive'             => 'media-src',
			'token'                 => 'blob:',
			'label'                 => 'Allow blob: URIs for audio/video',
			'risk_level'            => 'low',
			'risk_note'             => 'Low risk: a blob: media source cannot execute as script -- common with streaming/adaptive-bitrate players built on the Media Source Extensions API.',
			'violation_blocked_uri' => 'blob',
		),
		'style_src_attr_unsafe_hashes'  => array(
			'directive'             => 'style-src-attr',
			'token'                 => "'unsafe-hashes'",
			'label'                 => "Allow inline style attributes via hash approval (adds 'unsafe-hashes')",
			'risk_level'            => 'medium',
			'risk_note'             => 'Medium risk: only takes effect together with an approved content hash (CSP3 §6.1.2); does not affect script-src-attr or script execution of any kind. See docs/threat-model.md.',
			'violation_blocked_uri' => 'inline',
		),
		'script_src_attr_unsafe_hashes' => array(
			'directive'             => 'script-src-attr',
			'token'                 => "'unsafe-hashes'",
			'label'                 => "Allow inline event handler attributes via hash approval (adds 'unsafe-hashes')",
			'risk_level'            => 'medium',
			'risk_note'             => "Medium risk: only takes effect together with an approved content hash (CSP3 §6.1.2), and only for that exact hashed value -- does not enable 'unsafe-inline' or affect script-src/script-src-elem. Covers inline event handler attributes such as onclick=\"\"; script-src-attr is otherwise 'none' everywhere in this codebase.",
			'violation_blocked_uri' => 'inline',
		),
		'script_src_wasm_unsafe_eval'   => array(
			'directive'             => 'script-src',
			'token'                 => "'wasm-unsafe-eval'",
			'label'                 => "Allow WebAssembly compilation (adds 'wasm-unsafe-eval')",
			'risk_level'            => 'medium',
			'risk_note'             => "Medium risk: CSP3's 'wasm-unsafe-eval' keyword permits only WebAssembly instantiation/compilation -- unlike 'unsafe-eval', it does not permit eval(), new Function(), or any other string-to-JS execution path. Needed by some image/video-processing, PDF-rendering, or cryptography libraries compiled to WebAssembly.",
			'violation_blocked_uri' => 'wasm-eval',
		),
		'worker_src_blob'               => array(
			'directive'             => 'worker-src',
			'token'                 => 'blob:',
			'label'                 => 'Allow blob: URIs for workers',
			'risk_level'            => 'high',
			'risk_note'             => 'Higher risk than the other entries here: unlike an image, font, or media source, a Worker constructed from a blob: URL does execute as JavaScript. Only enable this if a specific, identified library on this site genuinely constructs its worker from a blob (common with PDF.js and some video encoders, or bundler-generated workers) -- if nothing on the site does this, leave it off.',
			'violation_blocked_uri' => 'blob',
		),
	);

	/**
	 * Hard byte budget for the cumulative worst-case cost of approved
	 * hashes appended to the header. script-src/style-src hashes count
	 * twice (once for the base directive, once for its -elem counterpart
	 * -- see the hash-append loop in build_policy_string()); style-src-attr
	 * hashes count once. Exists purely as a safety net against unbounded
	 * csp_hash_inventory growth: a runaway hash-learning bug (an inline
	 * script whose content varies every request, never matching
	 * Hash_Manager's exact-content dedup) can otherwise grow the emitted
	 * header past common web-server response-header field limits
	 * (Apache's LimitRequestFieldSize default is 8190 bytes) and take the
	 * entire surface down with a silent 500 -- confirmed in production,
	 * 2026-08-19 (a 93,580-byte header, ~1,700 hashes, one surface).
	 * load_approved_hashes() returns hashes most-recently-seen first, so
	 * once this budget is exhausted every remaining hash is dropped
	 * oldest-first -- the ones least likely to still be needed. Filterable
	 * (`wp_sam_max_hash_token_budget_bytes`) so an admin who has confirmed
	 * their server/proxy chain tolerates a larger header can raise it; the
	 * default stays conservative. See also
	 * Hash_Manager::MAX_NEW_HASHES_PER_HOUR, a second, independent safety
	 * net on the hash-capture side.
	 */
	private const MAX_HASH_TOKEN_BUDGET_BYTES = 4096;

	/**
	 * Absolute ceiling on the fully serialised policy string, in bytes.
	 * Checked after the hash budget above has already been applied -- if
	 * the policy is still over this size (e.g. an unusually large admin
	 * override or approved-source list, not the hash-growth scenario the
	 * budget above guards against), fail safe by emitting no header at
	 * all for this surface/request rather than risk the web server
	 * rejecting the entire response. No CSP for one request is strictly
	 * safer than a 500 for every request. Filterable
	 * (`wp_sam_max_policy_string_bytes`).
	 */
	private const MAX_POLICY_STRING_BYTES = 7500;

	private Feature_Gate $gate;
	private ?Audit_Log $audit;

	/** @var callable|null */
	private $hash_loader;

	/** @var callable|null */
	private $source_loader;

	public function __construct(
		Feature_Gate $gate,
		?callable $hash_loader = null,
		?callable $source_loader = null,
		?Audit_Log $audit = null
	) {
		$this->gate          = $gate;
		$this->hash_loader   = $hash_loader;
		$this->source_loader = $source_loader;
		$this->audit         = $audit;
	}

	// ── Header emission ───────────────────────────────────────────────────────

	protected function is_profile_active( array $profile ): bool {
		return 'disabled' !== $profile['mode'];
	}

	protected function emit_profile_header( array $profile, string $surface ): bool {
		$policy = $this->build_policy_string( $profile, $surface );
		if ( empty( $policy ) ) {
			return false;
		}

		$is_report_only = ( 'report-only' === $profile['mode'] );
		$header_name    = $this->get_policy_header_name( $is_report_only );

		// Declare the Reporting API endpoint only when explicitly enabled. The default
		// direct report-uri path is intentionally quicker and easier to observe.
		if ( $this->uses_reporting_api() ) {
			Reporting_Endpoint::emit_headers();
		}

		header( $header_name . ': ' . $policy );
		return true;
	}

	public function get_policy_header_name( bool $is_report_only ): string {
		$custom = self::sanitize_custom_policy_header_name( get_option( 'wp_sam_policy_header_name', '' ) );
		if ( '' !== $custom ) {
			return $custom;
		}

		return $is_report_only ? self::DEFAULT_REPORT_ONLY_HEADER : self::DEFAULT_ENFORCE_HEADER;
	}

	public static function sanitize_reporting_transport( mixed $transport ): string {
		$transport = (string) $transport;
		if ( in_array( $transport, self::get_reporting_transport_options(), true ) ) {
			return $transport;
		}

		return self::REPORTING_TRANSPORT_DIRECT;
	}

	public static function get_reporting_transport_options(): array {
		return array(
			self::REPORTING_TRANSPORT_DIRECT,
			self::REPORTING_TRANSPORT_API,
			self::REPORTING_TRANSPORT_BOTH,
		);
	}

	private function uses_reporting_api(): bool {
		return in_array(
			$this->get_reporting_transport(),
			array( self::REPORTING_TRANSPORT_API, self::REPORTING_TRANSPORT_BOTH ),
			true
		);
	}

	private function get_reporting_transport(): string {
		return self::sanitize_reporting_transport( get_option( 'wp_sam_reporting_transport', self::REPORTING_TRANSPORT_DIRECT ) );
	}

	// ── Policy assembly ───────────────────────────────────────────────────────

	public function build_policy_string( array $profile, string $surface ): string {
		$nonce      = Plugin_Nonce_Manager::get_instance_nonce();
		$directives = json_decode( $profile['directives'], true );
		$overrides  = json_decode( $profile['overrides'], true );

		if ( ! is_array( $directives ) ) {
			return '';
		}

		// Merge admin overrides on top of base directives.
		if ( is_array( $overrides ) ) {
			foreach ( $overrides as $dir => $sources ) {
				$directives[ $dir ] = $sources;
			}
		}

		// Strip deprecated/removed directives that must never be emitted (R4).
		// These may have been stored in overrides; removing them here prevents
		// any upgrade path from accidentally re-enabling them.
		$forbidden_found = array_intersect_key( $directives, array_flip( self::FORBIDDEN_DIRECTIVES ) );
		if ( ! empty( $forbidden_found ) ) {
			$directives = array_diff_key( $directives, array_flip( self::FORBIDDEN_DIRECTIVES ) );
			// Surface a warning so admins know the override was silently blocked.
			do_action(
				'wp_sam_forbidden_directive_stripped',
				array_keys( $forbidden_found ),
				$surface
			);
		}

		// Inject nonce into script-src and style-src.
		if ( ! empty( $nonce ) ) {
			foreach ( array( 'script-src', 'script-src-elem', 'style-src', 'style-src-elem' ) as $dir ) {
				if ( isset( $directives[ $dir ] ) && is_array( $directives[ $dir ] ) ) {
					$directives[ $dir ][] = "'nonce-{$nonce}'";
				}
			}
		}

		// Append approved hashes from inventory. Applied to both the base directive
		// and its -elem counterpart (mirrors the nonce injection above): script-src-elem
		// and style-src-elem are always explicitly present (see default_directives()),
		// and per CSP3, once an -elem directive is explicitly set it has exclusive
		// authority over element-level checks -- the base directive is never
		// consulted as a fallback. A hash recorded only under the base directive
		// (Hash_Manager stores 'script-src'/'style-src') would therefore never
		// actually allow the inline block it was approved for.
		//
		// Directives already scoped to attribute context (style-src-attr) apply
		// only to themselves -- there is no "style-src-attr-elem" counterpart.
		// Note: a hash recorded under style-src-attr has no effect unless the
		// admin has also enabled the style_src_attr_unsafe_hashes bypass entry
		// below (CSP3 §6.1.2) -- captured hashes sit inert until then, same as
		// they did before any hash-capture support existed.
		$hashes            = $this->load_approved_hashes( $surface );
		$hash_budget_bytes = (int) apply_filters( 'wp_sam_max_hash_token_budget_bytes', self::MAX_HASH_TOKEN_BUDGET_BYTES, $surface );
		$hash_bytes_used   = 0;
		$hashes_dropped    = 0;

		foreach ( $hashes as $hash ) {
			$hash_token = "'{$hash['hash_algo']}-{$hash['hash_value']}'";
			$base_dir   = $hash['directive'];
			$targets    = str_ends_with( $base_dir, '-attr' )
				? array( $base_dir )
				: array( $base_dir, $base_dir . '-elem' );

			// Worst-case byte cost of admitting this hash: the token is
			// appended once per target directive (twice for script-src/
			// style-src, once for the -attr directives), plus one joining
			// space each.
			$token_cost = ( strlen( $hash_token ) + 1 ) * count( $targets );

			if ( $hash_bytes_used + $token_cost > $hash_budget_bytes ) {
				// load_approved_hashes() returns most-recently-seen first,
				// so everything reached here is older -- drop oldest first
				// under budget pressure rather than truncate arbitrarily.
				++$hashes_dropped;
				continue;
			}
			$hash_bytes_used += $token_cost;

			foreach ( $targets as $dir ) {
				if ( isset( $directives[ $dir ] ) && is_array( $directives[ $dir ] ) ) {
					$directives[ $dir ][] = $hash_token;
				}
			}
		}

		if ( $hashes_dropped > 0 ) {
			$this->log_once_per_hour(
				$surface,
				'hash_budget_exceeded',
				'policy_builder',
				sprintf(
					'Dropped %1$d least-recently-seen approved hash(es) for surface "%2$s" to keep the emitted header under the safety byte budget. This usually means csp_hash_inventory is growing unbounded for this surface -- check for an inline script/style whose content varies every request and never matches Hash_Manager\'s exact-content dedup.',
					$hashes_dropped,
					$surface
				),
				'warning'
			);
		}

		// When strict-dynamic is active, host-based allowlists in script-src(-elem) are
		// silently ignored by browsers (CSP3 §8.2). Suppress them to avoid misleading
		// noise. strict-dynamic must be added to script-src-elem as well as script-src:
		// script-src-elem is always explicitly present (see default_directives()), and
		// once it's set it has exclusive authority over <script> element checks -- a
		// strict-dynamic on script-src alone never reaches element-level enforcement,
		// so dynamically-inserted same-origin scripts (e.g. WP core's own
		// zxcvbn-async.js password-strength loader) are blocked even with
		// strict-dynamic "enabled".
		$skip_host_sources_for = array();
		if ( ! empty( $profile['strict_dynamic'] ) && $this->gate->is_allowed( 'strict_dynamic' ) ) {
			foreach ( array( 'script-src', 'script-src-elem' ) as $dir ) {
				if ( isset( $directives[ $dir ] ) && ! in_array( "'strict-dynamic'", $directives[ $dir ], true ) ) {
					$directives[ $dir ][] = "'strict-dynamic'";
				}
				$skip_host_sources_for[] = $dir;
			}
		}

		// Append approved source hosts from inventory.
		// FIX: use sanitize_text_field() not esc_attr() -- esc_attr() encodes
		// characters such as & that are invalid in HTTP header values.
		// FIX: prefix each host with its captured scheme (source_scheme, default
		// https) instead of emitting a bare host. A scheme-less CSP source token
		// matches that host on any scheme, including plain http; source_scheme
		// was already captured and stored at proposal time but never read back
		// out here, so every approved source silently lost its scheme.
		$sources = $this->load_approved_sources( $surface );
		foreach ( $sources as $src ) {
			$dir = $src['directive'];
			if ( in_array( $dir, $skip_host_sources_for, true ) ) {
				continue; // host allowlists ignored when strict-dynamic is present
			}
			if ( isset( $directives[ $dir ] ) && is_array( $directives[ $dir ] ) ) {
				$host   = sanitize_text_field( (string) $src['source_host'] );
				$scheme = strtolower( sanitize_text_field( (string) ( $src['source_scheme'] ?? '' ) ) );
				if ( '' === $scheme ) {
					$scheme = 'https';
				}
				$directives[ $dir ][] = "{$scheme}://{$host}";
			}
		}

		// sandbox is a document directive that browsers ignore in CSP-Report-Only and in
		// <meta http-equiv>. Only emit it in enforce mode. A null value means disabled.
		$is_report_only = ( 'report-only' === $profile['mode'] );
		if ( $is_report_only || ! isset( $directives['sandbox'] ) || null === $directives['sandbox'] ) {
			unset( $directives['sandbox'] );
		}

		// upgrade-insecure-requests has no effect on a policy delivered via the
		// Content-Security-Policy-Report-Only header -- browsers ignore it there,
		// same as sandbox above. Strip it in report-only mode rather than emit a
		// directive that does nothing and reads as misleading noise to an admin
		// or a CSP linter reviewing the header.
		if ( $is_report_only ) {
			unset( $directives['upgrade-insecure-requests'] );
		}

		// Per-surface "Bypass Best Practices" toggles (Profiles tab). See
		// BYPASS_CATALOG's docblock: entries span low through high risk,
		// but every one is individually reasoned about and requires this
		// explicit per-surface opt-in -- nothing here is ever automatic.
		$enabled_bypass_flags = json_decode( (string) ( $profile['bypass_flags'] ?? '' ), true );
		$enabled_bypass_flags = is_array( $enabled_bypass_flags ) ? $enabled_bypass_flags : array();
		foreach ( self::BYPASS_CATALOG as $flag => $entry ) {
			if ( ! in_array( $flag, $enabled_bypass_flags, true ) ) {
				continue;
			}
			$dir = $entry['directive'];
			if ( isset( $directives[ $dir ] ) && is_array( $directives[ $dir ] ) && ! in_array( $entry['token'], $directives[ $dir ], true ) ) {
				$directives[ $dir ][] = $entry['token'];
			}
		}

		// Always allow an empty inline attribute value -- see
		// EMPTY_CONTENT_HASH_TOKEN's docblock. Unconditional (not gated by
		// the BYPASS_CATALOG loop above): this doesn't turn on
		// 'unsafe-hashes' by itself, it only ever takes effect once a
		// surface's own opt-in for that has, same as any other captured
		// attribute hash.
		foreach ( array( 'script-src-attr', 'style-src-attr' ) as $attr_dir ) {
			if ( isset( $directives[ $attr_dir ] ) && is_array( $directives[ $attr_dir ] )
				&& ! in_array( self::EMPTY_CONTENT_HASH_TOKEN, $directives[ $attr_dir ], true )
			) {
				$directives[ $attr_dir ][] = self::EMPTY_CONTENT_HASH_TOKEN;
			}
		}

		// The per-surface Trusted Types toggle (Profiles tab) sets require-trusted-types-for
		// 'script' -- the one value this plugin's admin UI actually offers. An admin
		// wanting named policies or 'default'/'*' can still reach them via overrides.
		if ( ! empty( $profile['trusted_types'] ) ) {
			$directives['require-trusted-types-for'] = array( "'script'" );
		}

		// Trusted Types directives (require-trusted-types-for, trusted-types) are disabled
		// when their value list is empty. When enabled they are always emitted as report-only
		// regardless of surface mode (Chromium-strong; Baseline widely available ~2028).
		$trusted_types_enabled = ! empty( $directives['require-trusted-types-for'] )
			&& is_array( $directives['require-trusted-types-for'] );
		if ( ! $trusted_types_enabled ) {
			unset( $directives['require-trusted-types-for'] );
		}
		// trusted-types is independent of require-trusted-types-for and stripped
		// on its own empty check: emitting it with no policy names is at best
		// meaningless and at worst reads as "trusted-types 'none'" -- neither is
		// what an admin who only enabled require-trusted-types-for intended.
		if ( empty( $directives['trusted-types'] ) || ! is_array( $directives['trusted-types'] ) ) {
			unset( $directives['trusted-types'] );
		}

		// Append direct reporting by default. Reporting API is opt-in because some
		// browsers ignore report-uri when report-to is present, which delays learning.
		$reporting_transport = $this->get_reporting_transport();
		if ( self::REPORTING_TRANSPORT_API !== $reporting_transport ) {
			$directives['report-uri'] = array( Reporting_Endpoint::url() );
		}
		if ( in_array( $reporting_transport, array( self::REPORTING_TRANSPORT_API, self::REPORTING_TRANSPORT_BOTH ), true ) ) {
			$directives['report-to'] = array( Reporting_Endpoint::GROUP_NAME );
		}

		$directives = $this->normalize_none_sources( $directives );

		// Serialise: each directive becomes "name src1 src2 src3".
		// An empty source list (e.g. upgrade-insecure-requests) serialises to just
		// the directive name, which is the correct form for boolean directives.
		$parts = array();
		foreach ( $directives as $directive => $sources_list ) {
			if ( ! is_array( $sources_list ) ) {
				continue;
			}
			$sources_list = array_unique( array_filter( $sources_list ) );
			$parts[]      = trim( $directive . ' ' . implode( ' ', $sources_list ) );
		}

		$policy = implode( '; ', $parts );

		// Last-resort safety net: even after the hash budget above, an
		// unusually large admin override or approved-source list could
		// still push the policy past common web-server response-header
		// field limits. Emitting no header for this surface/request is
		// strictly safer than risking the entire response being rejected
		// by the web server.
		$max_policy_bytes = (int) apply_filters( 'wp_sam_max_policy_string_bytes', self::MAX_POLICY_STRING_BYTES, $surface );
		if ( strlen( $policy ) > $max_policy_bytes ) {
			$this->log_once_per_hour(
				$surface,
				'policy_too_large',
				'policy_builder',
				sprintf(
					'Refused to emit a %1$d-byte Content-Security-Policy header for surface "%2$s" -- exceeds the %3$d-byte safety ceiling even after hash pruning. No CSP header was sent for this request rather than risk the web server rejecting the entire response.',
					strlen( $policy ),
					$surface,
					$max_policy_bytes
				),
				'error'
			);
			return '';
		}

		return $policy;
	}

	/**
	 * Logs an audit event at most once per rolling hour, per surface+event
	 * combination. build_policy_string() runs on every request, so without
	 * this a surface stuck over budget (e.g. while csp_hash_inventory works
	 * through Hash_Manager::prune_stale_by_age()'s age-based cleanup) would
	 * write one audit_log row and one error_log line per pageview --
	 * confirmed in production, 2026-08-19: two near-identical
	 * hash_budget_exceeded rows five minutes apart from two ordinary page
	 * loads. Uses a transient counter rather than a DB query so the check
	 * stays cheap on every request while a surface is over budget --
	 * exactly the situation already generating the most load.
	 */
	private function log_once_per_hour( string $surface, string $event, string $component, string $detail, string $severity ): void {
		if ( null === $this->audit ) {
			return;
		}

		$key = 'wp_sam_policy_log_' . $event . '_' . $surface . '_' . gmdate( 'YmdH' );
		if ( get_transient( $key ) ) {
			return;
		}

		set_transient( $key, 1, HOUR_IN_SECONDS );
		$this->audit->log( $component, $event, $detail, $severity );
	}

	private function normalize_none_sources( array $directives ): array {
		foreach ( $directives as $directive => $sources_list ) {
			if ( ! is_array( $sources_list ) || count( array_filter( $sources_list ) ) < 2 ) {
				continue;
			}

			$without_none = array_values(
				array_filter(
					$sources_list,
					static fn ( mixed $source ): bool => "'none'" !== (string) $source
				)
			);

			if ( count( $without_none ) !== count( $sources_list ) && ! empty( $without_none ) ) {
				$directives[ $directive ] = $without_none;
			}
		}

		return $directives;
	}

	// ── DB reads ──────────────────────────────────────────────────────────────

	protected function load_profile( string $surface ): ?array {
		global $wpdb;
		$table = $wpdb->prefix . 'csp_policy_profiles';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE surface = %s LIMIT 1", $surface ), ARRAY_A );
		return ! empty( $row ) ? $row : null;
	}

	protected function load_approved_hashes( string $surface ): array {
		if ( null !== $this->hash_loader ) {
			return ( $this->hash_loader )( $surface );
		}
		global $wpdb;
		$table = $wpdb->prefix . 'csp_hash_inventory';
		// ORDER BY last_seen_at DESC, id DESC: the hash-append loop in
		// build_policy_string() relies on most-recently-seen rows coming
		// first, so its byte-budget cutoff drops the oldest hashes rather
		// than an arbitrary subset. `last_seen_at` is a datetime column
		// (one-second resolution) and many rows commonly get bumped to the
		// exact same second by the same page render, so ORDER BY on that
		// column alone leaves the relative order of everything tied on a
		// timestamp unspecified by SQL -- confirmed in production,
		// 2026-08-19: the same ~1,027-row backlog produced a
		// "Dropped 34" cutoff on one request and "Dropped 985" on another
		// moments later, because the arbitrary tie order happened to place
		// a different mix of cheap (style-src-attr, single-directive) vs
		// expensive (script-src/style-src, doubled) hashes before the
		// cutoff each time. `id DESC` breaks ties deterministically (a
		// row's id never changes on reactivation), so the same DB state
		// now always produces the same cutoff, not just "some" cutoff.
		// The LIMIT is a generous, defense-in-depth ceiling on rows loaded
		// into PHP memory in the first place -- not the primary safety
		// mechanism (that's the byte budget) -- so it's set well above
		// MAX_HASH_TOKEN_BUDGET_BYTES could ever actually use.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT directive, hash_algo, hash_value FROM {$table} WHERE surface = %s AND status = 'active' ORDER BY last_seen_at DESC, id DESC LIMIT 2000",
				$surface
			),
			ARRAY_A
		);
		return ! empty( $rows ) ? $rows : array();
	}

	protected function load_approved_sources( string $surface ): array {
		if ( null !== $this->source_loader ) {
			return ( $this->source_loader )( $surface );
		}
		global $wpdb;
		$table = $wpdb->prefix . 'csp_source_inventory';
		$rows  = $wpdb->get_results(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT directive, source_host, source_scheme FROM {$table} WHERE surface = %s AND approval_state = 'approved'",
				$surface
			),
			ARRAY_A
		);
		return ! empty( $rows ) ? $rows : array();
	}
}
