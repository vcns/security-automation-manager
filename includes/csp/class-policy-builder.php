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
 *     (there is no -elem counterpart for an attribute-scoped directive), and
 *     'unsafe-hashes' is added automatically wherever an *-attr directive
 *     receives at least one hash (CSP3 §6.1.2 requires it for attribute-context
 *     hash matching).
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
	 * Directives removed or deprecated by W3C that must never be emitted.
	 * References: CSP3 WD-20260505; MDN; research.md R4.
	 */
	private const FORBIDDEN_DIRECTIVES = array(
		'plugin-types',           // removed; plugins are gone from the web platform
		'block-all-mixed-content', // obsolete; superseded by default browser auto-upgrade
		'navigate-to',            // removed from CSP3 spec (was at-risk)
		'prefetch-src',           // deprecated/non-standard; Chromium intent-to-remove
	);

	private Feature_Gate $gate;

	/** @var callable|null */
	private $hash_loader;

	/** @var callable|null */
	private $source_loader;

	public function __construct(
		Feature_Gate $gate,
		?callable $hash_loader = null,
		?callable $source_loader = null
	) {
		$this->gate          = $gate;
		$this->hash_loader   = $hash_loader;
		$this->source_loader = $source_loader;
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
		$hashes                      = $this->load_approved_hashes( $surface );
		$attr_directives_with_hashes = array();
		foreach ( $hashes as $hash ) {
			$hash_token = "'{$hash['hash_algo']}-{$hash['hash_value']}'";
			$base_dir   = $hash['directive'];
			$targets    = str_ends_with( $base_dir, '-attr' )
				? array( $base_dir )
				: array( $base_dir, $base_dir . '-elem' );

			foreach ( $targets as $dir ) {
				if ( isset( $directives[ $dir ] ) && is_array( $directives[ $dir ] ) ) {
					$directives[ $dir ][] = $hash_token;
					if ( str_ends_with( $dir, '-attr' ) ) {
						$attr_directives_with_hashes[ $dir ] = true;
					}
				}
			}
		}

		// A hash source only takes effect in an attribute context (style
		// attributes, event handlers, javascript: URLs) when 'unsafe-hashes' is
		// also present in the directive -- CSP3 §6.1.2. Add it only to *-attr
		// directives that actually received a hash, so the bypass stays scoped
		// to exactly the approved content rather than being added speculatively.
		foreach ( array_keys( $attr_directives_with_hashes ) as $dir ) {
			if ( ! in_array( "'unsafe-hashes'", $directives[ $dir ], true ) ) {
				$directives[ $dir ][] = "'unsafe-hashes'";
			}
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

		return implode( '; ', $parts );
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
		$rows  = $wpdb->get_results(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT directive, hash_algo, hash_value FROM {$table} WHERE surface = %s AND status = 'active'",
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
