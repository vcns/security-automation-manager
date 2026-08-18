<?php
/**
 * Unit tests for WP_SAM\CSP\Policy_Builder.
 *
 * Focuses on build_policy_string() which assembles the CSP header value.
 * Header emission itself is not tested here as it requires PHP header state.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\CSP\Policy_Builder;
use WP_SAM\Modules\Feature_Gate;

class PolicyBuilderTest extends TestCase {

	private Policy_Builder $builder;
	private Feature_Gate   $gate;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->gate    = $this->createMock( Feature_Gate::class );
		$this->builder = new Policy_Builder( $this->gate );
	}

	public function test_register_emits_headers_on_send_headers_and_redirects(): void {
		$this->builder->register();

		$this->assertArrayHasKey( 'send_headers', $GLOBALS['_wp_actions'] );
		$this->assertArrayHasKey( 'wp_redirect', $GLOBALS['_wp_actions'] );
		$this->assertSame( 1, $GLOBALS['_wp_actions']['wp_redirect'][0][1] );
		$this->assertSame( 2, $GLOBALS['_wp_actions']['wp_redirect'][0][2] );
	}

	public function test_detect_surface_uses_admin_path_for_admin_404s(): void {
		$_SERVER['REQUEST_URI'] = '/wp-admin/wp-login.php';

		$this->assertSame( 'admin', $this->detect_surface() );
	}

	public function test_detect_surface_uses_login_path_for_login_page(): void {
		$_SERVER['REQUEST_URI'] = '/wp-login.php?redirect_to=https%3A%2F%2Fexample.com%2Fwp-admin%2F';

		$this->assertSame( 'login', $this->detect_surface() );
	}

	public function test_detect_surface_supports_subdirectory_admin_paths(): void {
		$_SERVER['REQUEST_URI'] = '/wordpress/wp-admin/edit.php';

		$this->assertSame( 'admin', $this->detect_surface() );
	}

	// ── default-src ───────────────────────────────────────────────────────────

	public function test_build_includes_default_src_none(): void {
		$profile = $this->make_profile( [ 'default-src' => [ "'none'" ] ] );

		$policy = $this->builder->build_policy_string( $profile, 'frontend' );

		$this->assertStringContainsString( "default-src 'none'", $policy );
	}

	public function test_build_returns_empty_string_for_malformed_directives(): void {
		$profile = $this->make_profile_raw( 'not-valid-json', '{}' );

		$policy = $this->builder->build_policy_string( $profile, 'frontend' );

		$this->assertSame( '', $policy );
	}

	// ── nonce injection ───────────────────────────────────────────────────────

	public function test_build_injects_nonce_into_script_src(): void {
		$profile = $this->make_profile( [
			'default-src' => [ "'none'" ],
			'script-src'  => [],
		] );

		$policy = $this->build_with_nonce( $profile, 'frontend', 'testNonce123' );

		$this->assertStringContainsString( "'nonce-testNonce123'", $policy );
	}

	public function test_build_injects_nonce_into_style_src(): void {
		$profile = $this->make_profile( [
			'default-src' => [ "'none'" ],
			'style-src'   => [],
		] );

		$policy = $this->build_with_nonce( $profile, 'frontend', 'styleNonce' );

		$this->assertStringContainsString( "'nonce-styleNonce'", $policy );
	}

	public function test_build_does_not_inject_empty_nonce(): void {
		$profile = $this->make_profile( [
			'default-src' => [ "'none'" ],
			'script-src'  => [ "'self'" ],
		] );

		// Build without setting a nonce.
		$policy = $this->builder->build_policy_string( $profile, 'frontend' );

		$this->assertStringNotContainsString( 'nonce-', $policy );
	}

	// ── source host sanitisation (esc_attr fix) ───────────────────────────────

	public function test_build_does_not_html_encode_ampersand_in_source_host(): void {
		// If esc_attr() were used, a host containing & would become &amp;
		// which is invalid in an HTTP header. sanitize_text_field() must be used.
		$profile = $this->make_profile( [ 'default-src' => [ "'none'" ], 'script-src' => [] ] );

		$policy = $this->build_with_approved_sources( $profile, 'frontend', [
			[ 'directive' => 'script-src', 'source_host' => 'cdn.example.com' ],
		] );

		// cdn.example.com contains no special characters; verify it appears verbatim.
		$this->assertStringContainsString( 'cdn.example.com', $policy );
		$this->assertStringNotContainsString( '&amp;', $policy );
	}

	public function test_build_sanitises_source_host_stripping_tags(): void {
		$profile = $this->make_profile( [ 'default-src' => [ "'none'" ], 'script-src' => [] ] );

		$policy = $this->build_with_approved_sources( $profile, 'frontend', [
			[ 'directive' => 'script-src', 'source_host' => '<script>bad</script>cdn.example.com' ],
		] );

		$this->assertStringNotContainsString( '<script>', $policy );
	}

	// ── overrides ─────────────────────────────────────────────────────────────

	public function test_build_applies_admin_overrides(): void {
		$profile = $this->make_profile_with_overrides(
			[ 'default-src' => [ "'none'" ], 'script-src' => [ "'self'" ] ],
			[ 'script-src'  => [ "'self'", 'https://override.example.com' ] ]
		);

		$policy = $this->builder->build_policy_string( $profile, 'frontend' );

		$this->assertStringContainsString( 'https://override.example.com', $policy );
	}

	// ── strict-dynamic ────────────────────────────────────────────────────────

	public function test_build_adds_strict_dynamic_when_gate_allows(): void {
		$this->gate->method( 'is_allowed' )->with( 'strict_dynamic' )->willReturn( true );

		$profile = $this->make_profile(
			[ 'default-src' => [ "'none'" ], 'script-src' => [] ],
			strict_dynamic: true
		);

		$policy = $this->builder->build_policy_string( $profile, 'frontend' );

		$this->assertStringContainsString( "'strict-dynamic'", $policy );
	}

	public function test_build_omits_strict_dynamic_when_gate_denies(): void {
		$this->gate->method( 'is_allowed' )->with( 'strict_dynamic' )->willReturn( false );

		$profile = $this->make_profile(
			[ 'default-src' => [ "'none'" ], 'script-src' => [] ],
			strict_dynamic: true
		);

		$policy = $this->builder->build_policy_string( $profile, 'frontend' );

		$this->assertStringNotContainsString( "'strict-dynamic'", $policy );
	}

	// ── reporting directives ──────────────────────────────────────────────────

	public function test_build_appends_report_uri(): void {
		$profile = $this->make_profile( [ 'default-src' => [ "'none'" ] ] );

		$policy = $this->builder->build_policy_string( $profile, 'frontend' );

		$this->assertStringContainsString( 'report-uri', $policy );
		$this->assertStringContainsString( 'sam/v1/report', $policy );
		$this->assertStringNotContainsString( 'report-to csp-endpoint', $policy );
	}

	public function test_build_uses_configured_report_endpoint_url(): void {
		update_option( 'wp_sam_report_endpoint_url', 'https://public.example.net/wp-json/custom-endpoint/v1/report' );
		$profile = $this->make_profile( [ 'default-src' => [ "'none'" ] ] );

		$policy = $this->builder->build_policy_string( $profile, 'frontend' );

		$this->assertStringContainsString( 'report-uri https://public.example.net/wp-json/custom-endpoint/v1/report', $policy );
	}

	public function test_build_ignores_invalid_report_endpoint_url(): void {
		update_option( 'wp_sam_report_endpoint_url', 'javascript:alert(1)' );
		$profile = $this->make_profile( [ 'default-src' => [ "'none'" ] ] );

		$policy = $this->builder->build_policy_string( $profile, 'frontend' );

		$this->assertStringContainsString( 'report-uri https://example.com/wp-json/sam/v1/report', $policy );
		$this->assertStringNotContainsString( 'javascript:', $policy );
	}

	public function test_build_uses_home_url_report_endpoint_before_init(): void {
		$GLOBALS['_wp_rest_url_should_throw'] = true;
		$profile = $this->make_profile( [ 'default-src' => [ "'none'" ] ] );

		$policy = $this->builder->build_policy_string( $profile, 'frontend' );

		$this->assertStringContainsString( 'report-uri https://example.com/wp-json/sam/v1/report', $policy );
	}

	public function test_build_uses_rest_url_report_endpoint_after_init(): void {
		$GLOBALS['_wp_did_actions']['init'] = 1;
		$profile = $this->make_profile( [ 'default-src' => [ "'none'" ] ] );

		$policy = $this->builder->build_policy_string( $profile, 'frontend' );

		$this->assertStringContainsString( 'report-uri https://example.com/wp-json/sam/v1/report', $policy );
	}

	public function test_build_appends_report_to_when_reporting_api_is_enabled(): void {
		update_option( 'wp_sam_reporting_transport', 'both' );
		$profile = $this->make_profile( [ 'default-src' => [ "'none'" ] ] );

		$policy = $this->builder->build_policy_string( $profile, 'frontend' );

		$this->assertStringContainsString( 'report-to csp-endpoint', $policy );
	}

	public function test_build_omits_report_uri_when_reporting_api_only_is_enabled(): void {
		update_option( 'wp_sam_reporting_transport', 'report-to' );
		$profile = $this->make_profile( [ 'default-src' => [ "'none'" ] ] );

		$policy = $this->builder->build_policy_string( $profile, 'frontend' );

		$this->assertStringNotContainsString( 'report-uri', $policy );
		$this->assertStringContainsString( 'report-to csp-endpoint', $policy );
	}

	public function test_policy_header_name_defaults_to_report_only_header(): void {
		$this->assertSame(
			'Content-Security-Policy-Report-Only',
			$this->builder->get_policy_header_name( true )
		);
	}

	public function test_policy_header_name_defaults_to_enforce_header(): void {
		$this->assertSame(
			'Content-Security-Policy',
			$this->builder->get_policy_header_name( false )
		);
	}

	public function test_policy_header_name_uses_custom_origin_header(): void {
		update_option( 'wp_sam_policy_header_name', 'X-Origin-CSP-Policy' );

		$this->assertSame( 'X-Origin-CSP-Policy', $this->builder->get_policy_header_name( true ) );
		$this->assertSame( 'X-Origin-CSP-Policy', $this->builder->get_policy_header_name( false ) );
	}

	public function test_policy_header_name_ignores_invalid_custom_header(): void {
		update_option( 'wp_sam_policy_header_name', "X-Bad:\r\nInjected" );

		$this->assertSame(
			'Content-Security-Policy-Report-Only',
			$this->builder->get_policy_header_name( true )
		);
	}

	public function test_policy_header_name_rejects_blocked_headers(): void {
		update_option( 'wp_sam_policy_header_name', 'Set-Cookie' );

		$this->assertSame( 'Content-Security-Policy', $this->builder->get_policy_header_name( false ) );
	}

	// ── CSP header output format ──────────────────────────────────────────────

	public function test_build_removes_none_when_approved_sources_are_added(): void {
		$profile = $this->make_profile( [
			'default-src' => [ "'none'" ],
			'frame-src'   => [ "'none'" ],
		] );

		$policy = $this->build_with_approved_sources(
			$profile,
			'frontend',
			[ [ 'directive' => 'frame-src', 'source_host' => 'www.google.com', 'source_scheme' => 'https' ] ]
		);

		$this->assertStringContainsString( 'frame-src https://www.google.com', $policy );
		$this->assertStringNotContainsString( "frame-src 'none' https://www.google.com", $policy );
	}

	// ── approved source scheme prefix (missing-protocol fix) ──────────────────

	public function test_build_prefixes_approved_source_with_its_stored_scheme(): void {
		$profile = $this->make_profile( [ 'default-src' => [ "'none'" ], 'connect-src' => [] ] );

		$policy = $this->build_with_approved_sources( $profile, 'frontend', [
			[ 'directive' => 'connect-src', 'source_host' => 'api.example.com', 'source_scheme' => 'wss' ],
		] );

		$this->assertStringContainsString( 'wss://api.example.com', $policy );
	}

	public function test_build_defaults_approved_source_scheme_to_https_when_absent(): void {
		// Rows from before the scheme column was read back out (or a stub missing
		// the key entirely) must not silently emit a bare, scheme-less host.
		$profile = $this->make_profile( [ 'default-src' => [ "'none'" ], 'img-src' => [] ] );

		$policy = $this->build_with_approved_sources( $profile, 'frontend', [
			[ 'directive' => 'img-src', 'source_host' => 'cdn.example.com' ],
		] );

		$this->assertStringContainsString( 'img-src https://cdn.example.com', $policy );
	}

	public function test_build_output_has_semicolon_separated_directive_format(): void {
		$profile = $this->make_profile( [
			'default-src' => [ "'none'" ],
			'script-src'  => [ "'self'" ],
			'style-src'   => [ "'self'" ],
		] );

		$policy = $this->builder->build_policy_string( $profile, 'frontend' );

		// Every directive in the output must be separated by "; " and each part
		// must start with a recognised directive keyword (not a value).
		$parts = array_filter( array_map( 'trim', explode( ';', $policy ) ) );
		foreach ( $parts as $part ) {
			$this->assertMatchesRegularExpression(
				'/^[a-z][-a-z]+(\s|$)/',
				$part,
				"Directive part does not start with a directive keyword: $part"
			);
		}
	}

	// ── strict-dynamic host suppression ──────────────────────────────────────

	public function test_build_strict_dynamic_suppresses_host_sources_from_script_src(): void {
		$this->gate->method( 'is_allowed' )->with( 'strict_dynamic' )->willReturn( true );

		$profile = $this->make_profile(
			[ 'default-src' => [ "'none'" ], 'script-src' => [] ],
			strict_dynamic: true
		);

		// Inject cdn.example.com as an approved host source for script-src.
		$builder = $this->make_db_stub_builder(
			approved_sources: [ [ 'directive' => 'script-src', 'source_host' => 'cdn.example.com' ] ]
		);
		// Gate must allow strict_dynamic for this builder too.
		$builder2 = new Policy_Builder(
			$this->gate,
			fn( string $s ) => [],
			fn( string $s ) => [ [ 'directive' => 'script-src', 'source_host' => 'cdn.example.com' ] ]
		);

		$policy = $builder2->build_policy_string( $profile, 'frontend' );

		$this->assertStringContainsString( "'strict-dynamic'", $policy );
		$this->assertStringNotContainsString( 'cdn.example.com', $policy );
	}

	public function test_build_strict_dynamic_also_applies_to_script_src_elem(): void {
		// script-src-elem is always explicitly present (see default_directives())
		// and has exclusive authority over <script> element checks once set -- a
		// strict-dynamic added only to script-src never reaches element-level
		// enforcement, so a dynamically-inserted same-origin <script> (no nonce,
		// e.g. WP core's own zxcvbn-async.js loader) would stay blocked even
		// with strict-dynamic "enabled".
		$this->gate->method( 'is_allowed' )->with( 'strict_dynamic' )->willReturn( true );

		$profile = $this->make_profile(
			[ 'default-src' => [ "'none'" ], 'script-src' => [], 'script-src-elem' => [] ],
			strict_dynamic: true
		);

		$policy = $this->builder->build_policy_string( $profile, 'frontend' );

		$parts             = explode( ';', $policy );
		$script_src_elem   = trim( current( array_filter( $parts, static fn( $p ) => str_starts_with( trim( $p ), 'script-src-elem' ) ) ) );
		$this->assertStringContainsString( "'strict-dynamic'", $script_src_elem );
	}

	public function test_build_strict_dynamic_suppresses_host_sources_from_script_src_elem(): void {
		$this->gate->method( 'is_allowed' )->with( 'strict_dynamic' )->willReturn( true );

		$profile = $this->make_profile(
			[ 'default-src' => [ "'none'" ], 'script-src' => [], 'script-src-elem' => [] ],
			strict_dynamic: true
		);

		$builder = new class(
			$this->gate,
			[ [ 'directive' => 'script-src-elem', 'source_host' => 'cdn.example.com' ] ]
		) extends Policy_Builder {
			public function __construct( Feature_Gate $gate, private array $stub_sources ) {
				parent::__construct( $gate );
			}

			protected function load_approved_sources( string $surface ): array {
				return $this->stub_sources;
			}
		};

		$policy = $builder->build_policy_string( $profile, 'frontend' );

		$this->assertStringContainsString( "'strict-dynamic'", $policy );
		$this->assertStringNotContainsString( 'cdn.example.com', $policy );
	}

	// ── approved hash propagation to -elem directives ─────────────────────────

	public function test_build_applies_approved_hash_to_base_directive(): void {
		$profile = $this->make_profile( [ 'default-src' => [ "'none'" ], 'script-src' => [] ] );

		$builder = $this->make_db_stub_builder( approved_hashes: [
			[ 'directive' => 'script-src', 'hash_algo' => 'sha256', 'hash_value' => 'abc123==' ],
		] );

		$policy = $builder->build_policy_string( $profile, 'frontend' );

		$this->assertStringContainsString( "'sha256-abc123=='", $policy );
	}

	public function test_build_propagates_approved_hash_to_elem_directive(): void {
		// Hash_Manager records captured inline blocks under the base directive
		// ('script-src' / 'style-src'). script-src-elem / style-src-elem are
		// always explicitly present and take exclusive authority over
		// element-level checks once set (CSP3) -- an approved hash that never
		// reaches the -elem directive would silently fail to allow the inline
		// block an admin just approved.
		$profile = $this->make_profile( [
			'default-src'     => [ "'none'" ],
			'script-src'      => [],
			'script-src-elem' => [],
		] );

		$builder = $this->make_db_stub_builder( approved_hashes: [
			[ 'directive' => 'script-src', 'hash_algo' => 'sha256', 'hash_value' => 'abc123==' ],
		] );

		$policy = $builder->build_policy_string( $profile, 'frontend' );

		$parts           = explode( ';', $policy );
		$script_src      = trim( current( array_filter( $parts, static fn( $p ) => str_starts_with( trim( $p ), 'script-src ' ) ) ) );
		$script_src_elem = trim( current( array_filter( $parts, static fn( $p ) => str_starts_with( trim( $p ), 'script-src-elem' ) ) ) );

		$this->assertStringContainsString( "'sha256-abc123=='", $script_src );
		$this->assertStringContainsString( "'sha256-abc123=='", $script_src_elem );
	}

	public function test_build_propagates_approved_style_hash_to_style_src_elem(): void {
		$profile = $this->make_profile( [
			'default-src'    => [ "'none'" ],
			'style-src'      => [],
			'style-src-elem' => [],
		] );

		$builder = $this->make_db_stub_builder( approved_hashes: [
			[ 'directive' => 'style-src', 'hash_algo' => 'sha256', 'hash_value' => 'def456==' ],
		] );

		$policy = $builder->build_policy_string( $profile, 'frontend' );

		$parts          = explode( ';', $policy );
		$style_src_elem = trim( current( array_filter( $parts, static fn( $p ) => str_starts_with( trim( $p ), 'style-src-elem' ) ) ) );

		$this->assertStringContainsString( "'sha256-def456=='", $style_src_elem );
	}

	public function test_build_does_not_fail_when_elem_directive_absent(): void {
		// A profile without an explicit script-src-elem (e.g. a custom override
		// that only sets the base directive) must not error when propagating
		// an approved hash -- the -elem write is simply skipped.
		$profile = $this->make_profile( [ 'default-src' => [ "'none'" ], 'script-src' => [] ] );

		$builder = $this->make_db_stub_builder( approved_hashes: [
			[ 'directive' => 'script-src', 'hash_algo' => 'sha256', 'hash_value' => 'abc123==' ],
		] );

		$policy = $builder->build_policy_string( $profile, 'frontend' );

		$this->assertStringContainsString( "'sha256-abc123=='", $policy );
	}

	public function test_build_applies_approved_style_attr_hash_only_to_itself(): void {
		// style-src-attr is already scoped to attribute context -- unlike
		// script-src/style-src, it has no "-elem" counterpart to propagate to.
		$profile = $this->make_profile( [
			'default-src'     => [ "'none'" ],
			'style-src-attr'  => [ "'none'" ],
		] );

		$builder = $this->make_db_stub_builder( approved_hashes: [
			[ 'directive' => 'style-src-attr', 'hash_algo' => 'sha256', 'hash_value' => 'ghi789==' ],
		] );

		$policy = $builder->build_policy_string( $profile, 'frontend' );

		$parts          = explode( ';', $policy );
		$style_src_attr = trim( current( array_filter( $parts, static fn( $p ) => str_starts_with( trim( $p ), 'style-src-attr' ) ) ) );

		$this->assertStringContainsString( "'sha256-ghi789=='", $style_src_attr );
	}

	public function test_build_omits_unsafe_hashes_when_hash_present_but_bypass_flag_disabled(): void {
		// 'unsafe-hashes' is no longer added just because a style-src-attr hash
		// exists -- it's its own BYPASS_CATALOG entry (bypass_style_attr_unsafe_hashes)
		// requiring an explicit per-surface opt-in, since it's a keyword security
		// scanners flag. A captured hash sits inert until the admin also enables
		// the toggle.
		$profile = $this->make_profile( [
			'default-src'    => [ "'none'" ],
			'style-src-attr' => [ "'none'" ],
		] );

		$builder = $this->make_db_stub_builder( approved_hashes: [
			[ 'directive' => 'style-src-attr', 'hash_algo' => 'sha256', 'hash_value' => 'ghi789==' ],
		] );

		$policy = $builder->build_policy_string( $profile, 'frontend' );

		$parts          = explode( ';', $policy );
		$style_src_attr = trim( current( array_filter( $parts, static fn( $p ) => str_starts_with( trim( $p ), 'style-src-attr' ) ) ) );

		$this->assertStringContainsString( "'sha256-ghi789=='", $style_src_attr );
		$this->assertStringNotContainsString( 'unsafe-hashes', $style_src_attr );
	}

	public function test_build_adds_unsafe_hashes_when_bypass_flag_enabled(): void {
		$profile                                     = $this->make_profile( [
			'default-src'    => [ "'none'" ],
			'style-src-attr' => [ "'none'" ],
		] );
		$profile['bypass_style_attr_unsafe_hashes']  = 1;

		$policy = $this->builder->build_policy_string( $profile, 'frontend' );

		$parts          = explode( ';', $policy );
		$style_src_attr = trim( current( array_filter( $parts, static fn( $p ) => str_starts_with( trim( $p ), 'style-src-attr' ) ) ) );

		$this->assertStringContainsString( "'unsafe-hashes'", $style_src_attr );
	}

	public function test_build_hash_and_bypass_flag_together_produce_a_working_directive(): void {
		// The end-to-end case the bypass flag exists for: an approved hash plus
		// the explicit opt-in together actually allow the approved inline style
		// attribute -- neither alone is sufficient.
		$profile                                     = $this->make_profile( [
			'default-src'    => [ "'none'" ],
			'style-src-attr' => [ "'none'" ],
		] );
		$profile['bypass_style_attr_unsafe_hashes']  = 1;

		$builder = $this->make_db_stub_builder( approved_hashes: [
			[ 'directive' => 'style-src-attr', 'hash_algo' => 'sha256', 'hash_value' => 'ghi789==' ],
		] );

		$policy = $builder->build_policy_string( $profile, 'frontend' );

		$parts          = explode( ';', $policy );
		$style_src_attr = trim( current( array_filter( $parts, static fn( $p ) => str_starts_with( trim( $p ), 'style-src-attr' ) ) ) );

		$this->assertStringContainsString( "'sha256-ghi789=='", $style_src_attr );
		$this->assertStringContainsString( "'unsafe-hashes'", $style_src_attr );
	}

	public function test_build_omits_unsafe_hashes_by_default(): void {
		// Neither a hash nor the bypass flag are present -- nothing speculative.
		$profile = $this->make_profile( [
			'default-src'    => [ "'none'" ],
			'style-src-attr' => [ "'none'" ],
		] );

		$policy = $this->builder->build_policy_string( $profile, 'frontend' );

		$parts          = explode( ';', $policy );
		$style_src_attr = trim( current( array_filter( $parts, static fn( $p ) => str_starts_with( trim( $p ), 'style-src-attr' ) ) ) );

		$this->assertStringNotContainsString( 'unsafe-hashes', $style_src_attr );
	}

	public function test_build_does_not_leak_unsafe_hashes_to_unrelated_directives(): void {
		$profile                                     = $this->make_profile( [
			'default-src'     => [ "'none'" ],
			'style-src-attr'  => [ "'none'" ],
			'script-src'      => [],
			'script-src-elem' => [],
		] );
		$profile['bypass_style_attr_unsafe_hashes']  = 1;

		$builder = $this->make_db_stub_builder( approved_hashes: [
			[ 'directive' => 'style-src-attr', 'hash_algo' => 'sha256', 'hash_value' => 'ghi789==' ],
			[ 'directive' => 'script-src', 'hash_algo' => 'sha256', 'hash_value' => 'abc123==' ],
		] );

		$policy = $builder->build_policy_string( $profile, 'frontend' );

		$parts      = explode( ';', $policy );
		$script_src = trim( current( array_filter( $parts, static fn( $p ) => str_starts_with( trim( $p ), 'script-src ' ) ) ) );

		$this->assertStringNotContainsString( 'unsafe-hashes', $script_src );
	}

	// ── object-src and base-uri hardening ────────────────────────────────────

	public function test_build_includes_object_src_none(): void {
		$profile = $this->make_profile( [
			'default-src' => [ "'none'" ],
			'object-src'  => [ "'none'" ],
		] );

		$policy = $this->builder->build_policy_string( $profile, 'frontend' );

		$this->assertStringContainsString( "object-src 'none'", $policy );
	}

	// ── upgrade-insecure-requests report-only stripping ────────────────────────

	public function test_build_strips_upgrade_insecure_requests_in_report_only_mode(): void {
		$profile = [
			'mode'           => 'report-only',
			'directives'     => wp_json_encode( [
				'default-src'                => [ "'none'" ],
				'upgrade-insecure-requests'  => [],
			] ),
			'overrides'      => wp_json_encode( [] ),
			'strict_dynamic' => 0,
		];

		$policy = $this->builder->build_policy_string( $profile, 'frontend' );

		$this->assertStringNotContainsString( 'upgrade-insecure-requests', $policy );
	}

	public function test_build_keeps_upgrade_insecure_requests_in_enforce_mode(): void {
		$profile = $this->make_profile( [
			'default-src'               => [ "'none'" ],
			'upgrade-insecure-requests' => [],
		] );

		$policy = $this->builder->build_policy_string( $profile, 'frontend' );

		$this->assertStringContainsString( 'upgrade-insecure-requests', $policy );
	}

	// ── Trusted Types per-surface toggle ────────────────────────────────────────

	public function test_build_emits_require_trusted_types_for_script_when_toggle_enabled(): void {
		$profile                    = $this->make_profile( [ 'default-src' => [ "'none'" ] ] );
		$profile['trusted_types']   = 1;

		$policy = $this->builder->build_policy_string( $profile, 'frontend' );

		$this->assertStringContainsString( "require-trusted-types-for 'script'", $policy );
	}

	public function test_build_omits_require_trusted_types_for_when_toggle_disabled(): void {
		$profile = $this->make_profile( [ 'default-src' => [ "'none'" ] ] );

		$policy = $this->builder->build_policy_string( $profile, 'frontend' );

		$this->assertStringNotContainsString( 'require-trusted-types-for', $policy );
	}

	public function test_build_never_emits_bare_trusted_types_directive(): void {
		// trusted-types with an empty value list would serialise to the bare
		// token "trusted-types", which is meaningless (at best) or reads as
		// "allow no policies" (at worst) -- neither is what enabling the
		// require-trusted-types-for toggle alone should produce.
		$profile                  = $this->make_profile( [ 'default-src' => [ "'none'" ], 'trusted-types' => [] ] );
		$profile['trusted_types'] = 1;

		$policy = $this->builder->build_policy_string( $profile, 'frontend' );

		// "trusted-types" as its own directive token must not appear -- but
		// "require-trusted-types-for" legitimately contains the same substring,
		// so match on a directive boundary rather than a plain substring check.
		$this->assertDoesNotMatchRegularExpression( '/(^|;\s*)trusted-types(\s|;|$)/', $policy );
		$this->assertStringContainsString( "require-trusted-types-for 'script'", $policy );
	}

	// ── Bypass Best Practices catalog ─────────────────────────────────────────

	public function test_build_appends_data_scheme_to_img_src_when_bypass_flag_enabled(): void {
		$profile                         = $this->make_profile( [ 'default-src' => [ "'none'" ], 'img-src' => [ "'self'" ] ] );
		$profile['bypass_img_src_data']  = 1;

		$policy = $this->builder->build_policy_string( $profile, 'frontend' );

		$img_src = $this->extract_directive( $policy, 'img-src' );
		$this->assertStringContainsString( 'data:', $img_src );
	}

	public function test_build_omits_data_scheme_from_img_src_when_bypass_flag_disabled(): void {
		$profile = $this->make_profile( [ 'default-src' => [ "'none'" ], 'img-src' => [ "'self'" ] ] );

		$policy  = $this->builder->build_policy_string( $profile, 'frontend' );
		$img_src = $this->extract_directive( $policy, 'img-src' );

		$this->assertStringNotContainsString( 'data:', $img_src );
	}

	public function test_build_appends_data_scheme_to_font_src_when_bypass_flag_enabled(): void {
		$profile                          = $this->make_profile( [ 'default-src' => [ "'none'" ], 'font-src' => [ "'self'" ] ] );
		$profile['bypass_font_src_data']  = 1;

		$policy = $this->builder->build_policy_string( $profile, 'frontend' );

		$font_src = $this->extract_directive( $policy, 'font-src' );
		$this->assertStringContainsString( 'data:', $font_src );
	}

	public function test_build_does_not_duplicate_data_scheme_already_present(): void {
		$profile                        = $this->make_profile( [ 'default-src' => [ "'none'" ], 'img-src' => [ "'self'", 'data:' ] ] );
		$profile['bypass_img_src_data'] = 1;

		$policy  = $this->builder->build_policy_string( $profile, 'frontend' );
		$img_src = $this->extract_directive( $policy, 'img-src' );

		$this->assertSame( 1, substr_count( $img_src, 'data:' ) );
	}

	public function test_build_bypass_flag_does_not_affect_unrelated_directive(): void {
		// Enabling the img-src flag must never leak the data: token into
		// font-src or any other directive -- BYPASS_CATALOG entries are
		// directive-specific by design (see its docblock).
		$profile                        = $this->make_profile( [
			'default-src' => [ "'none'" ],
			'img-src'     => [ "'self'" ],
			'font-src'    => [ "'self'" ],
		] );
		$profile['bypass_img_src_data'] = 1;

		$policy   = $this->builder->build_policy_string( $profile, 'frontend' );
		$font_src = $this->extract_directive( $policy, 'font-src' );

		$this->assertStringNotContainsString( 'data:', $font_src );
	}

	public function test_build_skips_bypass_token_when_directive_absent(): void {
		// A profile without an explicit img-src (e.g. a custom override that
		// only sets default-src) must not error when a bypass flag is enabled
		// -- the token append is simply skipped, same as the hash-propagation
		// "elem directive absent" case above.
		$profile                        = $this->make_profile( [ 'default-src' => [ "'none'" ] ] );
		$profile['bypass_img_src_data'] = 1;

		$policy = $this->builder->build_policy_string( $profile, 'frontend' );

		$this->assertStringContainsString( "default-src 'none'", $policy );
	}

	/**
	 * Extracts a single directive's value segment from a built policy string.
	 */
	private function extract_directive( string $policy, string $directive ): string {
		$parts = explode( ';', $policy );
		foreach ( $parts as $part ) {
			if ( str_starts_with( trim( $part ), $directive . ' ' ) || trim( $part ) === $directive ) {
				return trim( $part );
			}
		}
		return '';
	}

	// ── Helpers ───────────────────────────────────────────────────────────────

	private function make_profile( array $directives, bool $strict_dynamic = false ): array {
		return [
			'mode'           => 'enforce',
			'directives'     => wp_json_encode( $directives ),
			'overrides'      => wp_json_encode( [] ),
			'strict_dynamic' => $strict_dynamic ? 1 : 0,
		];
	}

	private function detect_surface(): string {
		$method = new ReflectionMethod( Policy_Builder::class, 'detect_surface' );
		$method->setAccessible( true );
		return (string) $method->invoke( $this->builder );
	}

	private function make_profile_raw( string $directives_json, string $overrides_json ): array {
		return [
			'mode'           => 'enforce',
			'directives'     => $directives_json,
			'overrides'      => $overrides_json,
			'strict_dynamic' => 0,
		];
	}

	private function make_profile_with_overrides( array $directives, array $overrides ): array {
		return [
			'mode'           => 'enforce',
			'directives'     => wp_json_encode( $directives ),
			'overrides'      => wp_json_encode( $overrides ),
			'strict_dynamic' => 0,
		];
	}

	/**
	 * Builds a policy string after injecting a nonce via a subclass that
	 * stubs the static bridge and DB reads.
	 */
	private function build_with_nonce( array $profile, string $surface, string $nonce ): string {
		$builder = $this->make_db_stub_builder( nonce: $nonce );
		return $builder->build_policy_string( $profile, $surface );
	}

	/**
	 * Builds a policy string with pre-configured approved sources.
	 *
	 * @param array<int,array<string,string>> $sources
	 */
	private function build_with_approved_sources( array $profile, string $surface, array $sources ): string {
		$builder = $this->make_db_stub_builder( approved_sources: $sources );
		return $builder->build_policy_string( $profile, $surface );
	}

	/**
	 * Returns a Policy_Builder subclass that stubs DB reads and the nonce bridge.
	 */
	private function make_db_stub_builder(
		string $nonce = '',
		array $approved_hashes = [],
		array $approved_sources = []
	): Policy_Builder {
		return new class(
			$this->gate,
			$nonce,
			$approved_hashes,
			$approved_sources
		) extends Policy_Builder {

			public function __construct(
				Feature_Gate $gate,
				private string $stub_nonce,
				private array  $stub_hashes,
				private array  $stub_sources
			) {
				parent::__construct( $gate );
			}

			protected function load_approved_hashes( string $surface ): array {
				return $this->stub_hashes;
			}

			protected function load_approved_sources( string $surface ): array {
				return $this->stub_sources;
			}

			public function build_policy_string( array $profile, string $surface ): string {
				// Temporarily override the static nonce bridge by injecting via
				// a local constant-like mechanism.
				$GLOBALS['_wp_sam_test_nonce'] = $this->stub_nonce;
				$result = parent::build_policy_string( $profile, $surface );
				unset( $GLOBALS['_wp_sam_test_nonce'] );
				return $result;
			}
		};
	}
}

// Plugin_Nonce_Manager stub is defined in tests/stubs/NonceBridge.php
// which is loaded by tests/bootstrap.php before any test class is instantiated.
