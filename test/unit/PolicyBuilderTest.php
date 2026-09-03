<?php
/**
 * Unit tests for WP_SAM\CSP\Policy_Builder.
 *
 * Focuses on build_policy_string() which assembles the CSP header value.
 * Header emission itself is not tested here as it requires PHP header state.
 *
 * Policy input is stubbed via Stub_Policy_Data_Loader (test/unit/
 * Stub_Policy_Data_Loader.php), never by subclassing Policy_Builder
 * itself (GitHub issue #170) -- direct SQL/query-shape coverage for the
 * real data-loading implementation now lives in
 * test/unit/WpdbPolicyDataLoaderTest.php instead.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\CSP\Policy_Builder;
use WP_SAM\CSP\Policy_Data_Loader;
use WP_SAM\Modules\Audit_Log;
use WP_SAM\Modules\Feature_Gate;

class PolicyBuilderTest extends TestCase {

	private Policy_Builder $builder;
	private Feature_Gate   $gate;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->gate    = $this->createMock( Feature_Gate::class );
		$this->builder = new Policy_Builder( $this->gate );
	}

	// ── Policy_Data_Loader dependency boundary (GitHub issue #170) ───────────

	/**
	 * Confirms the constructor's default collaborator is a real, working
	 * Wpdb_Policy_Data_Loader when none is injected -- production wiring
	 * (Plugin::bootstrap()) never passes one explicitly, so this is what
	 * every real WordPress request actually gets.
	 */
	public function test_load_profile_defaults_to_the_real_wpdb_backed_loader(): void {
		$GLOBALS['_wpdb_get_row'] = array( 'surface' => 'frontend', 'mode' => 'enforce' );

		$this->assertSame( $GLOBALS['_wpdb_get_row'], $this->invoke_load_profile( $this->builder, 'frontend' ) );
	}

	public function test_load_profile_delegates_to_an_injected_data_loader(): void {
		$builder = new Policy_Builder( $this->gate, new Stub_Policy_Data_Loader( profile: array( 'surface' => 'admin', 'mode' => 'report-only' ) ) );

		$this->assertSame( array( 'surface' => 'admin', 'mode' => 'report-only' ), $this->invoke_load_profile( $builder, 'admin' ) );
	}

	private function invoke_load_profile( Policy_Builder $builder, string $surface ): ?array {
		$method = new ReflectionMethod( $builder, 'load_profile' );
		$method->setAccessible( true );
		return $method->invoke( $builder, $surface );
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

	public function test_build_report_endpoint_is_identical_before_init(): void {
		// Reporting_Endpoint::url() delegates unconditionally to rest_url();
		// did_action('init') deliberately left unset here.
		$profile = $this->make_profile( [ 'default-src' => [ "'none'" ] ] );

		$policy = $this->builder->build_policy_string( $profile, 'frontend' );

		$this->assertStringContainsString( 'report-uri https://example.com/wp-json/sam/v1/report', $policy );
	}

	public function test_build_report_endpoint_is_identical_after_init(): void {
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
		$builder = new Policy_Builder(
			$this->gate,
			new Stub_Policy_Data_Loader( sources: [ [ 'directive' => 'script-src', 'source_host' => 'cdn.example.com' ] ] )
		);

		$policy = $builder->build_policy_string( $profile, 'frontend' );

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

		$builder = new Policy_Builder(
			$this->gate,
			new Stub_Policy_Data_Loader( sources: [ [ 'directive' => 'script-src-elem', 'source_host' => 'cdn.example.com' ] ] )
		);

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
		// exists -- it's its own BYPASS_CATALOG entry (style_src_attr_unsafe_hashes)
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
		$profile['bypass_flags']  = wp_json_encode( array( 'style_src_attr_unsafe_hashes' ) );

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
		$profile['bypass_flags']  = wp_json_encode( array( 'style_src_attr_unsafe_hashes' ) );

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
		$profile['bypass_flags']  = wp_json_encode( array( 'style_src_attr_unsafe_hashes' ) );

		$builder = $this->make_db_stub_builder( approved_hashes: [
			[ 'directive' => 'style-src-attr', 'hash_algo' => 'sha256', 'hash_value' => 'ghi789==' ],
			[ 'directive' => 'script-src', 'hash_algo' => 'sha256', 'hash_value' => 'abc123==' ],
		] );

		$policy = $builder->build_policy_string( $profile, 'frontend' );

		$parts      = explode( ';', $policy );
		$script_src = trim( current( array_filter( $parts, static fn( $p ) => str_starts_with( trim( $p ), 'script-src ' ) ) ) );

		$this->assertStringNotContainsString( 'unsafe-hashes', $script_src );
	}

	// ── always-allowed empty inline attribute value (2026-08-19 incident) ─────

	public function test_build_always_includes_the_empty_content_hash_in_style_src_attr(): void {
		$profile = $this->make_profile( [ 'default-src' => [ "'none'" ], 'style-src-attr' => [ "'none'" ] ] );

		$policy = $this->builder->build_policy_string( $profile, 'frontend' );

		$this->assertStringContainsString( "'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='", $policy );
	}

	public function test_build_always_includes_the_empty_content_hash_in_script_src_attr(): void {
		$profile = $this->make_profile( [ 'default-src' => [ "'none'" ], 'script-src-attr' => [ "'none'" ] ] );

		$policy = $this->builder->build_policy_string( $profile, 'frontend' );

		$parts            = explode( ';', $policy );
		$script_src_attr  = trim( current( array_filter( $parts, static fn( $p ) => str_starts_with( trim( $p ), 'script-src-attr ' ) ) ) );

		$this->assertStringContainsString( "'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='", $script_src_attr );
	}

	public function test_build_does_not_leave_none_alongside_the_empty_content_hash(): void {
		// normalize_none_sources() should still strip the contradictory
		// 'none' now that a real token is present, exactly as it already
		// does for any other addition to a directive seeded as ['none'].
		$profile = $this->make_profile( [ 'default-src' => [ "'none'" ], 'style-src-attr' => [ "'none'" ] ] );

		$policy = $this->builder->build_policy_string( $profile, 'frontend' );

		$parts           = explode( ';', $policy );
		$style_src_attr  = trim( current( array_filter( $parts, static fn( $p ) => str_starts_with( trim( $p ), 'style-src-attr ' ) ) ) );

		$this->assertStringNotContainsString( "'none'", $style_src_attr );
	}

	public function test_build_does_not_add_the_empty_content_hash_to_unrelated_directives(): void {
		$profile = $this->make_profile( [ 'default-src' => [ "'none'" ], 'script-src' => [ "'self'" ] ] );

		$policy = $this->builder->build_policy_string( $profile, 'frontend' );

		$parts      = explode( ';', $policy );
		$script_src = trim( current( array_filter( $parts, static fn( $p ) => str_starts_with( trim( $p ), 'script-src ' ) ) ) );

		$this->assertStringNotContainsString( "'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='", $script_src );
	}

	// ── hash byte-budget safety cap (2026-08-19 incident) ──────────────────────

	public function test_build_drops_oldest_hashes_once_the_byte_budget_is_exhausted(): void {
		// Real sha256 hash tokens are a fixed ~53 bytes each; script-src
		// hashes are doubled into script-src-elem, so ~40 of them
		// comfortably exceeds MAX_HASH_TOKEN_BUDGET_BYTES (4096 bytes) and
		// reproduces the unbounded-header-growth incident at a much
		// smaller, deterministic scale.
		$approved_hashes = $this->make_fake_hash_rows( 80, 'script-src' );

		$profile = $this->make_profile( [ 'default-src' => [ "'none'" ], 'script-src' => [], 'script-src-elem' => [] ] );
		$builder = $this->make_db_stub_builder( approved_hashes: $approved_hashes );

		$policy = $builder->build_policy_string( $profile, 'frontend' );

		// The most-recently-seen hash (index 0, first in the array -- see
		// load_approved_hashes()'s ORDER BY last_seen_at DESC contract)
		// must survive; the least-recently-seen one must not.
		$this->assertStringContainsString( $approved_hashes[0]['hash_value'], $policy );
		$this->assertStringNotContainsString( $approved_hashes[79]['hash_value'], $policy );

		// The policy must stay well under the raw (undropped) size 80 hashes
		// would have produced, confirming something was actually dropped.
		$this->assertLessThan( 80 * 2 * 60, strlen( $policy ) );
	}

	public function test_build_logs_a_warning_when_hashes_are_dropped_for_budget(): void {
		$audit = $this->createMock( Audit_Log::class );
		$audit->expects( $this->once() )
			->method( 'log' )
			->with( 'policy_builder', 'hash_budget_exceeded', $this->anything(), 'warning' );

		$approved_hashes = $this->make_fake_hash_rows( 80, 'script-src' );
		$profile         = $this->make_profile( [ 'default-src' => [ "'none'" ], 'script-src' => [], 'script-src-elem' => [] ] );
		$builder         = $this->make_db_stub_builder( approved_hashes: $approved_hashes, audit: $audit );

		$builder->build_policy_string( $profile, 'frontend' );
	}

	public function test_build_does_not_log_when_all_hashes_fit_the_budget(): void {
		$audit = $this->createMock( Audit_Log::class );
		$audit->expects( $this->never() )->method( 'log' );

		$approved_hashes = $this->make_fake_hash_rows( 2, 'script-src' );
		$profile         = $this->make_profile( [ 'default-src' => [ "'none'" ], 'script-src' => [], 'script-src-elem' => [] ] );
		$builder         = $this->make_db_stub_builder( approved_hashes: $approved_hashes, audit: $audit );

		$builder->build_policy_string( $profile, 'frontend' );
	}

	public function test_build_logs_hash_budget_exceeded_at_most_once_per_hour(): void {
		// build_policy_string() runs on every request -- a surface stuck
		// over budget must not write a fresh audit_log row and error_log
		// line on every single pageview. Confirmed in production,
		// 2026-08-19: two near-identical rows five minutes apart.
		$audit = $this->createMock( Audit_Log::class );
		$audit->expects( $this->once() )
			->method( 'log' )
			->with( 'policy_builder', 'hash_budget_exceeded', $this->anything(), 'warning' );

		$approved_hashes = $this->make_fake_hash_rows( 80, 'script-src' );
		$profile         = $this->make_profile( [ 'default-src' => [ "'none'" ], 'script-src' => [], 'script-src-elem' => [] ] );
		$builder         = $this->make_db_stub_builder( approved_hashes: $approved_hashes, audit: $audit );

		// Three separate "requests" against the same builder instance --
		// only the first should actually call Audit_Log::log().
		$builder->build_policy_string( $profile, 'frontend' );
		$builder->build_policy_string( $profile, 'frontend' );
		$builder->build_policy_string( $profile, 'frontend' );
	}

	public function test_build_refuses_to_emit_a_policy_over_the_absolute_byte_ceiling(): void {
		// A pathologically large approved-source list (not the hash-growth
		// scenario the budget above guards against) must still trip the
		// final safety net and produce no header at all rather than an
		// oversized one.
		$approved_sources = [];
		for ( $i = 0; $i < 600; $i++ ) {
			$approved_sources[] = [ 'directive' => 'script-src', 'source_host' => "host{$i}.example.com" ];
		}

		$audit = $this->createMock( Audit_Log::class );
		$audit->expects( $this->once() )
			->method( 'log' )
			->with( 'policy_builder', 'policy_too_large', $this->anything(), 'error' );

		$profile = $this->make_profile( [ 'default-src' => [ "'none'" ], 'script-src' => [] ] );
		$builder = $this->make_db_stub_builder( approved_sources: $approved_sources, audit: $audit );

		$policy = $builder->build_policy_string( $profile, 'frontend' );

		$this->assertSame( '', $policy );
	}

	/**
	 * @return array<int,array<string,string>>
	 */
	private function make_fake_hash_rows( int $count, string $directive ): array {
		$rows = [];
		for ( $i = 0; $i < $count; $i++ ) {
			$rows[] = [
				'directive'  => $directive,
				'hash_algo'  => 'sha256',
				// Same length as a real base64-encoded sha256 digest (44
				// chars) so the byte-budget math in this test matches what
				// production hash tokens actually cost.
				'hash_value' => sprintf( '%044d', $i ),
			];
		}
		return $rows;
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
		$profile['bypass_flags']  = wp_json_encode( array( 'img_src_data' ) );

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
		$profile['bypass_flags']  = wp_json_encode( array( 'font_src_data' ) );

		$policy = $this->builder->build_policy_string( $profile, 'frontend' );

		$font_src = $this->extract_directive( $policy, 'font-src' );
		$this->assertStringContainsString( 'data:', $font_src );
	}

	public function test_build_does_not_duplicate_data_scheme_already_present(): void {
		$profile                        = $this->make_profile( [ 'default-src' => [ "'none'" ], 'img-src' => [ "'self'", 'data:' ] ] );
		$profile['bypass_flags'] = wp_json_encode( array( 'img_src_data' ) );

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
		$profile['bypass_flags'] = wp_json_encode( array( 'img_src_data' ) );

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
		$profile['bypass_flags'] = wp_json_encode( array( 'img_src_data' ) );

		$policy = $this->builder->build_policy_string( $profile, 'frontend' );

		$this->assertStringContainsString( "default-src 'none'", $policy );
	}

	// ── Bypass Best Practices catalog: 2026-08-19 expansion ────────────────────

	public function test_build_appends_blob_scheme_to_img_src_when_bypass_flag_enabled(): void {
		$profile                 = $this->make_profile( [ 'default-src' => [ "'none'" ], 'img-src' => [ "'self'" ] ] );
		$profile['bypass_flags'] = wp_json_encode( array( 'img_src_blob' ) );

		$policy  = $this->builder->build_policy_string( $profile, 'frontend' );
		$img_src = $this->extract_directive( $policy, 'img-src' );

		$this->assertStringContainsString( 'blob:', $img_src );
	}

	public function test_build_appends_data_and_blob_scheme_to_media_src_when_bypass_flags_enabled(): void {
		$profile                 = $this->make_profile( [ 'default-src' => [ "'none'" ], 'media-src' => [ "'self'" ] ] );
		$profile['bypass_flags'] = wp_json_encode( array( 'media_src_data', 'media_src_blob' ) );

		$policy    = $this->builder->build_policy_string( $profile, 'frontend' );
		$media_src = $this->extract_directive( $policy, 'media-src' );

		$this->assertStringContainsString( 'data:', $media_src );
		$this->assertStringContainsString( 'blob:', $media_src );
	}

	public function test_build_adds_unsafe_hashes_to_script_src_attr_when_bypass_flag_enabled(): void {
		$profile                 = $this->make_profile( [ 'default-src' => [ "'none'" ], 'script-src-attr' => [ "'none'" ] ] );
		$profile['bypass_flags'] = wp_json_encode( array( 'script_src_attr_unsafe_hashes' ) );

		$policy           = $this->builder->build_policy_string( $profile, 'frontend' );
		$script_src_attr  = $this->extract_directive( $policy, 'script-src-attr' );

		$this->assertStringContainsString( "'unsafe-hashes'", $script_src_attr );
	}

	public function test_build_script_src_attr_bypass_does_not_leak_into_style_src_attr(): void {
		$profile                 = $this->make_profile( [
			'default-src'     => [ "'none'" ],
			'script-src-attr' => [ "'none'" ],
			'style-src-attr'  => [ "'none'" ],
		] );
		$profile['bypass_flags'] = wp_json_encode( array( 'script_src_attr_unsafe_hashes' ) );

		$policy         = $this->builder->build_policy_string( $profile, 'frontend' );
		$style_src_attr = $this->extract_directive( $policy, 'style-src-attr' );

		$this->assertStringNotContainsString( 'unsafe-hashes', $style_src_attr );
	}

	public function test_build_adds_wasm_unsafe_eval_to_script_src_when_bypass_flag_enabled(): void {
		$profile                 = $this->make_profile( [ 'default-src' => [ "'none'" ], 'script-src' => [ "'self'" ] ] );
		$profile['bypass_flags'] = wp_json_encode( array( 'script_src_wasm_unsafe_eval' ) );

		$policy     = $this->builder->build_policy_string( $profile, 'frontend' );
		$script_src = $this->extract_directive( $policy, 'script-src' );

		$this->assertStringContainsString( "'wasm-unsafe-eval'", $script_src );
	}

	public function test_build_appends_blob_scheme_to_worker_src_when_bypass_flag_enabled(): void {
		$profile                 = $this->make_profile( [ 'default-src' => [ "'none'" ], 'worker-src' => [ "'none'" ] ] );
		$profile['bypass_flags'] = wp_json_encode( array( 'worker_src_blob' ) );

		$policy      = $this->builder->build_policy_string( $profile, 'frontend' );
		$worker_src  = $this->extract_directive( $policy, 'worker-src' );

		$this->assertStringContainsString( 'blob:', $worker_src );
	}

	public function test_build_multiple_bypass_flags_together_do_not_interfere(): void {
		$profile                 = $this->make_profile( [
			'default-src' => [ "'none'" ],
			'img-src'     => [ "'self'" ],
			'font-src'    => [ "'self'" ],
			'media-src'   => [ "'self'" ],
			'worker-src'  => [ "'none'" ],
		] );
		$profile['bypass_flags'] = wp_json_encode( array( 'img_src_data', 'font_src_data', 'media_src_blob', 'worker_src_blob' ) );

		$policy = $this->builder->build_policy_string( $profile, 'frontend' );

		$this->assertStringContainsString( 'data:', $this->extract_directive( $policy, 'img-src' ) );
		$this->assertStringContainsString( 'data:', $this->extract_directive( $policy, 'font-src' ) );
		$this->assertStringContainsString( 'blob:', $this->extract_directive( $policy, 'media-src' ) );
		$this->assertStringNotContainsString( 'blob:', $this->extract_directive( $policy, 'img-src' ) );
		$this->assertStringContainsString( 'blob:', $this->extract_directive( $policy, 'worker-src' ) );
	}

	public function test_build_ignores_unknown_bypass_flags_in_stored_json(): void {
		// Defensive: a bypass_flags value referencing a key that no longer
		// exists in BYPASS_CATALOG (e.g. after a future catalog rename) must
		// not error -- it's simply not found in the foreach and skipped.
		$profile                 = $this->make_profile( [ 'default-src' => [ "'none'" ], 'img-src' => [ "'self'" ] ] );
		$profile['bypass_flags'] = wp_json_encode( array( 'some_removed_or_renamed_flag' ) );

		$policy = $this->builder->build_policy_string( $profile, 'frontend' );

		$this->assertStringContainsString( "img-src 'self'", $policy );
	}

	public function test_build_handles_missing_bypass_flags_key_gracefully(): void {
		// make_profile() doesn't set bypass_flags at all by default -- most
		// tests in this file rely on that not erroring.
		$profile = $this->make_profile( [ 'default-src' => [ "'none'" ], 'img-src' => [ "'self'" ] ] );

		$policy = $this->builder->build_policy_string( $profile, 'frontend' );

		$this->assertStringNotContainsString( 'data:', $this->extract_directive( $policy, 'img-src' ) );
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
	 * Returns a Policy_Builder with a Stub_Policy_Data_Loader injected
	 * (GitHub issue #170) and the nonce bridge stubbed. The nonce bridge
	 * itself is a separate, pre-existing mechanism (see NonceBridge.php)
	 * outside #170's scope, so it's still worked around via
	 * $GLOBALS['_wp_sam_test_nonce'] and a build_policy_string() override
	 * -- that method isn't part of the data-loading boundary #170 is about.
	 */
	private function make_db_stub_builder(
		string $nonce = '',
		array $approved_hashes = [],
		array $approved_sources = [],
		?Audit_Log $audit = null
	): Policy_Builder {
		return new class(
			$this->gate,
			new Stub_Policy_Data_Loader( $approved_hashes, $approved_sources ),
			$nonce,
			$audit
		) extends Policy_Builder {

			public function __construct(
				Feature_Gate $gate,
				Policy_Data_Loader $data_loader,
				private string $stub_nonce,
				?Audit_Log $audit
			) {
				parent::__construct( $gate, $data_loader, $audit );
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

// Plugin_Nonce_Manager stub is defined in test/unit/NonceBridge.php,
// which is loaded by test/bootstrap.php before any test class is instantiated.
