<?php
/**
 * Unit tests for WP_SAM\Intelligence\Baseline_State_Builder.
 *
 * Policy_Builder is constructed with no-op hash/source loader callables so
 * build_policy_string() never makes its own additional wpdb calls -- this
 * class's own four table queries (csp_policy_profiles, sam_pillar_profiles,
 * sam_dependency_inventory, sam_internal_asset_inventory) stay the only
 * wpdb interaction to sequence via _wpdb_get_results_queue.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\CSP\Policy_Builder;
use WP_SAM\Intelligence\Baseline_State_Builder;
use WP_SAM\Modules\Feature_Gate;

class BaselineStateBuilderTest extends TestCase {

	private Baseline_State_Builder $builder;

	protected function setUp(): void {
		wp_test_reset_globals();
		$policy_builder = new Policy_Builder( new Feature_Gate(), static fn ( string $s ) => array(), static fn ( string $s ) => array() );
		$this->builder   = new Baseline_State_Builder( $policy_builder );
	}

	public function test_build_returns_no_csp_rows_when_no_profiles_exist(): void {
		$GLOBALS['_wpdb_get_results_queue'] = array( array(), array(), array(), array(), array() );

		$state = $this->builder->build();

		$csp_rows = array_filter( $state, static fn ( array $r ) => 'csp_header' === $r['category'] );
		$this->assertSame( array(), $csp_rows );
	}

	public function test_build_includes_a_csp_header_row_per_surface(): void {
		$GLOBALS['_wpdb_get_results_queue'] = array(
			array( array( 'surface' => 'frontend', 'mode' => 'enforce', 'directives' => '{}', 'overrides' => '{}' ) ),
			array(),
			array(),
			array(),
			array(),
		);

		$state = $this->builder->build();

		$csp_rows = array_values( array_filter( $state, static fn ( array $r ) => 'csp_header' === $r['category'] ) );
		$this->assertCount( 1, $csp_rows );
		$this->assertSame( 'frontend', $csp_rows[0]['surface'] );
		$this->assertStringStartsWith( 'enforce|', $csp_rows[0]['value'] );
	}

	public function test_build_includes_pillar_toggle_rows(): void {
		$GLOBALS['_wpdb_get_results_queue'] = array(
			array(),
			array( array( 'pillar' => 'x-frame-options', 'surface' => 'frontend', 'enabled' => 1, 'payload' => '{"value":"SAMEORIGIN"}' ) ),
			array(),
			array(),
			array(),
		);

		$state = $this->builder->build();

		$pillar_rows = array_values( array_filter( $state, static fn ( array $r ) => 'pillar' === $r['category'] ) );
		$this->assertCount( 1, $pillar_rows );
		$this->assertSame( 'x-frame-options', $pillar_rows[0]['item_key'] );
		$this->assertStringStartsWith( 'on|', $pillar_rows[0]['value'] );
	}

	public function test_build_includes_dependency_rows(): void {
		$GLOBALS['_wpdb_get_results_queue'] = array(
			array(),
			array(),
			array( array( 'surface' => 'frontend', 'resource_type' => 'script', 'origin' => 'https://fonts.googleapis.com', 'classification' => 'approved' ) ),
			array(),
			array(),
		);

		$state = $this->builder->build();

		$dep_rows = array_values( array_filter( $state, static fn ( array $r ) => 'dependency' === $r['category'] ) );
		$this->assertCount( 1, $dep_rows );
		$this->assertSame( 'script:https://fonts.googleapis.com', $dep_rows[0]['item_key'] );
		$this->assertSame( 'approved', $dep_rows[0]['value'] );
	}

	public function test_build_includes_internal_asset_rows(): void {
		$GLOBALS['_wpdb_get_results_queue'] = array(
			array(),
			array(),
			array(),
			array( array( 'surface' => 'frontend', 'path' => '/wp-content/themes/x/style.css', 'hash' => 'sha384-abc' ) ),
			array(),
		);

		$state = $this->builder->build();

		$asset_rows = array_values( array_filter( $state, static fn ( array $r ) => 'internal_asset' === $r['category'] ) );
		$this->assertCount( 1, $asset_rows );
		$this->assertSame( '/wp-content/themes/x/style.css', $asset_rows[0]['item_key'] );
		$this->assertSame( 'sha384-abc', $asset_rows[0]['value'] );
	}

	public function test_build_includes_wordpress_environment_rows(): void {
		$GLOBALS['_wpdb_get_results_queue'] = array( array(), array(), array(), array(), array() );
		$GLOBALS['_wp_current_theme']       = new WP_Theme( 'my-theme', '2.1' );
		$GLOBALS['_wp_plugins']             = array( 'akismet/akismet.php' => array( 'Version' => '5.3' ) );
		$GLOBALS['_wp_options']['active_plugins'] = array( 'akismet/akismet.php' );

		$state = $this->builder->build();

		$core_rows   = array_values( array_filter( $state, static fn ( array $r ) => 'core_version' === $r['category'] ) );
		$theme_rows  = array_values( array_filter( $state, static fn ( array $r ) => 'theme_version' === $r['category'] ) );
		$plugin_rows = array_values( array_filter( $state, static fn ( array $r ) => 'plugin_version' === $r['category'] ) );

		$this->assertCount( 1, $core_rows );
		$this->assertSame( 'my-theme', $theme_rows[0]['item_key'] );
		$this->assertSame( '2.1', $theme_rows[0]['value'] );
		$this->assertSame( 'akismet/akismet.php', $plugin_rows[0]['item_key'] );
		$this->assertSame( '5.3', $plugin_rows[0]['value'] );
	}

	// ── normalise_nonce() ────────────────────────────────────────────────────

	/**
	 * build_policy_string() embeds a fresh CSP nonce on every single call
	 * (Plugin_Nonce_Manager::get_instance_nonce() -- unique per request by
	 * design). Without normalising it away, every drift scan would report
	 * every surface's CSP header as "changed" even when nothing about the
	 * actual policy did.
	 */
	private function invoke_normalise_nonce( string $header ): string {
		$method = new ReflectionMethod( Baseline_State_Builder::class, 'normalise_nonce' );
		$method->setAccessible( true );
		return $method->invoke( $this->builder, $header );
	}

	public function test_normalise_nonce_replaces_a_nonce_token_with_a_stable_placeholder(): void {
		$header = "script-src 'self' 'nonce-aBcD1234+/='; style-src 'self' 'nonce-aBcD1234+/='";

		$normalised = $this->invoke_normalise_nonce( $header );

		$this->assertStringNotContainsString( 'aBcD1234', $normalised );
		$this->assertStringContainsString( "'nonce-STABLE'", $normalised );
	}

	public function test_normalise_nonce_produces_the_same_result_for_two_different_random_nonces(): void {
		$header_a = "script-src 'self' 'nonce-aaaaaaaaaaaa'";
		$header_b = "script-src 'self' 'nonce-bbbbbbbbbbbb'";

		$this->assertSame( $this->invoke_normalise_nonce( $header_a ), $this->invoke_normalise_nonce( $header_b ) );
	}

	public function test_normalise_nonce_leaves_a_header_without_a_nonce_unchanged(): void {
		$header = "script-src 'self' https://example.com";

		$this->assertSame( $header, $this->invoke_normalise_nonce( $header ) );
	}

	// ── hash() ───────────────────────────────────────────────────────────────

	public function test_hash_is_stable_regardless_of_input_order(): void {
		$a = array(
			array( 'category' => 'pillar', 'surface' => 'frontend', 'item_key' => 'x', 'value' => '1' ),
			array( 'category' => 'pillar', 'surface' => 'frontend', 'item_key' => 'y', 'value' => '2' ),
		);
		$b = array_reverse( $a );

		$this->assertSame( $this->builder->hash( $a ), $this->builder->hash( $b ) );
	}

	public function test_hash_changes_when_a_value_changes(): void {
		$a = array( array( 'category' => 'pillar', 'surface' => 'frontend', 'item_key' => 'x', 'value' => '1' ) );
		$b = array( array( 'category' => 'pillar', 'surface' => 'frontend', 'item_key' => 'x', 'value' => '2' ) );

		$this->assertNotSame( $this->builder->hash( $a ), $this->builder->hash( $b ) );
	}

	public function test_hash_of_empty_state_is_deterministic(): void {
		$this->assertSame( $this->builder->hash( array() ), $this->builder->hash( array() ) );
	}
}
