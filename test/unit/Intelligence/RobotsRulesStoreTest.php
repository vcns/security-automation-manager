<?php
/**
 * Unit tests for WP_SAM\Intelligence\Robots_Rules_Store.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Robots_Rules_Store;

class RobotsRulesStoreTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	private function http_response( string $body, int $code = 200 ): array {
		return array(
			'response' => array( 'code' => $code ),
			'body'     => $body,
		);
	}

	public function test_rules_is_empty_when_nothing_cached(): void {
		$this->assertSame( array(), ( new Robots_Rules_Store() )->rules() );
	}

	public function test_is_disallowed_is_false_with_no_cached_rules(): void {
		$this->assertFalse( ( new Robots_Rules_Store() )->is_disallowed( '/wp-admin/' ) );
	}

	public function test_is_disallowed_is_false_for_an_empty_path(): void {
		update_option( 'wp_sam_robots_disallow_rules', array( '/wp-admin/' ) );

		$this->assertFalse( ( new Robots_Rules_Store() )->is_disallowed( '' ) );
	}

	public function test_refresh_parses_the_wildcard_user_agent_blocks_disallow_rules(): void {
		$body  = "User-agent: *\nDisallow: /wp-admin/\nAllow: /wp-admin/admin-ajax.php\n";
		$store = new Robots_Rules_Store( fn( string $url ) => $this->http_response( $body ) );

		$result = $store->refresh();

		$this->assertSame( 'refreshed', $result['status'] );
		$this->assertSame( array( '/wp-admin/' ), get_option( 'wp_sam_robots_disallow_rules' ) );
	}

	public function test_refresh_ignores_named_bot_specific_blocks(): void {
		// Only the generic "*" block's Disallow lines should be captured.
		$body  = "User-agent: BadBot\nDisallow: /secret/\n\nUser-agent: *\nDisallow: /private/\n";
		$store = new Robots_Rules_Store( fn( string $url ) => $this->http_response( $body ) );

		$store->refresh();

		$this->assertSame( array( '/private/' ), get_option( 'wp_sam_robots_disallow_rules' ) );
	}

	public function test_refresh_ignores_comments_and_blank_lines(): void {
		$body  = "# a comment\nUser-agent: *\n\nDisallow: /wp-admin/\n# another comment\n";
		$store = new Robots_Rules_Store( fn( string $url ) => $this->http_response( $body ) );

		$store->refresh();

		$this->assertSame( array( '/wp-admin/' ), get_option( 'wp_sam_robots_disallow_rules' ) );
	}

	public function test_refresh_treats_a_blank_disallow_value_as_no_rule(): void {
		// "Disallow:" with nothing after it means "disallow nothing" per
		// the Robots Exclusion Protocol -- must not become an empty-string
		// rule that (via str_starts_with) would match every path.
		$body  = "User-agent: *\nDisallow: \n";
		$store = new Robots_Rules_Store( fn( string $url ) => $this->http_response( $body ) );

		$store->refresh();

		$this->assertSame( array(), get_option( 'wp_sam_robots_disallow_rules' ) );
	}

	public function test_is_disallowed_matches_by_prefix(): void {
		update_option( 'wp_sam_robots_disallow_rules', array( '/wp-admin/' ) );
		$store = new Robots_Rules_Store();

		$this->assertTrue( $store->is_disallowed( '/wp-admin/plugins.php' ) );
		$this->assertFalse( $store->is_disallowed( '/wp-content/' ) );
	}

	public function test_refresh_returns_nulls_on_a_wp_error_response_and_keeps_existing_rules(): void {
		update_option( 'wp_sam_robots_disallow_rules', array( '/wp-admin/' ) );
		$store = new Robots_Rules_Store( static fn( string $url ) => new WP_Error( 'http_request_failed', 'timeout' ) );

		$result = $store->refresh();

		$this->assertSame( 'failed', $result['status'] );
		$this->assertSame( array( '/wp-admin/' ), get_option( 'wp_sam_robots_disallow_rules' ) );
	}

	public function test_refresh_keeps_existing_rules_on_a_non_200_response(): void {
		update_option( 'wp_sam_robots_disallow_rules', array( '/wp-admin/' ) );
		$store = new Robots_Rules_Store( fn( string $url ) => $this->http_response( '', 404 ) );

		$result = $store->refresh();

		$this->assertSame( 'failed', $result['status'] );
		$this->assertSame( array( '/wp-admin/' ), get_option( 'wp_sam_robots_disallow_rules' ) );
	}

	public function test_last_refreshed_at_is_null_before_any_refresh(): void {
		$this->assertNull( ( new Robots_Rules_Store() )->last_refreshed_at() );
	}

	public function test_last_fetch_status_reflects_a_successful_refresh(): void {
		$store = new Robots_Rules_Store( fn( string $url ) => $this->http_response( "User-agent: *\nDisallow: /x/\n" ) );

		$store->refresh();

		$this->assertSame( 'success', $store->last_fetch_status() );
		$this->assertNotNull( $store->last_refreshed_at() );
	}
}
