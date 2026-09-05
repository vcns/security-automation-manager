<?php
/**
 * Unit tests for WP_SAM\Intelligence\Agents_Rules_Store -- mirrors
 * RobotsRulesStoreTest since the two classes share the same parsing logic
 * and option-storage shape.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Agents_Rules_Store;

class AgentsRulesStoreTest extends TestCase {

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
		$this->assertSame( array(), ( new Agents_Rules_Store() )->rules() );
	}

	public function test_refresh_parses_the_wildcard_user_agent_blocks_disallow_rules(): void {
		$body  = "User-agent: *\nDisallow: /private/\n";
		$store = new Agents_Rules_Store( fn( string $url ) => $this->http_response( $body ) );

		$result = $store->refresh();

		$this->assertSame( 'refreshed', $result['status'] );
		$this->assertSame( array( '/private/' ), get_option( 'wp_sam_agents_disallow_rules' ) );
	}

	public function test_is_disallowed_matches_by_prefix(): void {
		update_option( 'wp_sam_agents_disallow_rules', array( '/no-agents/' ) );
		$store = new Agents_Rules_Store();

		$this->assertTrue( $store->is_disallowed( '/no-agents/page' ) );
		$this->assertFalse( $store->is_disallowed( '/public/' ) );
	}

	public function test_refresh_keeps_existing_rules_on_a_wp_error_response(): void {
		update_option( 'wp_sam_agents_disallow_rules', array( '/private/' ) );
		$store = new Agents_Rules_Store( static fn( string $url ) => new WP_Error( 'http_request_failed', 'timeout' ) );

		$result = $store->refresh();

		$this->assertSame( 'failed', $result['status'] );
		$this->assertSame( array( '/private/' ), get_option( 'wp_sam_agents_disallow_rules' ) );
	}

	public function test_refresh_strips_an_inline_comment_from_a_user_agent_line(): void {
		// Without stripping, "* # applies to everyone" never equals '*',
		// so $in_wildcard_block would never be set and every Disallow line
		// under it would be silently dropped.
		$body  = "User-agent: * # applies to everyone\nDisallow: /private/\n";
		$store = new Agents_Rules_Store( fn( string $url ) => $this->http_response( $body ) );

		$store->refresh();

		$this->assertSame( array( '/private/' ), $store->rules() );
	}

	public function test_refresh_strips_an_inline_comment_from_a_disallow_line(): void {
		// Without stripping, the stored rule would be "/private/ # internal
		// only", which str_starts_with() would never match against any
		// real request path.
		$body  = "User-agent: *\nDisallow: /private/ # internal only\n";
		$store = new Agents_Rules_Store( fn( string $url ) => $this->http_response( $body ) );

		$store->refresh();

		$this->assertTrue( $store->is_disallowed( '/private/page' ) );
	}

	public function test_last_fetch_status_reflects_a_successful_refresh(): void {
		$store = new Agents_Rules_Store( fn( string $url ) => $this->http_response( "User-agent: *\nDisallow: /x/\n" ) );

		$store->refresh();

		$this->assertSame( 'success', $store->last_fetch_status() );
		$this->assertNotNull( $store->last_refreshed_at() );
	}
}
