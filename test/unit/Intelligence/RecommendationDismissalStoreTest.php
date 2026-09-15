<?php
/**
 * Unit tests for WP_SAM\Intelligence\Recommendation_Dismissal_Store.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Recommendation_Dismissal_Store;

class RecommendationDismissalStoreTest extends TestCase {

	private Recommendation_Dismissal_Store $store;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->store = new Recommendation_Dismissal_Store();
	}

	public function test_dismiss_requires_a_non_empty_reason(): void {
		$this->assertFalse( $this->store->dismiss( 'some_key', 5, '' ) );
		$this->assertFalse( $this->store->dismiss( 'some_key', 5, '   ' ) );
		$this->assertSame( array(), $GLOBALS['_wpdb_queries'] );
	}

	public function test_dismiss_writes_the_key_user_and_reason(): void {
		$ok = $this->store->dismiss( 'csp_enforce_ready_frontend', 5, 'Deliberately staying report-only for now.' );

		$this->assertTrue( $ok );
		$this->assertCount( 1, $GLOBALS['_wpdb_queries'] );
		$this->assertStringContainsString( "'csp_enforce_ready_frontend'", $GLOBALS['_wpdb_queries'][0] );
		$this->assertStringContainsString( 'Deliberately staying report-only for now.', $GLOBALS['_wpdb_queries'][0] );
	}

	public function test_is_dismissed_is_false_when_nothing_is_stored(): void {
		$GLOBALS['_wpdb_get_row'] = null;

		$this->assertFalse( $this->store->is_dismissed( 'some_key', '2026-01-01 00:00:00' ) );
	}

	public function test_is_dismissed_is_true_while_the_dismissal_is_newer_than_the_evidence(): void {
		$GLOBALS['_wpdb_get_row'] = array( 'dismissed_at' => '2026-06-01 00:00:00' );

		$this->assertTrue( $this->store->is_dismissed( 'some_key', '2026-01-01 00:00:00' ) );
	}

	public function test_is_dismissed_is_false_once_evidence_is_newer_than_the_dismissal(): void {
		$GLOBALS['_wpdb_get_row'] = array( 'dismissed_at' => '2026-01-01 00:00:00' );

		$this->assertFalse( $this->store->is_dismissed( 'some_key', '2026-06-01 00:00:00' ) );
	}

	public function test_all_returns_stored_rows(): void {
		$GLOBALS['_wpdb_get_results'] = array( array( 'recommendation_key' => 'some_key' ) );

		$this->assertSame( array( array( 'recommendation_key' => 'some_key' ) ), $this->store->all() );
	}
}
