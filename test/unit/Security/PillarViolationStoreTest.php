<?php
/**
 * Unit tests for WP_SAM\Security\Pillar_Violation_Store.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Security\Pillar_Violation_Store;

class PillarViolationStoreTest extends TestCase {

	private Pillar_Violation_Store $store;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->store = new Pillar_Violation_Store();
	}

	public function test_store_writes_an_insert_query(): void {
		$this->store->store( 'cross-origin-opener-policy', 'frontend', 'coop', 'enforce', [ 'property' => 'closed' ] );

		$this->assertSame( 'query', $GLOBALS['_wpdb_last_operation'] );
		$this->assertStringContainsString( 'sam_pillar_violation_reports', $GLOBALS['_wpdb_last_query'] );
		$this->assertStringContainsString( "'cross-origin-opener-policy'", $GLOBALS['_wpdb_last_query'] );
		$this->assertStringContainsString( "'frontend'", $GLOBALS['_wpdb_last_query'] );
		$this->assertStringContainsString( "'coop'", $GLOBALS['_wpdb_last_query'] );
		$this->assertStringContainsString( "'enforce'", $GLOBALS['_wpdb_last_query'] );
	}

	public function test_store_serialises_detail_as_json(): void {
		$this->store->store( 'cross-origin-embedder-policy', 'admin', 'coep', 'reporting', [ 'blockedURL' => 'https://embeds.example.net/widget' ] );

		$this->assertStringContainsString( 'blockedURL', $GLOBALS['_wpdb_last_query'] );
		$this->assertStringContainsString( 'embeds.example.net', $GLOBALS['_wpdb_last_query'] );
	}

	public function test_store_defaults_unrecognised_surface_to_frontend(): void {
		$this->store->store( 'cross-origin-opener-policy', 'not-a-real-surface', 'coop', 'enforce', [] );

		$this->assertStringContainsString( "'frontend'", $GLOBALS['_wpdb_last_query'] );
	}

	public function test_store_defaults_unrecognised_disposition_to_reporting(): void {
		$this->store->store( 'cross-origin-opener-policy', 'frontend', 'coop', 'not-a-real-disposition', [] );

		$this->assertStringContainsString( "'reporting'", $GLOBALS['_wpdb_last_query'] );
	}

	public function test_store_is_a_noop_for_empty_pillar(): void {
		$this->store->store( '', 'frontend', 'coop', 'enforce', [] );

		$this->assertNull( $GLOBALS['_wpdb_last_operation'] ?? null );
	}

	public function test_store_does_nothing_for_empty_report_type(): void {
		$this->store->store( 'cross-origin-opener-policy', 'frontend', '', 'enforce', [] );

		$this->assertNull( $GLOBALS['_wpdb_last_operation'] ?? null );
	}

	public function test_store_respects_rate_limit_per_pillar_and_surface(): void {
		$GLOBALS['_wp_transients']['wp_sam_pillar_viol_rate_cross-origin-opener-policy_frontend'] = 500;

		$this->store->store( 'cross-origin-opener-policy', 'frontend', 'coop', 'enforce', [] );

		$this->assertNull( $GLOBALS['_wpdb_last_operation'] ?? null );
	}

	public function test_store_rate_limit_is_scoped_per_pillar(): void {
		// A saturated COOP rate limit must not block COEP reports for the same surface.
		$GLOBALS['_wp_transients']['wp_sam_pillar_viol_rate_cross-origin-opener-policy_frontend'] = 500;

		$this->store->store( 'cross-origin-embedder-policy', 'frontend', 'coep', 'enforce', [] );

		$this->assertSame( 'query', $GLOBALS['_wpdb_last_operation'] );
	}

	public function test_store_fingerprint_ignores_detail_contents(): void {
		// Two reports with the same pillar/surface/report_type/disposition but
		// different detail payloads must upsert into the same row (same
		// fingerprint), not create separate rows -- the fingerprint is
		// deliberately coarse (see class docblock).
		$this->store->store( 'cross-origin-opener-policy', 'frontend', 'coop', 'enforce', [ 'property' => 'closed' ] );
		$first_query = $GLOBALS['_wpdb_last_query'];

		$this->store->store( 'cross-origin-opener-policy', 'frontend', 'coop', 'enforce', [ 'property' => 'postMessage' ] );
		$second_query = $GLOBALS['_wpdb_last_query'];

		preg_match( "/'([a-f0-9]{64})'/", $first_query, $first_match );
		preg_match( "/'([a-f0-9]{64})'/", $second_query, $second_match );

		$this->assertNotEmpty( $first_match );
		$this->assertSame( $first_match[1], $second_match[1] );
	}
}
