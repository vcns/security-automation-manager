<?php
/**
 * Unit tests for WP_SAM\Intelligence\Event_Store.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Event_Store;

class EventStoreTest extends TestCase {

	private Event_Store $store;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->store = new Event_Store();
	}

	public function test_record_writes_an_insert_query(): void {
		$this->store->record( 'sqli-probe', 'injection', 'frontend', 'high', 0.75, '203.0.113.42', array( 'path' => '/?id=1%27' ) );

		$this->assertSame( 'query', $GLOBALS['_wpdb_last_operation'] );
		$this->assertStringContainsString( 'sam_request_events', $GLOBALS['_wpdb_last_query'] );
		$this->assertStringContainsString( "'sqli-probe'", $GLOBALS['_wpdb_last_query'] );
		$this->assertStringContainsString( "'injection'", $GLOBALS['_wpdb_last_query'] );
		$this->assertStringContainsString( "'frontend'", $GLOBALS['_wpdb_last_query'] );
		$this->assertStringContainsString( "'high'", $GLOBALS['_wpdb_last_query'] );
	}

	public function test_record_serialises_detail_as_json(): void {
		$this->store->record( 'sqli-probe', 'injection', 'frontend', 'high', null, '203.0.113.42', array( 'user_agent' => 'sqlmap/1.7' ) );

		$this->assertStringContainsString( 'user_agent', $GLOBALS['_wpdb_last_query'] );
		$this->assertStringContainsString( 'sqlmap', $GLOBALS['_wpdb_last_query'] );
	}

	public function test_record_defaults_unrecognised_surface_to_frontend(): void {
		$this->store->record( 'sqli-probe', 'injection', 'not-a-real-surface', 'high', null, '203.0.113.42', array() );

		$this->assertStringContainsString( "'frontend'", $GLOBALS['_wpdb_last_query'] );
	}

	public function test_record_defaults_unrecognised_severity_to_unknown(): void {
		$this->store->record( 'sqli-probe', 'injection', 'frontend', 'not-a-real-severity', null, '203.0.113.42', array() );

		$this->assertStringContainsString( "'unknown'", $GLOBALS['_wpdb_last_query'] );
	}

	public function test_record_is_a_noop_for_empty_detector_id(): void {
		$this->store->record( '', 'injection', 'frontend', 'high', null, '203.0.113.42', array() );

		$this->assertNull( $GLOBALS['_wpdb_last_operation'] ?? null );
	}

	public function test_record_is_a_noop_for_empty_detector_family(): void {
		$this->store->record( 'sqli-probe', '', 'frontend', 'high', null, '203.0.113.42', array() );

		$this->assertNull( $GLOBALS['_wpdb_last_operation'] ?? null );
	}

	/**
	 * confidence is a real FLOAT column, but the test wpdb stub's prepare()
	 * only substitutes %s/%d/%% (see class docblock) -- confirms the NULLIF(%s, '')
	 * binding actually produces a numeric literal, not a silently-unsubstituted
	 * %f placeholder.
	 */
	public function test_record_binds_confidence_as_a_formatted_numeric_string(): void {
		$this->store->record( 'sqli-probe', 'injection', 'frontend', 'high', 0.5, '203.0.113.42', array() );

		$this->assertStringContainsString( "NULLIF('0.5000', '')", $GLOBALS['_wpdb_last_query'] );
	}

	public function test_record_binds_null_confidence_as_nullif_empty_string(): void {
		$this->store->record( 'sqli-probe', 'injection', 'frontend', 'high', null, '203.0.113.42', array() );

		$this->assertStringContainsString( "NULLIF('', '')", $GLOBALS['_wpdb_last_query'] );
	}

	public function test_record_respects_rate_limit_per_detector_and_surface(): void {
		$GLOBALS['_wp_transients']['wp_sam_request_event_rate_sqli-probe_frontend'] = 500;

		$this->store->record( 'sqli-probe', 'injection', 'frontend', 'high', null, '203.0.113.42', array() );

		$this->assertNull( $GLOBALS['_wpdb_last_operation'] ?? null );
	}

	public function test_record_rate_limit_is_scoped_per_detector(): void {
		// A saturated rate limit for one detector must not block a different
		// detector on the same surface.
		$GLOBALS['_wp_transients']['wp_sam_request_event_rate_sqli-probe_frontend'] = 500;

		$this->store->record( 'xss-probe', 'injection', 'frontend', 'high', null, '203.0.113.42', array() );

		$this->assertSame( 'query', $GLOBALS['_wpdb_last_operation'] );
	}

	public function test_record_fingerprint_ignores_detail_contents(): void {
		// Two events with the same detector/surface/ip but different detail
		// payloads must upsert into the same row (same fingerprint), not
		// create separate rows.
		$this->store->record( 'sqli-probe', 'injection', 'frontend', 'high', null, '203.0.113.42', array( 'path' => '/a' ) );
		$first_query = $GLOBALS['_wpdb_last_query'];

		$this->store->record( 'sqli-probe', 'injection', 'frontend', 'high', null, '203.0.113.42', array( 'path' => '/b' ) );
		$second_query = $GLOBALS['_wpdb_last_query'];

		preg_match( "/'([a-f0-9]{64})'/", $first_query, $first_match );
		preg_match( "/'([a-f0-9]{64})'/", $second_query, $second_match );

		$this->assertNotEmpty( $first_match );
		$this->assertSame( $first_match[1], $second_match[1] );
	}

	/**
	 * A different requesting IP is a genuinely different fingerprint --
	 * two different attackers hitting the same detector on the same surface
	 * must not collapse into one occurrence-counted row.
	 */
	public function test_record_fingerprint_differs_by_ip(): void {
		$this->store->record( 'sqli-probe', 'injection', 'frontend', 'high', null, '203.0.113.42', array() );
		$first_query = $GLOBALS['_wpdb_last_query'];

		$this->store->record( 'sqli-probe', 'injection', 'frontend', 'high', null, '198.51.100.7', array() );
		$second_query = $GLOBALS['_wpdb_last_query'];

		preg_match( "/'([a-f0-9]{64})'/", $first_query, $first_match );
		preg_match( "/'([a-f0-9]{64})'/", $second_query, $second_match );

		$this->assertNotEmpty( $first_match );
		$this->assertNotEmpty( $second_match );
		$this->assertNotSame( $first_match[1], $second_match[1] );
	}

	/**
	 * A single detector can carry several rules of differing severity (see
	 * Detectors\Pattern_Detector) -- a repeat hit from the same source that
	 * matches a DIFFERENT rule than the first hit must refresh severity/
	 * confidence together with detail, not leave them stale from whichever
	 * rule matched first. Otherwise a row's own detail (naming the latest
	 * matched rule) could disagree with its severity/confidence columns.
	 */
	public function test_record_upsert_refreshes_severity_and_confidence_not_just_detail(): void {
		$this->store->record( 'sql-injection', 'sql-injection', 'frontend', 'medium', 0.5, '203.0.113.42', array( 'rule_id' => 'SQLI-003' ) );

		$this->assertStringContainsString( 'severity = VALUES(severity)', $GLOBALS['_wpdb_last_query'] );
		$this->assertStringContainsString( 'confidence = VALUES(confidence)', $GLOBALS['_wpdb_last_query'] );
	}
}
