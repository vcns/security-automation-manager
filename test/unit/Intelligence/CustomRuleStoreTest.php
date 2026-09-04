<?php
/**
 * Unit tests for WP_SAM\Intelligence\Custom_Rule_Store.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Custom_Rule_Store;

class CustomRuleStoreTest extends TestCase {

	private Custom_Rule_Store $store;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->store = new Custom_Rule_Store();
	}

	/** @return array<string,mixed> */
	private function valid_input( array $overrides = array() ): array {
		return array_merge(
			array(
				'name'          => 'Old backup file probe',
				'pattern'       => '/\.bak$/i',
				'subject_field' => 'request_uri',
				'severity'      => 'high',
				'surfaces'      => array( 'frontend' ),
				'description'   => 'Flags requests for stray .bak files.',
			),
			$overrides
		);
	}

	// ── create() ──────────────────────────────────────────────────────────────

	public function test_create_with_valid_input_succeeds_and_stores_sanitised_fields(): void {
		$result = $this->store->create( $this->valid_input() );

		$this->assertTrue( $result['success'] );
		$this->assertSame( array(), $result['errors'] );
		$this->assertGreaterThan( 0, $result['id'] );

		$row = $GLOBALS['_wpdb_inserted_rows'][0]['data'];
		$this->assertSame( 'Old backup file probe', $row['name'] );
		$this->assertSame( '/\.bak$/i', $row['pattern'] );
		$this->assertSame( 'request_uri', $row['subject_field'] );
		$this->assertSame( 'high', $row['severity'] );
		$this->assertSame( array( 'frontend' ), json_decode( $row['surfaces'], true ) );
	}

	public function test_create_rejects_a_blank_name(): void {
		$result = $this->store->create( $this->valid_input( array( 'name' => '  ' ) ) );

		$this->assertFalse( $result['success'] );
		$this->assertNotEmpty( $result['errors'] );
		$this->assertSame( array(), $GLOBALS['_wpdb_inserted_rows'] );
	}

	public function test_create_rejects_a_blank_pattern(): void {
		$result = $this->store->create( $this->valid_input( array( 'pattern' => '' ) ) );

		$this->assertFalse( $result['success'] );
		$this->assertSame( array(), $GLOBALS['_wpdb_inserted_rows'] );
	}

	public function test_create_rejects_a_pattern_that_does_not_compile(): void {
		// Unbalanced group -- not a valid PCRE.
		$result = $this->store->create( $this->valid_input( array( 'pattern' => '/(unterminated/' ) ) );

		$this->assertFalse( $result['success'] );
		$this->assertSame( array(), $GLOBALS['_wpdb_inserted_rows'] );
	}

	public function test_create_rejects_a_name_over_the_length_cap(): void {
		$result = $this->store->create( $this->valid_input( array( 'name' => str_repeat( 'a', Custom_Rule_Store::MAX_NAME_LENGTH + 1 ) ) ) );

		$this->assertFalse( $result['success'] );
	}

	public function test_create_rejects_a_pattern_over_the_length_cap(): void {
		$oversized = '/' . str_repeat( 'a', Custom_Rule_Store::MAX_PATTERN_LENGTH ) . '/';
		$result    = $this->store->create( $this->valid_input( array( 'pattern' => $oversized ) ) );

		$this->assertFalse( $result['success'] );
	}

	public function test_create_falls_back_to_request_uri_for_an_unrecognised_subject_field(): void {
		$result = $this->store->create( $this->valid_input( array( 'subject_field' => 'not-a-real-field' ) ) );

		$this->assertTrue( $result['success'] );
		$this->assertSame( 'request_uri', $GLOBALS['_wpdb_inserted_rows'][0]['data']['subject_field'] );
	}

	public function test_create_falls_back_to_medium_for_an_unrecognised_severity(): void {
		$result = $this->store->create( $this->valid_input( array( 'severity' => 'catastrophic' ) ) );

		$this->assertTrue( $result['success'] );
		$this->assertSame( 'medium', $GLOBALS['_wpdb_inserted_rows'][0]['data']['severity'] );
	}

	public function test_create_ignores_an_unrecognised_surface_value(): void {
		$result = $this->store->create( $this->valid_input( array( 'surfaces' => array( 'frontend', 'not-a-surface' ) ) ) );

		$this->assertTrue( $result['success'] );
		$this->assertSame( array( 'frontend' ), json_decode( $GLOBALS['_wpdb_inserted_rows'][0]['data']['surfaces'], true ) );
	}

	/**
	 * Selecting every valid surface is functionally identical to selecting
	 * none (Detector::applicable_surfaces()'s own "empty means every
	 * surface" contract) -- stored as empty so a rule meant for every
	 * surface behaves the same whether or not a new surface is added later.
	 */
	public function test_create_normalises_every_surface_selected_to_an_empty_list(): void {
		$result = $this->store->create( $this->valid_input( array( 'surfaces' => array( 'frontend', 'admin', 'login', 'api' ) ) ) );

		$this->assertTrue( $result['success'] );
		$this->assertSame( array(), json_decode( $GLOBALS['_wpdb_inserted_rows'][0]['data']['surfaces'], true ) );
	}

	// ── update() ──────────────────────────────────────────────────────────────

	public function test_update_with_valid_input_succeeds(): void {
		$result = $this->store->update( 7, $this->valid_input( array( 'name' => 'Renamed' ) ) );

		$this->assertTrue( $result['success'] );
		$this->assertSame( 7, $result['id'] );
		$this->assertSame( 'Renamed', $GLOBALS['_wpdb_updated_rows'][0]['data']['name'] );
		$this->assertSame( array( 'id' => 7 ), $GLOBALS['_wpdb_updated_rows'][0]['where'] );
	}

	public function test_update_rejects_an_invalid_pattern_without_writing_anything(): void {
		$result = $this->store->update( 7, $this->valid_input( array( 'pattern' => '/(unterminated/' ) ) );

		$this->assertFalse( $result['success'] );
		$this->assertSame( array(), $GLOBALS['_wpdb_updated_rows'] );
	}

	// ── delete() ──────────────────────────────────────────────────────────────

	public function test_delete_issues_a_delete_query(): void {
		$this->assertTrue( $this->store->delete( 5 ) );
		$this->assertStringContainsString( 'DELETE FROM', $GLOBALS['_wpdb_last_query'] );
		$this->assertStringContainsString( 'id = 5', $GLOBALS['_wpdb_last_query'] );
	}

	// ── all() / get() ────────────────────────────────────────────────────────

	public function test_all_returns_stored_rows(): void {
		$GLOBALS['_wpdb_get_results'] = array( array( 'id' => 1, 'name' => 'x' ) );

		$this->assertSame( $GLOBALS['_wpdb_get_results'], $this->store->all() );
	}

	public function test_all_returns_empty_array_when_none_stored(): void {
		$GLOBALS['_wpdb_get_results'] = array();

		$this->assertSame( array(), $this->store->all() );
	}

	public function test_get_returns_null_when_not_found(): void {
		$GLOBALS['_wpdb_get_row'] = null;

		$this->assertNull( $this->store->get( 999 ) );
	}

	public function test_get_returns_the_stored_row(): void {
		$GLOBALS['_wpdb_get_row'] = array( 'id' => 4, 'name' => 'x' );

		$this->assertSame( $GLOBALS['_wpdb_get_row'], $this->store->get( 4 ) );
	}

	// ── test() ───────────────────────────────────────────────────────────────

	public function test_test_returns_true_for_a_matching_pattern(): void {
		$this->assertTrue( $this->store->test( '/\.bak$/i', '/old/config.BAK' ) );
	}

	public function test_test_returns_false_for_a_non_matching_pattern(): void {
		$this->assertFalse( $this->store->test( '/\.bak$/i', '/index.html' ) );
	}

	public function test_test_returns_null_for_an_invalid_pattern(): void {
		$this->assertNull( $this->store->test( '/(unterminated/', 'anything' ) );
	}

	public function test_test_returns_null_for_a_blank_pattern(): void {
		$this->assertNull( $this->store->test( '', 'anything' ) );
	}

	public function test_test_returns_null_for_a_pattern_over_the_length_cap(): void {
		$oversized = '/' . str_repeat( 'a', Custom_Rule_Store::MAX_PATTERN_LENGTH ) . '/';

		$this->assertNull( $this->store->test( $oversized, 'anything' ) );
	}
}
