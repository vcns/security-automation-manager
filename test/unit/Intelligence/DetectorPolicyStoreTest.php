<?php
/**
 * Unit tests for WP_SAM\Intelligence\Detector_Policy_Store.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Detector;
use WP_SAM\Intelligence\Detector_Policy_Store;

class DetectorPolicyStoreTest extends TestCase {

	private Detector_Policy_Store $store;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->store = new Detector_Policy_Store();
	}

	public function test_is_enabled_defaults_true_with_no_saved_row(): void {
		$GLOBALS['_wpdb_get_row'] = null;

		$this->assertTrue( $this->store->is_enabled( 'observe-only-fixture' ) );
	}

	public function test_is_enabled_reflects_a_saved_disabled_row(): void {
		$GLOBALS['_wpdb_get_row'] = array(
			'detector_id'    => 'observe-only-fixture',
			'is_enabled'     => 0,
			'control_action' => 'observe',
		);

		$this->assertFalse( $this->store->is_enabled( 'observe-only-fixture' ) );
	}

	public function test_control_action_for_returns_the_detectors_own_default_with_no_saved_row(): void {
		$GLOBALS['_wpdb_get_row'] = null;

		$this->assertSame( 'observe', $this->store->control_action_for( new Policy_Store_Observe_Only_Fixture_Detector() ) );
	}

	public function test_control_action_for_returns_a_saved_override_when_still_allowed(): void {
		$GLOBALS['_wpdb_get_row'] = array(
			'detector_id'    => 'enforce-capable-fixture',
			'is_enabled'     => 1,
			'control_action' => 'enforce',
		);

		$this->assertSame( 'enforce', $this->store->control_action_for( new Policy_Store_Enforce_Capable_Fixture_Detector() ) );
	}

	public function test_control_action_for_falls_back_to_default_when_the_saved_action_is_no_longer_allowed(): void {
		// Simulates a saved 'enforce' row surviving a detector class change
		// that later narrowed allowed_control_actions() back to observe-only.
		$GLOBALS['_wpdb_get_row'] = array(
			'detector_id'    => 'observe-only-fixture',
			'is_enabled'     => 1,
			'control_action' => 'enforce',
		);

		$this->assertSame( 'observe', $this->store->control_action_for( new Policy_Store_Observe_Only_Fixture_Detector() ) );
	}

	public function test_all_returns_every_saved_row(): void {
		$GLOBALS['_wpdb_get_results'] = array(
			array( 'detector_id' => 'a', 'is_enabled' => 1, 'control_action' => 'observe' ),
			array( 'detector_id' => 'b', 'is_enabled' => 0, 'control_action' => 'observe' ),
		);

		$this->assertCount( 2, $this->store->all() );
	}

	public function test_set_inserts_a_new_row_when_none_exists(): void {
		$GLOBALS['_wpdb_get_var'] = null;

		$result = $this->store->set( 'enforce-capable-fixture', true, 'enforce', array( 'observe', 'enforce' ) );

		$this->assertTrue( $result );
		$this->assertCount( 1, $GLOBALS['_wpdb_inserted_rows'] );
		$inserted = $GLOBALS['_wpdb_inserted_rows'][0]['data'];
		$this->assertSame( 'enforce-capable-fixture', $inserted['detector_id'] );
		$this->assertSame( 1, $inserted['is_enabled'] );
		$this->assertSame( 'enforce', $inserted['control_action'] );
	}

	public function test_set_updates_the_existing_row_when_one_exists(): void {
		$GLOBALS['_wpdb_get_var'] = '7';

		$this->store->set( 'enforce-capable-fixture', false, 'observe', array( 'observe', 'enforce' ) );

		$this->assertCount( 1, $GLOBALS['_wpdb_updated_rows'] );
		$this->assertSame( array( 'id' => 7 ), $GLOBALS['_wpdb_updated_rows'][0]['where'] );
	}

	public function test_set_silently_falls_back_to_observe_for_a_disallowed_control_action(): void {
		$GLOBALS['_wpdb_get_var'] = null;

		$this->store->set( 'observe-only-fixture', true, 'enforce', array( 'observe' ) );

		$this->assertSame( 'observe', $GLOBALS['_wpdb_inserted_rows'][0]['data']['control_action'] );
	}
}

final class Policy_Store_Observe_Only_Fixture_Detector extends Detector {
	public function id(): string {
		return 'observe-only-fixture';
	}
	public function family(): string {
		return 'fixture-family';
	}
	public function applicable_surfaces(): array {
		return array();
	}
	public function evaluate( array $context ): ?array {
		return null;
	}
}

final class Policy_Store_Enforce_Capable_Fixture_Detector extends Detector {
	public function id(): string {
		return 'enforce-capable-fixture';
	}
	public function family(): string {
		return 'fixture-family';
	}
	public function applicable_surfaces(): array {
		return array();
	}
	public function evaluate( array $context ): ?array {
		return null;
	}
	public function allowed_control_actions(): array {
		return array( 'observe', 'enforce' );
	}
}
