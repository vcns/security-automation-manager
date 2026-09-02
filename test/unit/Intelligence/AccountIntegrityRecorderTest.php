<?php
/**
 * Unit tests for WP_SAM\Intelligence\Account_Integrity_Recorder.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Account_Integrity_Recorder;
use WP_SAM\Intelligence\Change_Log_Store;

class AccountIntegrityRecorderTest extends TestCase {

	private Account_Integrity_Recorder $recorder;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->recorder = new Account_Integrity_Recorder( new Change_Log_Store() );
	}

	public function test_register_hooks_set_user_role(): void {
		$this->recorder->register();

		$this->assertArrayHasKey( 'set_user_role', $GLOBALS['_wp_actions'] );
	}

	public function test_new_administrator_with_no_prior_roles_records_account_created(): void {
		$GLOBALS['_wp_userdata'][7] = 'jane';

		$this->recorder->on_set_user_role( 7, 'administrator', array() );

		$this->assertCount( 1, $GLOBALS['_wpdb_inserted_rows'] );
		$data = $GLOBALS['_wpdb_inserted_rows'][0]['data'];
		$this->assertSame( 'admin_account_created', $data['change_type'] );
		$this->assertSame( 'jane', $data['item_name'] );
		$this->assertSame( 'administrator', $data['new_version'] );
	}

	public function test_existing_user_promoted_to_administrator_records_role_granted(): void {
		$GLOBALS['_wp_userdata'][7] = 'jane';

		$this->recorder->on_set_user_role( 7, 'administrator', array( 'editor' ) );

		$data = $GLOBALS['_wpdb_inserted_rows'][0]['data'];
		$this->assertSame( 'admin_role_granted', $data['change_type'] );
		$this->assertSame( 'editor', $data['old_version'] );
	}

	public function test_already_an_administrator_records_nothing(): void {
		$this->recorder->on_set_user_role( 7, 'administrator', array( 'administrator' ) );

		$this->assertSame( array(), $GLOBALS['_wpdb_inserted_rows'] );
	}

	public function test_a_non_administrator_role_records_nothing(): void {
		$this->recorder->on_set_user_role( 7, 'editor', array() );

		$this->assertSame( array(), $GLOBALS['_wpdb_inserted_rows'] );
	}

	public function test_falls_back_to_the_user_id_when_userdata_is_unavailable(): void {
		$this->recorder->on_set_user_role( 42, 'administrator', array() );

		$this->assertSame( '42', $GLOBALS['_wpdb_inserted_rows'][0]['data']['item_name'] );
	}
}
