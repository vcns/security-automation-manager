<?php
/**
 * Smoke/regression coverage for includes/admin/views/page-traffic.php's
 * Custom Rules tab (Phase 4C extension -- fail2ban-style custom detection
 * rules). No test previously rendered this view file at all; the other
 * tabs (Policy/IP Rules/Blocks/Network Intelligence/Detectors) are a
 * pre-existing gap outside this coverage's scope.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;

class PageTrafficTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	public function test_custom_rules_tab_renders_without_fatal_when_empty(): void {
		$_GET['tab'] = 'custom-rules';
		$GLOBALS['_wpdb_get_results'] = array();

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-traffic.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'] );

		$this->assertStringContainsString( 'Custom Rules', $output );
		$this->assertStringContainsString( 'No custom rules yet.', $output );
		$this->assertStringContainsString( 'wp_sam_custom_rule_save', $output );
		$this->assertStringContainsString( 'wp-sam-custom-rule-test-button', $output );
	}

	public function test_custom_rules_tab_lists_a_stored_rule(): void {
		$_GET['tab'] = 'custom-rules';
		$GLOBALS['_wpdb_get_results'] = array(
			array(
				'id'            => 3,
				'name'          => 'Old backup file probe',
				'pattern'       => '/\.bak$/i',
				'subject_field' => 'request_uri',
				'severity'      => 'high',
				'surfaces'      => '[]',
				'description'   => '',
			),
		);

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-traffic.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'] );

		$this->assertStringContainsString( 'Old backup file probe', $output );
		$this->assertStringContainsString( 'custom_3', $output );
		$this->assertStringContainsString( 'All', $output );
	}

	public function test_custom_rules_tab_shows_validation_errors_from_a_failed_save(): void {
		$_GET['tab']              = 'custom-rules';
		$GLOBALS['_wpdb_get_results'] = array();
		set_transient( 'wp_sam_custom_rule_errors_' . get_current_user_id(), array( 'Pattern is required.' ) );
		set_transient( 'wp_sam_custom_rule_input_' . get_current_user_id(), array( 'name' => 'Half-typed rule' ) );

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-traffic.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'] );

		$this->assertStringContainsString( 'Rule not saved', $output );
		$this->assertStringContainsString( 'Pattern is required.', $output );
		$this->assertStringContainsString( 'Half-typed rule', $output );
	}

	public function test_custom_rules_tab_prefills_the_form_when_editing(): void {
		$_GET['tab']  = 'custom-rules';
		$_GET['edit'] = '3';
		$GLOBALS['_wpdb_get_results'] = array();
		$GLOBALS['_wpdb_get_row']     = array(
			'id'            => 3,
			'name'          => 'Old backup file probe',
			'pattern'       => '/\.bak$/i',
			'subject_field' => 'path',
			'severity'      => 'high',
			'surfaces'      => '["frontend"]',
			'description'   => 'Notes here',
		);

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-traffic.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'], $_GET['edit'] );

		$this->assertStringContainsString( 'Edit rule', $output );
		$this->assertStringContainsString( 'value="Old backup file probe"', $output );
		$this->assertStringContainsString( 'Notes here', $output );
	}
}
