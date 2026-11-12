<?php
/**
 * Smoke/regression coverage for includes/admin/views/page-advanced.php's
 * Campaigns tab -- no test previously rendered this view file at all.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;

class PageAdvancedTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	public function test_campaigns_tab_explains_the_actual_detection_criteria(): void {
		$_GET['tab'] = 'campaigns';
		$GLOBALS['_wpdb_get_results'] = array();

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-advanced.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'] );

		$this->assertStringContainsString( '10 or more distinct IPs', $output );
		$this->assertStringContainsString( '24-hour window', $output );
	}

	public function test_campaigns_tab_renders_one_shared_reason_field_and_both_forms(): void {
		$_GET['tab'] = 'campaigns';
		$GLOBALS['_wpdb_get_results'] = array( $this->campaign_row() );
		$GLOBALS['_wpdb_get_col']     = array( '203.0.113.10', '203.0.113.11' );

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-advanced.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'] );

		$this->assertSame( 1, substr_count( $output, 'placeholder="Reason"' ) );
		$this->assertStringContainsString( 'wp_sam_campaign_disposition', $output );
		$this->assertStringContainsString( 'wp_sam_campaign_block', $output );
		$this->assertStringContainsString( 'wp-sam-campaign-note-target', $output );
	}

	public function test_campaigns_tab_shows_participant_ips_in_the_info_popover(): void {
		$_GET['tab'] = 'campaigns';
		$GLOBALS['_wpdb_get_results'] = array( $this->campaign_row() );
		$GLOBALS['_wpdb_get_col']     = array( '203.0.113.10', '203.0.113.11' );

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-advanced.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'] );

		$this->assertStringContainsString( 'wp-sam-meta-popover', $output );
		$this->assertStringContainsString( '203.0.113.10', $output );
		$this->assertStringContainsString( '203.0.113.11', $output );
	}

	public function test_campaigns_tab_renders_the_dedicated_width_class(): void {
		$_GET['tab'] = 'campaigns';
		$GLOBALS['_wpdb_get_results'] = array();

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-advanced.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'] );

		$this->assertStringContainsString( 'wp-sam-campaigns-table', $output );
		$this->assertStringContainsString( 'No campaign detected yet.', $output );
	}

	public function test_campaigns_tab_labels_live_and_detected_counts_separately(): void {
		$_GET['tab'] = 'campaigns';
		$GLOBALS['_wpdb_get_results'] = array( $this->campaign_row() );
		$GLOBALS['_wpdb_get_col']     = array( '203.0.113.10', '203.0.113.11' );

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-advanced.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'] );

		$this->assertStringContainsString( '2 active', $output );
		$this->assertStringContainsString( '26 when detected', $output );
		$this->assertStringContainsString( 'IPs active in the last 24 hours:', $output );
		$this->assertStringContainsString( 'Block 2 Active IPs', $output );
	}

	public function test_campaigns_tab_marks_the_viewers_ip_and_leaves_it_out_of_the_block_count(): void {
		$_GET['tab']            = 'campaigns';
		$_SERVER['REMOTE_ADDR'] = '203.0.113.10';
		$GLOBALS['_wpdb_get_results'] = array( $this->campaign_row() );
		$GLOBALS['_wpdb_get_col']     = array( '203.0.113.10', '203.0.113.11' );

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-advanced.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'], $_SERVER['REMOTE_ADDR'] );

		$this->assertStringContainsString( '<code>203.0.113.10 (your IP)</code>', $output );
		$this->assertStringContainsString( 'Block 1 Active IP', $output );
		$this->assertStringNotContainsString( 'Block 2 Active IPs', $output );
	}

	public function test_campaigns_tab_disables_block_when_only_the_viewers_ip_is_active(): void {
		$_GET['tab']            = 'campaigns';
		$_SERVER['REMOTE_ADDR'] = '91.125.72.135';
		$GLOBALS['_wpdb_get_results'] = array( $this->campaign_row() );
		$GLOBALS['_wpdb_get_col']     = array( '91.125.72.135' );

		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-advanced.php';
		$output = (string) ob_get_clean();

		unset( $_GET['tab'], $_SERVER['REMOTE_ADDR'] );

		$this->assertStringContainsString( 'Nothing to Block', $output );
		$this->assertStringNotContainsString( 'return confirm(', $output );
		$this->assertStringContainsString( '1 active', $output );
		$this->assertStringContainsString( '26 when detected', $output );
	}

	/** @return array<string, mixed> */
	private function campaign_row(): array {
		return array(
			'id'                 => 5,
			'detector_id'        => 'header-consistency',
			'detector_family'    => 'header-consistency',
			'surface'            => 'frontend',
			'participant_count'  => 26,
			'status'             => 'detected',
			'first_detected_at'  => '2026-09-06 02:03:20',
			'last_detected_at'   => '2026-09-08 02:03:23',
			'disposition_note'   => '',
		);
	}
}
