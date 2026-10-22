<?php
/**
 * The four lifecycle pages (Observe, Decide, Control, Verify) are how staff
 * reach every page hidden from the left-hand menu. Covers the links to
 * Advanced Intelligence's tabs, which used to sit in the menu as a sixth
 * item of their own.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;

class PageLifecycleTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	/**
	 * @return array<string, array{0: string, 1: string, 2: string}>
	 */
	public static function advanced_intelligence_links(): array {
		return array(
			'Observe -> Timeline'       => array( 'observe', 'tab=timeline', 'View Timeline' ),
			'Decide -> Campaigns'       => array( 'decide', 'tab=campaigns', 'View Campaigns' ),
			'Control -> Honey Paths'    => array( 'control', 'tab=honeypaths', 'Manage Honey Paths' ),
			'Verify -> Change Windows'  => array( 'verify', 'tab=change-windows', 'View Change Windows' ),
		);
	}

	/**
	 * @dataProvider advanced_intelligence_links
	 */
	public function test_each_advanced_intelligence_tab_is_linked_from_its_lifecycle_stage( string $stage, string $tab_query, string $link_text ): void {
		$output = $this->render( $stage );

		$this->assertStringContainsString( 'admin.php?page=security-automation-manager-advanced&' . $tab_query, $output );
		$this->assertStringContainsString( $link_text, $output );
	}

	public function test_decide_counts_campaigns_awaiting_a_decision(): void {
		// Queue order follows the page's own queries: pending sources,
		// active exceptions, then campaigns still 'detected'.
		$GLOBALS['_wpdb_get_var_queue'] = array( 0, 0, 3 );

		$this->assertStringContainsString( '3 campaigns awaiting a decision.', $this->render( 'decide' ) );
	}

	private function render( string $stage ): string {
		ob_start();
		require WP_SAM_DIR . 'includes/admin/views/page-' . $stage . '.php';
		return (string) ob_get_clean();
	}
}
