<?php
/**
 * Smoke/regression coverage for includes/admin/views/page-overview.php's
 * Getting Started tab (Phase 4G guided onboarding flow) -- the first test to
 * directly exercise this view at all. Each checklist step's "done" state is
 * read live from the same stores the relevant admin page itself reads from
 * (Pillar_Registry, Traffic_Policy_Store, Baseline_Store, Certificate_Store,
 * and a direct csp_policy_profiles count), so this only asserts the correct
 * label/badge appears for each state -- not those stores' own behaviour,
 * which has its own test coverage elsewhere.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Recommendation_Registry;

class PageOverviewTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
		$GLOBALS['_wp_current_user_can']['manage_options'] = true;
		Recommendation_Registry::reset();
	}

	private function render_getting_started(): string {
		$_GET['tab'] = 'getting-started';

		$plugin   = \WP_SAM\Plugin::instance();
		$admin_ui = new \WP_SAM\Admin\Admin_UI( $plugin );

		ob_start();
		$admin_ui->render_overview();
		$output = (string) ob_get_clean();

		unset( $_GET['tab'] );

		return $output;
	}

	public function test_renders_every_step_as_not_started_on_a_fresh_install(): void {
		$GLOBALS['_wpdb_get_var']     = 0;
		$GLOBALS['_wpdb_get_results'] = array();
		$GLOBALS['_wpdb_get_row']     = null;

		$output = $this->render_getting_started();

		$this->assertStringContainsString( 'Getting Started', $output );
		$this->assertStringContainsString( 'Not started', $output );
		$this->assertStringContainsString( 'None enabled yet', $output );
		$this->assertStringContainsString( 'Every surface still Observe', $output );
		$this->assertStringContainsString( 'Not captured yet', $output );
		// "Certificates" appears twice ("Not configured" label plus the
		// "Go there" link text), so this only asserts the not-issued label.
		$this->assertStringContainsString( 'Not configured', $output );
	}

	public function test_renders_every_step_as_done_once_each_signal_is_present(): void {
		// Order matters for the queued globals below: matches the exact call
		// sequence inside page-overview.php's 'getting-started' data-loading
		// block. get_var uses the flat fallback instead of a queue -- some
		// earlier bootstrap/plugin-init code path also calls get_var, so a
		// one-shot queue entry gets consumed before this tab's own call runs.
		$GLOBALS['_wpdb_get_var']           = 1; // CSP: one non-disabled surface.
		$GLOBALS['_wpdb_get_results_queue'] = array(
			array( // Pillar_Registry::fetch_rows() -- one enabled pillar/surface row.
				array(
					'pillar'  => 'x-frame-options',
					'surface' => 'frontend',
					'enabled' => 1,
					'payload' => '',
				),
			),
			array( // Traffic_Policy_Store::all() -- one surface already enforcing.
				array(
					'surface'                   => 'frontend',
					'mode'                      => 'enforce',
					'rate_limit_max_requests'   => 100,
					'rate_limit_window_seconds' => 60,
					'login_max_failed_attempts' => 5,
					'login_lockout_seconds'     => 900,
				),
			),
		);
		$GLOBALS['_wpdb_get_row_queue'] = array(
			array( // Baseline_Store::get_current() -- a captured baseline.
				'id'         => 1,
				'is_current' => 1,
			),
			array( // Certificate_Store::latest_certificate() -- an issued cert.
				'id'         => 1,
				'domains'    => '["example.com"]',
				'key_pem'    => '',
				'not_after'  => '2027-01-01 00:00:00',
				'status'     => 'issued',
				'environment' => 'production',
			),
		);

		$output = $this->render_getting_started();

		$this->assertStringContainsString( 'In progress or active', $output );
		$this->assertStringContainsString( 'At least one enabled', $output );
		$this->assertStringContainsString( 'At least one surface enforcing', $output );
		$this->assertStringContainsString( 'Captured', $output );
		$this->assertStringContainsString( 'Issued', $output );
	}

	private function render_recommendations(): string {
		$_GET['tab'] = 'recommendations';

		$plugin   = \WP_SAM\Plugin::instance();
		$admin_ui = new \WP_SAM\Admin\Admin_UI( $plugin );

		ob_start();
		$admin_ui->render_overview();
		$output = (string) ob_get_clean();

		unset( $_GET['tab'] );

		return $output;
	}

	public function test_recommendations_tab_shows_the_empty_state_when_nothing_needs_attention(): void {
		// Every registered rule's own bare-defaults condition is "don't fire"
		// (no certificate configured, no drift, no exception due) -- asserted
		// per-rule in each rule's own test; this just confirms the view
		// handles an all-quiet result set correctly.
		$output = $this->render_recommendations();

		$this->assertStringContainsString( 'Recommendations', $output );
		$this->assertStringContainsString( 'Nothing to suggest right now', $output );
	}

	public function test_recommendations_tab_renders_a_populated_recommendation(): void {
		// Drives Recommendation_Rule_Unexplained_Drift (no domain/cert config
		// needed, so this is the simplest rule to populate live through the
		// view -- its own isolated behaviour is covered by
		// RecommendationRuleUnexplainedDriftTest). Queued in rule-evaluation
		// order (Certificate_Renewal_Rule makes no wpdb call at all when no
		// domain is configured; Unexplained_Drift_Rule's get_results() is
		// first, Exception_Expiring_Rule's is second).
		$GLOBALS['_wpdb_get_results_queue'] = array(
			array(
				array(
					'category'     => 'pillar',
					'surface'      => 'frontend',
					'item_key'     => 'x-frame-options.enabled',
					'risk_level'   => 'high',
					'last_seen_at' => '2026-01-01 00:00:00',
				),
			),
			array(), // Exception_Expiring_Rule -- nothing due.
		);

		$output = $this->render_recommendations();

		$this->assertStringNotContainsString( 'Nothing to suggest right now', $output );
		$this->assertStringContainsString( 'high or critical risk', $output );
		$this->assertStringContainsString( 'High risk', $output );
		$this->assertStringContainsString( 'Go there', $output );
	}

	public function test_other_tabs_still_render_and_link_to_getting_started(): void {
		$GLOBALS['_wpdb_get_var']     = 0;
		$GLOBALS['_wpdb_get_results'] = array();
		$GLOBALS['_wpdb_get_row']     = null;

		$_GET['tab'] = 'about';
		$plugin      = \WP_SAM\Plugin::instance();
		$admin_ui    = new \WP_SAM\Admin\Admin_UI( $plugin );

		ob_start();
		$admin_ui->render_overview();
		$output = (string) ob_get_clean();
		unset( $_GET['tab'] );

		$this->assertStringContainsString( 'Getting Started', $output );
	}
}
