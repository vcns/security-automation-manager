<?php
/**
 * Unit tests for WP_SAM\Admin\Security_Scorecard.
 *
 * counts() calls Protection_Status::areas() (see ProtectionStatusTest's own
 * docblock for its exact wpdb call sequence) and then Action_Centre::
 * count_open(), which re-runs Recommendation_Engine plus its own two
 * get_var() calls (pending CSP sources, unclassified dependencies) -- the
 * unclassified-dependency get_var() is shared with Protection_Status's own
 * scripts/dependencies area, so a single _wpdb_get_var value covers both
 * call sites consistently in these tests.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Admin\Security_Scorecard;
use WP_SAM\Intelligence\Recommendation_Registry;

class SecurityScorecardTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
		Recommendation_Registry::reset();
		$GLOBALS['_wpdb_get_col']           = array();
		$GLOBALS['_wpdb_get_results_queue'] = array( array(), array(), array() );
		$GLOBALS['_wpdb_get_var']           = 0;
		$GLOBALS['_wpdb_get_row_queue']     = array( null, null );
	}

	public function test_fresh_install_is_all_zero(): void {
		$counts = ( new Security_Scorecard() )->counts();

		$this->assertSame( array( 'protected' => 0, 'learning' => 0, 'needs_attention' => 0 ), $counts );
	}

	public function test_protected_areas_are_counted_and_not_in_use_areas_are_not(): void {
		// CSP enforced (protected) + traffic still observing (learning) + everything else stays not-in-use.
		$GLOBALS['_wpdb_get_col']              = array( 'enforce' );
		$GLOBALS['_wpdb_get_results_queue'][0] = array( array( 'surface' => 'frontend', 'mode' => 'observe' ) );

		$counts = ( new Security_Scorecard() )->counts();

		$this->assertSame( 1, $counts['protected'] );
		$this->assertSame( 1, $counts['learning'] );
	}

	public function test_learning_and_monitoring_both_bucket_into_learning(): void {
		// CSP report-only (learning) + traffic observe-only (monitoring) -- both land in the same tile.
		$GLOBALS['_wpdb_get_col']              = array( 'report-only' );
		$GLOBALS['_wpdb_get_results_queue'][0] = array( array( 'surface' => 'frontend', 'mode' => 'observe' ) );

		$counts = ( new Security_Scorecard() )->counts();

		$this->assertSame( 2, $counts['learning'] );
		$this->assertSame( 0, $counts['protected'] );
	}

	public function test_needs_attention_comes_from_action_centre_not_from_protection_status_directly(): void {
		// One unclassified dependency: Protection_Status marks that ONE area
		// "needs attention", and Action_Centre reports the SAME underlying
		// fact as one aggregate item -- needs_attention must read 1, not 2.
		// get_var() call order: (1) Protection_Status's own unclassified-
		// dependency count, (2) Action_Centre's pending-CSP-source count,
		// (3) Action_Centre's own unclassified-dependency count.
		$GLOBALS['_wpdb_get_results_queue'][1] = array(
			array(
				'pillar'  => 'dependency-governance',
				'surface' => 'frontend',
				'enabled' => 1,
				'payload' => wp_json_encode( array( 'mode' => 'enforce' ) ),
			),
		);
		$GLOBALS['_wpdb_get_var_queue'] = array( 1, 0, 1 );

		$counts = ( new Security_Scorecard() )->counts();

		$this->assertSame( 1, $counts['needs_attention'] );
	}
}
