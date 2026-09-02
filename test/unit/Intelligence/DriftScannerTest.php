<?php
/**
 * Unit tests for WP_SAM\Intelligence\Drift_Scanner.
 *
 * classify_risk() and correlate() are pure logic exercised directly via
 * reflection (mirroring ActivatorTest's convention for private methods) --
 * orchestrating four real collaborators' DB calls for every risk/
 * correlation combination would mean re-testing Baseline_State_Builder/
 * Baseline_Store/Drift_Store/Change_Log_Store's own already-covered
 * behaviour just to reach them. One full scan() test proves the wiring
 * itself works end to end.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\CSP\Policy_Builder;
use WP_SAM\Intelligence\Baseline_State_Builder;
use WP_SAM\Intelligence\Baseline_Store;
use WP_SAM\Intelligence\Change_Log_Store;
use WP_SAM\Intelligence\Drift_Scanner;
use WP_SAM\Intelligence\Drift_Store;
use WP_SAM\Modules\Feature_Gate;

class DriftScannerTest extends TestCase {

	private Drift_Scanner $scanner;

	protected function setUp(): void {
		wp_test_reset_globals();
		$policy_builder = new Policy_Builder( new Feature_Gate(), static fn ( string $s ) => array(), static fn ( string $s ) => array() );
		$this->scanner   = new Drift_Scanner(
			new Baseline_State_Builder( $policy_builder ),
			new Baseline_Store(),
			new Drift_Store(),
			new Change_Log_Store()
		);
	}

	private function invoke_classify_risk( string $category, ?array $old, ?array $new ): array {
		$method = new ReflectionMethod( Drift_Scanner::class, 'classify_risk' );
		$method->setAccessible( true );
		return $method->invoke( $this->scanner, $category, $old, $new );
	}

	private function invoke_correlate( string $category, string $item_key, array $recent_log ): string {
		$method = new ReflectionMethod( Drift_Scanner::class, 'correlate' );
		$method->setAccessible( true );
		return $method->invoke( $this->scanner, $category, $item_key, $recent_log );
	}

	// ── scan() ───────────────────────────────────────────────────────────────

	public function test_scan_with_no_baseline_reports_no_baseline_status(): void {
		$GLOBALS['_wpdb_get_row'] = null;

		$result = $this->scanner->scan();

		$this->assertSame( 'no_baseline', $result['status'] );
		$this->assertSame( 0, $result['drift_count'] );
		$this->assertSame( array(), $GLOBALS['_wpdb_inserted_rows'] ); // Nothing recorded without something to diff against.
	}

	public function test_scan_detects_a_changed_value_and_records_drift(): void {
		$baseline_state = array(
			array( 'category' => 'pillar', 'surface' => 'frontend', 'item_key' => 'x-frame-options', 'value' => 'on|SAMEORIGIN' ),
			// Baseline_State_Builder always contributes core/theme version rows
			// (via get_bloginfo()/wp_get_theme(), not the wpdb queue below) --
			// matching values here so only the pillar row above drifts.
			array( 'category' => 'core_version', 'surface' => '', 'item_key' => 'core', 'value' => '7.0' ),
			array( 'category' => 'theme_version', 'surface' => '', 'item_key' => 'default-theme', 'value' => '1.0' ),
		);
		$GLOBALS['_wpdb_get_row'] = array(
			'id'         => 1,
			'state_json' => wp_json_encode( $baseline_state ),
		);
		$GLOBALS['_wpdb_get_results_queue'] = array(
			array(), // csp_headers()
			array( array( 'pillar' => 'x-frame-options', 'surface' => 'frontend', 'enabled' => 1, 'payload' => 'DENY' ) ), // pillar_toggles()
			array(), // dependencies()
			array(), // internal_assets()
			array(), // certificates()
			array(), // Change_Log_Store::recent()
		);
		$GLOBALS['_wpdb_get_var'] = null; // Drift_Store::record()'s existing-row check.

		$result = $this->scanner->scan();

		$this->assertSame( 'scanned', $result['status'] );
		$this->assertSame( 1, $result['drift_count'] );
		$this->assertCount( 1, $GLOBALS['_wpdb_inserted_rows'] );
		$inserted = $GLOBALS['_wpdb_inserted_rows'][0]['data'];
		$this->assertSame( 'pillar', $inserted['category'] );
		$this->assertSame( 'x-frame-options', $inserted['item_key'] );
		$this->assertSame( 'on|SAMEORIGIN', $inserted['old_value'] );
	}

	public function test_scan_resolves_a_previously_drifted_item_that_now_matches(): void {
		$baseline_state = array(
			array( 'category' => 'pillar', 'surface' => 'frontend', 'item_key' => 'x-frame-options', 'value' => 'on|SAMEORIGIN' ),
			array( 'category' => 'core_version', 'surface' => '', 'item_key' => 'core', 'value' => '7.0' ),
			array( 'category' => 'theme_version', 'surface' => '', 'item_key' => 'default-theme', 'value' => '1.0' ),
		);
		$GLOBALS['_wpdb_get_row'] = array(
			'id'         => 1,
			'state_json' => wp_json_encode( $baseline_state ),
		);
		$GLOBALS['_wpdb_get_results_queue'] = array(
			array(),
			array( array( 'pillar' => 'x-frame-options', 'surface' => 'frontend', 'enabled' => 1, 'payload' => 'SAMEORIGIN' ) ), // Same as baseline.
			array(),
			array(),
			array(),
			array(),
		);

		$this->scanner->scan();

		// Every matching key (the pillar row plus the always-present core/theme
		// version rows fixed up above) gets a resolve() call -- harmless when
		// there was no open drift for that key, since the UPDATE simply
		// matches zero rows. All three must be resolves, none inserts.
		$this->assertSame( array(), $GLOBALS['_wpdb_inserted_rows'] );
		$this->assertCount( 3, $GLOBALS['_wpdb_updated_rows'] );
		foreach ( $GLOBALS['_wpdb_updated_rows'] as $update ) {
			$this->assertSame( 'resolved', $update['data']['disposition'] );
		}
	}

	// ── classify_risk() ──────────────────────────────────────────────────────

	public function test_version_changes_are_low_risk(): void {
		foreach ( array( 'core_version', 'plugin_version', 'theme_version' ) as $category ) {
			list( $risk ) = $this->invoke_classify_risk( $category, array( 'value' => '1.0' ), array( 'value' => '1.1' ) );
			$this->assertSame( 'low', $risk, "Expected low risk for {$category}" );
		}
	}

	public function test_csp_header_and_pillar_changes_are_medium_risk(): void {
		list( $risk1 ) = $this->invoke_classify_risk( 'csp_header', array( 'value' => 'a' ), array( 'value' => 'b' ) );
		list( $risk2 ) = $this->invoke_classify_risk( 'pillar', array( 'value' => 'a' ), array( 'value' => 'b' ) );

		$this->assertSame( 'medium', $risk1 );
		$this->assertSame( 'medium', $risk2 );
	}

	public function test_new_dependency_is_medium_a_reclassified_one_is_low(): void {
		list( $new_risk ) = $this->invoke_classify_risk( 'dependency', null, array( 'value' => 'approved' ) );
		list( $changed_risk ) = $this->invoke_classify_risk( 'dependency', array( 'value' => 'unclassified' ), array( 'value' => 'approved' ) );

		$this->assertSame( 'medium', $new_risk );
		$this->assertSame( 'low', $changed_risk );
	}

	public function test_internal_asset_hash_change_is_high_risk(): void {
		list( $risk, $reason ) = $this->invoke_classify_risk( 'internal_asset', array( 'value' => 'sha384-a' ), array( 'value' => 'sha384-b' ) );

		$this->assertSame( 'high', $risk );
		$this->assertStringContainsString( 'integrity hash changed', $reason );
	}

	public function test_certificate_change_is_high_risk(): void {
		list( $risk ) = $this->invoke_classify_risk( 'certificate', array( 'value' => 'expires:2026-01-01' ), array( 'value' => 'expires:2026-06-01' ) );

		$this->assertSame( 'high', $risk );
	}

	public function test_unrecognised_category_is_unknown_risk(): void {
		list( $risk ) = $this->invoke_classify_risk( 'something-new', array( 'value' => 'a' ), array( 'value' => 'b' ) );

		$this->assertSame( 'unknown', $risk );
	}

	// ── correlate() -- must never claim causation, only correlation ─────────

	public function test_correlate_returns_empty_string_with_no_recent_changes(): void {
		$this->assertSame( '', $this->invoke_correlate( 'plugin_version', 'akismet/akismet.php', array() ) );
	}

	public function test_correlate_matches_a_plugin_version_change_by_exact_item_name(): void {
		$log = array(
			array( 'change_type' => 'plugin_updated', 'item_name' => 'akismet/akismet.php', 'occurred_at' => gmdate( 'Y-m-d H:i:s', time() - 600 ) ),
		);

		$note = $this->invoke_correlate( 'plugin_version', 'akismet/akismet.php', $log );

		$this->assertStringContainsString( 'Correlates with', $note );
	}

	public function test_correlate_does_not_match_a_different_plugin(): void {
		$log = array(
			array( 'change_type' => 'plugin_updated', 'item_name' => 'other-plugin/other.php', 'occurred_at' => gmdate( 'Y-m-d H:i:s' ) ),
		);

		$this->assertSame( '', $this->invoke_correlate( 'plugin_version', 'akismet/akismet.php', $log ) );
	}

	public function test_correlate_matches_internal_asset_by_path_substring(): void {
		$log = array(
			array( 'change_type' => 'theme_updated', 'item_name' => 'twentytwentyfive', 'occurred_at' => gmdate( 'Y-m-d H:i:s' ) ),
		);

		$note = $this->invoke_correlate( 'internal_asset', '/wp-content/themes/twentytwentyfive/style.css', $log );

		$this->assertStringContainsString( 'Correlates with', $note );
	}

	public function test_correlate_gives_a_hedged_generic_note_for_unmatched_categories(): void {
		$log = array(
			array( 'change_type' => 'core_updated', 'item_name' => 'core', 'occurred_at' => gmdate( 'Y-m-d H:i:s', time() - 1200 ) ),
		);

		$note = $this->invoke_correlate( 'csp_header', 'frontend', $log );

		$this->assertNotSame( '', $note );
		$this->assertStringContainsString( 'related', $note );
	}

	/**
	 * §17 is explicit: "must not claim causation where only correlation
	 * exists". Every correlation note this class can produce must avoid
	 * causal language.
	 */
	public function test_correlation_wording_never_claims_causation(): void {
		$log = array(
			array( 'change_type' => 'plugin_updated', 'item_name' => 'akismet/akismet.php', 'occurred_at' => gmdate( 'Y-m-d H:i:s' ) ),
			array( 'change_type' => 'core_updated', 'item_name' => 'core', 'occurred_at' => gmdate( 'Y-m-d H:i:s' ) ),
		);

		$notes = array(
			$this->invoke_correlate( 'plugin_version', 'akismet/akismet.php', $log ),
			$this->invoke_correlate( 'csp_header', 'frontend', $log ),
		);

		foreach ( $notes as $note ) {
			foreach ( array( 'caused', 'because', 'due to', 'resulted in' ) as $causal_word ) {
				$this->assertStringNotContainsStringIgnoringCase( $causal_word, $note );
			}
		}
	}
}
