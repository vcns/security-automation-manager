<?php
/**
 * Unit tests for WP_SAM\Security\Dependency_Integrity_Monitor.
 *
 * scan_surface()'s actual tag-parsing/mismatch-detection depends on
 * WP_HTML_Tag_Processor, a WordPress core class this lightweight test
 * environment does not load (see DependencyGovernanceBuilderTest and
 * ReverseTabnabbingBuilderTest for the same, already-accepted limitation).
 * These tests cover the guard clauses that matter most for safety: the scan
 * never fetches anything third-party-facing when there's nothing pinned to
 * check against, and fails closed (no crash, empty result) when the tag
 * processor is unavailable, rather than fetching a URL it then can't inspect.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Modules\Audit_Log;
use WP_SAM\Security\Dependency_Integrity_Monitor;

class DependencyIntegrityMonitorTest extends TestCase {

	private Audit_Log $audit;
	private Dependency_Integrity_Monitor $monitor;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->audit   = new Audit_Log();
		$this->monitor = new Dependency_Integrity_Monitor( $this->audit );
	}

	public function test_scan_surface_skips_fetch_when_nothing_is_pinned(): void {
		$GLOBALS['_wpdb_get_results_queue'] = array( array() );

		$result = $this->monitor->scan_surface( 'frontend', 'https://example.com/' );

		$this->assertSame( array(), $result );
		$this->assertSame( array(), $GLOBALS['_wp_remote_get_requests'] );
	}

	public function test_scan_surface_ignores_pinned_rows_with_no_expected_sri(): void {
		$GLOBALS['_wpdb_get_results_queue'] = array(
			array(
				array( 'resource_type' => 'script', 'origin' => 'https://cdn.example.com', 'expected_sri' => '' ),
				array( 'resource_type' => 'script', 'origin' => 'https://cdn.example.com', 'expected_sri' => null ),
			),
		);

		$result = $this->monitor->scan_surface( 'frontend', 'https://example.com/' );

		$this->assertSame( array(), $result );
		$this->assertSame( array(), $GLOBALS['_wp_remote_get_requests'] );
	}

	public function test_scan_surface_fails_closed_when_html_tag_processor_is_unavailable(): void {
		if ( class_exists( 'WP_HTML_Tag_Processor' ) ) {
			$this->markTestSkipped( 'WP_HTML_Tag_Processor is available in this environment; fail-open guard is not exercised.' );
		}

		$GLOBALS['_wpdb_get_results_queue'] = array(
			array(
				array( 'resource_type' => 'script', 'origin' => 'https://cdn.example.com', 'expected_sri' => 'sha384-abc123' ),
			),
		);

		$result = $this->monitor->scan_surface( 'frontend', 'https://example.com/' );

		$this->assertSame( array(), $result );
		// Never fetched the homepage at all: no point making the request if the
		// result can't be inspected once it arrives.
		$this->assertSame( array(), $GLOBALS['_wp_remote_get_requests'] );
	}

	// ── Fetching the page ────────────────────────────────────────────────────
	//
	// Reached through reflection: scan_surface() only fetches once
	// WP_HTML_Tag_Processor exists, which this environment doesn't load.

	private function fetch_page( Dependency_Integrity_Monitor $monitor, string $url ): ?string {
		return ( new ReflectionMethod( Dependency_Integrity_Monitor::class, 'fetch_page' ) )->invoke( $monitor, $url );
	}

	public function test_a_redirect_away_from_this_site_is_logged_without_its_destination_and_not_followed(): void {
		$GLOBALS['_wp_remote_get_response_queue'] = array(
			array(
				'response' => array( 'code' => 302 ),
				'headers'  => array( 'location' => 'https://other-copy.example.org/' ),
				'body'     => '',
			),
			array(
				'response' => array( 'code' => 200 ),
				'body'     => '<script src="https://cdn.example.net/app.js" integrity="sha384-other"></script>',
			),
		);
		$audit = $this->createMock( Audit_Log::class );
		$audit->expects( $this->once() )
			->method( 'log' )
			->with(
				'dependency_integrity_monitor',
				'scan_redirected_offsite',
				$this->logicalAnd(
					$this->stringContains( 'https://example.com/ redirected away from this site (HTTP 302)' ),
					$this->logicalNot( $this->stringContains( 'other-copy' ) )
				),
				'warning'
			);

		$this->assertNull( $this->fetch_page( new Dependency_Integrity_Monitor( $audit ), 'https://example.com/' ) );
		$this->assertCount( 1, $GLOBALS['_wp_remote_get_requests'], 'The other site is never requested, so its markup is never compared.' );
	}

	public function test_the_page_is_read_when_this_site_serves_it(): void {
		$GLOBALS['_wp_remote_get_response'] = array(
			'response' => array( 'code' => 200 ),
			'body'     => '<p>home</p>',
		);

		$this->assertSame( '<p>home</p>', $this->fetch_page( $this->monitor, 'https://example.com/' ) );
	}

	// ── maybe_run_scan() gating ──────────────────────────────────────────────

	public function test_maybe_run_scan_sets_the_daily_transient_gate(): void {
		$GLOBALS['_wpdb_get_results_queue'] = array( array() );

		$this->monitor->maybe_run_scan();

		$this->assertSame( 1, $GLOBALS['_wp_transients']['wp_sam_dependency_integrity_scan_ran'] );
	}

	public function test_maybe_run_scan_is_a_noop_when_the_gate_is_already_set(): void {
		$GLOBALS['_wp_transients']['wp_sam_dependency_integrity_scan_ran'] = 1;

		$this->monitor->maybe_run_scan();

		$this->assertSame( array(), $GLOBALS['_wp_remote_get_requests'] );
	}
}
