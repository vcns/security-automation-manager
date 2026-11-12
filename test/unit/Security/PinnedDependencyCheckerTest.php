<?php
/**
 * Unit tests for WP_SAM\Security\Pinned_Dependency_Checker (daily re-hash
 * of pinned third-party files) and the shared Dependency_Sri_Fetcher guard.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Modules\Audit_Log;
use WP_SAM\Security\Dependency_Sri_Fetcher;
use WP_SAM\Security\Pinned_Dependency_Checker;

class PinnedDependencyCheckerTest extends TestCase {

	private const BODY = 'console.log("vendor v1");';

	private Pinned_Dependency_Checker $checker;

	protected function setUp(): void {
		wp_test_reset_globals();
		// Audit_Log only writes once its table exists (SHOW TABLES LIKE).
		$GLOBALS['_wpdb_get_var'] = 'wp_sam_audit_log';
		$this->checker            = new Pinned_Dependency_Checker( new Audit_Log() );
	}

	private static function sri( string $algorithm, string $body ): string {
		return $algorithm . '-' . base64_encode( hash( $algorithm, $body, true ) );
	}

	/** @param array<string, mixed> $overrides */
	private function row( array $overrides = array() ): array {
		return array_merge(
			array(
				'id'                 => 7,
				'surface'            => 'frontend',
				'resource_type'      => 'script',
				'origin'             => 'https://cdn.example.net',
				'expected_sri'       => self::sri( 'sha384', self::BODY ),
				'pinned_url'         => 'https://cdn.example.net/lib/v1/lib.min.js',
				'last_seen_url'      => 'https://cdn.example.net/lib/v1/other.js',
				'drift_detected_at'  => null,
				'drift_observed_sri' => null,
			),
			$overrides
		);
	}

	/** @param array<int, array<string, mixed>> $rows */
	private function with_rows( array $rows ): void {
		$GLOBALS['_wpdb_get_results_queue'] = array( $rows );
	}

	private function respond( string $body, int $code = 200 ): void {
		$GLOBALS['_wp_remote_get_response'] = array(
			'response' => array( 'code' => $code ),
			'body'     => $body,
		);
	}

	/** @return array<int, array<string, mixed>> audit rows written to sam_audit_log */
	private function audit_rows(): array {
		return array_values(
			array_filter(
				$GLOBALS['_wpdb_inserted_rows'],
				static fn( array $insert ): bool => str_ends_with( $insert['table'], 'sam_audit_log' )
			)
		);
	}

	// ── register() ───────────────────────────────────────────────────────────

	public function test_register_schedules_the_daily_event_once(): void {
		$this->checker->register();
		$first = $GLOBALS['_wp_cron'][ Pinned_Dependency_Checker::CHECK_HOOK ] ?? null;
		$this->assertNotNull( $first );

		$this->checker->register();
		$this->assertSame( $first, $GLOBALS['_wp_cron'][ Pinned_Dependency_Checker::CHECK_HOOK ] );
	}

	public function test_deactivation_unschedules_the_check(): void {
		$this->checker->register();

		\WP_SAM\Deactivator::deactivate();

		$this->assertArrayNotHasKey( Pinned_Dependency_Checker::CHECK_HOOK, $GLOBALS['_wp_cron'] );
	}

	// ── match / mismatch ─────────────────────────────────────────────────────

	public function test_matching_file_clears_drift_and_records_check_time(): void {
		$this->with_rows( array( $this->row( array( 'drift_detected_at' => '2026-10-01 00:00:00', 'drift_observed_sri' => 'sha384-old' ) ) ) );
		$this->respond( self::BODY );

		$summary = $this->checker->run_check();

		$this->assertSame( 1, $summary['matched'] );
		$this->assertSame( 'https://cdn.example.net/lib/v1/lib.min.js', $GLOBALS['_wp_remote_get_requests'][0]['url'] );
		$update = $GLOBALS['_wpdb_updated_rows'][0];
		$this->assertSame( array( 'id' => 7 ), $update['where'] );
		$this->assertNull( $update['data']['drift_detected_at'] );
		$this->assertNull( $update['data']['drift_observed_sri'] );
		$this->assertNull( $update['data']['integrity_check_error'] );
		$this->assertNotEmpty( $update['data']['integrity_checked_at'] );
		$this->assertSame( array(), $this->audit_rows() );
	}

	public function test_changed_file_records_drift_and_warns_once(): void {
		$this->with_rows( array( $this->row() ) );
		$this->respond( 'console.log("vendor v2");' );

		$summary = $this->checker->run_check();

		$this->assertSame( 1, $summary['drifted'] );
		$update = $GLOBALS['_wpdb_updated_rows'][0]['data'];
		$this->assertSame( self::sri( 'sha384', 'console.log("vendor v2");' ), $update['drift_observed_sri'] );
		$this->assertNotEmpty( $update['drift_detected_at'] );

		$audit = $this->audit_rows();
		$this->assertCount( 1, $audit );
		$this->assertSame( 'dependency_integrity_monitor', $audit[0]['data']['component'] );
		$this->assertSame( 'pinned_hash_drift', $audit[0]['data']['event'] );
		$this->assertSame( 'warning', $audit[0]['data']['severity'] );
		$this->assertStringContainsString( 'Decide → Dependency Classification', $audit[0]['data']['detail'] );
	}

	public function test_already_drifting_row_keeps_first_detection_time_and_does_not_warn_again(): void {
		$observed = self::sri( 'sha384', 'console.log("vendor v2");' );
		$this->with_rows( array( $this->row( array( 'drift_detected_at' => '2026-10-01 03:00:00', 'drift_observed_sri' => $observed ) ) ) );
		$this->respond( 'console.log("vendor v2");' );

		$this->checker->run_check();

		$update = $GLOBALS['_wpdb_updated_rows'][0]['data'];
		$this->assertSame( '2026-10-01 03:00:00', $update['drift_detected_at'] );
		$this->assertSame( array(), $this->audit_rows() );
	}

	public function test_a_second_vendor_change_warns_again_but_keeps_first_detection_time(): void {
		$this->with_rows( array( $this->row( array( 'drift_detected_at' => '2026-10-01 03:00:00', 'drift_observed_sri' => 'sha384-v2' ) ) ) );
		$this->respond( 'console.log("vendor v3");' );

		$this->checker->run_check();

		$this->assertSame( '2026-10-01 03:00:00', $GLOBALS['_wpdb_updated_rows'][0]['data']['drift_detected_at'] );
		$this->assertCount( 1, $this->audit_rows() );
	}

	// ── fetch failures are never drift ──────────────────────────────────────

	/** @return array<string, array{0: mixed}> */
	public static function failing_responses(): array {
		return array(
			'transport error' => array( new WP_Error( 'http_request_failed', 'timeout' ) ),
			'404'             => array( array( 'response' => array( 'code' => 404 ), 'body' => 'not found' ) ),
			'empty body'      => array( array( 'response' => array( 'code' => 200 ), 'body' => '' ) ),
			'over 5 MB'       => array( array( 'response' => array( 'code' => 200 ), 'body' => str_repeat( 'a', 5 * MB_IN_BYTES + 1 ) ) ),
		);
	}

	/** @dataProvider failing_responses */
	public function test_fetch_failure_is_recorded_separately_and_never_as_drift( mixed $response ): void {
		$this->with_rows( array( $this->row( array( 'drift_detected_at' => null ) ) ) );
		$GLOBALS['_wp_remote_get_response'] = $response;

		$summary = $this->checker->run_check();

		$this->assertSame( 1, $summary['failed'] );
		$this->assertSame( 0, $summary['drifted'] );
		$update = $GLOBALS['_wpdb_updated_rows'][0]['data'];
		$this->assertArrayNotHasKey( 'drift_detected_at', $update );
		$this->assertArrayNotHasKey( 'drift_observed_sri', $update );
		$this->assertArrayNotHasKey( 'integrity_checked_at', $update );
		$this->assertNotEmpty( $update['integrity_check_error'] );
		$this->assertSame( array(), $this->audit_rows() );
	}

	// ── algorithm ────────────────────────────────────────────────────────────

	/** @return array<string, array{0: string}> */
	public static function algorithms(): array {
		return array(
			'sha256' => array( 'sha256' ),
			'sha384' => array( 'sha384' ),
			'sha512' => array( 'sha512' ),
		);
	}

	/** @dataProvider algorithms */
	public function test_hashes_with_the_pinned_hash_algorithm( string $algorithm ): void {
		$this->with_rows( array( $this->row( array( 'expected_sri' => self::sri( $algorithm, self::BODY ) ) ) ) );
		$this->respond( self::BODY );

		$summary = $this->checker->run_check();

		$this->assertSame( 1, $summary['matched'], "A {$algorithm} pin must be re-hashed with {$algorithm}, not the Suggest default." );
	}

	// ── same-origin guard / URL choice ──────────────────────────────────────

	public function test_falls_back_to_last_seen_url_for_rows_pinned_before_v48(): void {
		$this->with_rows( array( $this->row( array( 'pinned_url' => null ) ) ) );
		$this->respond( self::BODY );

		$this->checker->run_check();

		$this->assertSame( 'https://cdn.example.net/lib/v1/other.js', $GLOBALS['_wp_remote_get_requests'][0]['url'] );
	}

	public function test_never_fetches_a_url_on_another_origin(): void {
		$this->with_rows( array( $this->row( array( 'pinned_url' => 'https://169.254.169.254/latest/meta-data' ) ) ) );

		$summary = $this->checker->run_check();

		$this->assertSame( array(), $GLOBALS['_wp_remote_get_requests'] );
		$this->assertSame( 1, $summary['failed'] );
		$this->assertSame( Dependency_Sri_Fetcher::ERROR_ORIGIN_MISMATCH, $GLOBALS['_wpdb_updated_rows'][0]['data']['integrity_check_error'] );
	}

	public function test_never_fetches_plain_http(): void {
		$this->with_rows( array( $this->row( array( 'origin' => 'http://cdn.example.net', 'pinned_url' => 'http://cdn.example.net/lib.js' ) ) ) );

		$this->checker->run_check();

		$this->assertSame( array(), $GLOBALS['_wp_remote_get_requests'] );
		$this->assertSame( Dependency_Sri_Fetcher::ERROR_NOT_HTTPS, $GLOBALS['_wpdb_updated_rows'][0]['data']['integrity_check_error'] );
	}

	public function test_fetch_uses_tls_verification_timeout_size_cap_and_unsafe_url_rejection(): void {
		$this->with_rows( array( $this->row() ) );
		$this->respond( self::BODY );

		$this->checker->run_check();

		$args = $GLOBALS['_wp_remote_get_requests'][0]['args'];
		$this->assertTrue( $args['sslverify'] );
		$this->assertSame( 10, $args['timeout'] );
		$this->assertTrue( $args['reject_unsafe_urls'] );
		$this->assertSame( 5 * MB_IN_BYTES + 1, $args['limit_response_size'] );
	}

	// ── cost cap ─────────────────────────────────────────────────────────────

	public function test_query_is_capped_and_ordered_least_recently_attempted_first(): void {
		$this->with_rows( array() );

		$this->checker->run_check();

		$query = (string) $GLOBALS['_wpdb_last_get_results_query'];
		$this->assertStringContainsString( "classification = 'immutable_pinned'", $query );
		$this->assertStringContainsString( 'ORDER BY integrity_attempted_at ASC', $query );
		$this->assertStringContainsString( 'LIMIT ' . Pinned_Dependency_Checker::MAX_ROWS_PER_RUN, $query );
	}

	public function test_processes_at_most_the_cap_even_if_more_rows_come_back(): void {
		$rows = array();
		for ( $i = 1; $i <= Pinned_Dependency_Checker::MAX_ROWS_PER_RUN + 5; $i++ ) {
			$rows[] = $this->row(
				array(
					'id'         => $i,
					'pinned_url' => "https://cdn.example.net/lib/{$i}.js",
				)
			);
		}
		$this->with_rows( $rows );
		$this->respond( self::BODY );

		$summary = $this->checker->run_check();

		$this->assertSame( Pinned_Dependency_Checker::MAX_ROWS_PER_RUN, $summary['checked'] );
		$this->assertCount( Pinned_Dependency_Checker::MAX_ROWS_PER_RUN, $GLOBALS['_wp_remote_get_requests'] );
	}

	public function test_same_url_on_several_surfaces_is_fetched_once_per_run(): void {
		$this->with_rows(
			array(
				$this->row( array( 'id' => 1 ) ),
				$this->row( array( 'id' => 2, 'surface' => 'login' ) ),
			)
		);
		$this->respond( self::BODY );

		$summary = $this->checker->run_check();

		$this->assertSame( 2, $summary['matched'] );
		$this->assertCount( 1, $GLOBALS['_wp_remote_get_requests'] );
	}

	public function test_skips_rows_with_a_malformed_expected_sri_without_fetching(): void {
		$this->with_rows( array( $this->row( array( 'expected_sri' => 'md5-abc' ) ) ) );

		$summary = $this->checker->run_check();

		$this->assertSame( 0, $summary['checked'] );
		$this->assertSame( array(), $GLOBALS['_wp_remote_get_requests'] );
	}

	// ── Dependency_Sri_Fetcher helpers ──────────────────────────────────────

	public function test_algorithm_of_parses_only_well_formed_single_hashes(): void {
		$this->assertSame( 'sha256', Dependency_Sri_Fetcher::algorithm_of( 'sha256-abc=' ) );
		$this->assertSame( 'sha512', Dependency_Sri_Fetcher::algorithm_of( ' sha512-abc ' ) );
		$this->assertNull( Dependency_Sri_Fetcher::algorithm_of( 'sha1-abc' ) );
		$this->assertNull( Dependency_Sri_Fetcher::algorithm_of( 'sha384-abc sha384-def' ) );
		$this->assertNull( Dependency_Sri_Fetcher::algorithm_of( '' ) );
	}

	public function test_is_allowed_url_requires_https_and_the_exact_origin(): void {
		$this->assertTrue( Dependency_Sri_Fetcher::is_allowed_url( 'https://cdn.example.net/a.js', 'https://cdn.example.net' ) );
		$this->assertFalse( Dependency_Sri_Fetcher::is_allowed_url( 'https://evil.example.net/a.js', 'https://cdn.example.net' ) );
		$this->assertFalse( Dependency_Sri_Fetcher::is_allowed_url( 'https://cdn.example.net.evil.test/a.js', 'https://cdn.example.net' ) );
		$this->assertFalse( Dependency_Sri_Fetcher::is_allowed_url( 'http://cdn.example.net/a.js', 'http://cdn.example.net' ) );
		$this->assertFalse( Dependency_Sri_Fetcher::is_allowed_url( '', 'https://cdn.example.net' ) );
	}
}
