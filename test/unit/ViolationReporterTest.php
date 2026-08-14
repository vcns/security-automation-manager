<?php
/**
 * Unit tests for WP_SAM\CSP\Violation_Reporter.
 *
 * Tests normalisation of both CSP Level 3 and Reporting API payloads,
 * deduplication fingerprint generation, rate limiting, and edge cases.
 * Database writes are stubbed via a subclass.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\CSP\Learning_Window;
use WP_SAM\CSP\Violation_Reporter;
use WP_SAM\Modules\Audit_Log;

class ViolationReporterTest extends TestCase {

	private Audit_Log          $audit;
	private Violation_Reporter $reporter;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->audit    = $this->createMock( Audit_Log::class );
		$this->reporter = new Violation_Reporter( $this->audit );
	}

	// ── handle(): Content-Type enforcement ───────────────────────────────────

	public function test_wrong_content_type_returns_400(): void {
		$GLOBALS['_wp_rest_headers']['content-type'] = 'text/plain';
		$request = $this->make_request(
			'{"csp-report":{"violated-directive":"script-src","document-uri":"https://example.com/","blocked-uri":"https://evil.com"}}'
		);

		$response = $this->reporter->handle( $request );

		$this->assertSame( 400, $response->get_status() );
	}

	public function test_csp_report_content_type_is_accepted(): void {
		$GLOBALS['_wp_rest_headers']['content-type'] = 'application/csp-report';
		$request = $this->make_request(
			'{"csp-report":{"violated-directive":"script-src","document-uri":"https://example.com/","blocked-uri":"https://cdn.example.com"}}'
		);

		$response = $this->reporter->handle( $request );

		$this->assertSame( 204, $response->get_status() );
	}

	public function test_reports_json_content_type_is_accepted(): void {
		$GLOBALS['_wp_rest_headers']['content-type'] = 'application/reports+json';
		$request = $this->make_request(
			'[{"type":"csp-violation","body":{"violatedDirective":"script-src","documentURL":"https://example.com/","blockedURL":"https://cdn.example.com"}}]'
		);

		$response = $this->reporter->handle( $request );

		$this->assertSame( 204, $response->get_status() );
	}

	// ── handle(): Cross-origin rejection ──────────────────────────────────────

	public function test_cross_origin_document_uri_is_silently_discarded(): void {
		$GLOBALS['_wp_rest_headers']['content-type'] = 'application/csp-report';
		$request = $this->make_request(
			'{"csp-report":{"violated-directive":"script-src","document-uri":"https://attacker.net/page","blocked-uri":"https://cdn.example.com"}}'
		);

		$response = $this->reporter->handle( $request );

		// Still returns 204 — must not reveal rejection to the sender.
		$this->assertSame( 204, $response->get_status() );
		// Rate-limit transient must not be set (report was dropped before rate check).
		$this->assertArrayNotHasKey( 'wp_sam_viol_rate_frontend_script-src', $GLOBALS['_wp_transients'] );
	}

	// ── handle(): Rate limiting ────────────────────────────────────────────────

	public function test_configured_report_endpoint_host_is_accepted_as_document_origin(): void {
		update_option( 'wp_sam_report_endpoint_url', 'https://staging.example.net/wp-json/custom-endpoint/v1/report' );
		$GLOBALS['_wp_rest_headers']['content-type'] = 'application/csp-report';

		$request = $this->make_request(
			'{"csp-report":{"violated-directive":"img-src","document-uri":"https://staging.example.net/","blocked-uri":"https://cdn.example.com/pixel.png"}}'
		);

		$this->reporter->handle( $request );

		$this->assertSame( 'query', $GLOBALS['_wpdb_last_operation'] );
		$this->assertArrayHasKey( 'wp_sam_viol_rate_frontend_img-src', $GLOBALS['_wp_transients'] );
	}

	public function test_forwarded_host_is_accepted_as_document_origin(): void {
		$_SERVER['HTTP_X_FORWARDED_HOST']            = 'staging.example.net, internal.example.local';
		$GLOBALS['_wp_rest_headers']['content-type'] = 'application/csp-report';

		$request = $this->make_request(
			'{"csp-report":{"violated-directive":"img-src","document-uri":"https://staging.example.net/","blocked-uri":"https://cdn.example.com/pixel.png"}}'
		);

		$this->reporter->handle( $request );

		$this->assertSame( 'query', $GLOBALS['_wpdb_last_operation'] );
		$this->assertArrayHasKey( 'wp_sam_viol_rate_frontend_img-src', $GLOBALS['_wp_transients'] );
	}

	public function test_report_is_dropped_when_rate_limit_exceeded(): void {
		$GLOBALS['_wp_rest_headers']['content-type']                       = 'application/csp-report';
		$GLOBALS['_wp_transients']['wp_sam_viol_rate_frontend_script-src'] = 500;

		$request = $this->make_request(
			'{"csp-report":{"violated-directive":"script-src","document-uri":"https://example.com/","blocked-uri":"https://cdn.example.com"}}'
		);

		$this->reporter->handle( $request );

		$this->assertSame( 500, $GLOBALS['_wp_transients']['wp_sam_viol_rate_frontend_script-src'] );
		$this->assertNull( $GLOBALS['_wpdb_last_operation'] );
	}

	public function test_rate_limit_is_scoped_per_directive_not_shared_across_surface(): void {
		$GLOBALS['_wp_rest_headers']['content-type']                       = 'application/csp-report';
		// style-src-attr is saturated, but img-src on the same surface has its own budget.
		$GLOBALS['_wp_transients']['wp_sam_viol_rate_frontend_style-src-attr'] = 500;

		$request = $this->make_request(
			'{"csp-report":{"violated-directive":"img-src","document-uri":"https://example.com/","blocked-uri":"https://cdn.example.com/pixel.png"}}'
		);

		$this->reporter->handle( $request );

		$this->assertSame( 'query', $GLOBALS['_wpdb_last_operation'] );
		$this->assertArrayHasKey( 'wp_sam_viol_rate_frontend_img-src', $GLOBALS['_wp_transients'] );
	}

	// ── Competing-header (disposition mismatch) detection ────────────────────

	public function test_mismatched_disposition_logs_conflict_detector_warning(): void {
		$GLOBALS['_wpdb_get_var']                    = 'report-only';
		$GLOBALS['_wp_rest_headers']['content-type'] = 'application/csp-report';

		$this->audit->expects( $this->once() )
			->method( 'log' )
			->with(
				'conflict_detector',
				'csp_disposition_mismatch',
				$this->stringContains( "reported 'enforce'" ),
				'warning'
			);

		$request = $this->make_request(
			'{"csp-report":{"violated-directive":"img-src","document-uri":"https://example.com/","blocked-uri":"https://cdn.example.com/pixel.png","disposition":"enforce"}}'
		);

		$this->reporter->handle( $request );
	}

	public function test_matching_disposition_does_not_log_conflict(): void {
		$GLOBALS['_wpdb_get_var']                    = 'enforce';
		$GLOBALS['_wp_rest_headers']['content-type'] = 'application/csp-report';

		$this->audit->expects( $this->never() )->method( 'log' );

		$request = $this->make_request(
			'{"csp-report":{"violated-directive":"img-src","document-uri":"https://example.com/","blocked-uri":"https://cdn.example.com/pixel.png","disposition":"enforce"}}'
		);

		$this->reporter->handle( $request );
	}

	public function test_no_configured_profile_does_not_log_conflict(): void {
		$GLOBALS['_wpdb_get_var']                    = null;
		$GLOBALS['_wp_rest_headers']['content-type'] = 'application/csp-report';

		$this->audit->expects( $this->never() )->method( 'log' );

		$request = $this->make_request(
			'{"csp-report":{"violated-directive":"img-src","document-uri":"https://example.com/","blocked-uri":"https://cdn.example.com/pixel.png","disposition":"enforce"}}'
		);

		$this->reporter->handle( $request );
	}

	public function test_disposition_mismatch_is_throttled_within_cooldown(): void {
		$GLOBALS['_wpdb_get_var']                    = 'report-only';
		$GLOBALS['_wp_rest_headers']['content-type'] = 'application/csp-report';

		// Two mismatched reports for the same (surface, directive) within the
		// cooldown window -- the underlying cause doesn't change between them,
		// so only the first should log.
		$this->audit->expects( $this->once() )->method( 'log' );

		$request = $this->make_request(
			'{"csp-report":{"violated-directive":"img-src","document-uri":"https://example.com/","blocked-uri":"https://cdn.example.com/a.png","disposition":"enforce"}}'
		);
		$this->reporter->handle( $request );

		$request2 = $this->make_request(
			'{"csp-report":{"violated-directive":"img-src","document-uri":"https://example.com/","blocked-uri":"https://cdn.example.com/b.png","disposition":"enforce"}}'
		);
		$this->reporter->handle( $request2 );
	}

	public function test_rate_limited_report_still_checks_for_disposition_mismatch(): void {
		$GLOBALS['_wpdb_get_var']                                       = 'report-only';
		$GLOBALS['_wp_rest_headers']['content-type']                    = 'application/csp-report';
		$GLOBALS['_wp_transients']['wp_sam_viol_rate_frontend_img-src'] = 500;

		// A saturated rate cap is itself often a symptom of a competing header --
		// the diagnostic must still fire even though the report is dropped.
		$this->audit->expects( $this->once() )->method( 'log' );

		$request = $this->make_request(
			'{"csp-report":{"violated-directive":"img-src","document-uri":"https://example.com/","blocked-uri":"https://cdn.example.com/pixel.png","disposition":"enforce"}}'
		);

		$this->reporter->handle( $request );

		$this->assertNull( $GLOBALS['_wpdb_last_operation'] );
	}

	// ── handle(): Deduplication (UPDATE vs INSERT) ────────────────────────────

	public function test_duplicate_report_triggers_update_not_insert(): void {
		$GLOBALS['_wp_rest_headers']['content-type'] = 'application/csp-report';
		// get_var returns a non-null row ID → duplicate detected, UPDATE path taken.
		$GLOBALS['_wpdb_get_var'] = '42';

		$request = $this->make_request(
			'{"csp-report":{"violated-directive":"script-src","document-uri":"https://example.com/","blocked-uri":"https://cdn.example.com"}}'
		);

		$this->reporter->handle( $request );

		$this->assertSame( 'query', $GLOBALS['_wpdb_last_operation'] );
	}

	public function test_new_report_uses_upsert_query(): void {
		$GLOBALS['_wp_rest_headers']['content-type'] = 'application/csp-report';
		$request = $this->make_request(
			'{"csp-report":{"violated-directive":"script-src","document-uri":"https://example.com/","blocked-uri":"https://cdn.example.com"}}'
		);

		$this->reporter->handle( $request );

		$this->assertSame( 'query', $GLOBALS['_wpdb_last_operation'] );
		$this->assertStringContainsString( 'ON DUPLICATE KEY UPDATE', $GLOBALS['_wpdb_last_query'] );
	}

	/**
	 * Regression test: disposition (and effective_directive, original_policy,
	 * status_code) were written on first INSERT but never refreshed by the
	 * ON DUPLICATE KEY UPDATE clause -- once a fingerprint row existed, its
	 * stored disposition was frozen forever at whatever the very first report
	 * happened to carry, even after a surface was promoted from report-only
	 * to enforce and every subsequent browser report genuinely started
	 * arriving with disposition=enforce. The Violations tab kept showing
	 * "report" indefinitely for any fingerprint first seen before promotion,
	 * which read as a competing-CSP-header symptom but was actually just this.
	 */
	public function test_duplicate_report_refreshes_disposition_on_update(): void {
		$GLOBALS['_wp_rest_headers']['content-type'] = 'application/csp-report';
		// get_var returns a non-null row ID -> duplicate detected, UPDATE path taken.
		$GLOBALS['_wpdb_get_var'] = '42';

		$request = $this->make_request(
			'{"csp-report":{"violated-directive":"style-src-attr","document-uri":"https://example.com/","blocked-uri":"inline","disposition":"enforce"}}'
		);

		$this->reporter->handle( $request );

		$query = (string) $GLOBALS['_wpdb_last_query'];
		$this->assertStringContainsString( 'disposition = VALUES(disposition)', $query );
		$this->assertStringContainsString( 'effective_directive = VALUES(effective_directive)', $query );
		$this->assertStringContainsString( 'original_policy = VALUES(original_policy)', $query );
		$this->assertStringContainsString( 'status_code = VALUES(status_code)', $query );
	}

	public function test_report_endpoint_learning_creates_pending_source_candidate_when_window_open(): void {
		update_option( Learning_Window::OPTION_LAST_CHANGE, gmdate( 'Y-m-d H:i:s' ) );
		update_option( Learning_Window::OPTION_WINDOW_HOURS, 48 );
		$GLOBALS['_wp_rest_headers']['content-type'] = 'application/csp-report';

		$reporter = new Violation_Reporter( $this->audit, new Learning_Window() );
		$request  = $this->make_request(
			'{"csp-report":{"effective-directive":"connect-src","violated-directive":"connect-src","document-uri":"https://example.com/","blocked-uri":"https://api.vendor.example/v1/ping"}}'
		);

		$reporter->handle( $request );

		$this->assertCount( 1, $GLOBALS['_wpdb_inserted_rows'] );
		$source_insert = $GLOBALS['_wpdb_inserted_rows'][0]['data'];
		$this->assertSame( 'frontend', $source_insert['surface'] );
		$this->assertSame( 'connect-src', $source_insert['directive'] );
		$this->assertSame( 'api.vendor.example', $source_insert['source_host'] );
		$this->assertSame( 'pending', $source_insert['approval_state'] );
		$this->assertSame( 'report-endpoint', $source_insert['owner_component'] );
	}

	public function test_report_endpoint_learning_is_locked_after_window_expires(): void {
		update_option( Learning_Window::OPTION_LAST_CHANGE, gmdate( 'Y-m-d H:i:s', time() - ( 49 * HOUR_IN_SECONDS ) ) );
		update_option( Learning_Window::OPTION_WINDOW_HOURS, 48 );
		$GLOBALS['_wp_rest_headers']['content-type'] = 'application/csp-report';

		$reporter = new Violation_Reporter( $this->audit, new Learning_Window() );
		$request  = $this->make_request(
			'{"csp-report":{"effective-directive":"connect-src","violated-directive":"connect-src","document-uri":"https://example.com/","blocked-uri":"https://api.vendor.example/v1/ping"}}'
		);

		$reporter->handle( $request );

		$this->assertCount( 0, $GLOBALS['_wpdb_inserted_rows'] );
		$this->assertSame( 'query', $GLOBALS['_wpdb_last_operation'] );
	}

	public function test_report_endpoint_learning_skips_inline_reports(): void {
		update_option( Learning_Window::OPTION_LAST_CHANGE, gmdate( 'Y-m-d H:i:s' ) );
		update_option( Learning_Window::OPTION_WINDOW_HOURS, 48 );
		$GLOBALS['_wp_rest_headers']['content-type'] = 'application/csp-report';

		$reporter = new Violation_Reporter( $this->audit, new Learning_Window() );
		$request  = $this->make_request(
			'{"csp-report":{"effective-directive":"script-src","violated-directive":"script-src","document-uri":"https://example.com/","blocked-uri":"inline"}}'
		);

		$reporter->handle( $request );

		$this->assertCount( 0, $GLOBALS['_wpdb_inserted_rows'] );
		$this->assertSame( 'query', $GLOBALS['_wpdb_last_operation'] );
	}

	/**
	 * Regression test for the "one-shot" source-learning bug: previously,
	 * only a violation report that happened to be the fingerprint's very
	 * first INSERT ever attempted to propose a source. A report for an
	 * already-existing violation fingerprint (simulated here via
	 * _wpdb_query_result = 2, matching MySQL's own ON DUPLICATE KEY UPDATE
	 * convention) must still be able to create a source proposal -- e.g. if
	 * the learning window was closed the first time this exact violation
	 * was ever seen, every later occurrence is the only remaining chance.
	 */
	public function test_report_endpoint_learning_still_creates_proposal_for_a_duplicate_violation_row(): void {
		update_option( Learning_Window::OPTION_LAST_CHANGE, gmdate( 'Y-m-d H:i:s' ) );
		update_option( Learning_Window::OPTION_WINDOW_HOURS, 48 );
		$GLOBALS['_wp_rest_headers']['content-type'] = 'application/csp-report';
		$GLOBALS['_wpdb_query_result']               = 2;

		$reporter = new Violation_Reporter( $this->audit, new Learning_Window() );
		$request  = $this->make_request(
			'{"csp-report":{"effective-directive":"connect-src","violated-directive":"connect-src","document-uri":"https://example.com/","blocked-uri":"https://api.vendor.example/v1/ping"}}'
		);

		$reporter->handle( $request );

		$this->assertCount( 1, $GLOBALS['_wpdb_inserted_rows'] );
		$this->assertSame( 'api.vendor.example', $GLOBALS['_wpdb_inserted_rows'][0]['data']['source_host'] );
	}

	/**
	 * The other half of the same fix: once a source has actually reached
	 * csp_source_inventory (pending, approved, or rejected), repeat reports
	 * for the same violation must not keep re-proposing it -- that would
	 * spam the audit log with "previously rejected" entries for an
	 * administrator-blocked source that keeps firing in production.
	 */
	public function test_report_endpoint_learning_skips_when_a_source_proposal_already_exists(): void {
		update_option( Learning_Window::OPTION_LAST_CHANGE, gmdate( 'Y-m-d H:i:s' ) );
		update_option( Learning_Window::OPTION_WINDOW_HOURS, 48 );
		$GLOBALS['_wp_rest_headers']['content-type'] = 'application/csp-report';
		// First get_var() call is the disposition-mismatch profile-mode lookup
		// (null -> no profile found -> no mismatch check); the second is
		// has_existing_source_proposal()'s own existence check.
		$GLOBALS['_wpdb_get_var_queue'] = [ null, '7' ];

		$reporter = new Violation_Reporter( $this->audit, new Learning_Window() );
		$request  = $this->make_request(
			'{"csp-report":{"effective-directive":"connect-src","violated-directive":"connect-src","document-uri":"https://example.com/","blocked-uri":"https://api.vendor.example/v1/ping"}}'
		);

		$reporter->handle( $request );

		$this->assertCount( 0, $GLOBALS['_wpdb_inserted_rows'] );
	}

	// ── Payload normalisation ─────────────────────────────────────────────────

	public function test_normalise_csp_level3_payload(): void {
		$reporter = $this->make_capturing_reporter();

		$body = [
			'csp-report' => [
				'blocked-uri'       => 'https://evil.example.com/script.js',
				'violated-directive' => 'script-src',
				'document-uri'      => 'https://example.com/',
				'disposition'       => 'report',
			],
		];

		$stored = $reporter->capture_stored_reports( $body );

		$this->assertCount( 1, $stored );
		$this->assertSame( 'https://evil.example.com/script.js', $stored[0]['blocked_uri'] );
		$this->assertSame( 'script-src', $stored[0]['violated_directive'] );
	}

	public function test_normalise_reporting_api_payload(): void {
		$reporter = $this->make_capturing_reporter();

		$body = [
			[
				'type' => 'csp-violation',
				'body' => [
					'blockedURL'         => 'https://cdn.evil.com/track.js',
					'violatedDirective'  => 'script-src-elem',
					'documentURL'        => 'https://example.com/page',
					'disposition'        => 'enforce',
				],
			],
		];

		$stored = $reporter->capture_stored_reports( $body );

		$this->assertCount( 1, $stored );
		$this->assertSame( 'https://cdn.evil.com/track.js', $stored[0]['blocked_uri'] );
		$this->assertSame( 'script-src-elem', $stored[0]['violated_directive'] );
	}

	public function test_empty_body_produces_no_stored_reports(): void {
		$reporter = $this->make_capturing_reporter();

		$stored = $reporter->capture_stored_reports( [] );

		$this->assertEmpty( $stored );
	}

	public function test_unknown_reporting_api_type_is_ignored(): void {
		$reporter = $this->make_capturing_reporter();

		$body = [
			[ 'type' => 'network-error', 'body' => [ 'url' => 'https://example.com' ] ],
		];

		$stored = $reporter->capture_stored_reports( $body );

		$this->assertEmpty( $stored );
	}

	public function test_missing_violated_directive_is_skipped(): void {
		$reporter = $this->make_capturing_reporter();

		$body = [
			'csp-report' => [
				'blocked-uri' => 'https://evil.example.com/x.js',
				// violated-directive intentionally absent
			],
		];

		$stored = $reporter->capture_stored_reports( $body );

		// store_report() skips records with empty violated_directive.
		$this->assertEmpty( $stored );
	}

	// ── Surface detection ─────────────────────────────────────────────────────

	public function test_document_uri_in_wp_admin_maps_to_admin_surface(): void {
		$reporter = $this->make_capturing_reporter();

		$body = [
			'csp-report' => [
				'blocked-uri'        => 'https://evil.example.com/x.js',
				'violated-directive' => 'script-src',
				'document-uri'       => 'https://example.com/wp-admin/edit.php',
			],
		];

		$stored = $reporter->capture_stored_reports( $body );

		$this->assertSame( 'admin', $stored[0]['profile_surface'] );
	}

	public function test_document_uri_in_wp_login_maps_to_login_surface(): void {
		$reporter = $this->make_capturing_reporter();

		$body = [
			'csp-report' => [
				'blocked-uri'        => 'https://evil.example.com/x.js',
				'violated-directive' => 'script-src',
				'document-uri'       => 'https://example.com/wp-login.php',
			],
		];

		$stored = $reporter->capture_stored_reports( $body );

		$this->assertSame( 'login', $stored[0]['profile_surface'] );
	}

	public function test_document_uri_in_wp_json_maps_to_api_surface(): void {
		$reporter = $this->make_capturing_reporter();

		$body = [
			'csp-report' => [
				'blocked-uri'        => 'https://evil.example.com/x.js',
				'violated-directive' => 'script-src',
				'document-uri'       => 'https://example.com/wp-json/sam/v1/report',
			],
		];

		$stored = $reporter->capture_stored_reports( $body );

		$this->assertSame( 'api', $stored[0]['profile_surface'] );
	}

	public function test_unknown_document_uri_maps_to_frontend_surface(): void {
		$reporter = $this->make_capturing_reporter();

		$body = [
			'csp-report' => [
				'blocked-uri'        => 'https://evil.example.com/x.js',
				'violated-directive' => 'script-src',
				'document-uri'       => 'https://example.com/some-page',
			],
		];

		$stored = $reporter->capture_stored_reports( $body );

		$this->assertSame( 'frontend', $stored[0]['profile_surface'] );
	}

	// ── Deduplication fingerprint ─────────────────────────────────────────────

	public function test_same_report_produces_same_fingerprint(): void {
		$reporter = $this->make_capturing_reporter();

		$report = [
			'csp-report' => [
				'blocked-uri'        => 'https://evil.example.com/x.js',
				'violated-directive' => 'script-src',
				'document-uri'       => 'https://example.com/',
			],
		];

		$stored1 = $reporter->capture_stored_reports( $report );
		$stored2 = $reporter->capture_stored_reports( $report );

		$this->assertSame( $stored1[0]['fingerprint'], $stored2[0]['fingerprint'] );
	}

	public function test_different_blocked_uri_produces_different_fingerprint(): void {
		$reporter = $this->make_capturing_reporter();

		$report1 = [ 'csp-report' => [ 'blocked-uri' => 'https://a.example.com/x.js', 'violated-directive' => 'script-src', 'document-uri' => 'https://example.com/' ] ];
		$report2 = [ 'csp-report' => [ 'blocked-uri' => 'https://b.example.com/y.js', 'violated-directive' => 'script-src', 'document-uri' => 'https://example.com/' ] ];

		$stored1 = $reporter->capture_stored_reports( $report1 );
		$stored2 = $reporter->capture_stored_reports( $report2 );

		$this->assertNotSame( $stored1[0]['fingerprint'], $stored2[0]['fingerprint'] );
	}

	// ── Host-level dedup fingerprint ──────────────────────────────────────────

	public function test_different_filenames_under_same_host_produce_same_fingerprint(): void {
		$reporter = $this->make_capturing_reporter();

		$report1 = [ 'csp-report' => [ 'blocked-uri' => 'https://fonts.gstatic.com/s/poppins/v24/aaaa.woff2', 'violated-directive' => 'font-src', 'document-uri' => 'https://example.com/' ] ];
		$report2 = [ 'csp-report' => [ 'blocked-uri' => 'https://fonts.gstatic.com/s/poppins/v24/bbbb.woff2', 'violated-directive' => 'font-src', 'document-uri' => 'https://example.com/' ] ];

		$stored1 = $reporter->capture_stored_reports( $report1 );
		$stored2 = $reporter->capture_stored_reports( $report2 );

		$this->assertSame( $stored1[0]['fingerprint'], $stored2[0]['fingerprint'] );
	}

	public function test_different_hosts_still_produce_different_fingerprints(): void {
		$reporter = $this->make_capturing_reporter();

		$report1 = [ 'csp-report' => [ 'blocked-uri' => 'https://fonts.gstatic.com/a.woff2', 'violated-directive' => 'font-src', 'document-uri' => 'https://example.com/' ] ];
		$report2 = [ 'csp-report' => [ 'blocked-uri' => 'https://other.example.net/a.woff2', 'violated-directive' => 'font-src', 'document-uri' => 'https://example.com/' ] ];

		$stored1 = $reporter->capture_stored_reports( $report1 );
		$stored2 = $reporter->capture_stored_reports( $report2 );

		$this->assertNotSame( $stored1[0]['fingerprint'], $stored2[0]['fingerprint'] );
	}

	public function test_keyword_blocked_uri_keeps_exact_value_fingerprint(): void {
		$reporter = $this->make_capturing_reporter();

		$report1 = [ 'csp-report' => [ 'blocked-uri' => 'inline', 'violated-directive' => 'script-src', 'document-uri' => 'https://example.com/' ] ];
		$report2 = [ 'csp-report' => [ 'blocked-uri' => 'eval', 'violated-directive' => 'script-src', 'document-uri' => 'https://example.com/' ] ];

		$stored1 = $reporter->capture_stored_reports( $report1 );
		$stored2 = $reporter->capture_stored_reports( $report2 );

		$this->assertNotSame( $stored1[0]['fingerprint'], $stored2[0]['fingerprint'] );
	}

	public function test_new_report_upsert_query_stores_extracted_blocked_host(): void {
		$GLOBALS['_wp_rest_headers']['content-type'] = 'application/csp-report';
		$request                                     = $this->make_request(
			'{"csp-report":{"violated-directive":"font-src","document-uri":"https://example.com/","blocked-uri":"https://fonts.gstatic.com/s/poppins/v24/aaaa.woff2"}}'
		);

		$this->reporter->handle( $request );

		$this->assertStringContainsString( "'fonts.gstatic.com'", $GLOBALS['_wpdb_last_query'] );
	}

	public function test_new_report_with_keyword_blocked_uri_stores_null_blocked_host(): void {
		$GLOBALS['_wp_rest_headers']['content-type'] = 'application/csp-report';
		$request                                     = $this->make_request(
			'{"csp-report":{"violated-directive":"script-src","document-uri":"https://example.com/","blocked-uri":"inline"}}'
		);

		$this->reporter->handle( $request );

		// blocked_host is bound as NULLIF('', '') so an empty string becomes genuine SQL NULL.
		$this->assertStringContainsString( "NULLIF('', '')", $GLOBALS['_wpdb_last_query'] );
	}

	// ── extract_blocked_host() ────────────────────────────────────────────────

	public function test_extract_blocked_host_returns_lowercased_host(): void {
		$this->assertSame( 'fonts.gstatic.com', Violation_Reporter::extract_blocked_host( 'HTTPS://Fonts.Gstatic.com/s/poppins/v24/aaaa.woff2' ) );
	}

	public function test_extract_blocked_host_handles_protocol_relative_uri(): void {
		$this->assertSame( 'cdn.example.com', Violation_Reporter::extract_blocked_host( '//cdn.example.com/lib.js' ) );
	}

	public function test_extract_blocked_host_returns_null_for_keyword_values(): void {
		foreach ( [ 'inline', 'eval', 'wasm-eval', 'data', 'blob', 'about' ] as $keyword ) {
			$this->assertNull( Violation_Reporter::extract_blocked_host( $keyword ), "expected null for '{$keyword}'" );
		}
	}

	public function test_extract_blocked_host_returns_null_for_data_uri(): void {
		$this->assertNull( Violation_Reporter::extract_blocked_host( 'data:image/png;base64,aaaa' ) );
	}

	public function test_extract_blocked_host_returns_null_for_empty_string(): void {
		$this->assertNull( Violation_Reporter::extract_blocked_host( '' ) );
		$this->assertNull( Violation_Reporter::extract_blocked_host( '   ' ) );
	}

	// ── Rate limiting ─────────────────────────────────────────────────────────

	public function test_rate_limit_blocks_reports_beyond_cap(): void {
		$reporter = $this->make_capturing_reporter( rate_limit_cap: 2 );

		$make_report = static fn( int $i ) => [
			'csp-report' => [
				'blocked-uri'        => "https://evil.example.com/script{$i}.js",
				'violated-directive' => 'script-src',
				'document-uri'       => 'https://example.com/',
			],
		];

		$reporter->capture_stored_reports( $make_report( 1 ) );
		$reporter->capture_stored_reports( $make_report( 2 ) );
		$stored_third = $reporter->capture_stored_reports( $make_report( 3 ) );

		// Third report exceeds the cap of 2 and should be dropped.
		$this->assertEmpty( $stored_third );
	}

	// ── COOP/COEP Reporting API dispatch ────────────────────────────────────────

	public function test_handle_routes_coop_report_to_pillar_violation_store(): void {
		$pillar_violations = $this->createMock( \WP_SAM\Security\Pillar_Violation_Store::class );
		$pillar_violations->expects( $this->once() )
			->method( 'store' )
			->with(
				'cross-origin-opener-policy',
				'frontend',
				'coop',
				'enforce',
				[ 'disposition' => 'enforce', 'property' => 'postMessage' ]
			);

		$reporter = new Violation_Reporter( $this->audit, pillar_violations: $pillar_violations );

		$GLOBALS['_wp_rest_headers']['content-type'] = 'application/reports+json';
		$request                                     = $this->make_request(
			'[{"type":"coop","url":"https://example.com/page","body":{"disposition":"enforce","property":"postMessage"}}]'
		);

		$response = $reporter->handle( $request );

		$this->assertSame( 204, $response->get_status() );
	}

	public function test_handle_routes_coep_report_to_pillar_violation_store(): void {
		$pillar_violations = $this->createMock( \WP_SAM\Security\Pillar_Violation_Store::class );
		$pillar_violations->expects( $this->once() )
			->method( 'store' )
			->with(
				'cross-origin-embedder-policy',
				'admin',
				'coep',
				'reporting',
				$this->anything()
			);

		$reporter = new Violation_Reporter( $this->audit, pillar_violations: $pillar_violations );

		$GLOBALS['_wp_rest_headers']['content-type'] = 'application/reports+json';
		$request                                     = $this->make_request(
			'[{"type":"coep","url":"https://example.com/wp-admin/edit.php","body":{"disposition":"reporting","blockedURL":"https://embeds.example.net/widget"}}]'
		);

		$reporter->handle( $request );
	}

	public function test_handle_ignores_unrecognised_reporting_api_types(): void {
		$pillar_violations = $this->createMock( \WP_SAM\Security\Pillar_Violation_Store::class );
		$pillar_violations->expects( $this->never() )->method( 'store' );

		$reporter = new Violation_Reporter( $this->audit, pillar_violations: $pillar_violations );

		$GLOBALS['_wp_rest_headers']['content-type'] = 'application/reports+json';
		$request                                     = $this->make_request(
			'[{"type":"deprecation","url":"https://example.com/page","body":{"id":"unused-api"}}]'
		);

		$reporter->handle( $request );
	}

	public function test_handle_discards_cross_origin_coop_report(): void {
		$pillar_violations = $this->createMock( \WP_SAM\Security\Pillar_Violation_Store::class );
		$pillar_violations->expects( $this->never() )->method( 'store' );

		$reporter = new Violation_Reporter( $this->audit, pillar_violations: $pillar_violations );

		$GLOBALS['_wp_rest_headers']['content-type'] = 'application/reports+json';
		$request                                     = $this->make_request(
			'[{"type":"coop","url":"https://attacker.net/page","body":{"disposition":"enforce"}}]'
		);

		$response = $reporter->handle( $request );

		// Still 204 -- must not reveal rejection to the sender.
		$this->assertSame( 204, $response->get_status() );
	}

	public function test_handle_routes_mixed_batch_of_csp_and_coop_reports(): void {
		$pillar_violations = $this->createMock( \WP_SAM\Security\Pillar_Violation_Store::class );
		$pillar_violations->expects( $this->once() )
			->method( 'store' )
			->with( 'cross-origin-opener-policy', 'frontend', 'coop', 'enforce', $this->anything() );

		$reporter = new Violation_Reporter( $this->audit, pillar_violations: $pillar_violations );

		$GLOBALS['_wp_rest_headers']['content-type'] = 'application/reports+json';
		$request                                     = $this->make_request(
			'[' .
			'{"type":"csp-violation","body":{"violatedDirective":"script-src","documentURL":"https://example.com/","blockedURL":"https://evil.example.com"}},' .
			'{"type":"coop","url":"https://example.com/page","body":{"disposition":"enforce"}}' .
			']'
		);

		$response = $reporter->handle( $request );

		$this->assertSame( 204, $response->get_status() );
		// CSP path is unaffected -- still writes to the DB as usual.
		$this->assertSame( 'query', $GLOBALS['_wpdb_last_operation'] );
	}

	// ── Helpers ───────────────────────────────────────────────────────────────

	private function make_request( string $body ): WP_REST_Request {
		$GLOBALS['_wp_rest_body'] = $body;
		return new WP_REST_Request( 'POST', '/sam/v1/report' );
	}

	/**
	 * Returns a Violation_Reporter subclass that captures store_report() calls
	 * rather than writing to the DB, making assertions straightforward.
	 */
	private function make_capturing_reporter( int $rate_limit_cap = 500 ): object {
		return new class( $this->audit, $rate_limit_cap ) extends Violation_Reporter {

			private array $captured = [];
			private int   $cap;

			public function __construct( Audit_Log $audit, int $cap ) {
				parent::__construct( $audit );
				$this->cap = $cap;
			}

			/**
			 * Exposes the private normalise + store flow for testing.
			 * Returns the array of reports that would have been stored.
			 */
			public function capture_stored_reports( array $body ): array {
				$this->captured = [];
				$reports = $this->call_normalise( $body );
				foreach ( $reports as $report ) {
					$this->call_store( $report );
				}
				return $this->captured;
			}

			protected function store_report( array $r ): void {
				if ( empty( $r['violated_directive'] ) ) {
					return;
				}

				// Apply the rate-limit logic manually using the test cap, keyed
				// per (surface, directive) to mirror the real implementation.
				$surface  = $this->call_surface( $r['document_uri'] ?? '' );
				$rate_key = 'wp_sam_viol_rate_' . $surface . '_' . $r['violated_directive'];
				$count    = (int) get_transient( $rate_key );
				if ( $count >= $this->cap ) {
					return;
				}
				set_transient( $rate_key, $count + 1, HOUR_IN_SECONDS );

				$blocked_uri          = substr( $r['blocked_uri'] ?? '', 0, 2048 );
				$violated_directive   = substr( $r['violated_directive'] ?? '', 0, 128 );
				// Mirrors store_report()'s real fingerprinting via the shared static
				// helper, rather than a second hand-rolled copy that could drift.
				$blocked_host         = Violation_Reporter::extract_blocked_host( $blocked_uri );
				$fingerprint_subject  = $blocked_host ?? $blocked_uri;
				$fingerprint          = hash( 'sha256', $surface . '|' . $fingerprint_subject . '|' . $violated_directive );

				$this->captured[] = array_merge( $r, [
					'profile_surface' => $surface,
					'fingerprint'     => $fingerprint,
				] );
			}

			private function call_normalise( array $body ): array {
				$ref = new ReflectionMethod( $this, 'normalise_body' );
				$ref->setAccessible( true );
				return $ref->invoke( $this, $body );
			}

			private function call_store( array $r ): void {
				$this->store_report( $r );
			}

			private function call_surface( string $uri ): string {
				$ref = new ReflectionMethod( $this, 'surface_from_document_uri' );
				$ref->setAccessible( true );
				return $ref->invoke( $this, $uri );
			}
		};
	}
}
