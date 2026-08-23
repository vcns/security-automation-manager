<?php
/**
 * Unit tests for WP_SAM\CSP\Hash_Manager.
 *
 * Tests the hash computation, captured hash map, and retire_stale() guard.
 * Output buffering hooks are tested indirectly via flush_buffer() by calling
 * the private method through reflection.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\CSP\Hash_Manager;
use WP_SAM\Modules\Audit_Log;
use WP_SAM\Modules\Feature_Gate;

class HashManagerTest extends TestCase {

	private Hash_Manager $manager;
	private Audit_Log    $audit;

	protected function setUp(): void {
		wp_test_reset_globals();

		// Stub a minimal Audit_Log that records calls without touching the DB.
		$this->audit   = $this->createMock( Audit_Log::class );
		$gate          = $this->createMock( Feature_Gate::class );
		$this->manager = new Hash_Manager( $this->audit, $gate );
	}

	// ── register ──────────────────────────────────────────────────────────────

	/**
	 * WordPress core prints enqueued styles -- every wp_add_inline_style()
	 * block, which is how themes and page builders emit per-page <style>
	 * CSS -- via wp_print_styles at head priority 8, and head scripts at
	 * priority 9. The capture buffer must open before both on every head
	 * hook, or those blocks are emitted before ob_start() runs and never
	 * get hashed: the exact gap that left page-builder head CSS blocked
	 * under an enforce-mode policy.
	 */
	public function test_register_opens_buffer_before_core_style_printing(): void {
		$this->manager->register();

		// Each surface has its own start method (start_buffer_frontend/
		// _admin/_login) rather than one shared start_buffer(), so
		// flush_buffer() can later verify it's closing the exact buffer
		// level+surface it opened -- see Hash_Manager::start_buffer()'s
		// docblock.
		$hook_to_method = array(
			'wp_head'    => 'start_buffer_frontend',
			'admin_head' => 'start_buffer_admin',
			'login_head' => 'start_buffer_login',
		);

		foreach ( $hook_to_method as $hook => $method ) {
			$registrations = array_filter(
				$GLOBALS['_wp_actions'][ $hook ] ?? array(),
				static function ( array $registration ) use ( $method ): bool {
					return is_array( $registration[0] ) && $method === ( $registration[0][1] ?? '' );
				}
			);

			$this->assertNotEmpty( $registrations, "{$method} is not registered on {$hook}." );

			foreach ( $registrations as $registration ) {
				$this->assertLessThan(
					8,
					$registration[1],
					"{$method} on {$hook} must run before wp_print_styles (priority 8)."
				);
			}
		}
	}

	public function test_register_installs_a_shutdown_fallback_closer(): void {
		$this->manager->register();

		$registrations = array_filter(
			$GLOBALS['_wp_actions']['shutdown'] ?? array(),
			static function ( array $registration ): bool {
				return is_array( $registration[0] ) && 'maybe_end_buffer_on_shutdown' === ( $registration[0][1] ?? '' );
			}
		);

		$this->assertNotEmpty( $registrations, 'maybe_end_buffer_on_shutdown is not registered on shutdown.' );
	}

	// ── Buffer lifecycle ─────────────────────────────────────────────────────
	// Every test opens its OWN outer capture buffer BEFORE the manager opens
	// its buffer (nested inside the capture buffer), matching the real-world
	// scenario this class's own docblock describes -- nested inside any
	// buffer a page-cache plugin opened earlier in the request -- so
	// whatever the manager re-emits flows into the capture buffer rather
	// than escaping past it. Opening the capture buffer AFTER the manager's
	// own start() would put it on the wrong side of the stack: the
	// manager's own unwind loop would then treat the capture buffer itself
	// as unowned nested content and flush it away before the manager's real
	// content is ever captured.

	public function test_normal_lifecycle_captures_and_reemits_its_own_content(): void {
		$baseline = ob_get_level();
		$manager  = $this->make_db_stub_manager();

		ob_start(); // outer capture buffer
		$manager->start_buffer_frontend();
		echo '<style>body{color:red}</style>';
		$manager->end_buffer_frontend();
		$output = ob_get_clean();

		$this->assertStringContainsString( '<style>body{color:red}</style>', $output );
		$this->assertSame( $baseline, ob_get_level(), 'flush_buffer() must leave the buffer stack exactly as it found it.' );
	}

	public function test_flush_buffer_is_a_no_op_when_something_else_already_closed_it(): void {
		$baseline = ob_get_level();
		$manager  = $this->make_db_stub_manager();

		ob_start(); // outer capture buffer
		$manager->start_buffer_frontend();
		// Simulate another plugin (or PHP itself) already having closed our
		// buffer before our own footer hook got a chance to run.
		ob_end_clean();

		// Must not throw, and must not touch whatever buffer level is
		// current now (there may be none, or a completely unrelated one).
		$manager->end_buffer_frontend();
		ob_end_clean(); // this test's own outer capture buffer

		$this->assertSame( $baseline, ob_get_level() );
	}

	public function test_nested_buffer_opened_by_something_else_is_preserved_not_discarded(): void {
		$baseline = ob_get_level();
		$manager  = $this->make_db_stub_manager();

		ob_start(); // outer capture buffer
		$manager->start_buffer_frontend();
		echo '<style>body{color:blue}</style>';

		// Something else (another plugin) nests its own buffer inside ours
		// without closing it before our footer hook fires.
		ob_start();
		echo '<!-- another plugin\'s buffered content -->';

		$manager->end_buffer_frontend();
		$output = ob_get_clean();

		// Our own buffer's content was captured/re-emitted; the other
		// plugin's nested content was flushed through (preserved), not
		// discarded, even though this class doesn't own it.
		$this->assertStringContainsString( '<style>body{color:blue}</style>', $output );
		$this->assertStringContainsString( "<!-- another plugin's buffered content -->", $output );
		$this->assertSame( $baseline, ob_get_level(), 'both buffers must be fully unwound.' );
	}

	public function test_shutdown_fallback_closes_a_buffer_whose_footer_hook_never_fired(): void {
		$baseline = ob_get_level();
		$manager  = $this->make_db_stub_manager();

		ob_start(); // outer capture buffer
		// login_head fired, but the request redirected + exit()ed before
		// login_footer ever ran -- the exact gap several wp-login.php
		// POST-handling branches hit.
		$manager->start_buffer_login();
		echo '<style>body{color:green}</style>';
		$manager->maybe_end_buffer_on_shutdown();
		$output = ob_get_clean();

		$this->assertStringContainsString( '<style>body{color:green}</style>', $output );
		$this->assertSame( $baseline, ob_get_level() );
	}

	public function test_shutdown_fallback_is_a_no_op_after_a_normal_footer_close(): void {
		$baseline = ob_get_level();
		$manager  = $this->make_db_stub_manager();

		ob_start();
		$manager->start_buffer_frontend();
		echo '<style>body{color:red}</style>';
		$manager->end_buffer_frontend();
		ob_get_clean();

		// The normal happy path: footer hook already closed everything.
		// The shutdown fallback must be a genuine no-op here, not a second
		// attempt to close something that no longer exists.
		ob_start();
		$manager->maybe_end_buffer_on_shutdown();
		$fallback_output = ob_get_clean();

		$this->assertSame( '', $fallback_output );
		$this->assertSame( $baseline, ob_get_level() );
	}

	// ── record_hash ───────────────────────────────────────────────────────────

	public function test_record_hash_returns_sha256_prefixed_string(): void {
		// We cannot call the real upsert() without a DB, so we test the return
		// value format only, using a subclass that stubs the DB write.
		$manager = $this->make_db_stub_manager();

		$result = $manager->record_hash( 'console.log("hello");', 'script-src', 'frontend' );

		$this->assertStringStartsWith( 'sha256-', $result );
	}

	public function test_record_hash_base64_encodes_sha256(): void {
		$manager = $this->make_db_stub_manager();
		$content = 'var x = 1;';

		$result = $manager->record_hash( $content, 'script-src', 'frontend' );

		$expected_raw = hash( 'sha256', $content, true );
		$expected_b64 = base64_encode( $expected_raw );
		$this->assertSame( "sha256-{$expected_b64}", $result );
	}

	public function test_record_hash_adds_to_captured_map(): void {
		$manager = $this->make_db_stub_manager();
		$content = 'alert(1);';

		$manager->record_hash( $content, 'script-src', 'frontend' );

		$captured = $manager->get_captured_hashes();
		$this->assertNotEmpty( $captured );

		$hash_raw = hash( 'sha256', $content, true );
		$hash_b64 = base64_encode( $hash_raw );
		$this->assertArrayHasKey( $hash_b64, $captured );
	}

	public function test_captured_map_accumulates_multiple_hashes(): void {
		$manager = $this->make_db_stub_manager();

		$manager->record_hash( 'var a = 1;', 'script-src', 'frontend' );
		$manager->record_hash( 'var b = 2;', 'script-src', 'frontend' );

		$this->assertCount( 2, $manager->get_captured_hashes() );
	}

	public function test_captured_map_deduplicates_identical_content(): void {
		$manager  = $this->make_db_stub_manager();
		$content  = 'var x = 1;';

		$manager->record_hash( $content, 'script-src', 'frontend' );
		$manager->record_hash( $content, 'script-src', 'frontend' );

		// Same content produces the same hash key; map should have one entry.
		$this->assertCount( 1, $manager->get_captured_hashes() );
	}

	// ── retire_stale ──────────────────────────────────────────────────────────

	public function test_retire_stale_returns_zero_when_map_is_empty(): void {
		// The fixed retire_stale() must not retire anything when given an empty
		// map, because absence of data is not evidence of changed content.
		$manager = $this->make_db_stub_manager();

		$retired = $manager->retire_stale( [], 'frontend' );

		$this->assertSame( 0, $retired );
	}

	public function test_retire_stale_returns_zero_when_all_hashes_present(): void {
		// When all stored hashes appear in the current map with matching
		// fingerprints, nothing should be retired.
		$content     = 'var x = 1;';
		$hash_raw    = hash( 'sha256', $content, true );
		$hash_b64    = base64_encode( $hash_raw );
		$fingerprint = hash( 'sha256', $content );

		$current_hashes = [ $hash_b64 => $fingerprint ];

		// Use a manager subclass that stubs the DB query to return one row.
		$manager = $this->make_db_stub_manager_with_stored_hashes( [
			[ 'id' => 1, 'hash_value' => $hash_b64, 'content_fingerprint' => $fingerprint ],
		] );

		$retired = $manager->retire_stale( $current_hashes, 'frontend' );

		$this->assertSame( 0, $retired );
	}

	// ── inline extraction (via reflection) ───────────────────────────────────

	public function test_extract_and_record_ignores_external_scripts(): void {
		$manager = $this->make_db_stub_manager();
		$html    = '<script src="https://cdn.example.com/app.js"></script>';

		$this->invoke_extract( $manager, $html, 'script', 'script-src', 'frontend' );

		$this->assertEmpty( $manager->get_captured_hashes() );
	}

	public function test_extract_and_record_captures_inline_script(): void {
		$manager = $this->make_db_stub_manager();
		$content = 'console.log("test");';
		$html    = "<script>{$content}</script>";

		$this->invoke_extract( $manager, $html, 'script', 'script-src', 'frontend' );

		$this->assertCount( 1, $manager->get_captured_hashes() );
	}

	public function test_extract_and_record_skips_nonce_tagged_scripts(): void {
		$manager = $this->make_db_stub_manager();
		$html    = '<script nonce="abc123">console.log("nonce");</script>';

		$this->invoke_extract( $manager, $html, 'script', 'script-src', 'frontend' );

		// Nonce-tagged scripts are covered by the nonce manager; no hash needed.
		$this->assertEmpty( $manager->get_captured_hashes() );
	}

	public function test_extract_and_record_skips_nonce_tagged_style_blocks(): void {
		// Regression: extract_and_record()'s nonce-skip check used to be
		// script-only, so a nonce'd <style> block (see
		// inject_nonce_into_wp_inline_style_blocks()) would still be hashed
		// unnecessarily -- wasteful, and defeats the point of nonce'ing it.
		$manager = $this->make_db_stub_manager();
		$html    = '<style nonce="abc123">body { color: red; }</style>';

		$this->invoke_extract( $manager, $html, 'style', 'style-src', 'frontend' );

		$this->assertEmpty( $manager->get_captured_hashes() );
	}

	public function test_extract_and_record_skips_empty_blocks(): void {
		$manager = $this->make_db_stub_manager();
		$html    = '<script>   </script>';

		$this->invoke_extract( $manager, $html, 'script', 'script-src', 'frontend' );

		$this->assertEmpty( $manager->get_captured_hashes() );
	}

	public function test_extract_and_record_captures_inline_style(): void {
		$manager = $this->make_db_stub_manager();
		$content = 'body { color: red; }';
		$html    = "<style>{$content}</style>";

		$this->invoke_extract( $manager, $html, 'style', 'style-src', 'frontend' );

		$this->assertCount( 1, $manager->get_captured_hashes() );
	}

	public function test_extract_and_record_normalises_crlf_line_endings(): void {
		$manager  = $this->make_db_stub_manager();
		$unix     = "var x = 1;\nvar y = 2;";
		$windows  = "var x = 1;\r\nvar y = 2;";

		$this->invoke_extract( $manager, "<script>{$unix}</script>",   'script', 'script-src', 'frontend' );
		$hashes_unix = $manager->get_captured_hashes();

		// Reset captured map by creating a new instance.
		$manager2 = $this->make_db_stub_manager();
		$this->invoke_extract( $manager2, "<script>{$windows}</script>", 'script', 'script-src', 'frontend' );
		$hashes_windows = $manager2->get_captured_hashes();

		// After CRLF normalisation both should produce identical hashes.
		$this->assertSame( array_keys( $hashes_unix ), array_keys( $hashes_windows ) );
	}

	// ── inline style attribute extraction (via reflection) ───────────────────

	public function test_extract_style_attributes_captures_inline_style_attr(): void {
		$manager = $this->make_db_stub_manager();
		$html    = '<div style="color:red;margin-top:10px">hi</div>';

		$this->invoke_extract_style_attributes( $manager, $html, 'frontend' );

		$this->assertCount( 1, $manager->get_captured_hashes() );
	}

	public function test_extract_style_attributes_ignores_empty_style_attr(): void {
		$manager = $this->make_db_stub_manager();
		$html    = '<div style="">hi</div>';

		$this->invoke_extract_style_attributes( $manager, $html, 'frontend' );

		$this->assertEmpty( $manager->get_captured_hashes() );
	}

	public function test_extract_style_attributes_captures_multiple_distinct_values(): void {
		$manager = $this->make_db_stub_manager();
		$html    = '<div style="color:red">a</div><span style="color:blue">b</span>';

		$this->invoke_extract_style_attributes( $manager, $html, 'frontend' );

		$this->assertCount( 2, $manager->get_captured_hashes() );
	}

	public function test_extract_style_attributes_dedupes_identical_values(): void {
		$manager = $this->make_db_stub_manager();
		$html    = '<div style="color:red">a</div><span style="color:red">b</span>';

		$this->invoke_extract_style_attributes( $manager, $html, 'frontend' );

		$this->assertCount( 1, $manager->get_captured_hashes() );
	}

	public function test_extract_style_attributes_supports_single_quoted_values(): void {
		$manager = $this->make_db_stub_manager();
		$html    = "<div style='color:red'>a</div>";

		$this->invoke_extract_style_attributes( $manager, $html, 'frontend' );

		$this->assertCount( 1, $manager->get_captured_hashes() );
	}

	public function test_extract_style_attributes_hashes_the_html_entity_decoded_value(): void {
		// Browsers evaluate the parsed (entity-decoded) attribute value, so the
		// stored hash must be computed from the decoded string, not raw source
		// bytes, or it will never match what the browser hashes.
		$manager = $this->make_db_stub_manager();
		$html    = '<div style="content:&quot;x&quot;">a</div>';

		$this->invoke_extract_style_attributes( $manager, $html, 'frontend' );

		$captured     = $manager->get_captured_hashes();
		$decoded      = 'content:"x"';
		$expected_b64 = base64_encode( hash( 'sha256', $decoded, true ) );

		$this->assertArrayHasKey( $expected_b64, $captured );
	}

	// ── upsert(): source_file / source_context on insert ─────────────────────

	public function test_upsert_populates_source_file_from_request_uri_when_not_given(): void {
		$_SERVER['REQUEST_URI'] = '/some/page/?utm_source=x';

		$this->manager->record_hash( 'console.log(1);', 'script-src', 'frontend' );

		$this->assertNotEmpty( $GLOBALS['_wpdb_inserted_rows'] );
		$row = $GLOBALS['_wpdb_inserted_rows'][0];
		$this->assertSame( '/some/page/?utm_source=x', $row['data']['source_file'] );

		unset( $_SERVER['REQUEST_URI'] );
	}

	public function test_upsert_populates_source_context_with_a_content_excerpt(): void {
		$this->manager->record_hash( 'var x = 1; var y = 2;', 'script-src', 'frontend' );

		$row = $GLOBALS['_wpdb_inserted_rows'][0];
		$this->assertSame( 'var x = 1; var y = 2;', $row['data']['source_context'] );
	}

	public function test_upsert_does_not_reinsert_source_columns_when_reactivating_an_existing_hash(): void {
		// An existing row (get_var returns a truthy id) takes the update
		// branch, which must never insert -- reactivation only bumps
		// last_seen_at/status, it doesn't need fresh provenance since the
		// content, by definition of matching hash_uniq, hasn't changed.
		$GLOBALS['_wpdb_get_var'] = '42';

		$this->manager->record_hash( 'var x = 1;', 'script-src', 'frontend' );

		$this->assertEmpty( $GLOBALS['_wpdb_inserted_rows'] );
		$this->assertNotEmpty( $GLOBALS['_wpdb_updated_rows'] );
	}

	// ── upsert(): new-hash rate limiter (circuit breaker) ─────────────────────

	public function test_upsert_rate_limits_new_inserts_past_the_hourly_cap(): void {
		// Each record_hash() call uses distinct content, so every one would
		// otherwise be a brand-new row -- exactly the runaway-growth
		// scenario the circuit breaker exists to stop.
		for ( $i = 0; $i < 40; $i++ ) {
			$this->manager->record_hash( "var uniqueToken{$i} = {$i};", 'script-src', 'frontend' );
		}

		// MAX_NEW_HASHES_PER_HOUR is 30 -- everything after that is refused.
		$this->assertCount( 30, $GLOBALS['_wpdb_inserted_rows'] );
	}

	public function test_upsert_rate_limiter_logs_exactly_once_when_it_trips(): void {
		$audit = $this->createMock( Audit_Log::class );
		$audit->expects( $this->once() )
			->method( 'log' )
			->with( 'hash_manager', 'hash_learning_rate_limited', $this->anything(), 'error' );

		$manager = new Hash_Manager( $audit, $this->createMock( Feature_Gate::class ) );

		for ( $i = 0; $i < 40; $i++ ) {
			$manager->record_hash( "var uniqueToken{$i} = {$i};", 'script-src', 'frontend' );
		}
	}

	public function test_upsert_rate_limiter_never_blocks_reactivation_of_an_existing_hash(): void {
		// The update branch (existing row found) must be exempt from the
		// insert rate limit -- reactivating a known hash never grows the
		// table, so there's nothing for the circuit breaker to protect
		// against here, and blocking it would incorrectly stop a
		// legitimately static, frequently-rendered script from being
		// recognised as still active.
		$GLOBALS['_wpdb_get_var'] = '1';

		for ( $i = 0; $i < 40; $i++ ) {
			$this->manager->record_hash( 'var x = 1;', 'script-src', 'frontend' );
		}

		$this->assertCount( 40, $GLOBALS['_wpdb_updated_rows'] );
		$this->assertEmpty( $GLOBALS['_wpdb_inserted_rows'] );
	}

	// ── prune_stale_by_age() ───────────────────────────────────────────────────

	public function test_prune_stale_by_age_returns_the_retired_row_count(): void {
		$GLOBALS['_wpdb_query_result'] = 7;

		$retired = $this->manager->prune_stale_by_age( 30 );

		$this->assertSame( 7, $retired );
	}

	public function test_prune_stale_by_age_logs_when_rows_are_retired(): void {
		$GLOBALS['_wpdb_query_result'] = 3;

		$audit = $this->createMock( Audit_Log::class );
		$audit->expects( $this->once() )
			->method( 'log' )
			->with( 'hash_manager', 'hashes_pruned_by_age', $this->anything(), 'info' );

		$manager = new Hash_Manager( $audit, $this->createMock( Feature_Gate::class ) );
		$manager->prune_stale_by_age( 30 );
	}

	public function test_prune_stale_by_age_does_not_log_when_nothing_is_retired(): void {
		$GLOBALS['_wpdb_query_result'] = 0;

		$audit = $this->createMock( Audit_Log::class );
		$audit->expects( $this->never() )->method( 'log' );

		$manager = new Hash_Manager( $audit, $this->createMock( Feature_Gate::class ) );
		$manager->prune_stale_by_age( 30 );
	}

	// ── inject_nonce_into_wp_inline_style_blocks() ────────────────────────────

	public function test_injects_nonce_into_a_wp_add_inline_style_block(): void {
		$GLOBALS['_wp_sam_test_nonce'] = 'abc123';
		$html                          = "<style id='global-styles-inline-css'>:root{--x:1}</style>";

		$result = $this->invoke_inject_nonce( $html );

		$this->assertStringContainsString( 'nonce="abc123"', $result );
		$this->assertStringContainsString( ':root{--x:1}', $result );

		unset( $GLOBALS['_wp_sam_test_nonce'] );
	}

	public function test_matches_any_handle_using_the_inline_css_id_convention(): void {
		// Not just WordPress core's own "global-styles" handle -- any theme
		// or plugin calling wp_add_inline_style( $handle, $css ) produces
		// the same id="{$handle}-inline-css" convention.
		$GLOBALS['_wp_sam_test_nonce'] = 'abc123';
		$html                          = "<style id='my-theme-styles-inline-css'>.a{color:red}</style>";

		$result = $this->invoke_inject_nonce( $html );

		$this->assertStringContainsString( 'nonce="abc123"', $result );

		unset( $GLOBALS['_wp_sam_test_nonce'] );
	}

	public function test_does_not_inject_into_an_unrelated_style_block(): void {
		$GLOBALS['_wp_sam_test_nonce'] = 'abc123';
		$html                          = '<style id="some-other-block">.a{color:red}</style>';

		$result = $this->invoke_inject_nonce( $html );

		$this->assertStringNotContainsString( 'nonce=', $result );

		unset( $GLOBALS['_wp_sam_test_nonce'] );
	}

	public function test_does_not_double_inject_when_a_nonce_is_already_present(): void {
		$GLOBALS['_wp_sam_test_nonce'] = 'abc123';
		$html                          = '<style id="global-styles-inline-css" nonce="existing">:root{--x:1}</style>';

		$result = $this->invoke_inject_nonce( $html );

		$this->assertSame( 1, substr_count( $result, 'nonce=' ) );
		$this->assertStringContainsString( 'nonce="existing"', $result );

		unset( $GLOBALS['_wp_sam_test_nonce'] );
	}

	public function test_returns_html_unchanged_when_no_nonce_is_available(): void {
		$html = "<style id='global-styles-inline-css'>:root{--x:1}</style>";

		$result = $this->invoke_inject_nonce( $html );

		$this->assertSame( $html, $result );
	}

	// ── Helpers ───────────────────────────────────────────────────────────────

	/**
	 * Returns a Hash_Manager subclass that stubs the database upsert()
	 * so tests do not require a real wpdb connection.
	 */
	private function make_db_stub_manager(): Hash_Manager {
		return new class( $this->audit, $this->createMock( Feature_Gate::class ) ) extends Hash_Manager {
			protected function upsert( string $hash_b64, string $fingerprint, string $directive, string $surface, string $source_file ): void {
				// No-op: skip DB write in unit tests.
			}
		};
	}

	/**
	 * Returns a Hash_Manager subclass that stubs upsert() and the DB read
	 * inside retire_stale() to return a pre-configured set of stored rows.
	 *
	 * @param array<int,array<string,mixed>> $stored_rows
	 */
	private function make_db_stub_manager_with_stored_hashes( array $stored_rows ): Hash_Manager {
		return new class( $this->audit, $this->createMock( Feature_Gate::class ), $stored_rows ) extends Hash_Manager {
			private array $stored_rows;

			public function __construct( Audit_Log $audit, Feature_Gate $gate, array $stored_rows ) {
				parent::__construct( $audit, $gate );
				$this->stored_rows = $stored_rows;
			}

			protected function upsert( string $hash_b64, string $fingerprint, string $directive, string $surface, string $source_file ): void {}

			public function retire_stale( array $current_hashes, string $surface ): int {
				if ( empty( $current_hashes ) ) {
					return 0;
				}
				$retired = 0;
				foreach ( $this->stored_rows as $row ) {
					$hv = $row['hash_value'];
					if ( ! isset( $current_hashes[ $hv ] ) || $current_hashes[ $hv ] !== $row['content_fingerprint'] ) {
						++$retired;
					}
				}
				return $retired;
			}
		};
	}

	/**
	 * Calls the private extract_and_record() method via reflection.
	 */
	private function invoke_extract(
		Hash_Manager $manager,
		string $html,
		string $tag,
		string $directive,
		string $surface
	): void {
		$ref = new ReflectionMethod( $manager, 'extract_and_record' );
		$ref->setAccessible( true );
		$ref->invoke( $manager, $html, $tag, $directive, $surface );
	}

	/**
	 * Calls the private extract_and_record_style_attributes() method via
	 * reflection.
	 */
	private function invoke_extract_style_attributes( Hash_Manager $manager, string $html, string $surface ): void {
		$ref = new ReflectionMethod( $manager, 'extract_and_record_style_attributes' );
		$ref->setAccessible( true );
		$ref->invoke( $manager, $html, $surface );
	}

	/**
	 * Calls the private inject_nonce_into_wp_inline_style_blocks() method
	 * via reflection, on the real (non-stubbed) manager -- the method has
	 * no DB dependency, so the real class is fine to exercise directly.
	 */
	private function invoke_inject_nonce( string $html ): string {
		$ref = new ReflectionMethod( $this->manager, 'inject_nonce_into_wp_inline_style_blocks' );
		$ref->setAccessible( true );
		return (string) $ref->invoke( $this->manager, $html );
	}
}