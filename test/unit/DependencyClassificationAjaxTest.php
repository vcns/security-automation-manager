<?php
/**
 * Decide → Dependency Classification AJAX handlers in Admin_UI:
 * ajax_classify_dependency() (pinned_url recording, drift reset),
 * ajax_suggest_dependency_sri() (now via Dependency_Sri_Fetcher) and
 * ajax_reapprove_dependency_sri() ("Re-approve new hash").
 *
 * Relies on the bootstrap's throwing wp_send_json_*() stubs.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Admin\Admin_UI;
use WP_SAM\Modules\Audit_Log;
use WP_SAM\Plugin;

class DependencyClassificationAjaxTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
		$_POST = array();
	}

	protected function tearDown(): void {
		$_POST = array();
	}

	/** @param array<string, mixed> $overrides */
	private function row( array $overrides = array() ): array {
		return array_merge(
			array(
				'surface'            => 'frontend',
				'resource_type'      => 'script',
				'origin'             => 'https://cdn.example.net',
				'classification'     => 'immutable_pinned',
				'expected_sri'       => 'sha384-old',
				'pinned_url'         => 'https://cdn.example.net/lib.js',
				'last_seen_url'      => 'https://cdn.example.net/lib.js?ver=2',
				'drift_observed_sri' => 'sha384-new',
			),
			$overrides
		);
	}

	/**
	 * @param array<string, string>     $post
	 * @param array<string, mixed>|null $row  What the handler's get_row() sees.
	 */
	private function call( string $handler, array $post, ?array $row, bool $can = true ): WP_SAM_Test_Json_Response {
		$GLOBALS['_wp_current_user_can'] = array( 'manage_options' => $can );
		$GLOBALS['_wpdb_get_row']        = $row;
		// Audit_Log writes only once its table exists (SHOW TABLES LIKE).
		$GLOBALS['_wpdb_get_var'] = 'wp_sam_audit_log';
		$_POST                    = $post;

		$reflection    = new ReflectionClass( Plugin::class );
		$plugin        = $reflection->newInstanceWithoutConstructor();
		$plugin->audit = new Audit_Log();

		try {
			( new Admin_UI( $plugin ) )->$handler();
		} catch ( WP_SAM_Test_Json_Response $response ) {
			return $response;
		}

		$this->fail( "{$handler}() returned without sending a JSON response." );
	}

	/** @return array<string, mixed> data of the single sam_dependency_inventory update */
	private function inventory_update(): array {
		$updates = array_values(
			array_filter(
				$GLOBALS['_wpdb_updated_rows'],
				static fn( array $u ): bool => str_ends_with( $u['table'], 'sam_dependency_inventory' )
			)
		);
		$this->assertCount( 1, $updates );
		return $updates[0];
	}

	// ── Re-approve ───────────────────────────────────────────────────────────

	public function test_reapprove_copies_the_observed_hash_and_clears_drift(): void {
		$response = $this->call( 'ajax_reapprove_dependency_sri', array( 'id' => '5' ), $this->row() );

		$this->assertTrue( $response->success );
		$this->assertSame( 'sha384-new', $response->data['hash'] );

		$update = $this->inventory_update();
		$this->assertSame( array( 'id' => 5 ), $update['where'] );
		$this->assertSame( 'sha384-new', $update['data']['expected_sri'] );
		$this->assertArrayNotHasKey( 'pinned_url', $update['data'], 'pinned_url must be left unchanged.' );
		$this->assertNull( $update['data']['drift_detected_at'] );
		$this->assertNull( $update['data']['drift_observed_sri'] );

		$audit = array_values( array_filter( $GLOBALS['_wpdb_inserted_rows'], static fn( array $i ): bool => str_ends_with( $i['table'], 'sam_audit_log' ) ) );
		$this->assertCount( 1, $audit );
		$this->assertSame( 'pinned_hash_reapproved', $audit[0]['data']['event'] );
		$this->assertSame( 'info', $audit[0]['data']['severity'] );
		$this->assertStringContainsString( 'sha384-old', $audit[0]['data']['detail'] );
		$this->assertStringContainsString( 'sha384-new', $audit[0]['data']['detail'] );
	}

	public function test_reapprove_requires_manage_options(): void {
		$response = $this->call( 'ajax_reapprove_dependency_sri', array( 'id' => '5' ), $this->row(), false );

		$this->assertFalse( $response->success );
		$this->assertSame( 403, $response->status_code );
		$this->assertSame( array(), $GLOBALS['_wpdb_updated_rows'] );
	}

	public function test_reapprove_refuses_a_row_with_no_recorded_drift(): void {
		$response = $this->call( 'ajax_reapprove_dependency_sri', array( 'id' => '5' ), $this->row( array( 'drift_observed_sri' => null ) ) );

		$this->assertFalse( $response->success );
		$this->assertSame( array(), $GLOBALS['_wpdb_updated_rows'] );
	}

	public function test_reapprove_refuses_a_row_that_is_no_longer_pinned(): void {
		$response = $this->call( 'ajax_reapprove_dependency_sri', array( 'id' => '5' ), $this->row( array( 'classification' => 'mutable_provider' ) ) );

		$this->assertFalse( $response->success );
		$this->assertSame( array(), $GLOBALS['_wpdb_updated_rows'] );
	}

	public function test_reapprove_refuses_an_unknown_row(): void {
		$response = $this->call( 'ajax_reapprove_dependency_sri', array( 'id' => '5' ), null );

		$this->assertFalse( $response->success );
	}

	// ── Classify: pinned_url ─────────────────────────────────────────────────

	public function test_manual_pin_records_last_seen_url_as_pinned_url_and_clears_drift(): void {
		$response = $this->call(
			'ajax_classify_dependency',
			array(
				'id'             => '5',
				'classification' => 'immutable_pinned',
				'expected_sri'   => 'sha384-typed',
			),
			$this->row( array( 'pinned_url' => null ) )
		);

		$this->assertTrue( $response->success );
		$data = $this->inventory_update()['data'];
		$this->assertSame( 'sha384-typed', $data['expected_sri'] );
		$this->assertSame( 'https://cdn.example.net/lib.js?ver=2', $data['pinned_url'] );
		$this->assertNull( $data['drift_detected_at'] );
	}

	public function test_suggest_flow_records_the_hashed_url_as_pinned_url(): void {
		$response = $this->call(
			'ajax_classify_dependency',
			array(
				'id'             => '5',
				'classification' => 'immutable_pinned',
				'expected_sri'   => 'sha384-suggested',
				'pinned_url'     => 'https://cdn.example.net/exact/v3.js',
			),
			$this->row()
		);

		$this->assertTrue( $response->success );
		$this->assertSame( 'https://cdn.example.net/exact/v3.js', $this->inventory_update()['data']['pinned_url'] );
	}

	public function test_classify_rejects_a_pinned_url_on_another_origin(): void {
		$response = $this->call(
			'ajax_classify_dependency',
			array(
				'id'             => '5',
				'classification' => 'immutable_pinned',
				'expected_sri'   => 'sha384-suggested',
				'pinned_url'     => 'https://elsewhere.example/v3.js',
			),
			$this->row()
		);

		$this->assertFalse( $response->success );
		$this->assertSame( array(), $GLOBALS['_wpdb_updated_rows'] );
	}

	public function test_unchanged_hash_keeps_pinned_url_and_drift_state(): void {
		$response = $this->call(
			'ajax_classify_dependency',
			array(
				'id'             => '5',
				'classification' => 'immutable_pinned',
				'expected_sri'   => 'sha384-old',
			),
			$this->row()
		);

		$this->assertTrue( $response->success );
		$data = $this->inventory_update()['data'];
		$this->assertSame( 'https://cdn.example.net/lib.js', $data['pinned_url'] );
		$this->assertArrayNotHasKey( 'drift_observed_sri', $data );
	}

	public function test_allow_by_host_clears_hash_pin_and_drift(): void {
		$response = $this->call(
			'ajax_classify_dependency',
			array(
				'id'             => '5',
				'classification' => 'mutable_provider',
				'expected_sri'   => 'sha384-old',
			),
			$this->row()
		);

		$this->assertTrue( $response->success );
		$data = $this->inventory_update()['data'];
		$this->assertSame( 'mutable_provider', $data['classification'] );
		$this->assertNull( $data['expected_sri'] );
		$this->assertNull( $data['pinned_url'] );
		$this->assertNull( $data['drift_detected_at'] );
		$this->assertNull( $data['drift_observed_sri'] );
	}

	// ── Suggest ──────────────────────────────────────────────────────────────

	public function test_suggest_returns_hash_and_url_through_the_shared_fetcher(): void {
		$GLOBALS['_wp_remote_get_response'] = array(
			'response' => array( 'code' => 200 ),
			'body'     => 'abc',
		);

		$response = $this->call(
			'ajax_suggest_dependency_sri',
			array(
				'id'  => '5',
				'url' => 'https://cdn.example.net/lib.js',
			),
			array( 'origin' => 'https://cdn.example.net' )
		);

		$this->assertTrue( $response->success );
		$this->assertSame( 'sha384-' . base64_encode( hash( 'sha384', 'abc', true ) ), $response->data['hash'] );
		$this->assertSame( 'https://cdn.example.net/lib.js', $response->data['url'] );
		$this->assertTrue( $GLOBALS['_wp_remote_get_requests'][0]['args']['reject_unsafe_urls'] );
	}

	public function test_suggest_still_refuses_another_origin_without_fetching(): void {
		$response = $this->call(
			'ajax_suggest_dependency_sri',
			array(
				'id'  => '5',
				'url' => 'https://elsewhere.example/lib.js',
			),
			array( 'origin' => 'https://cdn.example.net' )
		);

		$this->assertFalse( $response->success );
		$this->assertSame( 'That URL must be on the same origin already shown for this row.', $response->data['message'] );
		$this->assertSame( array(), $GLOBALS['_wp_remote_get_requests'] );
	}
}
