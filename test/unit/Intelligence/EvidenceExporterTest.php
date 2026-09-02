<?php
/**
 * Unit tests for WP_SAM\Intelligence\Evidence_Exporter.
 *
 * build() orchestrates roughly two dozen wpdb calls across Security_Health
 * and its own queries. Rather than sequencing all of them, most tests rely
 * on the wpdb stub's un-queued defaults (get_var/get_row/get_results all
 * return the same static "nothing here" value for every call when no
 * queue is set) -- a perfectly valid "quiet site" fixture that needs no
 * precise call-order bookkeeping. A couple of the more interesting private
 * methods are exercised in isolation via reflection instead.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Evidence_Exporter;

class EvidenceExporterTest extends TestCase {

	private Evidence_Exporter $exporter;

	protected function setUp(): void {
		wp_test_reset_globals();
		$GLOBALS['_wpdb_get_var']     = 0;
		$GLOBALS['_wpdb_get_row']     = null;
		$GLOBALS['_wpdb_get_results'] = array();
		$this->exporter = new Evidence_Exporter();
	}

	private function invoke( string $method ) {
		$ref = new ReflectionMethod( Evidence_Exporter::class, $method );
		$ref->setAccessible( true );
		return $ref->invoke( $this->exporter );
	}

	public function test_build_includes_every_top_level_section(): void {
		$bundle = $this->exporter->build();

		foreach ( array( 'format_version', 'exported_at', 'site_url', 'plugin_version', 'disclaimer', 'framework_context', 'health_summary', 'controls', 'exceptions', 'certificates', 'baseline', 'drift_open_count', 'recent_change_log', 'audit_log_excerpt' ) as $key ) {
			$this->assertArrayHasKey( $key, $bundle );
		}
	}

	public function test_build_disclaims_certification(): void {
		$bundle = $this->exporter->build();

		$this->assertStringContainsString( 'not a certification', $bundle['disclaimer'] );
	}

	public function test_build_lists_frameworks_as_context_only_not_claims(): void {
		$bundle = $this->exporter->build();

		$this->assertContains( 'ISO/IEC 27001', $bundle['framework_context'] );
		$this->assertContains( 'PCI DSS', $bundle['framework_context'] );
	}

	public function test_build_controls_section_has_the_three_pillar_groups(): void {
		$bundle = $this->exporter->build();

		$this->assertArrayHasKey( 'csp', $bundle['controls'] );
		$this->assertArrayHasKey( 'pillars', $bundle['controls'] );
		$this->assertArrayHasKey( 'traffic_controls', $bundle['controls'] );
	}

	public function test_build_baseline_is_null_when_none_approved(): void {
		$bundle = $this->exporter->build();

		$this->assertNull( $bundle['baseline'] );
	}

	// ── baseline_detail() ────────────────────────────────────────────────────

	public function test_baseline_detail_returns_null_when_no_current_baseline(): void {
		$GLOBALS['_wpdb_get_row'] = null;

		$this->assertNull( $this->invoke( 'baseline_detail' ) );
	}

	public function test_baseline_detail_returns_version_and_note_when_present(): void {
		$GLOBALS['_wpdb_get_row'] = array(
			'version_number' => 3,
			'approved_at'    => '2026-09-02 00:00:00',
			'note'           => 'Post-launch baseline',
			'is_current'     => 1,
		);

		$detail = $this->invoke( 'baseline_detail' );

		$this->assertSame( 3, $detail['version_number'] );
		$this->assertSame( 'Post-launch baseline', $detail['note'] );
	}

	// ── exceptions_detail() ──────────────────────────────────────────────────

	public function test_exceptions_detail_has_the_four_expected_buckets(): void {
		$detail = $this->invoke( 'exceptions_detail' );

		$this->assertArrayHasKey( 'ip_allow_rules', $detail );
		$this->assertArrayHasKey( 'permanent_blocks', $detail );
		$this->assertArrayHasKey( 'dependency_exceptions', $detail );
		$this->assertArrayHasKey( 'csp_overrides', $detail );
	}
}
