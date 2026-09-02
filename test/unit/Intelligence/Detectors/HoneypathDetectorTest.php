<?php
/**
 * Unit tests for WP_SAM\Intelligence\Detectors\Honeypath_Detector.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Detectors\Honeypath_Detector;
use WP_SAM\Intelligence\Honeypath_Store;

class HoneypathDetectorTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	private function context( string $path ): array {
		return array(
			'surface'      => 'frontend',
			'path'         => $path,
			'query_string' => '',
		);
	}

	public function test_evaluate_returns_null_with_no_configured_paths(): void {
		$GLOBALS['_wpdb_get_results'] = array();
		$detector                     = new Honeypath_Detector( new Honeypath_Store() );

		$this->assertNull( $detector->evaluate( $this->context( '/wp-content/backup.zip' ) ) );
	}

	public function test_evaluate_matches_a_configured_decoy_path(): void {
		$GLOBALS['_wpdb_get_results'] = array(
			array(
				'id'   => 1,
				'path' => '/wp-content/backup.zip',
			),
		);
		$detector = new Honeypath_Detector( new Honeypath_Store() );

		$finding = $detector->evaluate( $this->context( '/wp-content/backup.zip' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'critical', $finding['severity'] );
	}

	public function test_evaluate_does_not_match_an_unconfigured_path(): void {
		$GLOBALS['_wpdb_get_results'] = array(
			array(
				'id'   => 1,
				'path' => '/wp-content/backup.zip',
			),
		);
		$detector = new Honeypath_Detector( new Honeypath_Store() );

		$this->assertNull( $detector->evaluate( $this->context( '/wp-content/other-file.zip' ) ) );
	}

	public function test_id_and_family(): void {
		$detector = new Honeypath_Detector( new Honeypath_Store() );

		$this->assertSame( 'honeypath', $detector->id() );
		$this->assertSame( 'deception', $detector->family() );
	}

	public function test_applicable_surfaces_is_every_surface(): void {
		$detector = new Honeypath_Detector( new Honeypath_Store() );

		$this->assertSame( array(), $detector->applicable_surfaces() );
	}
}
