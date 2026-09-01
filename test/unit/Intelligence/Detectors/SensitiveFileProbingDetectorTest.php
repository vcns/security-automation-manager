<?php
/**
 * Unit tests for WP_SAM\Intelligence\Detectors\Sensitive_File_Probing_Detector.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Detectors\Sensitive_File_Probing_Detector;

class SensitiveFileProbingDetectorTest extends TestCase {

	private Sensitive_File_Probing_Detector $detector;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->detector = new Sensitive_File_Probing_Detector();
	}

	private function context( string $path ): array {
		return array(
			'surface'      => 'frontend',
			'path'         => $path,
			'query_string' => '',
		);
	}

	public function test_positive_match_env_file(): void {
		$finding = $this->detector->evaluate( $this->context( '/.env' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'SFILE-002', $finding['detail']['rule_id'] );
	}

	public function test_negative_match_ordinary_wordpress_path(): void {
		$this->assertNull( $this->detector->evaluate( $this->context( '/wp-content/plugins/foo/foo.php' ) ) );
	}

	public function test_encoded_variant_of_wp_config_backup(): void {
		$finding = $this->detector->evaluate( $this->context( '/wp-config%2Ephp%2Ebak' ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'SFILE-006', $finding['detail']['rule_id'] );
	}

	public function test_benign_lookalike_generic_json_config_is_not_flagged(): void {
		// Roadmap §11.9: must not blindly classify every .json/.yaml/.conf
		// as malicious -- only specific, named secrets/credentials files.
		$this->assertNull( $this->detector->evaluate( $this->context( '/wp-content/plugins/foo/settings.json' ) ) );
		$this->assertNull( $this->detector->evaluate( $this->context( '/wp-content/themes/foo/theme.conf' ) ) );
	}

	public function test_surface_applicability_is_every_surface(): void {
		$this->assertSame( array(), $this->detector->applicable_surfaces() );
	}

	public function test_action_eligibility_finding_carries_no_control_field(): void {
		$finding = $this->detector->evaluate( $this->context( '/.env' ) );

		$this->assertArrayNotHasKey( 'action', $finding );
		$this->assertArrayNotHasKey( 'control', $finding );
	}

	public function test_confidence_outcome(): void {
		$finding = $this->detector->evaluate( $this->context( '/id_rsa' ) );

		$this->assertSame( 0.9, $finding['confidence'] );
	}

	public function test_false_positive_regression_dotenv_prefixed_word_not_matched(): void {
		// A path containing ".environment" (not the exact .env token) must
		// not match -- the rule requires .env to end at "/" or end-of-string
		// or be followed by another dot-suffix.
		$this->assertNull( $this->detector->evaluate( $this->context( '/wp-content/uploads/.environment-report.pdf' ) ) );
	}
}
