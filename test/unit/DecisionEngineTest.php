<?php
/**
 * Unit tests for WP_SAM\CSP\Decision_Engine.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\CSP\Automation_Config;
use WP_SAM\CSP\Decision_Engine;

class DecisionEngineTest extends TestCase {

	public function test_manual_mode_requires_human_review_for_low_risk_source(): void {
		$engine = new Decision_Engine();

		$result = $engine->evaluate_source(
			array(
				'directive'      => 'prefetch-src',
				'source_scheme'  => 'https',
				'source_host'    => 'cdn.example.test',
				'source_uri'     => 'https://cdn.example.test/app.js',
				'evidence_count' => 1,
			),
			array( 'mode' => Automation_Config::MODE_MANUAL )
		);

		$this->assertSame( Decision_Engine::ENGINE_VERSION, $result['engine_version'] );
		$this->assertSame( 'low', $result['risk'] );
		$this->assertFalse( $result['automation_eligible'] );
		$this->assertTrue( $result['required_human_review'] );
	}

	public function test_wildcard_is_hard_excluded_from_automation(): void {
		$engine = new Decision_Engine();

		$result = $engine->evaluate_source(
			array(
				'directive'      => 'img-src',
				'source_scheme'  => 'https',
				'source_host'    => '*.example.test',
				'source_uri'     => 'https://*.example.test/logo.png',
				'evidence_count' => 3,
			),
			array( 'mode' => Automation_Config::MODE_FULLY_AUTOMATIC )
		);

		$this->assertSame( 'high', $result['risk'] );
		$this->assertContains( 'wildcard_source', $result['hard_exclusions'] );
		$this->assertFalse( $result['automation_eligible'] );
	}

	public function test_low_risk_source_can_be_eligible_outside_manual_mode(): void {
		$engine = new Decision_Engine();

		$result = $engine->evaluate_source(
			array(
				'directive'      => 'prefetch-src',
				'source_scheme'  => 'https',
				'source_host'    => 'assets.example.test',
				'source_uri'     => 'https://assets.example.test/prefetch.json',
				'evidence_count' => 2,
			),
			array( 'mode' => Automation_Config::MODE_AUTOMATIC_MEDIUM_HIGH_APPROVAL )
		);

		$this->assertSame( 'low', $result['risk'] );
		$this->assertTrue( $result['automation_eligible'] );
	}

	public function test_medium_risk_requires_review_in_medium_high_approval_mode(): void {
		$engine = new Decision_Engine();

		$result = $engine->evaluate_source(
			array(
				'directive'      => 'img-src',
				'source_scheme'  => 'https',
				'source_host'    => 'images.example.test',
				'source_uri'     => 'https://images.example.test/logo.png',
				'evidence_count' => 2,
			),
			array( 'mode' => Automation_Config::MODE_AUTOMATIC_MEDIUM_HIGH_APPROVAL )
		);

		$this->assertSame( 'medium', $result['risk'] );
		$this->assertFalse( $result['automation_eligible'] );
		$this->assertTrue( $result['required_human_review'] );
	}

	public function test_medium_risk_is_eligible_when_only_high_requires_approval(): void {
		$engine = new Decision_Engine();

		$result = $engine->evaluate_source(
			array(
				'directive'      => 'img-src',
				'source_scheme'  => 'https',
				'source_host'    => 'images.example.test',
				'source_uri'     => 'https://images.example.test/logo.png',
				'evidence_count' => 2,
			),
			array( 'mode' => Automation_Config::MODE_AUTOMATIC_HIGH_APPROVAL )
		);

		$this->assertSame( 'medium', $result['risk'] );
		$this->assertTrue( $result['automation_eligible'] );
		$this->assertFalse( $result['required_human_review'] );
	}

	public function test_high_risk_is_eligible_only_in_fully_automatic_mode(): void {
		$engine = new Decision_Engine();

		$result = $engine->evaluate_source(
			array(
				'directive'      => 'frame-src',
				'source_scheme'  => 'https',
				'source_host'    => 'frames.example.test',
				'source_uri'     => 'https://frames.example.test/embed',
				'evidence_count' => 2,
			),
			array( 'mode' => Automation_Config::MODE_FULLY_AUTOMATIC )
		);

		$this->assertSame( 'high', $result['risk'] );
		$this->assertTrue( $result['automation_eligible'] );
		$this->assertFalse( $result['required_human_review'] );
	}
}
