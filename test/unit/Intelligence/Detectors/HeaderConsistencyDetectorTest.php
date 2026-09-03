<?php
/**
 * Unit tests for WP_SAM\Intelligence\Detectors\Header_Consistency_Detector.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Detectors\Header_Consistency_Detector;

class HeaderConsistencyDetectorTest extends TestCase {

	private Header_Consistency_Detector $detector;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->detector = new Header_Consistency_Detector();
	}

	/** @return array<string, mixed> */
	private function context( string $user_agent, string $accept_language = '' ): array {
		return array(
			'surface'         => 'frontend',
			'user_agent'      => $user_agent,
			'accept_language' => $accept_language,
		);
	}

	public function test_chrome_ua_without_accept_language_produces_a_finding(): void {
		$ua      = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36';
		$finding = $this->detector->evaluate( $this->context( $ua ) );

		$this->assertNotNull( $finding );
		$this->assertSame( 'browser_ua_missing_accept_language', $finding['detail']['header_signal'] );
		$this->assertSame( 'medium', $finding['severity'] );
	}

	public function test_chrome_ua_with_accept_language_produces_no_finding(): void {
		$ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36';

		$this->assertNull( $this->detector->evaluate( $this->context( $ua, 'en-US,en;q=0.9' ) ) );
	}

	public function test_firefox_ua_without_accept_language_produces_a_finding(): void {
		$ua      = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0';
		$finding = $this->detector->evaluate( $this->context( $ua ) );

		$this->assertNotNull( $finding );
	}

	public function test_edge_ua_without_accept_language_produces_a_finding(): void {
		$ua      = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59';
		$finding = $this->detector->evaluate( $this->context( $ua ) );

		$this->assertNotNull( $finding );
	}

	public function test_real_safari_ua_without_accept_language_produces_a_finding(): void {
		$ua      = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15';
		$finding = $this->detector->evaluate( $this->context( $ua ) );

		$this->assertNotNull( $finding );
	}

	public function test_webkit_based_bot_without_a_specific_browser_token_is_not_flagged(): void {
		// A bare "Safari/537.36" substring appears in many legitimate
		// crawler user agents without a Version/ prefix -- must not alone
		// trigger this detector (GPTBot's real UA is structured like this).
		$ua = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.4; +https://openai.com/gptbot';

		$this->assertNull( $this->detector->evaluate( $this->context( $ua ) ) );
	}

	public function test_empty_user_agent_produces_no_finding(): void {
		$this->assertNull( $this->detector->evaluate( $this->context( '' ) ) );
	}

	public function test_non_browser_user_agent_produces_no_finding(): void {
		$this->assertNull( $this->detector->evaluate( $this->context( 'curl/8.4.0' ) ) );
	}

	public function test_surface_applicability_is_every_surface(): void {
		$this->assertSame( array(), $this->detector->applicable_surfaces() );
	}

	public function test_control_action_defaults_to_observe_only(): void {
		$this->assertSame( array( 'observe' ), $this->detector->allowed_control_actions() );
		$this->assertSame( 'observe', $this->detector->default_control_action() );
	}
}
