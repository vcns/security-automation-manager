<?php
/**
 * Unit tests for WP_SAM\CSP\Frontend_Policy_Reader.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\CSP\Frontend_Policy_Reader;
use WP_SAM\CSP\Policy_Builder;
use WP_SAM\Modules\Feature_Gate;

class FrontendPolicyReaderTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	public function test_no_frontend_profile_reads_as_null(): void {
		$this->assertNull( $this->reader( null )->read() );
	}

	public function test_a_disabled_frontend_has_no_header_or_policy(): void {
		$this->assertSame(
			array(
				'mode'   => 'disabled',
				'header' => '',
				'policy' => '',
			),
			$this->reader( $this->profile( 'disabled' ) )->read()
		);
	}

	public function test_reads_the_header_and_policy_pages_are_sent_with(): void {
		$policy = $this->reader(
			$this->profile( 'report-only' ),
			array(
				array(
					'directive'   => 'script-src',
					'source_host' => 'https://www.example.com',
				),
			)
		)->read();

		$this->assertSame( 'report-only', $policy['mode'] );
		$this->assertSame( 'content-security-policy-report-only', $policy['header'] );
		$this->assertStringContainsString( 'https://www.example.com', $policy['policy'] );
	}

	public function test_a_custom_header_name_is_read_in_lower_case(): void {
		update_option( 'wp_sam_policy_header_name', 'X-Origin-CSP' );

		$this->assertSame( 'x-origin-csp', $this->reader( $this->profile( 'enforce' ) )->read()['header'] );
	}

	private function reader( ?array $profile, array $sources = array() ): Frontend_Policy_Reader {
		$loader = new Stub_Policy_Data_Loader( array(), $sources, $profile );

		return new Frontend_Policy_Reader( $loader, new Policy_Builder( new Feature_Gate(), $loader ) );
	}

	private function profile( string $mode ): array {
		return array(
			'surface'    => 'frontend',
			'mode'       => $mode,
			'directives' => wp_json_encode(
				array(
					'default-src' => array( "'self'" ),
					'script-src'  => array( "'self'" ),
				)
			),
			'overrides'  => wp_json_encode( array() ),
		);
	}
}
