<?php
/**
 * Unit tests for WP_SAM\Intelligence\Recommendation_Rule_Certificate_Renewal.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Certificates\Certificate_Store;
use WP_SAM\Intelligence\Recommendation_Rule_Certificate_Renewal;

class RecommendationRuleCertificateRenewalTest extends TestCase {

	private Recommendation_Rule_Certificate_Renewal $rule;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->rule = new Recommendation_Rule_Certificate_Renewal();
	}

	private function configure_domain(): void {
		$GLOBALS['_wp_options'][ Certificate_Store::CONFIG_OPTION ] = array( 'domains' => array( 'example.com' ) );
	}

	/** @return array<string, mixed> */
	private function fake_certificate_row( int $not_after_timestamp ): array {
		return array(
			'id'            => 1,
			'domains'       => (string) wp_json_encode( array( 'example.com' ) ),
			'environment'   => 'production',
			'key_pem'       => '',
			'fullchain_pem' => 'irrelevant',
			'not_before'    => gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS ),
			'not_after'     => gmdate( 'Y-m-d H:i:s', $not_after_timestamp ),
			'updated_at'    => gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS ),
		);
	}

	public function test_does_not_fire_when_no_domain_is_configured(): void {
		$GLOBALS['_wpdb_get_row'] = null;

		$this->assertSame( array(), $this->rule->evaluate() );
	}

	public function test_does_not_fire_when_configured_but_nothing_issued_yet(): void {
		$this->configure_domain();
		$GLOBALS['_wpdb_get_row'] = null;

		$this->assertSame( array(), $this->rule->evaluate() );
	}

	public function test_does_not_fire_when_the_certificate_is_healthy(): void {
		$this->configure_domain();
		$GLOBALS['_wpdb_get_row'] = $this->fake_certificate_row( time() + ( 60 * DAY_IN_SECONDS ) );

		$this->assertSame( array(), $this->rule->evaluate() );
	}

	public function test_fires_as_high_risk_when_expiring_within_the_renewal_window(): void {
		$this->configure_domain();
		$GLOBALS['_wpdb_get_row'] = $this->fake_certificate_row( time() + ( 10 * DAY_IN_SECONDS ) );

		$results = $this->rule->evaluate();

		$this->assertCount( 1, $results );
		$this->assertSame( 'certificate_renewal_due', $results[0]['key'] );
		$this->assertSame( 'high', $results[0]['risk'] );
		$this->assertTrue( $results[0]['dismissible'] );
	}

	public function test_fires_as_critical_risk_when_already_expired(): void {
		$this->configure_domain();
		$GLOBALS['_wpdb_get_row'] = $this->fake_certificate_row( time() - DAY_IN_SECONDS );

		$results = $this->rule->evaluate();

		$this->assertSame( 'critical', $results[0]['risk'] );
		$this->assertStringContainsString( 'already expired', $results[0]['observed'] );
	}
}
