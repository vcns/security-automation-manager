<?php
/**
 * Unit tests for WP_SAM\Intelligence\Campaign_Detector.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Campaign_Detector;
use WP_SAM\Intelligence\Campaign_Store;
use WP_SAM\Intelligence\Event_Store;
use WP_SAM\Intelligence\Ip_Rule_Store;

class CampaignDetectorTest extends TestCase {

	private Campaign_Detector $detector;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->detector = new Campaign_Detector( new Event_Store(), new Campaign_Store() );
	}

	public function test_scan_records_a_campaign_when_participants_meet_the_threshold(): void {
		$GLOBALS['_wpdb_get_results'] = array(
			array(
				'detector_id'     => 'sqli-probe',
				'detector_family' => 'injection',
				'surface'         => 'frontend',
			),
		);
		$GLOBALS['_wpdb_get_col'] = array_map( static fn( int $i ): string => "203.0.113.{$i}", range( 1, 12 ) );
		$GLOBALS['_wpdb_get_var'] = null;

		$result = $this->detector->scan( 24, 10 );

		$this->assertSame( 1, $result['campaigns_detected'] );
		$this->assertCount( 1, $GLOBALS['_wpdb_inserted_rows'] );
		$this->assertSame( 12, $GLOBALS['_wpdb_inserted_rows'][0]['data']['participant_count'] );
	}

	public function test_scan_skips_a_detector_surface_below_the_threshold(): void {
		$GLOBALS['_wpdb_get_results'] = array(
			array(
				'detector_id'     => 'sqli-probe',
				'detector_family' => 'injection',
				'surface'         => 'frontend',
			),
		);
		$GLOBALS['_wpdb_get_col'] = array( '203.0.113.1', '203.0.113.2' );

		$result = $this->detector->scan( 24, 10 );

		$this->assertSame( 0, $result['campaigns_detected'] );
		$this->assertSame( array(), $GLOBALS['_wpdb_inserted_rows'] );
	}

	public function test_scan_reports_zero_when_nothing_active(): void {
		$GLOBALS['_wpdb_get_results'] = array();

		$result = $this->detector->scan();

		$this->assertSame( 'scanned', $result['status'] );
		$this->assertSame( 0, $result['campaigns_detected'] );
	}

	public function test_block_participants_adds_every_live_ip_as_a_block_rule(): void {
		$GLOBALS['_wpdb_get_col'] = array( '203.0.113.1', '203.0.113.2', '203.0.113.3' );

		$campaign = array(
			'id'          => 5,
			'detector_id' => 'sqli-probe',
			'surface'     => 'frontend',
		);

		$blocked = $this->detector->block_participants( $campaign, 1, 'Confirmed malicious.', new Ip_Rule_Store() );

		$this->assertSame( 3, $blocked );
		$this->assertCount( 3, $GLOBALS['_wpdb_inserted_rows'] );
		foreach ( $GLOBALS['_wpdb_inserted_rows'] as $row ) {
			$this->assertSame( 'block', $row['data']['list_type'] );
		}
	}

	public function test_block_participants_marks_the_campaign_blocked(): void {
		$GLOBALS['_wpdb_get_col'] = array( '203.0.113.1' );

		$campaign = array(
			'id'          => 5,
			'detector_id' => 'sqli-probe',
			'surface'     => 'frontend',
		);

		$this->detector->block_participants( $campaign, 1, 'Confirmed malicious.', new Ip_Rule_Store() );

		$status_update = array_values(
			array_filter(
				$GLOBALS['_wpdb_updated_rows'],
				static fn( array $row ): bool => isset( $row['data']['status'] )
			)
		);
		$this->assertCount( 1, $status_update );
		$this->assertSame( 'blocked', $status_update[0]['data']['status'] );
	}
}
