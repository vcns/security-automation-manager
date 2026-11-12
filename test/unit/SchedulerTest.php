<?php
/**
 * Unit tests for WP_SAM\CSP\Scheduler's well-known-file refresh logging.
 *
 * A warning-severity audit entry becomes a wp-admin notice, so a site that
 * simply has no agents.txt (HTTP 404) must log at info -- only a genuine
 * fetch failure should keep surfacing a notice every day. The refresh_*
 * methods are private and build their own stores, so these drive them via
 * reflection with the bootstrap's wp_remote_get() stub as the transport.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\CSP\Scheduler;
use WP_SAM\Modules\Audit_Log;

class SchedulerTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	/** @return array<string, array{int, string, string}> */
	public static function agents_refresh_outcomes(): array {
		return array(
			'refreshed' => array( 200, 'agents_rules_refreshed', 'info' ),
			'absent'    => array( 404, 'agents_rules_absent', 'info' ),
			'failed'    => array( 500, 'agents_rules_refresh_failed', 'warning' ),
		);
	}

	/**
	 * @dataProvider agents_refresh_outcomes
	 */
	public function test_agents_refresh_logs_each_outcome_at_the_right_severity( int $code, string $event, string $severity ): void {
		$GLOBALS['_wp_remote_get_response'] = array(
			'response' => array( 'code' => $code ),
			'body'     => "User-agent: *\nDisallow: /x/\n",
		);

		$audit = $this->createMock( Audit_Log::class );
		$audit->expects( $this->once() )
			->method( 'log' )
			->with( 'scheduler', $event, $this->isType( 'string' ), $severity );

		$this->invoke_private( new Scheduler( $audit ), 'refresh_agents_rules' );
	}

	public function test_security_txt_absent_on_both_locations_logs_at_info(): void {
		$GLOBALS['_wp_remote_get_response'] = array(
			'response' => array( 'code' => 404 ),
			'body'     => '',
		);

		$audit = $this->createMock( Audit_Log::class );
		$audit->expects( $this->once() )
			->method( 'log' )
			->with( 'scheduler', 'security_txt_absent', $this->stringContains( 'No security.txt on this site' ), 'info' );

		$this->invoke_private( new Scheduler( $audit ), 'refresh_security_txt' );
	}

	private function invoke_private( Scheduler $scheduler, string $method ): void {
		( new ReflectionMethod( $scheduler, $method ) )->invoke( $scheduler );
	}
}
