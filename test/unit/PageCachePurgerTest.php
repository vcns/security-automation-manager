<?php
/**
 * Unit tests for WP_SAM\CSP\Page_Cache_Purger.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\CSP\Page_Cache_Purger;
use WP_SAM\Modules\Audit_Log;

class PageCachePurgerTest extends TestCase {

	/** @var array{mode: string, header: string, policy: string}|null */
	private ?array $policy;

	/** @var list<string> */
	private array $cleared;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->policy  = array(
			'mode'   => 'report-only',
			'header' => 'content-security-policy-report-only',
			'policy' => "default-src 'self'; script-src 'self' 'nonce-one'",
		);
		$this->cleared = array();
	}

	public function test_first_check_records_a_baseline_without_clearing(): void {
		$this->purger()->check();

		$this->assertNotSame( '', get_option( Page_Cache_Purger::OPTION_FINGERPRINT, '' ) );
		$this->assertSame( array(), $this->cleared );
	}

	public function test_unchanged_policy_clears_nothing(): void {
		$purger = $this->purger();
		$purger->ensure_baseline();

		$purger->check();

		$this->assertSame( array(), $this->cleared );
	}

	public function test_a_changed_policy_clears_every_detected_cache_once(): void {
		$purger = $this->purger();
		$purger->ensure_baseline();
		$changed = null;
		add_action( Page_Cache_Purger::CHANGED_ACTION, static function ( array $purged ) use ( &$changed ): void {
			$changed = $purged;
		} );

		$this->policy['policy'] .= ' https://www.example.com';
		$purger->check();
		$purger->check();

		$this->assertSame( array( 'Detected Cache' ), $this->cleared, 'Only the detected cache is cleared, and only once.' );
		$this->assertSame( array( 'Detected Cache' ), $changed );
		$this->assertSame( array( 'Detected Cache' ), get_option( Page_Cache_Purger::OPTION_NOTICE )['caches'] );
		$this->assertSame( array( 'Detected Cache' ), get_option( Page_Cache_Purger::OPTION_LAST_PURGE )['caches'] );
	}

	public function test_a_promotion_to_enforce_clears_caches(): void {
		$purger = $this->purger();
		$purger->ensure_baseline();

		$this->policy['mode']   = 'enforce';
		$this->policy['header'] = 'content-security-policy';
		$purger->check();

		$this->assertSame( array( 'Detected Cache' ), $this->cleared );
	}

	public function test_new_nonces_and_learned_hashes_do_not_clear_caches(): void {
		$purger = $this->purger();
		$purger->ensure_baseline();

		$this->policy['policy'] = "default-src 'self'; script-src 'self' 'nonce-two' 'sha256-AAAA'";
		$purger->check();

		$this->assertSame( array(), $this->cleared );
	}

	public function test_switched_off_records_the_change_without_clearing(): void {
		update_option( Page_Cache_Purger::OPTION_ENABLED, '0' );
		$purger = $this->purger();
		$purger->ensure_baseline();
		$changed = null;
		add_action( Page_Cache_Purger::CHANGED_ACTION, static function ( array $purged ) use ( &$changed ): void {
			$changed = $purged;
		} );

		$this->policy['policy'] .= ' https://www.example.com';
		$purger->check();

		$this->assertSame( array(), $this->cleared );
		$this->assertSame( array(), $changed, 'The change is still announced, so the visitor check runs.' );
		$this->assertFalse( get_option( Page_Cache_Purger::OPTION_NOTICE ) );
	}

	public function test_a_second_change_within_a_minute_is_deferred_to_cron(): void {
		$purger = $this->purger();
		$purger->ensure_baseline();
		$this->policy['policy'] .= ' https://one.example.com';
		$purger->check();
		$fingerprint_after_first = get_option( Page_Cache_Purger::OPTION_FINGERPRINT );

		$this->policy['policy'] .= ' https://two.example.com';
		$purger->check();

		$this->assertSame( array( 'Detected Cache' ), $this->cleared, 'The second change is not cleared straight away.' );
		$this->assertNotFalse( wp_next_scheduled( Page_Cache_Purger::CHECK_HOOK ) );
		$this->assertSame( $fingerprint_after_first, get_option( Page_Cache_Purger::OPTION_FINGERPRINT ), 'The deferred check must still see the change.' );

		// The deferred check, once the minute has passed.
		update_option( Page_Cache_Purger::OPTION_LAST_PURGE, array( 'at' => time() - 120, 'caches' => array( 'Detected Cache' ) ) );
		$purger->check();

		$this->assertSame( array( 'Detected Cache', 'Detected Cache' ), $this->cleared );
	}

	public function test_a_failing_cache_is_logged_and_the_others_still_cleared(): void {
		$audit = $this->createMock( Audit_Log::class );
		$audit->expects( $this->exactly( 2 ) )
			->method( 'log' )
			->willReturnCallback(
				function ( string $component, string $event, string $detail, string $severity ): void {
					$this->assertSame( 'page_cache', $component );
					$this->assertContains( $event, array( 'purge_failed', 'purged' ) );
					if ( 'purge_failed' === $event ) {
						$this->assertSame( 'warning', $severity );
						$this->assertStringContainsString( 'Broken Cache', $detail );
					}
				}
			);

		$caches = array(
			array(
				'name'   => 'Broken Cache',
				'detect' => static fn (): bool => true,
				'purge'  => static function (): void {
					throw new RuntimeException( 'disk full' );
				},
			),
			$this->cache( 'Working Cache', true ),
		);

		$this->assertSame( array( 'Working Cache' ), ( new Page_Cache_Purger( fn () => $this->policy, $caches, $audit ) )->purge() );
	}

	public function test_writes_to_policy_tables_schedule_a_check_at_shutdown(): void {
		$purger = $this->purger();
		$purger->register();

		$purger->watch_query( 'SELECT * FROM wp_csp_policy_profiles' );
		$purger->watch_query( "UPDATE `wp_csp_hash_inventory` SET last_seen_at = '2026-11-13'" );
		$this->assertArrayNotHasKey( 'shutdown', $GLOBALS['_wp_actions'], 'Reads and hash learning are not policy changes.' );

		$purger->watch_query( "UPDATE `wp_csp_source_inventory` SET `approval_state` = 'approved' WHERE `id` = 7" );
		$this->assertCount( 1, $GLOBALS['_wp_actions']['shutdown'] );
		$this->assertLessThan( 0, $GLOBALS['_wp_actions']['shutdown'][0][1], 'Runs before LiteSpeed Cache sends its headers at priority 0.' );

		$purger->watch_query( "UPDATE `wp_csp_policy_profiles` SET `mode` = 'enforce'" );
		$this->assertCount( 1, $GLOBALS['_wp_actions']['shutdown'], 'One check per request.' );
	}

	public function test_saving_a_header_option_schedules_a_check_at_shutdown(): void {
		$this->purger()->register();

		do_action( 'update_option_wp_sam_policy_header_name', '', 'X-Origin-CSP' );

		$this->assertArrayHasKey( 'shutdown', $GLOBALS['_wp_actions'] );
	}

	public function test_no_frontend_profile_means_nothing_to_compare(): void {
		$this->policy = null;
		$purger       = $this->purger();

		$purger->ensure_baseline();
		$purger->check();

		$this->assertFalse( get_option( Page_Cache_Purger::OPTION_FINGERPRINT ) );
		$this->assertSame( array(), $this->cleared );
	}

	public function test_detected_caches_lists_only_present_ones(): void {
		$this->assertSame( array( 'Detected Cache' ), $this->purger()->detected_caches() );
	}

	public function test_default_caches_detect_a_cache_by_its_purge_hook(): void {
		add_action( 'litespeed_purge_all', static function (): void {} );

		$names = ( new Page_Cache_Purger( fn () => $this->policy, Page_Cache_Purger::default_caches() ) )->detected_caches();

		$this->assertSame( array( 'LiteSpeed Cache' ), $names );
	}

	public function test_sanitize_enabled_treats_an_unticked_box_as_off(): void {
		$this->assertSame( '0', Page_Cache_Purger::sanitize_enabled( null ) );
		$this->assertSame( '1', Page_Cache_Purger::sanitize_enabled( '1' ) );
	}

	private function purger(): Page_Cache_Purger {
		return new Page_Cache_Purger(
			fn (): ?array => $this->policy,
			array(
				$this->cache( 'Detected Cache', true ),
				$this->cache( 'Absent Cache', false ),
			)
		);
	}

	/** @return array{name: string, detect: callable, purge: callable} */
	private function cache( string $name, bool $present ): array {
		return array(
			'name'   => $name,
			'detect' => static fn (): bool => $present,
			'purge'  => function () use ( $name ): void {
				$this->cleared[] = $name;
			},
		);
	}
}
