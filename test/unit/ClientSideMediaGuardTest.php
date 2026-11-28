<?php
/**
 * Unit tests for WP_SAM\CSP\Client_Side_Media_Guard: WordPress 7.1+'s
 * in-browser media processing is switched off while the admin CSP is
 * enforced, because it needs 'unsafe-eval' and blob: workers SAM never
 * allows, and WordPress has no fallback when it's blocked.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\CSP\Client_Side_Media_Guard;
use WP_SAM\CSP\Policy_Data_Loader;

class ClientSideMediaGuardTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	/** A loader that returns a fixed admin profile and counts reads. */
	private function loader( ?array $admin_profile ): Policy_Data_Loader {
		return new class( $admin_profile ) implements Policy_Data_Loader {
			public int $profile_reads = 0;

			public function __construct( private ?array $admin_profile ) {}

			public function load_profile( string $surface ): ?array {
				++$this->profile_reads;
				return 'admin' === $surface ? $this->admin_profile : null;
			}

			public function load_approved_hashes( string $surface ): array {
				return array();
			}

			public function load_approved_sources( string $surface ): array {
				return array();
			}
		};
	}

	public function test_register_hooks_cores_own_filter(): void {
		( new Client_Side_Media_Guard( $this->loader( null ) ) )->register();

		$this->assertArrayHasKey( 'wp_client_side_media_processing_enabled', $GLOBALS['_wp_actions'] );
	}

	public function test_enforced_admin_turns_processing_off(): void {
		$guard = new Client_Side_Media_Guard( $this->loader( array( 'mode' => 'enforce' ) ) );

		$this->assertFalse( $guard->filter_enabled( true ) );
	}

	public function test_report_only_admin_leaves_processing_on(): void {
		$guard = new Client_Side_Media_Guard( $this->loader( array( 'mode' => 'report-only' ) ) );

		$this->assertTrue( $guard->filter_enabled( true ) );
	}

	public function test_disabled_admin_leaves_processing_on(): void {
		$guard = new Client_Side_Media_Guard( $this->loader( array( 'mode' => 'disabled' ) ) );

		$this->assertTrue( $guard->filter_enabled( true ) );
	}

	public function test_missing_admin_profile_leaves_processing_on(): void {
		$guard = new Client_Side_Media_Guard( $this->loader( null ) );

		$this->assertTrue( $guard->filter_enabled( true ) );
	}

	public function test_never_turns_processing_on_when_core_had_it_off(): void {
		// Core turns it off outside a secure context; SAM must never turn it
		// back on, whatever the admin mode.
		$loader = $this->loader( array( 'mode' => 'report-only' ) );
		$guard  = new Client_Side_Media_Guard( $loader );

		$this->assertFalse( $guard->filter_enabled( false ) );
		$this->assertSame( 0, $loader->profile_reads );
	}

	public function test_reads_the_admin_profile_once_per_request(): void {
		$loader = $this->loader( array( 'mode' => 'enforce' ) );
		$guard  = new Client_Side_Media_Guard( $loader );

		$guard->filter_enabled( true );
		$guard->filter_enabled( true );
		$guard->admin_enforced();

		$this->assertSame( 1, $loader->profile_reads );
	}

	public function test_core_filter_sees_the_guards_answer(): void {
		( new Client_Side_Media_Guard( $this->loader( array( 'mode' => 'enforce' ) ) ) )->register();

		$this->assertFalse( (bool) apply_filters( 'wp_client_side_media_processing_enabled', true ) );
	}

	public function test_a_later_filter_can_turn_processing_back_on(): void {
		( new Client_Side_Media_Guard( $this->loader( array( 'mode' => 'enforce' ) ) ) )->register();
		add_filter( 'wp_client_side_media_processing_enabled', static fn(): bool => true, 20 );

		$this->assertTrue( (bool) apply_filters( 'wp_client_side_media_processing_enabled', true ) );
	}

	public function test_default_loader_reads_the_admin_profile_from_the_database(): void {
		$GLOBALS['_wpdb_get_row'] = array(
			'surface' => 'admin',
			'mode'    => 'enforce',
		);

		$this->assertTrue( ( new Client_Side_Media_Guard() )->admin_enforced() );
	}
}
