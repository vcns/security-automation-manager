<?php
/**
 * Unit tests for WP_SAM\CSP\Discovery.
 *
 * Focused on get_crawl_urls(), tested via reflection since it's private.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\CSP\Discovery;
use WP_SAM\CSP\Policy_Change_Manager;
use WP_SAM\Modules\Audit_Log;
use WP_SAM\Modules\Feature_Gate;

class DiscoveryTest extends TestCase {

	private Discovery $discovery;

	protected function setUp(): void {
		wp_test_reset_globals();

		$audit           = $this->createMock( Audit_Log::class );
		$gate            = $this->createMock( Feature_Gate::class );
		$policy_changes  = $this->createMock( Policy_Change_Manager::class );
		$this->discovery = new Discovery( $audit, $gate, $policy_changes );
	}

	public function test_admin_surface_has_no_crawl_targets(): void {
		// An anonymous wp_remote_get() to wp-admin never sees real admin
		// content -- WordPress redirects a logged-out request to
		// wp-login.php, and it has been observed to trigger a fatal error on
		// some hosts/security plugins for a bot-like request there. The
		// 'admin' surface must not be crawled anonymously.
		$this->assertSame( [], $this->get_crawl_urls( 'admin' ) );
	}

	public function test_unknown_surface_has_no_crawl_targets(): void {
		$this->assertSame( [], $this->get_crawl_urls( 'not-a-real-surface' ) );
	}

	/**
	 * Calls the private get_crawl_urls() method via reflection.
	 *
	 * @return array<int,string>
	 */
	private function get_crawl_urls( string $surface ): array {
		$ref = new ReflectionMethod( $this->discovery, 'get_crawl_urls' );
		$ref->setAccessible( true );
		return $ref->invoke( $this->discovery, $surface );
	}
}
