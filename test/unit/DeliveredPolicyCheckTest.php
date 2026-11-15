<?php
/**
 * Unit tests for WP_SAM\CSP\Delivered_Policy_Check.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\CSP\Delivered_Policy_Check;
use WP_SAM\CSP\Page_Cache_Purger;
use WP_SAM\Modules\Audit_Log;

class DeliveredPolicyCheckTest extends TestCase {

	private const POLICY = "default-src 'self'; script-src 'self' 'nonce-current' https://www.googletagmanager.com; report-uri https://example.com/wp-json/sam/v1/report";

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	public function test_current_when_visitors_get_the_same_policy_with_another_nonce_and_hashes(): void {
		$result = $this->check()->evaluate(
			$this->expected(),
			$this->page(
				array(
					'Content-Security-Policy-Report-Only' => "default-src 'self'; script-src 'self' 'nonce-cached' 'sha256-AAAA' https://www.googletagmanager.com; report-uri https://example.com/wp-json/sam/v1/report",
					'cf-cache-status'                     => 'HIT',
					'age'                                 => '7200',
				)
			)
		);

		$this->assertSame( Delivered_Policy_Check::OUTCOME_CURRENT, $result['outcome'] );
		$this->assertSame( 'content-security-policy-report-only', $result['header'] );
		$this->assertSame(
			array(
				'cf-cache-status' => 'HIT',
				'age'             => '7200',
			),
			$result['cache']
		);
	}

	public function test_stale_names_what_the_cached_copy_is_missing(): void {
		$result = $this->check()->evaluate(
			$this->expected(),
			$this->page(
				array(
					'content-security-policy-report-only' => "default-src 'self'; script-src 'self' 'nonce-old'; report-uri https://example.com/wp-json/sam/v1/report",
					'cf-cache-status'                     => 'HIT',
				)
			)
		);

		$this->assertSame( Delivered_Policy_Check::OUTCOME_STALE, $result['outcome'] );
		$this->assertSame( array( 'script-src https://www.googletagmanager.com' ), $result['missing'] );
		$this->assertSame( array(), $result['unexpected'] );

		$text = Delivered_Policy_Check::describe( $result );
		$this->assertStringContainsString( 'older Content Security Policy', $text );
		$this->assertStringContainsString( 'script-src https://www.googletagmanager.com', $text );
		$this->assertStringContainsString( 'came from a cache (cf-cache-status: HIT)', $text );
	}

	public function test_stale_when_a_copy_cached_before_promotion_is_still_report_only(): void {
		$expected           = $this->expected();
		$expected['mode']   = 'enforce';
		$expected['header'] = 'content-security-policy';

		$result = $this->check()->evaluate(
			$expected,
			$this->page( array( 'content-security-policy-report-only' => self::POLICY ) )
		);

		$this->assertSame( Delivered_Policy_Check::OUTCOME_STALE, $result['outcome'] );
		$this->assertSame( array(), $result['missing'] );
		$this->assertStringContainsString( 'although the frontend is now in enforce mode', Delivered_Policy_Check::describe( $result ) );
	}

	public function test_missing_when_the_page_carries_no_policy(): void {
		$result = $this->check()->evaluate( $this->expected(), $this->page( array( 'x-litespeed-cache' => 'hit' ) ) );

		$this->assertSame( Delivered_Policy_Check::OUTCOME_MISSING, $result['outcome'] );
		$this->assertTrue( Delivered_Policy_Check::served_from_cache( $result['cache'] ) );
	}

	public function test_disabled_frontend_expects_no_policy(): void {
		$disabled = array(
			'mode'   => 'disabled',
			'header' => '',
			'policy' => '',
		);

		$none = $this->check()->evaluate( $disabled, $this->page( array() ) );
		$some = $this->check()->evaluate( $disabled, $this->page( array( 'content-security-policy' => self::POLICY ) ) );

		$this->assertSame( Delivered_Policy_Check::OUTCOME_CURRENT, $none['outcome'] );
		$this->assertSame( Delivered_Policy_Check::OUTCOME_UNEXPECTED, $some['outcome'] );
	}

	public function test_a_custom_origin_header_counts_as_delivered(): void {
		$expected           = $this->expected();
		$expected['header'] = 'x-origin-csp';

		$result = $this->check()->evaluate( $expected, $this->page( array( 'X-Origin-CSP' => self::POLICY ) ) );

		$this->assertSame( Delivered_Policy_Check::OUTCOME_CURRENT, $result['outcome'] );
	}

	public function test_an_offsite_redirect_is_reported_without_its_destination(): void {
		$fetched = array();
		$check   = new Delivered_Policy_Check(
			static function ( string $url ) use ( &$fetched ) {
				$fetched[] = $url;
				return new WP_Error( 'wp_sam_offsite_redirect', "Redirected away from this site (HTTP 301), so this site's own copy could not be read.", array( 'code' => 301 ) );
			},
			fn (): array => $this->expected()
		);

		$result = $check->run();

		$this->assertSame( array( 'https://example.com/' ), $fetched, 'Only this site\'s own home page is fetched.' );
		$this->assertSame( Delivered_Policy_Check::OUTCOME_UNREACHABLE, $result['outcome'] );
		$this->assertStringContainsString( 'Redirected away from this site (HTTP 301)', Delivered_Policy_Check::describe( $result ) );
		$this->assertStringNotContainsString( 'example.org', (string) wp_json_encode( get_option( Delivered_Policy_Check::OPTION_RESULT ) ) );
	}

	public function test_a_refused_request_is_unreachable(): void {
		$result = $this->check()->evaluate( $this->expected(), $this->page( array(), 403 ) );

		$this->assertSame( Delivered_Policy_Check::OUTCOME_UNREACHABLE, $result['outcome'] );
		$this->assertStringContainsString( 'refused the request (HTTP 403)', Delivered_Policy_Check::describe( $result ) );
	}

	public function test_cache_headers_keep_only_their_first_word(): void {
		$result = $this->check()->evaluate(
			$this->expected(),
			$this->page(
				array(
					'content-security-policy-report-only' => self::POLICY,
					'x-cache'                             => 'HIT from proxy.example.org',
				)
			)
		);

		$this->assertSame( array( 'x-cache' => 'HIT' ), $result['cache'] );
	}

	public function test_run_stores_the_result_and_logs_a_problem_only_when_first_found(): void {
		$audit = $this->createMock( Audit_Log::class );
		$audit->expects( $this->once() )
			->method( 'log' )
			->with( 'delivered_policy', 'stale', $this->stringContains( 'googletagmanager' ), 'warning' );

		$check = new Delivered_Policy_Check(
			fn ( string $url ): array => $this->page( array( 'content-security-policy-report-only' => "default-src 'self'; script-src 'self'; report-uri https://example.com/wp-json/sam/v1/report" ) ),
			fn (): array => $this->expected(),
			$audit
		);

		$check->run();
		$check->run();

		$this->assertSame( Delivered_Policy_Check::OUTCOME_STALE, $check->result()['outcome'] );
	}

	public function test_a_policy_change_schedules_one_check(): void {
		$check = $this->check();
		$check->register();

		do_action( Page_Cache_Purger::CHANGED_ACTION, array() );
		$first = wp_next_scheduled( Delivered_Policy_Check::CHECK_HOOK );
		do_action( Page_Cache_Purger::CHANGED_ACTION, array() );

		$this->assertNotFalse( $first );
		$this->assertSame( $first, wp_next_scheduled( Delivered_Policy_Check::CHECK_HOOK ) );
	}

	private function check(): Delivered_Policy_Check {
		return new Delivered_Policy_Check(
			fn ( string $url ): array => $this->page( array() ),
			fn (): array => $this->expected()
		);
	}

	/** @return array{mode: string, header: string, policy: string} */
	private function expected(): array {
		return array(
			'mode'   => 'report-only',
			'header' => 'content-security-policy-report-only',
			'policy' => self::POLICY,
		);
	}

	private function page( array $headers, int $code = 200 ): array {
		return array(
			'response' => array( 'code' => $code ),
			'headers'  => $headers,
			'body'     => '',
		);
	}
}
