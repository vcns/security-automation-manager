<?php
/**
 * Unit tests for WP_SAM\Modules\Checkout_Service.
 *
 * Verifies the plugin calls the Stripe API directly (no external proxy):
 * correct secret key/price ID resolution per mode+interval, correct request
 * shape, and correct success/error handling.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Modules\Checkout_Service;
use WP_SAM\Modules\Entitlement_Store;
use WP_SAM\Modules\Audit_Log;

class CheckoutServiceTest extends TestCase {

	private Entitlement_Store $entitlements;

	protected function setUp(): void {
		wp_test_reset_globals();

		if ( ! class_exists( Checkout_Service::class ) ) {
			$this->markTestSkipped( 'Checkout_Service offline module is not available.' );
		}

		$this->entitlements = new Entitlement_Store( $this->createMock( Audit_Log::class ) );
	}

	private function service(): Checkout_Service {
		return new Checkout_Service( $this->entitlements );
	}

	// ── Input validation ──────────────────────────────────────────────────────

	public function test_rejects_insecure_success_url(): void {
		$result = $this->service()->create_session( 'csp-automation-manager', 'http://example.com/ok', 'https://example.com/cancel' );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'insecure_url', $result->get_error_code() );
	}

	public function test_rejects_insecure_cancel_url(): void {
		$result = $this->service()->create_session( 'csp-automation-manager', 'https://example.com/ok', 'http://example.com/cancel' );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'insecure_url', $result->get_error_code() );
	}

	public function test_rejects_invalid_interval(): void {
		$result = $this->service()->create_session( 'csp-automation-manager', 'https://example.com/ok', 'https://example.com/cancel', 'weekly' );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'invalid_interval', $result->get_error_code() );
	}

	// ── Missing configuration ────────────────────────────────────────────────

	public function test_returns_error_when_secret_key_not_configured(): void {
		update_option( 'wp_sam_stripe_mode', 'test' );
		// No wp_sam_stripe_secret_key_test set.

		$result = $this->service()->create_session( 'csp-automation-manager', 'https://example.com/ok', 'https://example.com/cancel' );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'payment_not_configured', $result->get_error_code() );
		$this->assertNull( $GLOBALS['_wp_remote_post_requests'][0] ?? null );
	}

	public function test_returns_error_when_price_id_not_configured(): void {
		update_option( 'wp_sam_stripe_mode', 'test' );
		update_option( 'wp_sam_stripe_secret_key_test', 'sk_test_abc' );
		// No wp_sam_stripe_price_id_monthly_test set.

		$result = $this->service()->create_session( 'csp-automation-manager', 'https://example.com/ok', 'https://example.com/cancel', 'monthly' );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'price_not_configured', $result->get_error_code() );
	}

	// ── Request shape ────────────────────────────────────────────────────────

	public function test_calls_stripe_api_directly_with_bearer_auth(): void {
		update_option( 'wp_sam_stripe_mode', 'test' );
		update_option( 'wp_sam_stripe_secret_key_test', 'sk_test_abc123' );
		update_option( 'wp_sam_stripe_price_id_monthly_test', 'price_monthly_test' );
		$GLOBALS['_wp_remote_post_response'] = array(
			'response' => array( 'code' => 200 ),
			'body'     => wp_json_encode( array( 'url' => 'https://checkout.stripe.com/session_123' ) ),
		);

		$result = $this->service()->create_session( 'csp-automation-manager', 'https://example.com/ok', 'https://example.com/cancel', 'monthly' );

		$this->assertIsArray( $result );
		$this->assertSame( 'https://checkout.stripe.com/session_123', $result['url'] );

		$request = $GLOBALS['_wp_remote_post_requests'][0];
		$this->assertSame( 'https://api.stripe.com/v1/checkout/sessions', $request['url'] );
		$this->assertSame( 'Bearer sk_test_abc123', $request['args']['headers']['Authorization'] );
		$this->assertSame( 'price_monthly_test', $request['args']['body']['line_items[0][price]'] );
		$this->assertSame( 'subscription', $request['args']['body']['mode'] );
		$this->assertSame( 'monthly', $request['args']['body']['metadata[interval]'] );
		$this->assertSame( $this->entitlements->get_site_identity(), $request['args']['body']['metadata[site_identity]'] );
	}

	public function test_uses_live_key_and_price_when_mode_is_live(): void {
		update_option( 'wp_sam_stripe_mode', 'live' );
		update_option( 'wp_sam_stripe_secret_key_live', 'sk_live_xyz789' );
		update_option( 'wp_sam_stripe_price_id_annual_live', 'price_annual_live' );
		$GLOBALS['_wp_remote_post_response'] = array(
			'response' => array( 'code' => 200 ),
			'body'     => wp_json_encode( array( 'url' => 'https://checkout.stripe.com/session_456' ) ),
		);

		$result = $this->service()->create_session( 'csp-automation-manager', 'https://example.com/ok', 'https://example.com/cancel', 'annual' );

		$this->assertIsArray( $result );

		$request = $GLOBALS['_wp_remote_post_requests'][0];
		$this->assertSame( 'Bearer sk_live_xyz789', $request['args']['headers']['Authorization'] );
		$this->assertSame( 'price_annual_live', $request['args']['body']['line_items[0][price]'] );
	}

	// ── Stripe error handling ────────────────────────────────────────────────

	public function test_returns_error_on_non_200_stripe_response(): void {
		update_option( 'wp_sam_stripe_mode', 'test' );
		update_option( 'wp_sam_stripe_secret_key_test', 'sk_test_abc' );
		update_option( 'wp_sam_stripe_price_id_monthly_test', 'price_monthly_test' );
		$GLOBALS['_wp_remote_post_response'] = array(
			'response' => array( 'code' => 402 ),
			'body'     => wp_json_encode( array( 'error' => array( 'message' => 'Your card was declined.' ) ) ),
		);

		$result = $this->service()->create_session( 'csp-automation-manager', 'https://example.com/ok', 'https://example.com/cancel' );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'checkout_failed', $result->get_error_code() );
		$this->assertSame( 'Your card was declined.', $result->get_error_message() );
	}

	public function test_returns_error_when_wp_remote_post_fails(): void {
		update_option( 'wp_sam_stripe_mode', 'test' );
		update_option( 'wp_sam_stripe_secret_key_test', 'sk_test_abc' );
		update_option( 'wp_sam_stripe_price_id_monthly_test', 'price_monthly_test' );
		$GLOBALS['_wp_remote_post_response'] = new WP_Error( 'http_request_failed', 'Connection timed out' );

		$result = $this->service()->create_session( 'csp-automation-manager', 'https://example.com/ok', 'https://example.com/cancel' );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'http_request_failed', $result->get_error_code() );
	}

	public function test_returns_error_when_response_missing_url(): void {
		update_option( 'wp_sam_stripe_mode', 'test' );
		update_option( 'wp_sam_stripe_secret_key_test', 'sk_test_abc' );
		update_option( 'wp_sam_stripe_price_id_monthly_test', 'price_monthly_test' );
		$GLOBALS['_wp_remote_post_response'] = array(
			'response' => array( 'code' => 200 ),
			'body'     => wp_json_encode( array( 'id' => 'cs_test_no_url' ) ),
		);

		$result = $this->service()->create_session( 'csp-automation-manager', 'https://example.com/ok', 'https://example.com/cancel' );

		$this->assertInstanceOf( WP_Error::class, $result );
		$this->assertSame( 'checkout_failed', $result->get_error_code() );
	}
}
