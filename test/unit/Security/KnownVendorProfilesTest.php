<?php
/**
 * Unit tests for WP_SAM\Security\Known_Vendor_Profiles.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Security\Known_Vendor_Profiles;

class KnownVendorProfilesTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	/** @return array<string, array{0: string, 1: ?string, 2: string, 3: ?string}> origin, url, type, expected key */
	public static function cases(): array {
		return array(
			'GTM'                           => array( 'https://www.googletagmanager.com', 'https://www.googletagmanager.com/gtm.js?id=GTM-ABC', 'script', 'google_tag_manager' ),
			'gtag.js'                       => array( 'https://www.googletagmanager.com', 'https://www.googletagmanager.com/gtag/js?id=G-1', 'script', 'google_tag_manager' ),
			'GTM without a URL'             => array( 'https://www.googletagmanager.com', null, 'script', 'google_tag_manager' ),
			'Google Analytics'              => array( 'https://www.google-analytics.com', 'https://www.google-analytics.com/analytics.js', 'script', 'google_analytics' ),
			'Google Analytics (ssl.)'       => array( 'https://ssl.google-analytics.com', 'https://ssl.google-analytics.com/ga.js', 'script', 'google_analytics' ),
			'HubSpot loader'                => array( 'https://js.hs-scripts.com', 'https://js.hs-scripts.com/123.js', 'script', 'hubspot' ),
			'HubSpot regional loader'       => array( 'https://js-eu1.hs-scripts.com', 'https://js-eu1.hs-scripts.com/123.js', 'script', 'hubspot' ),
			'HubSpot forms'                 => array( 'https://js.hsforms.net', 'https://js.hsforms.net/forms/embed/v2.js', 'script', 'hubspot' ),
			'HubSpot chat'                  => array( 'https://js.usemessages.com', 'https://js.usemessages.com/conversations-embed.js', 'script', 'hubspot' ),
			'Turnstile'                     => array( 'https://challenges.cloudflare.com', 'https://challenges.cloudflare.com/turnstile/v0/api.js', 'script', 'cloudflare_turnstile' ),
			'reCAPTCHA api.js'              => array( 'https://www.google.com', 'https://www.google.com/recaptcha/api.js?render=x', 'script', 'google_recaptcha' ),
			'reCAPTCHA release on gstatic'  => array( 'https://www.gstatic.com', 'https://www.gstatic.com/recaptcha/releases/abc/recaptcha__en.js', 'script', 'google_recaptcha' ),
			'reCAPTCHA via recaptcha.net'   => array( 'https://www.recaptcha.net', 'https://www.recaptcha.net/recaptcha/api.js', 'script', 'google_recaptcha' ),
			'www.google.com, not reCAPTCHA' => array( 'https://www.google.com', 'https://www.google.com/maps/api/js', 'script', null ),
			'gstatic, not reCAPTCHA'        => array( 'https://www.gstatic.com', 'https://www.gstatic.com/charts/loader.js', 'script', null ),
			'www.google.com, URL unknown'   => array( 'https://www.google.com', null, 'script', null ),
			'path prefix on another host'   => array( 'https://www.google.com', 'https://evil.example/recaptcha/api.js', 'script', null ),
			'look-alike domain'             => array( 'https://js.hs-scripts.com.evil.test', 'https://js.hs-scripts.com.evil.test/1.js', 'script', null ),
			'suffix without a dot boundary' => array( 'https://evilhs-scripts.com', 'https://evilhs-scripts.com/1.js', 'script', null ),
			'GTM as a stylesheet'           => array( 'https://www.googletagmanager.com', 'https://www.googletagmanager.com/x.css', 'style', null ),
			'unrelated CDN'                 => array( 'https://cdn.jsdelivr.net', 'https://cdn.jsdelivr.net/npm/x@1.0.0/x.js', 'script', null ),
		);
	}

	/** @dataProvider cases */
	public function test_match( string $origin, ?string $url, string $type, ?string $expected_key ): void {
		$profile = Known_Vendor_Profiles::match( $origin, $url, $type );

		$this->assertSame( $expected_key, null === $profile ? null : $profile['key'] );
	}

	public function test_every_profile_carries_a_plain_language_reason(): void {
		foreach ( Known_Vendor_Profiles::all() as $profile ) {
			$this->assertNotSame( '', trim( $profile['reason'] ), "{$profile['key']} has no reason." );
			$this->assertNotSame( '', trim( $profile['vendor'] ) );
		}
	}

	public function test_list_is_filterable_and_malformed_entries_are_dropped(): void {
		add_filter(
			Known_Vendor_Profiles::FILTER,
			static function ( array $profiles ): array {
				$profiles[] = array(
					'key'    => 'example_widget',
					'vendor' => 'Example Widget',
					'hosts'  => array( 'widget.example.com' ),
					'reason' => 'Rebuilt nightly.',
				);
				$profiles[] = array( 'key' => 'broken' );
				return $profiles;
			}
		);

		$keys = array_column( Known_Vendor_Profiles::all(), 'key' );
		$this->assertContains( 'example_widget', $keys );
		$this->assertNotContains( 'broken', $keys );

		$match = Known_Vendor_Profiles::match( 'https://widget.example.com', 'https://widget.example.com/w.js', 'script' );
		$this->assertSame( 'example_widget', $match['key'] ?? null );
	}
}
