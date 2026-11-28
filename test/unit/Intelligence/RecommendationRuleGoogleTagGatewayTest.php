<?php
/**
 * Unit tests for WP_SAM\Intelligence\Recommendation_Rule_Google_Tag_Gateway:
 * Site Kit by Google loading tags from www.googletagmanager.com rather than
 * through its Google tag gateway for advertisers.
 *
 * Site Kit's option names and shapes are the ones in Site Kit 1.192.0.
 */

declare( strict_types=1 );

use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use PHPUnit\Framework\TestCase;
use WP_SAM\CSP\Policy_Data_Loader;
use WP_SAM\Intelligence\Recommendation_Rule_Google_Tag_Gateway;

class RecommendationRuleGoogleTagGatewayTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	/** Site Kit defines this in its main plugin file. */
	private function site_kit_installed(): void {
		if ( ! defined( 'GOOGLESITEKIT_VERSION' ) ) {
			define( 'GOOGLESITEKIT_VERSION', '1.192.0' );
		}
	}

	/** @param array<int, array<string, string>> $frontend_sources */
	private function rule( array $frontend_sources = array() ): Recommendation_Rule_Google_Tag_Gateway {
		$loader = new class( $frontend_sources ) implements Policy_Data_Loader {
			public function __construct( private array $frontend_sources ) {}

			public function load_profile( string $surface ): ?array {
				return null;
			}

			public function load_approved_hashes( string $surface ): array {
				return array();
			}

			public function load_approved_sources( string $surface ): array {
				return 'frontend' === $surface ? $this->frontend_sources : array();
			}
		};

		return new Recommendation_Rule_Google_Tag_Gateway( $loader );
	}

	private function tag_manager_connected(): void {
		$this->site_kit_installed();
		$GLOBALS['_wp_options']['googlesitekit_active_modules']      = array( 'search-console', 'tagmanager' );
		$GLOBALS['_wp_options']['googlesitekit_tagmanager_settings'] = array(
			'containerID' => 'GTM-ABC1234',
			'useSnippet'  => true,
		);
	}

	private function gateway( ?bool $enabled, ?bool $healthy = null, ?bool $script_access = null ): void {
		$GLOBALS['_wp_options']['googlesitekit_google_tag_gateway'] = array(
			'isEnabled'             => $enabled,
			'isGTGHealthy'          => $healthy,
			'isScriptAccessEnabled' => $script_access,
		);
	}

	// ── When it fires ───────────────────────────────────────────────────────

	public function test_fires_when_tag_manager_is_connected_and_the_gateway_is_off(): void {
		$this->tag_manager_connected();

		$recs = $this->rule()->evaluate();

		$this->assertCount( 1, $recs );
		$this->assertSame( 'google_tag_gateway_off', $recs[0]['key'] );
		$this->assertStringContainsString( 'Tag Manager', $recs[0]['observed'] );
		$this->assertStringContainsString( 'www.googletagmanager.com', $recs[0]['observed'] );
		$this->assertStringContainsString( 'Settings → Connected Services', $recs[0]['recommended_action'] );
		$this->assertStringContainsString( 'Google tag gateway for advertisers', $recs[0]['recommended_action'] );
		$this->assertTrue( $recs[0]['dismissible'] );
		$this->assertFalse( $recs[0]['automation_eligible'] );
		$this->assertSame( 'frontend', $recs[0]['surface'] );
	}

	public function test_names_every_site_kit_service_that_places_a_tag(): void {
		$this->site_kit_installed();
		$GLOBALS['_wp_options']['googlesitekit_active_modules']       = array( 'tagmanager', 'analytics-4', 'ads' );
		$GLOBALS['_wp_options']['googlesitekit_tagmanager_settings']  = array( 'containerID' => 'GTM-ABC1234' );
		$GLOBALS['_wp_options']['googlesitekit_analytics-4_settings'] = array( 'measurementID' => 'G-ABC1234' );
		$GLOBALS['_wp_options']['googlesitekit_ads_settings']         = array( 'conversionID' => 'AW-1234567' );

		$recs = $this->rule()->evaluate();

		$this->assertStringContainsString( '(Tag Manager, Analytics, Ads)', $recs[0]['observed'] );
	}

	// ── When it stays quiet ─────────────────────────────────────────────────

	public function test_silent_when_the_gateway_is_in_use(): void {
		$this->tag_manager_connected();
		$this->gateway( true, true, true );

		$this->assertSame( array(), $this->rule()->evaluate() );
	}

	public function test_silent_when_no_tag_module_is_connected(): void {
		$this->site_kit_installed();
		$GLOBALS['_wp_options']['googlesitekit_active_modules'] = array( 'search-console', 'pagespeed-insights' );

		$this->assertSame( array(), $this->rule()->evaluate() );
	}

	public function test_silent_when_tag_manager_is_active_but_not_set_up(): void {
		$this->site_kit_installed();
		$GLOBALS['_wp_options']['googlesitekit_active_modules']      = array( 'tagmanager' );
		$GLOBALS['_wp_options']['googlesitekit_tagmanager_settings'] = array( 'containerID' => '' );

		$this->assertSame( array(), $this->rule()->evaluate() );
	}

	public function test_silent_when_site_kit_places_no_snippet(): void {
		$this->site_kit_installed();
		$GLOBALS['_wp_options']['googlesitekit_active_modules']      = array( 'tagmanager' );
		$GLOBALS['_wp_options']['googlesitekit_tagmanager_settings'] = array(
			'containerID' => 'GTM-ABC1234',
			'useSnippet'  => false,
		);

		$this->assertSame( array(), $this->rule()->evaluate() );
	}

	/**
	 * Its own process, without the parent's constants: once another test
	 * has defined GOOGLESITEKIT_VERSION it can't be undefined.
	 */
	#[RunInSeparateProcess]
	#[PreserveGlobalState( false )]
	public function test_silent_when_site_kit_is_not_installed(): void {
		// Leftover Site Kit options from a removed plugin, but no plugin.
		$GLOBALS['_wp_options']['googlesitekit_active_modules']      = array( 'tagmanager' );
		$GLOBALS['_wp_options']['googlesitekit_tagmanager_settings'] = array( 'containerID' => 'GTM-ABC1234' );

		$this->assertFalse( defined( 'GOOGLESITEKIT_VERSION' ) );
		$this->assertSame( array(), $this->rule()->evaluate() );
	}

	// ── Gateway switched on but not in use ──────────────────────────────────

	public function test_switched_on_but_script_blocked_points_at_server_requirements(): void {
		$this->tag_manager_connected();
		$this->gateway( true, true, false );

		$rec = $this->rule()->evaluate()[0];

		$this->assertSame( 'google_tag_gateway_script_blocked', $rec['key'] );
		$this->assertStringContainsString( 'gtg/measurement.php', $rec['recommended_action'] );
		$this->assertStringEndsWith( '#server-requirements', $rec['docs'][0]['url'] );
	}

	public function test_switched_on_but_service_unreachable(): void {
		$this->tag_manager_connected();
		$this->gateway( true, false, true );

		$rec = $this->rule()->evaluate()[0];

		$this->assertSame( 'google_tag_gateway_service_unreachable', $rec['key'] );
		$this->assertStringContainsString( 'outgoing HTTPS requests', $rec['recommended_action'] );
	}

	public function test_switched_on_but_not_yet_checked(): void {
		$this->tag_manager_connected();
		$this->gateway( true );

		$rec = $this->rule()->evaluate()[0];

		$this->assertSame( 'google_tag_gateway_unconfirmed', $rec['key'] );
		$this->assertStringContainsString( 'Site Health', $rec['recommended_action'] );
		$this->assertSame( 'not checked', $rec['evidence']['gateway_service_healthy'] );
	}

	// ── Policy context ──────────────────────────────────────────────────────

	public function test_low_risk_and_links_to_site_kit_when_the_host_is_not_allowed(): void {
		$this->tag_manager_connected();

		$rec = $this->rule()->evaluate()[0];

		$this->assertSame( 'low', $rec['risk'] );
		$this->assertStringContainsString( 'page=googlesitekit-settings', $rec['cta_url'] );
		$this->assertStringNotContainsString( 'allows scripts from that host', $rec['observed'] );
	}

	public function test_medium_risk_and_links_to_for_review_when_the_host_is_allowed(): void {
		$this->tag_manager_connected();

		$rec = $this->rule(
			array(
				array(
					'directive'     => 'script-src-elem',
					'source_host'   => 'www.googletagmanager.com',
					'source_scheme' => 'https',
				),
			)
		)->evaluate()[0];

		$this->assertSame( 'medium', $rec['risk'] );
		$this->assertStringContainsString( 'allows scripts from that host', $rec['observed'] );
		$this->assertStringContainsString( 'tab=sources&src_host=www.googletagmanager.com', $rec['cta_url'] );
		$this->assertStringContainsString( 'Decide → For Review', $rec['recommended_action'] );
	}

	public function test_an_image_only_approval_does_not_count_as_allowing_scripts(): void {
		$this->tag_manager_connected();

		$rec = $this->rule(
			array(
				array(
					'directive'     => 'img-src',
					'source_host'   => 'www.googletagmanager.com',
					'source_scheme' => 'https',
				),
			)
		)->evaluate()[0];

		$this->assertSame( 'low', $rec['risk'] );
	}

	// ── Shape ───────────────────────────────────────────────────────────────

	public function test_carries_every_field_the_engine_requires_and_official_docs(): void {
		$this->tag_manager_connected();

		$rec = $this->rule()->evaluate()[0];

		foreach ( array( 'key', 'layer', 'pillar', 'surface', 'observed', 'why_it_matters', 'confidence', 'risk', 'evidence', 'recommended_action', 'alternative_action', 'automation_eligible', 'rollback_position', 'evidence_changed_at', 'cta_url', 'dismissible' ) as $field ) {
			$this->assertArrayHasKey( $field, $rec );
		}
		$this->assertMatchesRegularExpression( '/^[a-z0-9_]+$/', $rec['key'] );
		$this->assertNotFalse( strtotime( $rec['evidence_changed_at'] ) );
		$this->assertCount( 3, $rec['docs'] );
		foreach ( $rec['docs'] as $doc ) {
			$this->assertMatchesRegularExpression( '#^https://(sitekit\.withgoogle\.com|developers\.google\.com)/#', $doc['url'] );
			$this->assertNotSame( '', $doc['label'] );
		}
	}
}
