<?php
/**
 * Recommendation rule: Site Kit by Google loads Google tags (Tag Manager,
 * Analytics, Ads) straight from www.googletagmanager.com instead of through
 * its Google tag gateway for advertisers.
 *
 * Why it matters for a Content Security Policy: to let those tags run under
 * an enforced frontend policy, the policy has to allow scripts from
 * www.googletagmanager.com. Anyone can publish a Tag Manager container, and
 * every container is served from that one host, so allowing it also lets an
 * injected script tag load a container someone else controls -- and a
 * container can run any script (Custom HTML tags). One HTML-injection bug
 * then gets script execution in spite of the policy.
 *
 * With the gateway on, Site Kit serves the same tags from this site
 * (wp-content/plugins/google-site-kit/gtg/measurement.php) and enqueues
 * them through WordPress, so they carry SAM's nonce, and Tag Manager passes
 * the nonce on to the scripts it adds (Google's CSP guide:
 * developers.google.com/tag-platform/security/guides/csp). The policy no
 * longer has to allow www.googletagmanager.com for them.
 *
 * Everything is read from Site Kit's own options, checked against Site Kit
 * 1.192.0: googlesitekit_active_modules, each tag module's settings, and
 * googlesitekit_google_tag_gateway {isEnabled, isGTGHealthy,
 * isScriptAccessEnabled}. Site Kit only uses the gateway when all three are
 * true (Google_Tag_Gateway_Settings::is_google_tag_gateway_active()), so
 * "switched on" and "in use" are reported separately.
 *
 * Dismissible: a site can have a reason not to use the gateway. The key
 * carries the gateway's state, so a dismissal lasts until that state changes
 * (for example from off to switched on but blocked by the server) -- Site
 * Kit records no timestamp SAM could compare instead.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

use WP_SAM\CSP\Policy_Data_Loader;
use WP_SAM\CSP\Wpdb_Policy_Data_Loader;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Recommendation_Rule_Google_Tag_Gateway implements Recommendation_Rule {

	public const KEY_PREFIX = 'google_tag_gateway_';

	public const GTM_HOST = 'www.googletagmanager.com';

	public const STATE_OFF = 'off';

	public const STATE_SCRIPT_BLOCKED = 'script_blocked';

	public const STATE_SERVICE_UNREACHABLE = 'service_unreachable';

	public const STATE_UNCONFIRMED = 'unconfirmed';

	public const SITE_KIT_DOCS_URL = 'https://sitekit.withgoogle.com/documentation/features/google-tag-gateway-for-advertisers/';

	public const GOOGLE_SETUP_DOCS_URL = 'https://developers.google.com/tag-platform/tag-manager/gateway/setup-guide';

	public const GOOGLE_CSP_DOCS_URL = 'https://developers.google.com/tag-platform/security/guides/csp';

	/**
	 * Nothing in Site Kit's options says when the gateway state last
	 * changed, so dismissal currency comes from the state in the key
	 * instead (see the class docblock); this fixed value is always older
	 * than any dismissal.
	 */
	private const EVIDENCE_CHANGED_AT = '2000-01-01 00:00:00';

	private Policy_Data_Loader $data_loader;

	public function __construct( ?Policy_Data_Loader $data_loader = null ) {
		$this->data_loader = $data_loader ?? new Wpdb_Policy_Data_Loader();
	}

	public function id(): string {
		return 'google_tag_gateway';
	}

	/** @return array<int, array<string, mixed>> */
	public function evaluate(): array {
		if ( ! defined( 'GOOGLESITEKIT_VERSION' ) ) {
			return array();
		}

		$tags = self::site_kit_tags();
		if ( empty( $tags ) ) {
			return array();
		}

		$state = self::gateway_state();
		if ( null === $state ) {
			return array();
		}

		$host_allowed = $this->gtm_host_allowed();
		$tag_list     = implode( ', ', $tags );

		$observed = sprintf(
			/* translators: %s: the Site Kit services placing tags, e.g. "Tag Manager, Analytics" */
			__( 'Site Kit loads your Google tags (%s) from www.googletagmanager.com, not through its Google tag gateway.', 'vcns-security-automation-manager' ),
			$tag_list
		);
		if ( $host_allowed ) {
			$observed .= ' ' . __( 'Your frontend policy allows scripts from that host.', 'vcns-security-automation-manager' );
		}

		$after = $host_allowed
			? __( 'Once Site Kit shows the gateway as enabled (Tools → Site Health → Info → Site Kit by Google), revert the approval for www.googletagmanager.com under Decide → For Review, unless something else on the site still loads scripts from it.', 'vcns-security-automation-manager' )
			: __( "Once Site Kit shows the gateway as enabled (Tools → Site Health → Info → Site Kit by Google), there's no need to approve www.googletagmanager.com for these tags.", 'vcns-security-automation-manager' );

		$recommended = $this->recommended_action( $state ) . ' ' . $after;

		$docs = array(
			array(
				'label' => __( 'Site Kit: Google tag gateway for advertisers', 'vcns-security-automation-manager' ),
				'url'   => self::STATE_SCRIPT_BLOCKED === $state || self::STATE_SERVICE_UNREACHABLE === $state
					? self::SITE_KIT_DOCS_URL . '#server-requirements'
					: self::SITE_KIT_DOCS_URL,
			),
			array(
				'label' => __( 'Google: set up Google tag gateway, including on a CDN', 'vcns-security-automation-manager' ),
				'url'   => self::GOOGLE_SETUP_DOCS_URL,
			),
			array(
				'label' => __( 'Google: Content Security Policy for Google tags', 'vcns-security-automation-manager' ),
				'url'   => self::GOOGLE_CSP_DOCS_URL,
			),
		);

		$gateway = self::gateway_settings();

		return array(
			array(
				'key'                 => self::KEY_PREFIX . $state,
				'layer'               => __( 'Layer 4: Browser Security Policies', 'vcns-security-automation-manager' ),
				'pillar'              => __( 'Content Security Policy', 'vcns-security-automation-manager' ),
				'surface'             => 'frontend',
				'observed'            => $observed,
				'why_it_matters'      => __( "To let these tags run under an enforced policy, the frontend policy has to allow scripts from www.googletagmanager.com. Anyone can publish a Tag Manager container, and every container is served from that host, so allowing it also lets an injected script tag load a container someone else controls, which can run any script. With Site Kit's Google tag gateway for advertisers, Site Kit serves your own tags from this site, carrying SAM's nonce, so the policy doesn't need to allow that host for them.", 'vcns-security-automation-manager' ),
				'confidence'          => 'high',
				'risk'                => $host_allowed ? 'medium' : 'low',
				'evidence'            => array(
					'site_kit_version'        => (string) GOOGLESITEKIT_VERSION,
					'site_kit_tags'           => $tag_list,
					'gateway_state'           => $state,
					'gateway_enabled'         => self::flag_text( $gateway['isEnabled'] ?? null ),
					'gateway_service_healthy' => self::flag_text( $gateway['isGTGHealthy'] ?? null ),
					'gateway_script_access'   => self::flag_text( $gateway['isScriptAccessEnabled'] ?? null ),
					'frontend_allows_host'    => $host_allowed ? self::GTM_HOST : 'no',
				),
				'recommended_action'  => $recommended,
				'alternative_action'  => __( 'If the site is behind a CDN such as Cloudflare, you can run the gateway there instead: in Google Tag Manager or your Google tag, go to Admin → Google tag gateway. Google\'s setup guide covers Cloudflare and other CDNs.', 'vcns-security-automation-manager' ),
				'automation_eligible' => false,
				'rollback_position'   => __( 'Turning the gateway off in Site Kit puts the tags back on www.googletagmanager.com; approve that host again under Decide → For Review if you reverted it.', 'vcns-security-automation-manager' ),
				'evidence_changed_at' => self::EVIDENCE_CHANGED_AT,
				'cta_url'             => $host_allowed
					? admin_url( 'admin.php?page=security-automation-manager-dashboard&tab=sources&src_host=' . self::GTM_HOST )
					: admin_url( 'admin.php?page=googlesitekit-settings#/connected-services' ),
				'docs'                => $docs,
				'dismissible'         => true,
			),
		);
	}

	/**
	 * The Site Kit services that place a tag on the frontend, by the names
	 * Site Kit's own screens use. Mirrors each module's is_connected() and
	 * useSnippet check.
	 *
	 * @return array<int, string>
	 */
	public static function site_kit_tags(): array {
		$active = get_option( 'googlesitekit_active_modules', array() );
		$active = is_array( $active ) ? $active : array();
		$tags   = array();

		if ( in_array( 'tagmanager', $active, true ) ) {
			$settings = self::option_array( 'googlesitekit_tagmanager_settings' );
			if ( self::filled( $settings, 'containerID' ) && self::snippet_on( $settings ) ) {
				$tags[] = __( 'Tag Manager', 'vcns-security-automation-manager' );
			}
		}

		if ( in_array( 'analytics-4', $active, true ) ) {
			$settings = self::option_array( 'googlesitekit_analytics-4_settings' );
			if ( ( self::filled( $settings, 'measurementID' ) || self::filled( $settings, 'googleTagID' ) ) && self::snippet_on( $settings ) ) {
				$tags[] = __( 'Analytics', 'vcns-security-automation-manager' );
			}
		}

		if ( in_array( 'ads', $active, true ) ) {
			$settings = self::option_array( 'googlesitekit_ads_settings' );
			if ( self::filled( $settings, 'conversionID' ) || self::filled( $settings, 'paxConversionID' ) ) {
				$tags[] = __( 'Ads', 'vcns-security-automation-manager' );
			}
		}

		return $tags;
	}

	/**
	 * Null when Site Kit is using the gateway; otherwise why it isn't.
	 */
	public static function gateway_state(): ?string {
		$gateway = self::gateway_settings();

		if ( empty( $gateway['isEnabled'] ) ) {
			return self::STATE_OFF;
		}

		$script_access = $gateway['isScriptAccessEnabled'] ?? null;
		$healthy       = $gateway['isGTGHealthy'] ?? null;

		if ( false === $script_access ) {
			return self::STATE_SCRIPT_BLOCKED;
		}
		if ( false === $healthy ) {
			return self::STATE_SERVICE_UNREACHABLE;
		}
		if ( true === $script_access && true === $healthy ) {
			return null;
		}

		return self::STATE_UNCONFIRMED;
	}

	private function recommended_action( string $state ): string {
		switch ( $state ) {
			case self::STATE_SCRIPT_BLOCKED:
				return __( "Site Kit's gateway is switched on, but its health check couldn't open Site Kit's gtg/measurement.php file on this site, so Site Kit isn't using it. Ask your hosting provider to allow public access to wp-content/plugins/google-site-kit/gtg/measurement.php (Site Kit's documentation lists the server requirements), or run the gateway on your CDN instead.", 'vcns-security-automation-manager' );
			case self::STATE_SERVICE_UNREACHABLE:
				return __( "Site Kit's gateway is switched on, but its health check couldn't reach Google's gateway service from this server, so Site Kit isn't using it. Ask your hosting provider to allow outgoing HTTPS requests from the site (Site Kit's documentation lists the server requirements), or run the gateway on your CDN instead.", 'vcns-security-automation-manager' );
			case self::STATE_UNCONFIRMED:
				return __( "Site Kit's gateway is switched on, but Site Kit hasn't confirmed it works yet, so it isn't using it. Check Tools → Site Health → Info → Site Kit by Google: Service healthy and Script accessible both need to say Yes.", 'vcns-security-automation-manager' );
			default:
				return __( 'In Site Kit, go to Settings → Connected Services, select Edit on Tag Manager, Analytics or Ads, and turn on Google tag gateway for advertisers. Turning it on for one turns it on for all of them.', 'vcns-security-automation-manager' );
		}
	}

	/** Whether the frontend's approved CSP sources allow scripts from Tag Manager's host. */
	private function gtm_host_allowed(): bool {
		foreach ( $this->data_loader->load_approved_sources( 'frontend' ) as $source ) {
			$directive = (string) ( $source['directive'] ?? '' );
			$host      = strtolower( (string) ( $source['source_host'] ?? '' ) );
			if ( in_array( $directive, array( 'script-src', 'script-src-elem' ), true )
				&& in_array( $host, array( self::GTM_HOST, '*.googletagmanager.com' ), true )
			) {
				return true;
			}
		}

		return false;
	}

	/** @return array<string, mixed> */
	private static function gateway_settings(): array {
		return self::option_array( 'googlesitekit_google_tag_gateway' );
	}

	/** @return array<string, mixed> */
	private static function option_array( string $name ): array {
		$value = get_option( $name, array() );
		return is_array( $value ) ? $value : array();
	}

	private static function filled( array $settings, string $field ): bool {
		return '' !== trim( (string) ( $settings[ $field ] ?? '' ) );
	}

	/** Site Kit's own default for useSnippet is true. */
	private static function snippet_on( array $settings ): bool {
		return (bool) ( $settings['useSnippet'] ?? true );
	}

	private static function flag_text( mixed $value ): string {
		if ( true === $value ) {
			return 'yes';
		}
		if ( false === $value ) {
			return 'no';
		}
		return 'not checked';
	}
}
