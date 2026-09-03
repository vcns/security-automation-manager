<?php
/**
 * Decides whether Cache_Control_Builder is safe to emit on this install --
 * GitHub issue #221's own explicit safety requirement: "if another caching
 * mechanism is detected, this section must be disabled/grayed out rather
 * than emit a competing Cache-Control header."
 *
 * Deliberately NOT built the same way Conflict_Detector (CSP) works --
 * that class's HEAD-probe/`.htaccess`-scan approach exists because a
 * competing CSP header is inherently unusual, so its mere presence is a
 * strong signal. Cache-Control is the opposite: WordPress core itself
 * sends one (`no-cache, must-revalidate, max-age=0, no-store, private`,
 * via `nocache_headers()`) on nearly every dynamic admin/login/preview
 * request, confirmed live against this plugin's own test site -- treating
 * "a Cache-Control header already exists" as a conflict would gray this
 * pillar out on every WordPress site unconditionally, which is useless.
 * `Cache_Control_Builder::emit_profile_header()` calls `header()` on the
 * `send_headers`/`login_init` hooks, which fire after WP core's own early
 * `nocache_headers()` calls -- PHP's `header()` replaces a same-named
 * header by default, so this plugin's own value correctly wins over WP
 * core's default without needing `header_remove()` first; that's simply
 * not a "competing mechanism" in the sense this detector cares about.
 *
 * Two things this detector CAN reliably check instead:
 *  - A known caching plugin is active (`known_plugins()` below) -- pure
 *    PHP introspection (`defined()`/`class_exists()`/`function_exists()`
 *    against each plugin's own stable bootstrap-time marker), no HTTP
 *    call needed, and unlike a CSP header a caching plugin managing its
 *    own Cache-Control output is genuinely common and worth respecting.
 *  - A CDN or edge cache in front of the site -- per the issue's own
 *    admission this "may need to be a manual acknowledgement rather than
 *    automatic detection" (a reverse proxy/CDN's caching behaviour isn't
 *    observable from inside a single PHP request on the origin server).
 *    Stored as a plain site-wide option, set by the admin on the
 *    Information/Session & Cache Control page -- never auto-detected.
 */

declare( strict_types=1 );

namespace WP_SAM\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Cache_Control_Conflict_Detector {

	public const CDN_ACKNOWLEDGED_OPTION = 'wp_sam_cache_control_cdn_acknowledged';

	/**
	 * Each entry's `check` reads a stable, early-defined marker from that
	 * plugin's own main bootstrap file -- a version constant or top-level
	 * class, not something conditionally loaded only on certain requests.
	 * Every signature below was confirmed live against that plugin's
	 * current WordPress.org SVN trunk (or, for WP Rocket, its official
	 * GitHub repository) on 2026-09-03, not guessed from a similar-
	 * looking name -- a wrong constant would make detection silently
	 * useless, exactly the failure mode issue #221 itself warns against.
	 * Add a new entry here, verified the same way, as the documented
	 * process for covering more plugins over time (#221's own acceptance
	 * criterion); each entry is independent, so a stale signature only
	 * affects its own row.
	 *
	 * @return array<int, array{label: string, check: callable(): bool}>
	 */
	public static function known_plugins(): array {
		return array(
			array(
				'label' => 'WP Rocket',
				'check' => static fn (): bool => defined( 'WP_ROCKET_VERSION' ),
			),
			array(
				'label' => 'W3 Total Cache',
				'check' => static fn (): bool => defined( 'W3TC_VERSION' ),
			),
			array(
				'label' => 'WP Super Cache',
				'check' => static fn (): bool => defined( 'WPSC_VERSION_ID' ),
			),
			array(
				'label' => 'LiteSpeed Cache',
				'check' => static fn (): bool => defined( 'LSCWP_V' ),
			),
			array(
				'label' => 'WP Fastest Cache',
				'check' => static fn (): bool => class_exists( 'WpFastestCache' ),
			),
			array(
				'label' => 'Cache Enabler',
				'check' => static fn (): bool => defined( 'CACHE_ENABLER_VERSION' ),
			),
			array(
				'label' => 'SiteGround Speed Optimizer',
				'check' => static fn (): bool => defined( 'SiteGround_Optimizer\VERSION' ),
			),
			array(
				'label' => 'WP-Optimize',
				'check' => static fn (): bool => defined( 'WPO_VERSION' ),
			),
			array(
				'label' => 'Breeze',
				'check' => static fn (): bool => defined( 'BREEZE_VERSION' ),
			),
		);
	}

	/**
	 * @return array{blocked: bool, reason: ?string, detail: ?string}
	 */
	public static function detect(): array {
		foreach ( self::known_plugins() as $plugin ) {
			if ( ( $plugin['check'] )() ) {
				return array(
					'blocked' => true,
					'reason'  => 'known_plugin',
					/* translators: %s: caching plugin name, e.g. "WP Rocket" */
					'detail'  => sprintf( __( '%s is active and already manages caching for this site.', 'vcns-security-automation-manager' ), $plugin['label'] ),
				);
			}
		}

		if ( ! empty( get_option( self::CDN_ACKNOWLEDGED_OPTION, false ) ) ) {
			return array(
				'blocked' => true,
				'reason'  => 'cdn_acknowledged',
				'detail'  => __( 'A CDN or edge cache has been acknowledged as managing caching for this site.', 'vcns-security-automation-manager' ),
			);
		}

		return array(
			'blocked' => false,
			'reason'  => null,
			'detail'  => null,
		);
	}
}
