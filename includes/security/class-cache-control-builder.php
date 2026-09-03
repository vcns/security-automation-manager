<?php
/**
 * Emits Cache-Control on enabled surfaces -- GitHub issue #221.
 *
 * A small, named-preset value model (matching Referrer_Policy_Builder's
 * enum shape) rather than a free-form directive builder: Cache-Control
 * directives interact (e.g. "public" and "private" are mutually
 * exclusive; "max-age" is meaningless alongside "no-store"), and a
 * preset can never express a self-contradictory combination the way a
 * per-directive checkbox matrix could. If real-world demand for finer
 * control ever appears, the payload shape (`{"value": "..."}`) already
 * supports adding more presets without a schema change.
 *
 * Unlike every other simple pillar, this one is NOT seeded enabled by
 * default (see Activator::seed_default_pillar_profiles()) -- Cache-
 * Control is a performance/behaviour decision, not a universal security
 * hardening default the way X-Content-Type-Options or X-Frame-Options
 * are. WordPress core already sends a safe, strict Cache-Control on
 * every surface that needs one (nocache_headers(), confirmed live:
 * `no-cache, must-revalidate, max-age=0, no-store, private` on wp-admin/
 * wp-login.php); shipping this pillar pre-enabled would risk silently
 * changing a site's frontend caching behaviour on upgrade, which is a
 * real functional-regression risk this plugin has otherwise never taken
 * for a "simple" pillar.
 *
 * is_profile_active() additionally consults Cache_Control_Conflict_
 * Detector -- a stored enabled=1 row is never enough on its own; a known
 * caching plugin or an acknowledged CDN always wins, per issue #221's
 * own explicit safety requirement to never emit a competing header.
 *
 * No header_remove() before emitting: this fires on the send_headers/
 * login_init hooks, which run after WP core's own early nocache_headers()
 * calls, and PHP's header() replaces a same-named header by default -- so
 * this plugin's own value already wins without needing to remove WP
 * core's first (confirmed live).
 */

declare( strict_types=1 );

namespace WP_SAM\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Cache_Control_Builder extends Pillar_Header_Builder {

	public const PILLAR_KEY = 'cache-control';

	/**
	 * @var array<string,string> preset key => actual Cache-Control value.
	 */
	public const PRESET_VALUES = array(
		'no-store'         => 'no-store, no-cache, must-revalidate',
		'private-no-cache' => 'private, no-cache, must-revalidate',
		'public-short'     => 'public, max-age=300',
		'public-long'      => 'public, max-age=3600',
	);

	public const DEFAULT_VALUE = 'no-store';

	public static function sanitize_value( mixed $value ): string {
		$value = strtolower( trim( (string) $value ) );
		return array_key_exists( $value, self::PRESET_VALUES ) ? $value : '';
	}

	protected function is_profile_active( array $profile ): bool {
		if ( ! parent::is_profile_active( $profile ) ) {
			return false;
		}
		return ! Cache_Control_Conflict_Detector::detect()['blocked'];
	}

	protected function emit_profile_header( array $profile, string $surface ): bool {
		unset( $surface );
		$preset = self::extract_value( $profile );
		if ( '' === $preset ) {
			return false;
		}

		header( 'Cache-Control: ' . self::PRESET_VALUES[ $preset ] );
		return true;
	}

	public static function extract_value( array $profile ): string {
		$payload = json_decode( (string) ( $profile['payload'] ?? '' ), true );
		$value   = is_array( $payload ) ? (string) ( $payload['value'] ?? '' ) : '';
		return self::sanitize_value( $value );
	}
}
