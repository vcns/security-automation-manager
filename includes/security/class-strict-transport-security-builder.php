<?php
/**
 * Emits Strict-Transport-Security (HSTS) on enabled surfaces.
 *
 * Unlike the other simple pillars, a misconfigured HSTS header is sticky:
 * browsers cache max-age and refuse plain-HTTP connections for that long
 * regardless of what the header says afterward, and preload-listed domains
 * can take months to remove even after every other header is fixed. There
 * is also no report-only variant in the spec to rehearse a rollout with.
 * So this pillar, alone among the simple pillars, enforces two guardrails
 * the admin UI can't be trusted to skip: the header is only ever sent over
 * an HTTPS connection (sending it over HTTP is meaningless and would
 * misrepresent the site as HTTPS-only before it actually is), and the
 * preload directive is dropped unless the stored max-age/includeSubDomains
 * combination actually meets hstspreload.org's submission requirements.
 */

declare( strict_types=1 );

namespace WP_SAM\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Strict_Transport_Security_Builder extends Pillar_Header_Builder {

	public const PILLAR_KEY = 'strict-transport-security';

	public const MIN_MAX_AGE = 0;
	public const MAX_MAX_AGE = 63072000; // 2 years -- ceiling recommended by hstspreload.org.

	// Deliberately short: HSTS has no report-only mode to rehearse a rollout
	// with, so a new site should start with a max-age it can live down
	// quickly if something over HTTPS turns out to be broken, then ramp up.
	public const DEFAULT_MAX_AGE = 86400; // 1 day.

	// hstspreload.org's minimum max-age for preload list submission.
	public const PRELOAD_MIN_MAX_AGE = 31536000; // 1 year.

	public static function sanitize_max_age( mixed $value ): int {
		$value = (int) $value;
		return max( self::MIN_MAX_AGE, min( self::MAX_MAX_AGE, $value ) );
	}

	/**
	 * hstspreload.org requires max-age >= 1 year and includeSubDomains
	 * present on every response before a domain is eligible for submission.
	 */
	public static function preload_eligible( int $max_age, bool $include_subdomains ): bool {
		return $include_subdomains && $max_age >= self::PRELOAD_MIN_MAX_AGE;
	}

	protected function emit_profile_header( array $profile, string $surface ): bool {
		unset( $surface );

		if ( ! $this->is_https_request() ) {
			return false;
		}

		$value = self::build_header_value( $profile );
		if ( '' === $value ) {
			return false;
		}

		header( 'Strict-Transport-Security: ' . $value );
		return true;
	}

	protected function is_https_request(): bool {
		return is_ssl();
	}

	public static function build_header_value( array $profile ): string {
		$payload = json_decode( (string) ( $profile['payload'] ?? '' ), true );
		$payload = is_array( $payload ) ? $payload : array();

		$max_age            = self::sanitize_max_age( $payload['max_age'] ?? self::DEFAULT_MAX_AGE );
		$include_subdomains = ! empty( $payload['include_subdomains'] );
		$preload            = ! empty( $payload['preload'] ) && self::preload_eligible( $max_age, $include_subdomains );

		$parts = array( 'max-age=' . $max_age );
		if ( $include_subdomains ) {
			$parts[] = 'includeSubDomains';
		}
		if ( $preload ) {
			$parts[] = 'preload';
		}

		return implode( '; ', $parts );
	}

	/**
	 * @return array{max_age:int,include_subdomains:bool,preload:bool}
	 */
	public static function extract_settings( array $profile ): array {
		$payload = json_decode( (string) ( $profile['payload'] ?? '' ), true );
		$payload = is_array( $payload ) ? $payload : array();

		$max_age            = self::sanitize_max_age( $payload['max_age'] ?? self::DEFAULT_MAX_AGE );
		$include_subdomains = ! empty( $payload['include_subdomains'] );

		return array(
			'max_age'            => $max_age,
			'include_subdomains' => $include_subdomains,
			'preload'            => ! empty( $payload['preload'] ) && self::preload_eligible( $max_age, $include_subdomains ),
		);
	}
}
