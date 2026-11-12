<?php
/**
 * The country this website operates in, chosen by an administrator on
 * Control → Traffic Controls → Network Intelligence → Geo-IP.
 *
 * Used only to decide which sanctions groups the Country Block List's
 * "Select by group" offers (Country_Groups::by_category()): a site in France
 * is offered the UN and EU lists, one in Jersey the UN and UK lists. It
 * never blocks, allows or ticks anything itself.
 *
 * Empty means "not chosen", and every sanctions list is offered. That is
 * also the honest default: sanctions follow people and companies as well as
 * places (a US company's site hosted in Ireland is bound by both), so a
 * single country can only ever narrow the choice, never settle it.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Site_Country {

	public const OPTION = 'wp_sam_site_country';

	/** The saved ISO 3166-1 alpha-2 code, or '' when none has been chosen (or the saved value isn't a known country). */
	public static function get(): string {
		$saved = get_option( self::OPTION, '' );
		if ( ! is_string( $saved ) || ! array_key_exists( $saved, Iso_Countries::all() ) ) {
			return '';
		}
		return $saved;
	}

	/**
	 * Saves $code, or clears the choice when it is ''. Anything that isn't a
	 * code from Iso_Countries::all() is refused and nothing changes.
	 *
	 * @return bool Whether $code was accepted.
	 */
	public static function save( string $code ): bool {
		$code = strtoupper( trim( $code ) );
		if ( '' === $code ) {
			delete_option( self::OPTION );
			return true;
		}
		if ( ! array_key_exists( $code, Iso_Countries::all() ) ) {
			return false;
		}
		update_option( self::OPTION, $code );
		return true;
	}
}
