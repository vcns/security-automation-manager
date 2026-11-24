<?php
/**
 * The one data-retention setting, wp_sam_violation_retention_days.
 *
 * Despite its name it covers every log-like table that records visitors:
 * CSP and header violation reports, Continuous Intelligence events and
 * identities, network-rule block records, and the ASN and Geo-IP lookup
 * caches. Scheduler deletes rows
 * older than this every day. 0 keeps everything.
 *
 * The setting is registered in wp_sam_settings_group, whose form posts to
 * options.php. options.php writes every option in the group, using null for
 * any the form doesn't include, so sanitize() keeps the stored value when
 * none is posted instead of turning null into 0. Until 2.16.0 no form had
 * this field, so each save of Control -> Automation Settings did exactly
 * that and silently switched every purge off; see
 * Activator::migrate_repair_zeroed_retention().
 */

declare( strict_types=1 );

namespace WP_SAM;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Data_Retention {

	public const OPTION = 'wp_sam_violation_retention_days';

	public const DEFAULT_DAYS = 90;

	/** Ten years: anything longer is "keep everything" in practice; use 0 for that. */
	public const MAX_DAYS = 3650;

	/** Days to keep records; 0 means keep everything. */
	public static function days(): int {
		return max( 0, (int) get_option( self::OPTION, self::DEFAULT_DAYS ) );
	}

	/**
	 * Settings API sanitize callback.
	 *
	 * @param mixed $value Posted value; null when the submitted form has no field for it.
	 * @return int Days, 0 to self::MAX_DAYS.
	 */
	public static function sanitize( mixed $value ): int {
		if ( null === $value || '' === $value || is_array( $value ) ) {
			return self::days();
		}

		return min( self::MAX_DAYS, absint( $value ) );
	}
}
