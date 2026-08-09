<?php
/**
 * Shared storage layer for header pillars simple enough to live in
 * sam_pillar_profiles rather than CSP's directive/override/strict-dynamic
 * schema (X-Frame-Options, X-Content-Type-Options, Referrer-Policy).
 */

declare( strict_types=1 );

namespace WP_SAM\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

abstract class Pillar_Header_Builder extends Header_Builder {

	/**
	 * Every concrete subclass must declare:
	 *   public const PILLAR_KEY = '...'; // storage key in sam_pillar_profiles.pillar
	 */

	protected function load_profile( string $surface ): ?array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_pillar_profiles';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE pillar = %s AND surface = %s LIMIT 1", static::PILLAR_KEY, $surface ), ARRAY_A );
		return ! empty( $row ) ? $row : null;
	}

	protected function is_profile_active( array $profile ): bool {
		return ! empty( $profile['enabled'] );
	}
}
