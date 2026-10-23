<?php
/**
 * Emits X-Content-Type-Options: nosniff on enabled surfaces.
 *
 * No configurable value -- nosniff is the only defined value for this
 * header, so a surface is either on (nosniff) or off (no header).
 */

declare( strict_types=1 );

namespace WP_SAM\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class X_Content_Type_Options_Builder extends Pillar_Header_Builder {

	public const PILLAR_KEY = 'x-content-type-options';

	/**
	 * Sends X-Content-Type-Options: nosniff.
	 *
	 * @param array  $profile Pillar profile row, unused.
	 * @param string $surface Surface slug, unused.
	 * @return bool Always true.
	 */
	protected function emit_profile_header( array $profile, string $surface ): bool {
		unset( $profile, $surface );
		header( 'X-Content-Type-Options: nosniff' );
		return true;
	}
}
