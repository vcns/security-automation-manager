<?php
/**
 * Thin static bridge so Policy_Builder can read the nonce without
 * requiring a direct reference to the Nonce_Manager singleton.
 */

declare( strict_types=1 );

namespace WP_SAM\CSP;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Plugin_Nonce_Manager {
	/**
	 * Returns the nonce of the plugin's own nonce manager, cached for the request.
	 *
	 * @return string The nonce, or an empty string when there is no nonce manager.
	 */
	public static function get_instance_nonce(): string {
		static $nonce = null;
		if ( null === $nonce ) {
			$plugin = \WP_SAM\Plugin::instance();
			$nonce  = isset( $plugin->nonce_manager ) ? $plugin->nonce_manager->get_nonce() : '';
		}
		return $nonce;
	}
}
