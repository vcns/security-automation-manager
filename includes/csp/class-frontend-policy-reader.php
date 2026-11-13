<?php
/**
 * Reads the frontend Content Security Policy as it stands right now: the
 * surface's mode, the header name it is sent under, and the policy text
 * Policy_Builder would emit on the next uncached page.
 *
 * Shared by Page_Cache_Purger (has the policy changed?) and
 * Delivered_Policy_Check (is that what visitors receive?). Only the
 * frontend surface matters to either: page caches and CDNs store public
 * pages, never wp-admin or the login page.
 */

declare( strict_types=1 );

namespace WP_SAM\CSP;

use WP_SAM\Modules\Feature_Gate;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Frontend_Policy_Reader {

	public const SURFACE = 'frontend';

	private Policy_Data_Loader $loader;

	private ?Policy_Builder $builder;

	/**
	 * @param Policy_Data_Loader|null $loader  Profile loader; the real wpdb-backed one by default.
	 * @param Policy_Builder|null     $builder Policy builder; built on first use by default.
	 */
	public function __construct( ?Policy_Data_Loader $loader = null, ?Policy_Builder $builder = null ) {
		$this->loader  = $loader ?? new Wpdb_Policy_Data_Loader();
		$this->builder = $builder;
	}

	/**
	 * The frontend's current mode, header name (lower-case) and policy
	 * text. Header and policy are empty strings while the surface is
	 * disabled.
	 *
	 * @return array{mode: string, header: string, policy: string}|null Null before the frontend profile exists.
	 */
	public function read(): ?array {
		$profile = $this->loader->load_profile( self::SURFACE );
		if ( null === $profile || ! isset( $profile['mode'], $profile['directives'] ) ) {
			return null;
		}

		$mode = (string) $profile['mode'];
		if ( 'disabled' === $mode ) {
			return array(
				'mode'   => $mode,
				'header' => '',
				'policy' => '',
			);
		}

		$this->builder ??= $this->default_builder();

		return array(
			'mode'   => $mode,
			'header' => strtolower( $this->builder->get_policy_header_name( 'report-only' === $mode ) ),
			'policy' => $this->builder->build_policy_string( $profile, self::SURFACE ),
		);
	}

	/**
	 * The plugin's own builder, so the policy read here is built with the
	 * same feature gate (and so the same entitlement-dependent directives,
	 * such as 'strict-dynamic') as the policy pages are sent with.
	 */
	private function default_builder(): Policy_Builder {
		$plugin = \WP_SAM\Plugin::instance();
		if ( isset( $plugin->policy_builder ) ) {
			return $plugin->policy_builder;
		}

		return new Policy_Builder( isset( $plugin->gate ) ? $plugin->gate : new Feature_Gate(), $this->loader );
	}
}
