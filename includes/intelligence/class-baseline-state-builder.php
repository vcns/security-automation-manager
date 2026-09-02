<?php
/**
 * Assembles a flat, diffable snapshot of this site's locally-known
 * security-relevant configuration state (Phase 3F, .roadmap/phase3_early_
 * plan.md §19 Baseline and Drift).
 *
 * Deliberately scoped to state this server already knows about itself --
 * effective CSP headers, simple pillar toggles, the external dependency
 * and internal-asset-integrity inventories, certificate expiry, and
 * WordPress/theme/plugin versions. Externally-observed state (what a
 * client actually receives, redirects, DNS records, cookies) is §20
 * External Verification, a later phase with its own infrastructure
 * decisions -- this class has no opinion on that and doesn't attempt it.
 *
 * The return shape is a flat list of rows (category, surface, item_key,
 * value) rather than a nested structure, so Drift_Scanner can diff two
 * snapshots by building a `category|surface|item_key` lookup map from
 * each and comparing, without category-specific diff logic.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

use WP_SAM\CSP\Policy_Builder;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Baseline_State_Builder {

	private Policy_Builder $policy_builder;

	public function __construct( Policy_Builder $policy_builder ) {
		$this->policy_builder = $policy_builder;
	}

	/** @return array<int, array{category:string, surface:string, item_key:string, value:string}> */
	public function build(): array {
		$rows = array();

		foreach ( $this->csp_headers() as $row ) {
			$rows[] = $row;
		}
		foreach ( $this->pillar_toggles() as $row ) {
			$rows[] = $row;
		}
		foreach ( $this->dependencies() as $row ) {
			$rows[] = $row;
		}
		foreach ( $this->internal_assets() as $row ) {
			$rows[] = $row;
		}
		foreach ( $this->certificates() as $row ) {
			$rows[] = $row;
		}
		foreach ( $this->wordpress_environment() as $row ) {
			$rows[] = $row;
		}

		return $rows;
	}

	/** Sha256 of the sorted, JSON-encoded state -- cheap equality check without decoding both sides. */
	public function hash( array $state ): string {
		$sorted = $state;
		usort(
			$sorted,
			static fn ( array $a, array $b ): int => strcmp(
				$a['category'] . '|' . $a['surface'] . '|' . $a['item_key'],
				$b['category'] . '|' . $b['surface'] . '|' . $b['item_key']
			)
		);
		return hash( 'sha256', (string) wp_json_encode( $sorted ) );
	}

	/** @return array<int, array{category:string, surface:string, item_key:string, value:string}> */
	private function csp_headers(): array {
		global $wpdb;
		$table = $wpdb->prefix . 'csp_policy_profiles';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$profiles = $wpdb->get_results( "SELECT * FROM {$table}", ARRAY_A );
		$profiles = ! empty( $profiles ) ? $profiles : array();

		$rows = array();
		foreach ( $profiles as $profile ) {
			$surface = (string) $profile['surface'];
			$header  = $this->normalise_nonce( $this->policy_builder->build_policy_string( $profile, $surface ) );
			$rows[]  = array(
				'category' => 'csp_header',
				'surface'  => $surface,
				'item_key' => $surface,
				'value'    => (string) $profile['mode'] . '|' . $header,
			);
		}
		return $rows;
	}

	/**
	 * build_policy_string() embeds Plugin_Nonce_Manager::get_instance_nonce()
	 * -- unique per PHP request/instance by design (that's what makes a CSP
	 * nonce meaningful as a security control). Comparing the raw header
	 * across two separate requests would therefore always show "drift" even
	 * when nothing about the actual policy changed, so the nonce token is
	 * replaced with a fixed placeholder before this value is ever stored or
	 * diffed -- Drift_Scanner only needs to know whether the *structural*
	 * policy (mode, sources, hashes, directives) changed.
	 */
	private function normalise_nonce( string $header ): string {
		$normalised = preg_replace( "/'nonce-[^']+'/", "'nonce-STABLE'", $header );
		return null !== $normalised ? $normalised : $header;
	}

	/** @return array<int, array{category:string, surface:string, item_key:string, value:string}> */
	private function pillar_toggles(): array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_pillar_profiles';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$pillars = $wpdb->get_results( "SELECT * FROM {$table}", ARRAY_A );
		$pillars = ! empty( $pillars ) ? $pillars : array();

		$rows = array();
		foreach ( $pillars as $pillar ) {
			$rows[] = array(
				'category' => 'pillar',
				'surface'  => (string) $pillar['surface'],
				'item_key' => (string) $pillar['pillar'],
				'value'    => ( (int) $pillar['enabled'] ? 'on' : 'off' ) . '|' . (string) $pillar['payload'],
			);
		}
		return $rows;
	}

	/** @return array<int, array{category:string, surface:string, item_key:string, value:string}> */
	private function dependencies(): array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_dependency_inventory';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$deps = $wpdb->get_results( "SELECT * FROM {$table}", ARRAY_A );
		$deps = ! empty( $deps ) ? $deps : array();

		$rows = array();
		foreach ( $deps as $dep ) {
			$rows[] = array(
				'category' => 'dependency',
				'surface'  => (string) $dep['surface'],
				'item_key' => (string) $dep['resource_type'] . ':' . (string) $dep['origin'],
				'value'    => (string) $dep['classification'],
			);
		}
		return $rows;
	}

	/** @return array<int, array{category:string, surface:string, item_key:string, value:string}> */
	private function internal_assets(): array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_internal_asset_inventory';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$assets = $wpdb->get_results( "SELECT * FROM {$table}", ARRAY_A );
		$assets = ! empty( $assets ) ? $assets : array();

		$rows = array();
		foreach ( $assets as $asset ) {
			$rows[] = array(
				'category' => 'internal_asset',
				'surface'  => (string) $asset['surface'],
				'item_key' => (string) $asset['path'],
				'value'    => (string) $asset['hash'],
			);
		}
		return $rows;
	}

	/** @return array<int, array{category:string, surface:string, item_key:string, value:string}> */
	private function certificates(): array {
		global $wpdb;
		$table = $wpdb->prefix . 'sam_certificates';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$certs = $wpdb->get_results(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT * FROM {$table} WHERE status = %s",
				'issued'
			),
			ARRAY_A
		);
		$certs = ! empty( $certs ) ? $certs : array();

		$rows = array();
		foreach ( $certs as $cert ) {
			$rows[] = array(
				'category' => 'certificate',
				'surface'  => '',
				'item_key' => (string) $cert['domains'],
				'value'    => 'expires:' . (string) $cert['not_after'],
			);
		}
		return $rows;
	}

	/** @return array<int, array{category:string, surface:string, item_key:string, value:string}> */
	private function wordpress_environment(): array {
		$rows   = array();
		$rows[] = array(
			'category' => 'core_version',
			'surface'  => '',
			'item_key' => 'core',
			'value'    => get_bloginfo( 'version' ),
		);

		$theme  = wp_get_theme();
		$rows[] = array(
			'category' => 'theme_version',
			'surface'  => '',
			'item_key' => $theme->get_stylesheet(),
			'value'    => (string) $theme->get( 'Version' ),
		);

		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$active_plugins = (array) get_option( 'active_plugins', array() );
		$all_plugins    = get_plugins();
		foreach ( $active_plugins as $plugin_file ) {
			if ( ! isset( $all_plugins[ $plugin_file ] ) ) {
				continue;
			}
			$rows[] = array(
				'category' => 'plugin_version',
				'surface'  => '',
				'item_key' => (string) $plugin_file,
				'value'    => (string) ( $all_plugins[ $plugin_file ]['Version'] ?? '' ),
			);
		}

		return $rows;
	}
}
