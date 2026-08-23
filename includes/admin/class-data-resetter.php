<?php
/**
 * Destructive administrative reset for plugin-owned runtime data.
 */

declare( strict_types=1 );

namespace WP_SAM\Admin;

use WP_SAM\Activator;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Data_Resetter {

	public function reset(): array {
		global $wpdb;

		$result = array(
			'tables_cleared'     => array(),
			'tables_missing'     => array(),
			'tables_failed'      => array(),
			'options_deleted'    => Activator::get_all_option_names(),
			'transients_deleted' => Activator::get_transient_names(),
		);

		foreach ( Activator::get_all_table_suffixes() as $suffix ) {
			$table = $wpdb->prefix . $suffix;

			if ( ! $this->table_exists( $table ) ) {
				$result['tables_missing'][] = $table;
				continue;
			}

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$deleted = $wpdb->query( "DELETE FROM {$table}" );
			if ( false === $deleted ) {
				$result['tables_failed'][] = $table;
				continue;
			}

			$result['tables_cleared'][ $table ] = (int) $deleted;
		}

		foreach ( Activator::get_all_option_names() as $option ) {
			delete_option( $option );
		}

		foreach ( Activator::get_transient_names() as $transient ) {
			delete_transient( $transient );
		}

		if ( function_exists( 'wp_clear_scheduled_hook' ) ) {
			wp_clear_scheduled_hook( 'wp_sam_daily_scan' );
		} elseif ( function_exists( 'wp_unschedule_hook' ) ) {
			wp_unschedule_hook( 'wp_sam_daily_scan' );
		}

		Activator::activate();
		$this->disable_policy_profiles();

		return $result;
	}

	private function table_exists( string $table ): bool {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		return $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) ) === $table;
	}

	private function disable_policy_profiles(): void {
		global $wpdb;

		$table = $wpdb->prefix . 'csp_policy_profiles';
		if ( ! $this->table_exists( $table ) ) {
			return;
		}

		$updated_at = current_time( 'mysql', true );
		foreach ( array( 'frontend', 'admin', 'login', 'api' ) as $surface ) {
			$wpdb->update(
				$table,
				array(
					'mode'       => 'disabled',
					'updated_at' => $updated_at,
				),
				array( 'surface' => $surface ),
				array( '%s', '%s' ),
				array( '%s' )
			);
		}
	}
}
