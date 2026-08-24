<?php
/**
 * GitHub-channel extension: wires up the legacy commercial entitlement,
 * checkout, and webhook services when their implementation is present (see
 * offline/modules/ -- gitignored, never committed to this repository,
 * present only on a private/commercial build of the plugin). The shared
 * plugin (class-plugin.php, class-activator.php) has no knowledge of
 * Entitlement_Store, Checkout_Service, or Webhook_Controller by name, and
 * creates neither of their database tables -- this file is the only place
 * in the tracked codebase that references any of them, and it is
 * physically absent from the WordPress.org build (see
 * .github/workflows/wporg-deploy.yml and release-package.yml).
 *
 * This wiring is independent of includes/extensions/fully-automatic-mode.php
 * (which registers the paid automation mode itself) -- this file owns the
 * underlying entitlement/checkout/webhook infrastructure that mode's
 * availability check depends on, and that other future paid features could
 * reuse the same way.
 */

declare( strict_types=1 );

namespace WP_SAM\Extensions;

use WP_SAM\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

add_action(
	'wp_sam_register_commercial_services',
	static function ( Plugin $plugin ): void {
		if ( class_exists( \WP_SAM\Modules\Entitlement_Store::class ) ) {
			$plugin->entitlements = new \WP_SAM\Modules\Entitlement_Store( $plugin->audit );
		}
		if ( class_exists( \WP_SAM\Modules\Checkout_Service::class ) && null !== $plugin->entitlements ) {
			$plugin->checkout = new \WP_SAM\Modules\Checkout_Service( $plugin->entitlements );
		}
	}
);

add_action(
	'wp_sam_register_commercial_routes',
	static function ( Plugin $plugin ): void {
		if ( class_exists( \WP_SAM\Modules\Webhook_Controller::class ) && null !== $plugin->entitlements && null !== $plugin->checkout ) {
			( new \WP_SAM\Modules\Webhook_Controller( $plugin->entitlements, $plugin->audit, $plugin->checkout ) )->register_routes();
		}
	}
);

/**
 * Legacy per-site entitlement compatibility record, and the external event
 * idempotency log that guards it -- owned entirely by this extension now.
 * Fired from Activator::create_tables(), after it has already required
 * wp-admin/includes/upgrade.php (dbDelta's own definition) and resolved
 * $wpdb/$cc/$p, passed through unchanged so this uses the exact same
 * values the rest of that method's dbDelta() calls do.
 *
 * dbDelta() is additive/idempotent by design -- it only creates or extends
 * a table to match the given CREATE TABLE statement, and never drops a
 * table or column. On the WordPress.org channel, where this file never
 * loads, this action has no listener at all, so neither table is ever
 * created there. On an existing GitHub-channel install that already has
 * these tables (with real data), this is a no-op beyond ensuring their
 * columns match -- nothing here can lose or downgrade existing rows.
 */
add_action(
	'wp_sam_register_schema',
	static function ( \wpdb $wpdb, string $cc, string $p ): void {
		// Pre-v9 legacy rename, for these two tables specifically -- see
		// Activator::rename_table_if_needed()'s own docblock. Must run
		// before the dbDelta() calls below, same ordering
		// Activator::migrate_v9_table_renames() already uses for every
		// other table: rename first (preserving existing data under the
		// new name), then ensure columns match.
		\WP_SAM\Activator::rename_table_if_needed( 'csp_entitlements', 'sam_entitlements' );
		\WP_SAM\Activator::rename_table_if_needed( 'csp_processed_events', 'sam_processed_events' );

		dbDelta(
			"CREATE TABLE {$p}sam_entitlements (
  id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  site_identity varchar(255) NOT NULL,
  product_key varchar(64) NOT NULL,
  tier varchar(32) NOT NULL DEFAULT 'free',
  status varchar(16) NOT NULL DEFAULT 'active',
  stripe_customer_id varchar(64) DEFAULT NULL,
  stripe_session_id varchar(255) DEFAULT NULL,
  stripe_payment_intent_id varchar(255) DEFAULT NULL,
  config_version varchar(32) DEFAULT NULL,
  granted_at datetime NOT NULL,
  expires_at datetime DEFAULT NULL,
  revoked_at datetime DEFAULT NULL,
  revocation_reason varchar(255) DEFAULT NULL,
  grace_until datetime DEFAULT NULL,
  last_validated_at datetime DEFAULT NULL,
  created_at datetime NOT NULL,
  updated_at datetime NOT NULL,
  PRIMARY KEY  (id),
  KEY site_identity (site_identity(191)),
  KEY product_key (product_key),
  KEY status (status),
  UNIQUE KEY session_id (stripe_session_id)
) {$cc};"
		);

		dbDelta(
			"CREATE TABLE {$p}sam_processed_events (
  id bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
  stripe_event_id varchar(255) NOT NULL,
  stripe_session_id varchar(255) DEFAULT NULL,
  event_type varchar(128) NOT NULL,
  processed_at datetime NOT NULL,
  outcome varchar(16) NOT NULL,
  detail varchar(512) DEFAULT NULL,
  PRIMARY KEY  (id),
  UNIQUE KEY stripe_event_id (stripe_event_id),
  KEY stripe_session_id (stripe_session_id)
) {$cc};"
		);
	},
	10,
	3
);

add_filter(
	'wp_sam_table_suffixes',
	static function ( array $suffixes ): array {
		return array_merge( $suffixes, array( 'sam_entitlements', 'sam_processed_events' ) );
	}
);
