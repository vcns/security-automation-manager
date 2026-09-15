<?php
/**
 * GitHub-channel extension: registers the paid Fully Automatic automation
 * mode and its upsell presentation, entirely through generic hooks the
 * shared codebase exposes -- Plugin::bootstrap(), Admin_UI, and
 * page-csp-dashboard.php have no knowledge of this file, this class, the
 * string "fully_automatic", or any commercial-specific identifier or copy
 * anywhere in them. See Automation_Mode_Registry's own docblock for why
 * this is the real compliance boundary.
 *
 * This file is physically removed from the WordPress.org-channel build --
 * see .github/workflows/wporg-deploy.yml and release-package.yml -- so on
 * that channel none of the add_action() calls below ever run, "fully_
 * automatic" is never a registered mode, and none of this file's strings
 * (including this comment) ship in that package.
 *
 * This file no longer stores Stripe key material or calls the Stripe API
 * directly -- that path (Stripe secret/price/webhook settings, and the AJAX
 * checkout-session handler) was removed per docs/threat-model.md's "Stripe
 * secret storage" finding and docs/sam-portal-requirements-spec.md §21.2
 * ("WordPress direct-Stripe removal"), which requires any direct-Stripe
 * compatibility path in a commercial build to be migrated to
 * vcns/sam-licensing-service and removed. The one-time cleanup of any
 * previously-stored values (schema v46) lives right here, listening on
 * Activator's generic wp_sam_extension_migrations hook, rather than in
 * Activator itself -- a core migration referencing these exact option-name
 * strings would put them in a file every channel ships, defeating
 * .github/scripts/verify-wporg-package.sh's whole purpose. `fully_automatic`
 * is therefore unreachable in every build today -- Feature_Gate::
 * is_allowed() has no entitlement source to grant it (see commercial-
 * services.php's own docblock) -- until a sam-licensing-service-backed
 * entitlement source is built and wired the same way that file wires
 * today's dormant one.
 */

declare( strict_types=1 );

namespace WP_SAM\Extensions;

use WP_SAM\CSP\Automation_Mode_Registry;
use WP_SAM\Modules\Feature_Gate;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// define(), not const, guarded: this codebase's extension tests (see
// CommercialServicesSchemaTest.php) require() the same file more than once
// per process, since wp_test_reset_globals() clears registered hooks
// between tests -- a top-level const would fatal ("cannot redeclare") on
// the second require. A guarded define() is safe to re-run.
if ( ! defined( __NAMESPACE__ . '\\WP_SAM_FA_MODE_KEY' ) ) {
	define( __NAMESPACE__ . '\\WP_SAM_FA_MODE_KEY', 'fully_automatic' );
}

add_action(
	'wp_sam_register_automation_modes',
	static function ( Feature_Gate $gate ): void {
		Automation_Mode_Registry::register(
			WP_SAM_FA_MODE_KEY,
			__( 'Fully Automatic', 'vcns-security-automation-manager' ),
			array( 'low', 'medium', 'high' ),
			static fn(): bool => $gate->is_allowed( WP_SAM_FA_MODE_KEY )
		);
		Automation_Mode_Registry::register_legacy_alias( 'expert', WP_SAM_FA_MODE_KEY );
	}
);

// ── One-time cleanup: any previously-stored direct-Stripe values ───────────

add_action(
	'wp_sam_extension_migrations',
	static function (): void {
		foreach (
			array(
				'wp_sam_stripe_mode',
				'wp_sam_stripe_secret_key_test',
				'wp_sam_stripe_secret_key_live',
				'wp_sam_stripe_price_id_monthly_test',
				'wp_sam_stripe_price_id_annual_test',
				'wp_sam_stripe_price_id_monthly_live',
				'wp_sam_stripe_price_id_annual_live',
				'wp_sam_webhook_secret',
			) as $stale_option
		) {
			delete_option( $stale_option );
		}
	}
);

// ── Presentation: upgrade notice ─────────────────────────────────────────────

add_action(
	'wp_sam_automation_upgrade_notice',
	static function ( bool $has_unavailable_mode ): void {
		if ( ! $has_unavailable_mode || Automation_Mode_Registry::is_available( WP_SAM_FA_MODE_KEY ) ) {
			return;
		}
		?>
		<div id="wp-sam-upgrade" class="notice notice-info inline" style="padding:16px 20px;margin:1em 0;">
			<h3 style="margin-top:0;"><?php esc_html_e( 'Fully Automatic', 'vcns-security-automation-manager' ); ?></h3>
			<p><?php esc_html_e( 'Fully Automatic auto-applies low, medium, and high-risk proposals within the hard safety exclusions the deterministic engine already enforces -- zero manual review. Every other automation mode, and every other pillar, stays free.', 'vcns-security-automation-manager' ); ?></p>
			<p class="description"><?php esc_html_e( 'Upgrading is not available in this build of the plugin.', 'vcns-security-automation-manager' ); ?></p>
		</div>
		<?php
	}
);
