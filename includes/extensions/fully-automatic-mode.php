<?php
/**
 * GitHub-channel extension: registers the paid Fully Automatic automation
 * mode, and everything specific to it (its settings, its checkout AJAX
 * handler, its upsell presentation), entirely through generic hooks the
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
 */

declare( strict_types=1 );

namespace WP_SAM\Extensions;

use WP_SAM\CSP\Automation_Config;
use WP_SAM\CSP\Automation_Mode_Registry;
use WP_SAM\Modules\Feature_Gate;
use WP_SAM\Plugin;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

const WP_SAM_FA_MODE_KEY = 'fully_automatic';

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

// ── Settings: this mode's own checkout configuration ────────────────────────

add_action(
	'admin_init',
	static function (): void {
		$settings = array(
			'wp_sam_stripe_mode'                  => static fn( mixed $mode ): string => 'live' === $mode ? 'live' : 'test',
			'wp_sam_stripe_secret_key_test'       => 'sanitize_text_field',
			'wp_sam_stripe_secret_key_live'       => 'sanitize_text_field',
			'wp_sam_stripe_price_id_monthly_test' => 'sanitize_text_field',
			'wp_sam_stripe_price_id_annual_test'  => 'sanitize_text_field',
			'wp_sam_stripe_price_id_monthly_live' => 'sanitize_text_field',
			'wp_sam_stripe_price_id_annual_live'  => 'sanitize_text_field',
			'wp_sam_webhook_secret'               => 'sanitize_text_field',
		);
		foreach ( $settings as $option => $callback ) {
			register_setting( 'wp_sam_settings_group', $option, array( 'sanitize_callback' => $callback ) );
		}
	}
);

add_filter(
	'wp_sam_option_names',
	static function ( array $names ): array {
		return array_merge(
			$names,
			array(
				'wp_sam_stripe_mode',
				'wp_sam_stripe_secret_key_test',
				'wp_sam_stripe_secret_key_live',
				'wp_sam_stripe_price_id_monthly_test',
				'wp_sam_stripe_price_id_annual_test',
				'wp_sam_stripe_price_id_monthly_live',
				'wp_sam_stripe_price_id_annual_live',
				'wp_sam_webhook_secret',
			)
		);
	}
);

// ── Checkout: AJAX session creation ──────────────────────────────────────────

add_action(
	'wp_ajax_wp_sam_create_checkout_session',
	static function (): void {
		check_ajax_referer( 'wp_sam_admin_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( null, 403 );
		}

		$checkout = Plugin::instance()->checkout;
		if ( null === $checkout ) {
			wp_send_json_error(
				array( 'message' => __( 'Upgrading is not available in this build of the plugin.', 'vcns-security-automation-manager' ) )
			);
		}

		$interval = sanitize_text_field( wp_unslash( $_POST['interval'] ?? 'monthly' ) );
		if ( ! in_array( $interval, array( 'monthly', 'annual' ), true ) ) {
			$interval = 'monthly';
		}

		$session = $checkout->create_session(
			'csp-automation-manager',
			admin_url( 'admin.php?page=security-automation-manager-dashboard&wp_sam_checkout=success' ),
			admin_url( 'admin.php?page=security-automation-manager-dashboard&wp_sam_checkout=cancelled' ),
			$interval
		);

		if ( is_wp_error( $session ) ) {
			wp_send_json_error( array( 'message' => $session->get_error_message() ) );
		}

		wp_send_json_success( array( 'url' => $session['url'] ) );
	}
);

// ── Presentation: upgrade notice + this mode's own settings UI ──────────────

add_action(
	'wp_sam_automation_upgrade_notice',
	static function ( bool $has_unavailable_mode ): void {
		if ( ! $has_unavailable_mode || Automation_Mode_Registry::is_available( WP_SAM_FA_MODE_KEY ) ) {
			return;
		}
		$checkout = Plugin::instance()->checkout;
		?>
		<div id="wp-sam-upgrade" class="notice notice-info inline" style="padding:16px 20px;margin:1em 0;">
			<h3 style="margin-top:0;"><?php esc_html_e( 'Unlock Fully Automatic', 'vcns-security-automation-manager' ); ?></h3>
			<p><?php esc_html_e( 'Fully Automatic auto-applies low, medium, and high-risk proposals within the hard safety exclusions the deterministic engine already enforces -- zero manual review. Every other automation mode, and every other pillar, stays free.', 'vcns-security-automation-manager' ); ?></p>
			<?php if ( null !== $checkout ) : ?>
			<div class="wp-sam-product-cards">
				<div class="wp-sam-product-card">
					<h3><?php esc_html_e( 'Monthly', 'vcns-security-automation-manager' ); ?></h3>
					<p class="wp-sam-price">&pound;1.99<span style="font-size:0.4em;font-weight:normal;">/mo</span></p>
					<button type="button" class="button button-primary wp-sam-upgrade-button" data-interval="monthly"><?php esc_html_e( 'Subscribe monthly', 'vcns-security-automation-manager' ); ?></button>
				</div>
				<div class="wp-sam-product-card">
					<h3><?php esc_html_e( 'Annual', 'vcns-security-automation-manager' ); ?></h3>
					<p class="wp-sam-price">&pound;19.99<span style="font-size:0.4em;font-weight:normal;">/yr</span></p>
					<button type="button" class="button button-primary wp-sam-upgrade-button" data-interval="annual"><?php esc_html_e( 'Subscribe annually', 'vcns-security-automation-manager' ); ?></button>
				</div>
			</div>
			<p><span id="wp-sam-upgrade-status" role="status"></span></p>
			<?php else : ?>
			<p class="description"><?php esc_html_e( 'Upgrading is not available in this build of the plugin.', 'vcns-security-automation-manager' ); ?></p>
			<?php endif; ?>
		</div>
		<?php if ( null !== $checkout ) : ?>
		<h2 class="title"><?php esc_html_e( 'Payment provider configuration', 'vcns-security-automation-manager' ); ?></h2>
		<p class="description">
			<?php esc_html_e( 'This site calls the Stripe API directly to create checkout sessions -- no external proxy is involved. Create one Product with a recurring Monthly and Annual Price in your Stripe dashboard, then paste the resulting IDs below.', 'vcns-security-automation-manager' ); ?>
		</p>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><label for="wp_sam_stripe_mode"><?php esc_html_e( 'Mode', 'vcns-security-automation-manager' ); ?></label></th>
				<td>
					<select id="wp_sam_stripe_mode" name="wp_sam_stripe_mode">
						<option value="test" <?php selected( get_option( 'wp_sam_stripe_mode', 'test' ), 'test' ); ?>><?php esc_html_e( 'Test', 'vcns-security-automation-manager' ); ?></option>
						<option value="live" <?php selected( get_option( 'wp_sam_stripe_mode', 'test' ), 'live' ); ?>><?php esc_html_e( 'Live', 'vcns-security-automation-manager' ); ?></option>
					</select>
					<p class="description"><?php esc_html_e( 'Which key/price pair below is actually used for checkout. Test everything in Test mode first.', 'vcns-security-automation-manager' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="wp_sam_stripe_secret_key_test"><?php esc_html_e( 'Test Secret Key', 'vcns-security-automation-manager' ); ?></label></th>
				<td><input type="password" id="wp_sam_stripe_secret_key_test" name="wp_sam_stripe_secret_key_test" value="<?php echo esc_attr( get_option( 'wp_sam_stripe_secret_key_test', '' ) ); ?>" class="regular-text" autocomplete="off" placeholder="sk_test_…" /></td>
			</tr>
			<tr>
				<th scope="row"><label for="wp_sam_stripe_secret_key_live"><?php esc_html_e( 'Live Secret Key', 'vcns-security-automation-manager' ); ?></label></th>
				<td><input type="password" id="wp_sam_stripe_secret_key_live" name="wp_sam_stripe_secret_key_live" value="<?php echo esc_attr( get_option( 'wp_sam_stripe_secret_key_live', '' ) ); ?>" class="regular-text" autocomplete="off" placeholder="sk_live_…" /></td>
			</tr>
			<tr>
				<th scope="row"><label for="wp_sam_stripe_price_id_monthly_test"><?php esc_html_e( 'Test Price ID (Monthly)', 'vcns-security-automation-manager' ); ?></label></th>
				<td><input type="text" id="wp_sam_stripe_price_id_monthly_test" name="wp_sam_stripe_price_id_monthly_test" value="<?php echo esc_attr( get_option( 'wp_sam_stripe_price_id_monthly_test', '' ) ); ?>" class="regular-text" placeholder="price_…" /></td>
			</tr>
			<tr>
				<th scope="row"><label for="wp_sam_stripe_price_id_annual_test"><?php esc_html_e( 'Test Price ID (Annual)', 'vcns-security-automation-manager' ); ?></label></th>
				<td><input type="text" id="wp_sam_stripe_price_id_annual_test" name="wp_sam_stripe_price_id_annual_test" value="<?php echo esc_attr( get_option( 'wp_sam_stripe_price_id_annual_test', '' ) ); ?>" class="regular-text" placeholder="price_…" /></td>
			</tr>
			<tr>
				<th scope="row"><label for="wp_sam_stripe_price_id_monthly_live"><?php esc_html_e( 'Live Price ID (Monthly)', 'vcns-security-automation-manager' ); ?></label></th>
				<td><input type="text" id="wp_sam_stripe_price_id_monthly_live" name="wp_sam_stripe_price_id_monthly_live" value="<?php echo esc_attr( get_option( 'wp_sam_stripe_price_id_monthly_live', '' ) ); ?>" class="regular-text" placeholder="price_…" /></td>
			</tr>
			<tr>
				<th scope="row"><label for="wp_sam_stripe_price_id_annual_live"><?php esc_html_e( 'Live Price ID (Annual)', 'vcns-security-automation-manager' ); ?></label></th>
				<td><input type="text" id="wp_sam_stripe_price_id_annual_live" name="wp_sam_stripe_price_id_annual_live" value="<?php echo esc_attr( get_option( 'wp_sam_stripe_price_id_annual_live', '' ) ); ?>" class="regular-text" placeholder="price_…" /></td>
			</tr>
			<tr>
				<th scope="row"><label for="wp_sam_webhook_secret"><?php esc_html_e( 'Webhook Signing Secret', 'vcns-security-automation-manager' ); ?></label></th>
				<td>
					<input type="password" id="wp_sam_webhook_secret" name="wp_sam_webhook_secret" value="<?php echo esc_attr( get_option( 'wp_sam_webhook_secret', '' ) ); ?>" class="regular-text" autocomplete="off" placeholder="whsec_…" />
					<p class="description">
						<?php
						echo wp_kses_post(
							sprintf(
								/* translators: %s: the webhook URL to register in the Stripe dashboard */
								__( 'In the Stripe dashboard, add a webhook endpoint at %s listening for checkout.session.completed and checkout.session.async_payment_succeeded, then paste its signing secret here. One endpoint covers both Test and Live mode.', 'vcns-security-automation-manager' ),
								'<code>' . esc_html( rest_url( 'sam/v1/webhook/stripe' ) ) . '</code>'
							)
						);
						?>
					</p>
				</td>
			</tr>
		</table>
		<?php endif; ?>
		<?php
	}
);
