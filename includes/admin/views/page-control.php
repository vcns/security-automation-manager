<?php
/**
 * Admin view: Control -- the third stage of this plugin's operational
 * lifecycle (.roadmap/phase3_early_plan.md §3.3, §6.1): apply an explicitly
 * permitted response. In this build that means configuring a header policy
 * or a certificate action -- not blocking traffic. Real-time traffic
 * controls (rate-limiting, temporary blocking, challenge) are a future
 * phase and do not exist yet; nothing in this build blocks a visitor's
 * request (§30 Default-Safety).
 *
 * A curated set of links into existing configuration views, not a
 * re-implementation of any of them.
 *
 * Rendered by Admin_UI::render_control().
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<div class="wrap wp-sam-wrap">
	<h1><?php esc_html_e( 'Control', 'vcns-security-automation-manager' ); ?></h1>

	<p>
		<?php esc_html_e( '"Control" here means configuring a header policy or a certificate action, not blocking traffic. This build has no real-time traffic controls (rate-limiting, temporary blocking, challenge) yet -- nothing on this site is ever blocked by this plugin today.', 'vcns-security-automation-manager' ); ?>
	</p>

	<table class="widefat striped wp-sam-readiness-table">
		<thead>
			<tr>
				<th><?php esc_html_e( 'Area', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Manage', 'vcns-security-automation-manager' ); ?></th>
			</tr>
		</thead>
		<tbody>
			<tr>
				<td>
					<strong><?php esc_html_e( 'CSP Profiles', 'vcns-security-automation-manager' ); ?></strong>
					<p class="description"><?php esc_html_e( 'The per-surface Content Security Policy actually applied to this site.', 'vcns-security-automation-manager' ); ?></p>
				</td>
				<td>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=security-automation-manager-dashboard&tab=profiles' ) ); ?>">
						<?php esc_html_e( 'Manage CSP Profiles', 'vcns-security-automation-manager' ); ?>
					</a>
				</td>
			</tr>
			<tr>
				<td>
					<strong><?php esc_html_e( 'Automation Settings', 'vcns-security-automation-manager' ); ?></strong>
					<p class="description"><?php esc_html_e( 'How far CSP is allowed to progress from a human decision to automatic approval, per surface.', 'vcns-security-automation-manager' ); ?></p>
				</td>
				<td>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=security-automation-manager-dashboard&tab=settings' ) ); ?>">
						<?php esc_html_e( 'Manage Automation Settings', 'vcns-security-automation-manager' ); ?>
					</a>
				</td>
			</tr>
			<tr>
				<td>
					<strong><?php esc_html_e( 'Every header & content policy', 'vcns-security-automation-manager' ); ?></strong>
					<p class="description"><?php esc_html_e( 'The full status table for every browser security policy and transport/certificate control this plugin manages, grouped by protection layer.', 'vcns-security-automation-manager' ); ?></p>
				</td>
				<td>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=security-automation-manager' ) ); ?>">
						<?php esc_html_e( 'View Settings', 'vcns-security-automation-manager' ); ?>
					</a>
				</td>
			</tr>
			<tr>
				<td>
					<strong><?php esc_html_e( 'Certificates', 'vcns-security-automation-manager' ); ?></strong>
					<p class="description"><?php esc_html_e( 'Issue or renew this site\'s TLS certificate.', 'vcns-security-automation-manager' ); ?></p>
				</td>
				<td>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=security-automation-manager-certificates&tab=renew' ) ); ?>">
						<?php esc_html_e( 'Manage Certificates', 'vcns-security-automation-manager' ); ?>
					</a>
				</td>
			</tr>
		</tbody>
	</table>
</div>
