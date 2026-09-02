<?php
/**
 * Admin view: Control -- the third stage of this plugin's operational
 * lifecycle (.roadmap/phase3_early_plan.md §3.3, §6.1): apply an explicitly
 * permitted response. Since Phase 3E (Traffic Controls) that includes
 * real-time rate limiting and progressive blocking, alongside the existing
 * header-policy and certificate actions -- see Intelligence\Traffic_Guard's
 * docblock for the default-safety design every surface still starts under
 * (§30): nothing blocks until an administrator explicitly promotes a
 * surface from Observe to Enforce.
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
		<?php esc_html_e( '"Control" here means applying an explicitly permitted response: a header policy, a certificate action, or -- since Traffic Controls -- rate limiting and blocking. Every traffic-control surface starts in Observe mode and stays there until you explicitly switch it to Enforce.', 'vcns-security-automation-manager' ); ?>
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
					<strong><?php esc_html_e( 'Traffic Controls', 'vcns-security-automation-manager' ); ?></strong>
					<p class="description"><?php esc_html_e( 'Per-surface rate limiting, an IP allow/block list, and progressive-response blocks.', 'vcns-security-automation-manager' ); ?></p>
				</td>
				<td>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=security-automation-manager-traffic' ) ); ?>">
						<?php esc_html_e( 'Manage Traffic Controls', 'vcns-security-automation-manager' ); ?>
					</a>
				</td>
			</tr>
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
