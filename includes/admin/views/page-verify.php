<?php
/**
 * Admin view: Verify -- the fourth stage of this plugin's operational
 * lifecycle (.roadmap/phase3_early_plan.md §3.4, §6.1): confirm whether a
 * control had the intended effect. Since Phase 3F (Baseline and Drift)
 * that includes confirming whether a previously detected drift condition
 * has been resolved (§3.4's own example wording), alongside the existing
 * locally-confirmed header/certificate state. Independently confirming
 * what an external client actually receives is still External
 * Verification (§20), a future phase, and is not available yet.
 *
 * Rendered by Admin_UI::render_verify().
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<div class="wrap wp-sam-wrap">
	<h1><?php esc_html_e( 'Verify', 'vcns-security-automation-manager' ); ?></h1>

	<?php require WP_SAM_DIR . 'includes/admin/views/partials/personal-preferences-link.php'; ?>

	<p>
		<?php esc_html_e( 'Confirms state locally -- what this server is configured to send, and whether it has drifted from an approved baseline. Independently confirming what an external visitor actually receives is planned for a future phase and is not available yet.', 'vcns-security-automation-manager' ); ?>
	</p>

	<div class="wp-sam-table-wrap">
	<table class="widefat striped wp-sam-table wp-sam-readiness-table">
		<thead>
			<tr>
				<th class="wp-sam-col-primary"><?php esc_html_e( 'Area', 'vcns-security-automation-manager' ); ?></th>
				<th class="wp-sam-col-actions"><?php esc_html_e( 'View', 'vcns-security-automation-manager' ); ?></th>
			</tr>
		</thead>
		<tbody>
			<tr>
				<td class="wp-sam-col-primary">
					<strong><?php esc_html_e( 'Baseline & Drift', 'vcns-security-automation-manager' ); ?></strong>
					<p class="description"><?php esc_html_e( 'Confirms whether a previously detected drift condition has been resolved, and what still differs from the approved baseline.', 'vcns-security-automation-manager' ); ?></p>
				</td>
				<td class="wp-sam-col-actions">
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=security-automation-manager-baseline' ) ); ?>">
						<?php esc_html_e( 'View Baseline & Drift', 'vcns-security-automation-manager' ); ?>
					</a>
				</td>
			</tr>
			<tr>
				<td class="wp-sam-col-primary">
					<strong><?php esc_html_e( 'CSP Policy Audit', 'vcns-security-automation-manager' ); ?></strong>
					<p class="description"><?php esc_html_e( 'The effective header this site is currently configured to send, per surface -- confirms a policy change is actually present.', 'vcns-security-automation-manager' ); ?></p>
				</td>
				<td class="wp-sam-col-actions">
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=security-automation-manager-dashboard&tab=policy-audit' ) ); ?>">
						<?php esc_html_e( 'View Policy Audit', 'vcns-security-automation-manager' ); ?>
					</a>
				</td>
			</tr>
			<tr>
				<td class="wp-sam-col-primary">
					<strong><?php esc_html_e( 'Certificates -- Issue/Renew', 'vcns-security-automation-manager' ); ?></strong>
					<p class="description"><?php esc_html_e( 'Confirms a certificate was correctly issued and deployed.', 'vcns-security-automation-manager' ); ?></p>
				</td>
				<td class="wp-sam-col-actions">
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=security-automation-manager-certificates&tab=renew' ) ); ?>">
						<?php esc_html_e( 'View Certificates', 'vcns-security-automation-manager' ); ?>
					</a>
				</td>
			</tr>
		</tbody>
	</table>
	</div>
</div>
