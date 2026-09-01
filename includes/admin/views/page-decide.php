<?php
/**
 * Admin view: Decide -- the second stage of this plugin's operational
 * lifecycle (.roadmap/phase3_early_plan.md §3.2, §6.1): evaluate observed
 * evidence against deterministic rules, confidence, and policy. Nothing on
 * this page applies a response -- that's Control.
 *
 * A curated set of links into existing review/classification views, not a
 * re-implementation of any of them.
 *
 * Rendered by Admin_UI::render_decide().
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

global $wpdb;

// Same shape as the per-surface pending-count query already used on the CSP
// dashboard's own banner (page-csp-dashboard.php), just without the surface
// filter -- a plugin-wide total, not new aggregation logic.
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
$pending_sources = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}csp_source_inventory WHERE approval_state = 'pending'" );
?>
<div class="wrap wp-sam-wrap">
	<h1><?php esc_html_e( 'Decide', 'vcns-security-automation-manager' ); ?></h1>

	<p>
		<?php esc_html_e( 'Evidence evaluated against deterministic rules, confidence, and policy. Nothing here applies a response on its own -- accepted or approved decisions take effect once configured under Control.', 'vcns-security-automation-manager' ); ?>
	</p>

	<table class="widefat striped wp-sam-readiness-table">
		<thead>
			<tr>
				<th><?php esc_html_e( 'Area', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Status', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'View', 'vcns-security-automation-manager' ); ?></th>
			</tr>
		</thead>
		<tbody>
			<tr>
				<td>
					<strong><?php esc_html_e( 'For Review', 'vcns-security-automation-manager' ); ?></strong>
					<p class="description"><?php esc_html_e( 'CSP source candidates discovered on this site, awaiting an approve/reject decision.', 'vcns-security-automation-manager' ); ?></p>
				</td>
				<td>
					<?php if ( $pending_sources > 0 ) : ?>
						<?php
						echo esc_html(
							sprintf(
								/* translators: %d: number of sources awaiting a decision */
								_n( '%d source awaiting a decision.', '%d sources awaiting a decision.', $pending_sources, 'vcns-security-automation-manager' ),
								$pending_sources
							)
						);
						?>
					<?php else : ?>
						<?php esc_html_e( 'Nothing awaiting a decision.', 'vcns-security-automation-manager' ); ?>
					<?php endif; ?>
				</td>
				<td>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=security-automation-manager-dashboard&tab=sources' ) ); ?>">
						<?php esc_html_e( 'View For Review', 'vcns-security-automation-manager' ); ?>
					</a>
				</td>
			</tr>
			<tr>
				<td>
					<strong><?php esc_html_e( 'Policy Changes', 'vcns-security-automation-manager' ); ?></strong>
					<p class="description"><?php esc_html_e( 'The full decision ledger -- every approval, rejection, reversion, and undo, with a reason recorded for each.', 'vcns-security-automation-manager' ); ?></p>
				</td>
				<td>&mdash;</td>
				<td>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=security-automation-manager-dashboard&tab=policy-changes' ) ); ?>">
						<?php esc_html_e( 'View Policy Changes', 'vcns-security-automation-manager' ); ?>
					</a>
				</td>
			</tr>
			<tr>
				<td>
					<strong><?php esc_html_e( 'Policy Audit', 'vcns-security-automation-manager' ); ?></strong>
					<p class="description"><?php esc_html_e( 'Per-surface pending and high-risk counts at a glance, across every surface this site serves.', 'vcns-security-automation-manager' ); ?></p>
				</td>
				<td>&mdash;</td>
				<td>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=security-automation-manager-dashboard&tab=policy-audit' ) ); ?>">
						<?php esc_html_e( 'View Policy Audit', 'vcns-security-automation-manager' ); ?>
					</a>
				</td>
			</tr>
			<tr>
				<td>
					<strong><?php esc_html_e( 'Dependency Classification', 'vcns-security-automation-manager' ); ?></strong>
					<p class="description"><?php esc_html_e( 'Decide whether a third-party script or stylesheet origin is trusted.', 'vcns-security-automation-manager' ); ?></p>
				</td>
				<td>&mdash;</td>
				<td>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=security-automation-manager-scripts&tab=external' ) ); ?>">
						<?php esc_html_e( 'View Dependency Classification', 'vcns-security-automation-manager' ); ?>
					</a>
				</td>
			</tr>
		</tbody>
	</table>
</div>
