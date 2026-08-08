<?php
/**
 * Admin view: Security Automation Manager overview.
 * Landing page for the top-level menu -- a per-pillar status summary.
 * Rendered by Admin_UI::render_overview().
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

global $wpdb;

$surfaces = array( 'frontend', 'admin', 'login', 'api' );

// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
$profiles_raw     = $wpdb->get_results( "SELECT surface, mode FROM {$wpdb->prefix}csp_policy_profiles ORDER BY surface", ARRAY_A );
$modes_by_surface = array();
foreach ( ! empty( $profiles_raw ) ? $profiles_raw : array() as $row ) {
	$modes_by_surface[ $row['surface'] ] = $row['mode'];
}
?>
<div class="wrap wp-sam-wrap">
	<h1><?php esc_html_e( 'Security Automation Manager', 'security-automation-manager' ); ?></h1>
	<p>
		<?php esc_html_e( 'Configuration, reporting, and the decision engine are shared across every header this plugin manages. Each header is a pillar with its own page below.', 'security-automation-manager' ); ?>
	</p>

	<table class="widefat striped wp-sam-readiness-table">
		<thead>
			<tr>
				<th><?php esc_html_e( 'Pillar', 'security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Status', 'security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Details', 'security-automation-manager' ); ?></th>
			</tr>
		</thead>
		<tbody>
			<tr>
				<td>
					<strong><?php esc_html_e( 'Content Security Policy', 'security-automation-manager' ); ?></strong>
				</td>
				<td>
					<?php foreach ( $surfaces as $surface ) : ?>
						<?php $mode = $modes_by_surface[ $surface ] ?? 'disabled'; ?>
						<span class="wp-sam-mode-badge mode-<?php echo esc_attr( $mode ); ?>">
							<?php echo esc_html( ucfirst( $surface ) . ': ' . str_replace( '-', ' ', $mode ) ); ?>
						</span>
					<?php endforeach; ?>
				</td>
				<td>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=security-automation-manager-dashboard' ) ); ?>">
						<?php esc_html_e( 'Manage CSP', 'security-automation-manager' ); ?>
					</a>
				</td>
			</tr>
		</tbody>
	</table>

	<p class="description" style="margin-top: 1.5em;">
		<?php esc_html_e( 'Additional pillars (X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and others) are on the roadmap and will appear here once available.', 'security-automation-manager' ); ?>
	</p>

	<p>
		<a href="<?php echo esc_url( admin_url( 'admin.php?page=security-automation-manager-policy-audit' ) ); ?>">
			<?php esc_html_e( 'Policy Audit', 'security-automation-manager' ); ?>
		</a>
		&nbsp;|&nbsp;
		<a href="<?php echo esc_url( admin_url( 'admin.php?page=security-automation-manager-readiness' ) ); ?>">
			<?php esc_html_e( 'Readiness', 'security-automation-manager' ); ?>
		</a>
	</p>
</div>
