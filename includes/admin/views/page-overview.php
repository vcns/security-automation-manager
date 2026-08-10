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

// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
$pillar_profiles_raw = $wpdb->get_results( "SELECT pillar, surface, enabled FROM {$wpdb->prefix}sam_pillar_profiles", ARRAY_A );
$enabled_by_pillar   = array();
foreach ( ! empty( $pillar_profiles_raw ) ? $pillar_profiles_raw : array() as $row ) {
	$enabled_by_pillar[ $row['pillar'] ][ $row['surface'] ] = ! empty( $row['enabled'] );
}

$simple_pillars = array(
	\WP_SAM\Security\X_Frame_Options_Builder::PILLAR_KEY => array(
		'label' => __( 'X-Frame-Options', 'security-automation-manager' ),
		'page'  => 'security-automation-manager-xfo',
	),
	\WP_SAM\Security\X_Content_Type_Options_Builder::PILLAR_KEY => array(
		'label' => __( 'X-Content-Type-Options', 'security-automation-manager' ),
		'page'  => 'security-automation-manager-xcto',
	),
	\WP_SAM\Security\Referrer_Policy_Builder::PILLAR_KEY => array(
		'label' => __( 'Referrer-Policy', 'security-automation-manager' ),
		'page'  => 'security-automation-manager-referrer-policy',
	),
	\WP_SAM\Security\Permissions_Policy_Builder::PILLAR_KEY => array(
		'label' => __( 'Permissions-Policy', 'security-automation-manager' ),
		'page'  => 'security-automation-manager-permissions-policy',
	),
	\WP_SAM\Security\Strict_Transport_Security_Builder::PILLAR_KEY => array(
		'label' => __( 'Strict-Transport-Security', 'security-automation-manager' ),
		'page'  => 'security-automation-manager-hsts',
	),
	\WP_SAM\Security\Reverse_Tabnabbing_Builder::PILLAR_KEY => array(
		'label' => __( 'Reverse Tabnabbing Protection', 'security-automation-manager' ),
		'page'  => 'security-automation-manager-reverse-tabnabbing',
	),
	\WP_SAM\Security\Dependency_Governance_Builder::PILLAR_KEY => array(
		'label' => __( 'External Scripts', 'security-automation-manager' ),
		'page'  => 'security-automation-manager-external-scripts',
	),
);
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
			<?php foreach ( $simple_pillars as $pillar_key => $pillar ) : ?>
				<tr>
					<td>
						<strong><?php echo esc_html( $pillar['label'] ); ?></strong>
					</td>
					<td>
						<?php foreach ( $surfaces as $surface ) : ?>
							<?php $on = $enabled_by_pillar[ $pillar_key ][ $surface ] ?? false; ?>
							<span class="wp-sam-mode-badge mode-<?php echo esc_attr( $on ? 'enforce' : 'disabled' ); ?>">
								<?php echo esc_html( ucfirst( $surface ) . ': ' . ( $on ? __( 'On', 'security-automation-manager' ) : __( 'Off', 'security-automation-manager' ) ) ); ?>
							</span>
						<?php endforeach; ?>
					</td>
					<td>
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=' . $pillar['page'] ) ); ?>">
							<?php
							echo esc_html(
								sprintf(
									/* translators: %s: pillar label, e.g. "X-Frame-Options" */
									__( 'Manage %s', 'security-automation-manager' ),
									$pillar['label']
								)
							);
							?>
						</a>
					</td>
				</tr>
			<?php endforeach; ?>
		</tbody>
	</table>

	<p style="margin-top: 1.5em;">
		<a href="<?php echo esc_url( admin_url( 'admin.php?page=security-automation-manager-dashboard&tab=policy-audit' ) ); ?>">
			<?php esc_html_e( 'Policy Audit', 'security-automation-manager' ); ?>
		</a>
		&nbsp;|&nbsp;
		<a href="<?php echo esc_url( admin_url( 'admin.php?page=security-automation-manager-readiness' ) ); ?>">
			<?php esc_html_e( 'Readiness', 'security-automation-manager' ); ?>
		</a>
	</p>
</div>
