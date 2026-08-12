<?php
/**
 * Admin view: Security Automation Manager overview.
 * Landing page for the top-level menu, with three tabs: Overview (per-pillar
 * status summary, the default), Readiness (plugin-specific schema/runtime
 * checks and the data-reset flow -- previously its own submenu page), and
 * About (who built this and why, with links to the public help site).
 * Rendered by Admin_UI::render_overview().
 *
 * @var array $readiness Readiness report from Readiness_Checker.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

global $wpdb;

// Current tab.
$tab          = isset( $_GET['tab'] ) ? sanitize_text_field( wp_unslash( $_GET['tab'] ) ) : 'overview';
$allowed_tabs = array( 'overview', 'readiness', 'about' );
if ( ! in_array( $tab, $allowed_tabs, true ) ) {
	$tab = 'overview';
}

$base_url = admin_url( 'admin.php?page=security-automation-manager' );
$tab_help = array(
	'overview'  => array(
		'label'       => __( 'Overview', 'security-automation-manager' ),
		'description' => __( 'At-a-glance status for every pillar this plugin manages, and a link to configure each one.', 'security-automation-manager' ),
	),
	'readiness' => array(
		'label'       => __( 'Readiness', 'security-automation-manager' ),
		'description' => __( 'Plugin-specific checks for schema, runtime defaults, reporting configuration, and reset readiness.', 'security-automation-manager' ),
	),
	'about'     => array(
		'label'       => __( 'About', 'security-automation-manager' ),
		'description' => __( 'Who built this plugin, why, and where to find the full documentation.', 'security-automation-manager' ),
	),
);

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
		'page'  => 'security-automation-manager-scripts',
		'tab'   => 'external',
	),
	\WP_SAM\Security\Internal_Script_Integrity_Builder::PILLAR_KEY => array(
		'label' => __( 'Internal Script Integrity', 'security-automation-manager' ),
		'page'  => 'security-automation-manager-scripts',
		'tab'   => 'internal',
	),
	\WP_SAM\Security\Cross_Origin_Resource_Policy_Builder::PILLAR_KEY => array(
		'label' => __( 'Cross-Origin-Resource-Policy', 'security-automation-manager' ),
		'page'  => 'security-automation-manager-cross-origin',
		'tab'   => 'corp',
	),
	\WP_SAM\Security\X_Permitted_Cross_Domain_Policies_Builder::PILLAR_KEY => array(
		'label' => __( 'X-Permitted-Cross-Domain-Policies', 'security-automation-manager' ),
		'page'  => 'security-automation-manager-cross-origin',
		'tab'   => 'xpcdp',
	),
	\WP_SAM\Security\Cross_Origin_Opener_Policy_Builder::PILLAR_KEY => array(
		'label' => __( 'Cross-Origin-Opener-Policy', 'security-automation-manager' ),
		'page'  => 'security-automation-manager-cross-origin',
		'tab'   => 'coop',
	),
	\WP_SAM\Security\Cross_Origin_Embedder_Policy_Builder::PILLAR_KEY => array(
		'label' => __( 'Cross-Origin-Embedder-Policy', 'security-automation-manager' ),
		'page'  => 'security-automation-manager-cross-origin',
		'tab'   => 'coep',
	),
);

// Sorted alphabetically by label to match the left-nav ordering. "Content
// Security Policy" (the hardcoded row above this loop) already sorts first
// on its own -- "Content" < "Cross-..." -- so it needs no special handling.
uasort(
	$simple_pillars,
	static fn( array $a, array $b ): int => strcasecmp( $a['label'], $b['label'] )
);

// ── Readiness tab data ──────────────────────────────────────────────────────
$reset_result = sanitize_text_field( wp_unslash( $_GET['wp_sam_reset'] ?? '' ) );
$status_badge = static function ( string $status ): void {
	$labels = array(
		'pass'    => __( 'Pass', 'security-automation-manager' ),
		'warning' => __( 'Warning', 'security-automation-manager' ),
		'fail'    => __( 'Fail', 'security-automation-manager' ),
	);
	$label  = $labels[ $status ] ?? __( 'Unknown', 'security-automation-manager' );

	printf(
		'<span class="wp-sam-readiness-badge status-%1$s">%2$s</span>',
		esc_attr( $status ),
		esc_html( $label )
	);
};
?>
<div class="wrap wp-sam-wrap">
	<h1><?php esc_html_e( 'Security Automation Manager', 'security-automation-manager' ); ?></h1>

	<!-- ── Tabs ──────────────────────────────────────────────────────────── -->
	<nav class="nav-tab-wrapper wp-sam-tab-wrapper" role="tablist" aria-label="<?php esc_attr_e( 'Overview sections', 'security-automation-manager' ); ?>">
		<?php foreach ( $tab_help as $tab_key => $tab_data ) : ?>
		<a class="nav-tab<?php echo $tab_key === $tab ? ' nav-tab-active' : ''; ?>"
			href="<?php echo esc_url( add_query_arg( 'tab', $tab_key, $base_url ) ); ?>"
			role="tab"
			title="<?php echo esc_attr( $tab_data['description'] ); ?>"
			aria-describedby="wp-sam-tab-help-<?php echo esc_attr( $tab_key ); ?>"
			<?php echo $tab_key === $tab ? 'aria-selected="true" aria-current="page"' : 'aria-selected="false"'; ?>>
			<?php echo esc_html( $tab_data['label'] ); ?>
			<span class="screen-reader-text" id="wp-sam-tab-help-<?php echo esc_attr( $tab_key ); ?>">
				<?php echo esc_html( $tab_data['description'] ); ?>
			</span>
		</a>
		<?php endforeach; ?>
	</nav>
	<div class="wp-sam-tab-help" role="note">
		<strong><?php echo esc_html( $tab_help[ $tab ]['label'] ); ?>:</strong>
		<?php echo esc_html( $tab_help[ $tab ]['description'] ); ?>
	</div>

	<?php if ( 'overview' === $tab ) : ?>

	<table class="widefat striped wp-sam-readiness-table" style="margin-top: 1em;">
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
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=' . $pillar['page'] . ( isset( $pillar['tab'] ) ? '&tab=' . $pillar['tab'] : '' ) ) ); ?>">
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
	</p>

	<?php elseif ( 'readiness' === $tab ) : ?>

		<?php if ( 'success' === $reset_result ) : ?>
		<div class="notice notice-success is-dismissible">
			<p><?php esc_html_e( 'Security Automation Manager data has been reset and default profiles have been reseeded.', 'security-automation-manager' ); ?></p>
		</div>
	<?php elseif ( 'partial' === $reset_result ) : ?>
		<div class="notice notice-warning is-dismissible">
			<p><?php esc_html_e( 'Reset completed, but one or more plugin tables could not be cleared. Review schema health below.', 'security-automation-manager' ); ?></p>
		</div>
	<?php elseif ( 'failed' === $reset_result ) : ?>
		<div class="notice notice-error is-dismissible">
			<p><?php esc_html_e( 'Reset was not performed. Confirm the typed phrase and re-authenticate with your current WordPress password.', 'security-automation-manager' ); ?></p>
		</div>
	<?php endif; ?>

	<h2><?php esc_html_e( 'Plugin and Database', 'security-automation-manager' ); ?></h2>
	<table class="widefat striped wp-sam-readiness-table">
		<thead>
			<tr>
				<th scope="col"><?php esc_html_e( 'Check', 'security-automation-manager' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Value', 'security-automation-manager' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Status', 'security-automation-manager' ); ?></th>
			</tr>
		</thead>
		<tbody>
			<?php foreach ( $readiness['plugin'] as $item ) : ?>
				<tr>
					<th scope="row"><?php echo esc_html( $item['label'] ); ?></th>
					<td><code><?php echo esc_html( (string) $item['value'] ); ?></code></td>
					<td><?php $status_badge( $item['status'] ); ?></td>
				</tr>
			<?php endforeach; ?>
		</tbody>
	</table>

	<h2><?php esc_html_e( 'Schema Health', 'security-automation-manager' ); ?></h2>
	<table class="widefat striped wp-sam-readiness-table">
		<thead>
			<tr>
				<th scope="col"><?php esc_html_e( 'Table', 'security-automation-manager' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Rows', 'security-automation-manager' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Status', 'security-automation-manager' ); ?></th>
			</tr>
		</thead>
		<tbody>
			<?php foreach ( $readiness['schema'] as $item ) : ?>
				<tr>
					<th scope="row"><code><?php echo esc_html( $item['table'] ); ?></code></th>
					<td>
						<?php
						echo null === $item['rows']
							? esc_html__( 'Missing', 'security-automation-manager' )
							: esc_html( (string) $item['rows'] );
						?>
					</td>
					<td><?php $status_badge( $item['status'] ); ?></td>
				</tr>
			<?php endforeach; ?>
		</tbody>
	</table>

	<h2><?php esc_html_e( 'Operational Health', 'security-automation-manager' ); ?></h2>
	<table class="widefat striped wp-sam-readiness-table">
		<thead>
			<tr>
				<th scope="col"><?php esc_html_e( 'Check', 'security-automation-manager' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Value', 'security-automation-manager' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Status', 'security-automation-manager' ); ?></th>
			</tr>
		</thead>
		<tbody>
			<?php foreach ( $readiness['health'] as $item ) : ?>
				<tr>
					<th scope="row"><?php echo esc_html( $item['label'] ); ?></th>
					<td><code><?php echo esc_html( (string) $item['value'] ); ?></code></td>
					<td><?php $status_badge( $item['status'] ); ?></td>
				</tr>
			<?php endforeach; ?>
		</tbody>
	</table>

	<hr>

	<h2 id="wp-sam-reset"><?php esc_html_e( 'Reset Plugin Data', 'security-automation-manager' ); ?></h2>
	<p>
		<?php esc_html_e( 'This clears Security Automation Manager custom-table rows and plugin-owned runtime options, then reseeds the default policy profiles needed for a clean start.', 'security-automation-manager' ); ?>
	</p>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="wp-sam-reset-form">
		<?php wp_nonce_field( 'wp_sam_reset_data' ); ?>
		<input type="hidden" name="action" value="wp_sam_reset_data">
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row">
					<label for="wp_sam_current_password"><?php esc_html_e( 'Current password', 'security-automation-manager' ); ?></label>
				</th>
				<td>
					<input type="password" id="wp_sam_current_password" name="wp_sam_current_password" class="regular-text" autocomplete="current-password" required>
					<p class="description"><?php esc_html_e( 'Required to re-authenticate the currently logged-in administrator before destructive reset.', 'security-automation-manager' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row">
					<label for="wp_sam_reset_confirmation"><?php esc_html_e( 'Confirmation', 'security-automation-manager' ); ?></label>
				</th>
				<td>
					<input type="text" id="wp_sam_reset_confirmation" name="wp_sam_reset_confirmation" class="regular-text" pattern="RESET CSP DATA" required>
					<p class="description"><?php esc_html_e( 'Type RESET CSP DATA to start from a blank CSP canvas.', 'security-automation-manager' ); ?></p>
				</td>
			</tr>
		</table>
		<?php submit_button( __( 'Reset CSP Data', 'security-automation-manager' ), 'delete' ); ?>
	</form>

	<?php else /* about */ : ?>

	<div class="wp-sam-about" style="max-width: 760px; margin-top: 1em;">
		<p>
			<?php esc_html_e( 'Security Automation Manager is built and maintained by VCNS Tech Ltd.', 'security-automation-manager' ); ?>
		</p>

		<h2><?php esc_html_e( 'Why we built this', 'security-automation-manager' ); ?></h2>
		<p>
			<?php esc_html_e( 'Most WordPress security plugins bundle a firewall, malware scanner, and login hardening -- and treat modern browser security headers like Content Security Policy as an afterthought, if they touch CSP at all. Everywhere else on the web, CSP rollout is standard practice; on WordPress, it usually means hand-editing .htaccess or a theme functions file, with no visibility into what actually breaks, no safe way to test before enforcing, and no audit trail of who approved what.', 'security-automation-manager' ); ?>
		</p>
		<p>
			<?php esc_html_e( 'We built this plugin to close that gap: report-only rollout by default, browser-submitted violation reports turned into reviewable proposals, a reason-required decision ledger for every change, and the same report-first discipline applied to nine other header pillars alongside CSP -- all native to WordPress, with no external dashboard or proprietary scanning service required to use the free tier.', 'security-automation-manager' ); ?>
		</p>

		<h2><?php esc_html_e( 'The gap this fills', 'security-automation-manager' ); ?></h2>
		<p>
			<?php esc_html_e( 'CSP is widely regarded as one of the most effective defenses against cross-site scripting, but it is also one of the easiest security controls to deploy badly -- an overly strict policy silently breaks a theme or plugin, and an overly loose one defends nothing. This plugin exists to make the safe middle path the easy path: learn what a site actually needs before enforcing anything, and keep every decision reviewable.', 'security-automation-manager' ); ?>
		</p>

		<h2><?php esc_html_e( 'Learn more', 'security-automation-manager' ); ?></h2>
		<ul style="list-style: disc; padding-left: 1.5em;">
			<li>
				<a href="https://vcns.github.io/security-automation-manager/" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Help site', 'security-automation-manager' ); ?></a>
				&nbsp;&mdash;
				<?php esc_html_e( 'overview, getting started, and how the dashboard works', 'security-automation-manager' ); ?>
			</li>
			<li>
				<a href="https://vcns.github.io/security-automation-manager/user-guide.html" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'User guide', 'security-automation-manager' ); ?></a>
				&nbsp;&mdash;
				<?php esc_html_e( 'the full walkthrough: report-only rollout, reviewing proposals, and promoting to enforce', 'security-automation-manager' ); ?>
			</li>
			<li>
				<a href="https://vcns.github.io/security-automation-manager/faq.html" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'FAQ', 'security-automation-manager' ); ?></a>
			</li>
			<li>
				<a href="https://github.com/vcns/security-automation-manager" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'GitHub repository', 'security-automation-manager' ); ?></a>
				&nbsp;&mdash;
				<?php esc_html_e( 'source code, releases, and issue tracker', 'security-automation-manager' ); ?>
			</li>
			<li>
				<a href="https://vcns.tech" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'VCNS Tech Ltd', 'security-automation-manager' ); ?></a>
			</li>
		</ul>
	</div>

	<?php endif; ?>
</div>
