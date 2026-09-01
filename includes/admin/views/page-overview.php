<?php
/**
 * Admin view: Security Automation Manager overview.
 * Landing page for the top-level menu, with five tabs: Overview (per-pillar
 * status summary, the default), Readiness (plugin-specific schema/runtime
 * checks only), Recovery (schema-downgrade status, configuration snapshot
 * restore, full data reset, and configuration export/import -- previously
 * split across Readiness and nowhere), Updates (installed version, active
 * build channel, manifest/checksum/applied-update diagnostics -- previously
 * its own submenu page), and About (who built this and why, with links to
 * the public help site).
 * Rendered by Admin_UI::render_overview().
 *
 * @var array $readiness Readiness report from Readiness_Checker.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WP_SAM\Admin\Pillar_Registry;
use WP_SAM\Admin\Status_Badge;
use WP_SAM\Certificates\Certificate_Store;
use WP_SAM\CSP\Automation_Config;
use WP_SAM\Rollback_Guard;

global $wpdb;

// Current tab.
$tab          = isset( $_GET['tab'] ) ? sanitize_text_field( wp_unslash( $_GET['tab'] ) ) : 'overview';
$allowed_tabs = array( 'overview', 'readiness', 'recovery', 'updates', 'about' );
if ( ! in_array( $tab, $allowed_tabs, true ) ) {
	$tab = 'overview';
}

$base_url = admin_url( 'admin.php?page=security-automation-manager' );
$tab_help = array(
	'overview'  => array(
		'label'       => __( 'Overview', 'vcns-security-automation-manager' ),
		'description' => __( 'At-a-glance status for every pillar this plugin manages, and a link to configure each one.', 'vcns-security-automation-manager' ),
	),
	'readiness' => array(
		'label'       => __( 'Readiness', 'vcns-security-automation-manager' ),
		'description' => __( 'Plugin-specific checks for schema, runtime defaults, and reporting configuration.', 'vcns-security-automation-manager' ),
	),
	'recovery'  => array(
		'label'       => __( 'Recovery', 'vcns-security-automation-manager' ),
		'description' => __( 'Schema-downgrade status, configuration snapshot restore, full data reset, and configuration export/import.', 'vcns-security-automation-manager' ),
	),
	'updates'   => array(
		'label'       => __( 'Updates', 'vcns-security-automation-manager' ),
		'description' => __( 'Installed version, active build channel, and (GitHub-channel builds only) manifest, checksum, and applied-update diagnostics.', 'vcns-security-automation-manager' ),
	),
	'about'     => array(
		'label'       => __( 'About', 'vcns-security-automation-manager' ),
		'description' => __( 'Who built this plugin, why, and where to find the full documentation.', 'vcns-security-automation-manager' ),
	),
);

// ── Overview tab data ────────────────────────────────────────────────────────
// Scoped to the Overview tab only -- Pillar_Registry::fetch_rows() and the
// Certificate_Store/Certificate_Manager calls below have no reason to run
// when e.g. the Updates or Recovery tab is what's actually being rendered.
if ( 'overview' === $tab ) {
	$surfaces = Automation_Config::SURFACES;

	// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	$profiles_raw     = $wpdb->get_results( "SELECT surface, mode FROM {$wpdb->prefix}csp_policy_profiles ORDER BY surface", ARRAY_A );
	$modes_by_surface = array();
	foreach ( ! empty( $profiles_raw ) ? $profiles_raw : array() as $row ) {
		$modes_by_surface[ $row['surface'] ] = $row['mode'];
	}
	// CSP mode => cross-pillar Status_Badge state, for the Layer 4 table
	// only. csp_policy_profiles.mode itself, and CSP's own dedicated-page
	// CSS/JS, are untouched -- this is a display-layer mapping.
	$csp_status_by_mode = array(
		'disabled'    => Status_Badge::STATE_DISABLED,
		'report-only' => Status_Badge::STATE_REPORT_ONLY,
		'enforce'     => Status_Badge::STATE_ACTIVE,
	);
	$csp_status_labels  = array(
		Status_Badge::STATE_DISABLED    => __( 'Disabled', 'vcns-security-automation-manager' ),
		Status_Badge::STATE_REPORT_ONLY => __( 'Report-only', 'vcns-security-automation-manager' ),
		Status_Badge::STATE_ACTIVE      => __( 'Active', 'vcns-security-automation-manager' ),
	);

	$automation_config = new Automation_Config();

	$pillars     = Pillar_Registry::pillars();
	$pillar_rows = Pillar_Registry::fetch_rows();

	// Certificates (Layer 5) -- reuses the same data sources already used by
	// page-certificates.php and Admin_UI::maybe_show_cert_failure_warning(),
	// no status computation duplicated here.
	$cert_store  = new Certificate_Store();
	$cert_config = $cert_store->get_config();
	$cert_latest = $cert_store->latest_certificate();
	$cert_run    = $this->plugin->cert_manager->last_run();

	$cert_domains_configured = ! empty( array_filter( (array) $cert_config['domains'] ) );
	if ( ! $cert_domains_configured ) {
		$cert_status_text  = __( 'Not configured', 'vcns-security-automation-manager' );
		$cert_status_color = 'inherit';
	} elseif ( 'failed' === $cert_run['status'] ) {
		/* translators: %s: failure detail message */
		$cert_status_text  = sprintf( __( 'Failed -- %s', 'vcns-security-automation-manager' ), $cert_run['detail'] );
		$cert_status_color = '#d63638';
	} elseif ( 'running' === $cert_run['status'] ) {
		$cert_status_text  = __( 'Issuing…', 'vcns-security-automation-manager' );
		$cert_status_color = 'inherit';
	} elseif ( null !== $cert_latest ) {
		/* translators: %s: certificate expiry date/time (UTC) */
		$cert_status_text  = sprintf( __( 'Active -- expires %s UTC', 'vcns-security-automation-manager' ), $cert_latest['not_after'] );
		$cert_status_color = '#00a32a';
	} else {
		$cert_status_text  = __( 'Configured -- issuance not yet attempted', 'vcns-security-automation-manager' );
		$cert_status_color = 'inherit';
	}
	$cert_manage_url = admin_url( 'admin.php?page=security-automation-manager-certificates' . ( 'never' !== $cert_run['status'] ? '&tab=renew' : '' ) );
}

// ── Recovery tab data ────────────────────────────────────────────────────────
$reset_result       = sanitize_text_field( wp_unslash( $_GET['wp_sam_reset'] ?? '' ) );
$restore_result     = sanitize_text_field( wp_unslash( $_GET['wp_sam_restore'] ?? '' ) );
$restore_reason     = rawurldecode( sanitize_text_field( wp_unslash( $_GET['wp_sam_restore_reason'] ?? '' ) ) );
$import_result      = sanitize_text_field( wp_unslash( $_GET['wp_sam_import'] ?? '' ) );
$import_reason      = rawurldecode( sanitize_text_field( wp_unslash( $_GET['wp_sam_import_reason'] ?? '' ) ) );
$downgrade_flag     = get_option( Rollback_Guard::DOWNGRADE_OPTION, array() );
$rollback_snapshots = Rollback_Guard::list_snapshots();
$status_badge       = static function ( string $status ): void {
	$labels = array(
		'pass'    => __( 'Pass', 'vcns-security-automation-manager' ),
		'warning' => __( 'Warning', 'vcns-security-automation-manager' ),
		'fail'    => __( 'Fail', 'vcns-security-automation-manager' ),
	);
	$label  = $labels[ $status ] ?? __( 'Unknown', 'vcns-security-automation-manager' );

	printf(
		'<span class="wp-sam-readiness-badge status-%1$s">%2$s</span>',
		esc_attr( $status ),
		esc_html( $label )
	);
};
?>
<div class="wrap wp-sam-wrap">
	<h1><?php esc_html_e( 'Security Automation Manager', 'vcns-security-automation-manager' ); ?></h1>

	<!-- ── Tabs ──────────────────────────────────────────────────────────── -->
	<nav class="nav-tab-wrapper wp-sam-tab-wrapper" role="tablist" aria-label="<?php esc_attr_e( 'Overview sections', 'vcns-security-automation-manager' ); ?>">
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

	<p class="description">
		<?php esc_html_e( 'This table covers Layer 4 (Browser Security Policies) and Layer 5 (Transport & Certificate Trust). Layer 1 (governance and operations) is covered by the Readiness, Recovery, and Updates tabs above. Layer 3 (continuous intelligence) is planned for a future phase and is not yet available.', 'vcns-security-automation-manager' ); ?>
	</p>

	<h2><?php esc_html_e( 'Layer 4: Browser Security Policies', 'vcns-security-automation-manager' ); ?></h2>
	<table class="widefat striped wp-sam-readiness-table">
		<thead>
			<tr>
				<th><?php esc_html_e( 'Pillar', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Status', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Automation', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Manage', 'vcns-security-automation-manager' ); ?></th>
			</tr>
		</thead>
		<tbody>
			<tr>
				<td>
					<strong><?php esc_html_e( 'Content Security Policy', 'vcns-security-automation-manager' ); ?></strong>
				</td>
				<td>
					<?php foreach ( $surfaces as $surface ) : ?>
						<?php $mode = $modes_by_surface[ $surface ] ?? 'disabled'; ?>
						<?php $state = $csp_status_by_mode[ $mode ] ?? Status_Badge::STATE_DISABLED; ?>
						<?php echo Status_Badge::render( $state, ucfirst( $surface ) . ': ' . ( $csp_status_labels[ $state ] ?? $mode ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Status_Badge::render() returns pre-escaped HTML. ?>
					<?php endforeach; ?>
				</td>
				<td>
					<?php foreach ( $surfaces as $surface ) : ?>
						<?php $automation_mode = $automation_config->for_surface( $surface )['mode']; ?>
						<?php echo Status_Badge::render_automation( ucfirst( $surface ) . ': ' . Automation_Config::mode_label( $automation_mode ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Status_Badge::render_automation() returns pre-escaped HTML. ?>
					<?php endforeach; ?>
				</td>
				<td>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=security-automation-manager-dashboard' ) ); ?>">
						<?php esc_html_e( 'Manage CSP', 'vcns-security-automation-manager' ); ?>
					</a>
				</td>
			</tr>
			<?php foreach ( $pillars as $pillar_key => $pillar ) : ?>
				<tr>
					<td>
						<strong><?php echo esc_html( $pillar['label'] ); ?></strong>
					</td>
					<td>
						<?php foreach ( $surfaces as $surface ) : ?>
							<?php $status = Pillar_Registry::resolve_status( $pillar_key, $pillar_rows[ $pillar_key ][ $surface ] ?? null ); ?>
							<?php echo Status_Badge::render( $status['state'], ucfirst( $surface ) . ': ' . $status['label'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Status_Badge::render() returns pre-escaped HTML. ?>
						<?php endforeach; ?>
					</td>
					<td>&mdash;</td>
					<td>
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=' . $pillar['page'] . ( isset( $pillar['tab'] ) ? '&tab=' . $pillar['tab'] : '' ) ) ); ?>">
							<?php
							echo esc_html(
								sprintf(
									/* translators: %s: pillar label, e.g. "X-Frame-Options" */
									__( 'Manage %s', 'vcns-security-automation-manager' ),
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
			<?php esc_html_e( 'Policy Audit', 'vcns-security-automation-manager' ); ?>
		</a>
	</p>

	<h2><?php esc_html_e( 'Layer 5: Transport & Certificate Trust', 'vcns-security-automation-manager' ); ?></h2>
	<table class="widefat striped wp-sam-readiness-table">
		<thead>
			<tr>
				<th><?php esc_html_e( 'Pillar', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Status', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Manage', 'vcns-security-automation-manager' ); ?></th>
			</tr>
		</thead>
		<tbody>
			<tr>
				<td>
					<strong><?php esc_html_e( 'Certificates', 'vcns-security-automation-manager' ); ?></strong>
				</td>
				<td>
					<strong style="color:<?php echo esc_attr( $cert_status_color ); ?>"><?php echo esc_html( $cert_status_text ); ?></strong>
				</td>
				<td>
					<a href="<?php echo esc_url( $cert_manage_url ); ?>">
						<?php esc_html_e( 'Manage Certificates', 'vcns-security-automation-manager' ); ?>
					</a>
				</td>
			</tr>
		</tbody>
	</table>

	<?php elseif ( 'readiness' === $tab ) : ?>

	<h2><?php esc_html_e( 'Plugin and Database', 'vcns-security-automation-manager' ); ?></h2>
	<table class="widefat striped wp-sam-readiness-table">
		<thead>
			<tr>
				<th scope="col"><?php esc_html_e( 'Check', 'vcns-security-automation-manager' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Value', 'vcns-security-automation-manager' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Status', 'vcns-security-automation-manager' ); ?></th>
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

	<h2><?php esc_html_e( 'Schema Health', 'vcns-security-automation-manager' ); ?></h2>
	<table class="widefat striped wp-sam-readiness-table">
		<thead>
			<tr>
				<th scope="col"><?php esc_html_e( 'Table', 'vcns-security-automation-manager' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Rows', 'vcns-security-automation-manager' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Status', 'vcns-security-automation-manager' ); ?></th>
			</tr>
		</thead>
		<tbody>
			<?php foreach ( $readiness['schema'] as $item ) : ?>
				<tr>
					<th scope="row"><code><?php echo esc_html( $item['table'] ); ?></code></th>
					<td>
						<?php
						echo null === $item['rows']
							? esc_html__( 'Missing', 'vcns-security-automation-manager' )
							: esc_html( (string) $item['rows'] );
						?>
					</td>
					<td><?php $status_badge( $item['status'] ); ?></td>
				</tr>
			<?php endforeach; ?>
		</tbody>
	</table>

	<h2><?php esc_html_e( 'Operational Health', 'vcns-security-automation-manager' ); ?></h2>
	<table class="widefat striped wp-sam-readiness-table">
		<thead>
			<tr>
				<th scope="col"><?php esc_html_e( 'Check', 'vcns-security-automation-manager' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Value', 'vcns-security-automation-manager' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Status', 'vcns-security-automation-manager' ); ?></th>
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

	<?php elseif ( 'recovery' === $tab ) : ?>

		<?php if ( 'success' === $reset_result ) : ?>
		<div class="notice notice-success is-dismissible">
			<p><?php esc_html_e( 'Security Automation Manager data has been reset and default profiles have been reseeded.', 'vcns-security-automation-manager' ); ?></p>
		</div>
	<?php elseif ( 'partial' === $reset_result ) : ?>
		<div class="notice notice-warning is-dismissible">
			<p><?php esc_html_e( 'Reset completed, but one or more plugin tables could not be cleared. Review schema health below.', 'vcns-security-automation-manager' ); ?></p>
		</div>
	<?php elseif ( 'failed' === $reset_result ) : ?>
		<div class="notice notice-error is-dismissible">
			<p><?php esc_html_e( 'Reset was not performed. Confirm the typed phrase and re-authenticate with your current WordPress password.', 'vcns-security-automation-manager' ); ?></p>
		</div>
	<?php endif; ?>

		<?php if ( 'success' === $import_result ) : ?>
		<div class="notice notice-success is-dismissible">
			<p><?php esc_html_e( 'Configuration imported.', 'vcns-security-automation-manager' ); ?></p>
		</div>
	<?php elseif ( 'failed' === $import_result ) : ?>
		<div class="notice notice-error is-dismissible">
			<p>
				<?php esc_html_e( 'Configuration was not imported.', 'vcns-security-automation-manager' ); ?>
				<?php echo '' !== $import_reason ? esc_html( $import_reason ) : ''; ?>
			</p>
		</div>
	<?php endif; ?>

	<h2 id="wp-sam-rollback"><?php esc_html_e( 'Rollback and Recovery', 'vcns-security-automation-manager' ); ?></h2>

		<?php if ( ! empty( $downgrade_flag ) && is_array( $downgrade_flag ) ) : ?>
	<div class="notice notice-error inline">
		<p>
			<strong><?php esc_html_e( 'Database schema is newer than the running plugin code.', 'vcns-security-automation-manager' ); ?></strong>
			<?php
			printf(
				/* translators: 1: installed database schema version, 2: currently running plugin code's schema version */
				esc_html__( 'Installed schema: v%1$d. Running code: v%2$d. No automatic migration has been attempted -- see "Manual recovery" below.', 'vcns-security-automation-manager' ),
				(int) ( $downgrade_flag['installed'] ?? 0 ),
				(int) ( $downgrade_flag['code'] ?? 0 )
			);
			?>
		</p>
	</div>
	<?php endif; ?>

		<?php if ( 'success' === $restore_result ) : ?>
	<div class="notice notice-success is-dismissible">
		<p><?php esc_html_e( 'Configuration snapshot restored.', 'vcns-security-automation-manager' ); ?></p>
	</div>
	<?php elseif ( 'failed' === $restore_result ) : ?>
	<div class="notice notice-error is-dismissible">
		<p>
			<?php esc_html_e( 'Snapshot was not restored.', 'vcns-security-automation-manager' ); ?>
			<?php echo '' !== $restore_reason ? esc_html( $restore_reason ) : ''; ?>
		</p>
	</div>
	<?php endif; ?>

	<p>
		<?php esc_html_e( 'This plugin cannot swap its own code back to an older release -- that happens at the WordPress/hosting level. What it can do: refuse to run a migration when the database is already ahead of the running code (see the warning above if that applies here), and let you undo a migration\'s data effects while staying on the current code, using an automatic snapshot taken immediately before every schema upgrade.', 'vcns-security-automation-manager' ); ?>
	</p>
	<p class="description">
		<?php
		printf(
			wp_kses(
				/* translators: %s: link to the rollback and recovery documentation */
				__( 'Snapshots cover policy profiles, source/hash approvals, other pillar profiles, dependency classifications, and certificate records -- never the audit log or violation history, which are append-only and never overwritten. For anything beyond what\'s here, including swapping plugin code itself, see %s.', 'vcns-security-automation-manager' ),
				array(
					'a' => array(
						'href'   => array(),
						'target' => array(),
						'rel'    => array(),
					),
				)
			),
			'<a href="https://github.com/vcns/security-automation-manager/blob/main/docs/rollback-and-recovery.md" target="_blank" rel="noopener noreferrer">' . esc_html__( 'the manual recovery guide', 'vcns-security-automation-manager' ) . '</a>'
		);
		?>
	</p>

		<?php if ( empty( $rollback_snapshots ) ) : ?>
	<p class="description"><?php esc_html_e( 'No snapshots yet -- one is taken automatically the next time a schema migration runs.', 'vcns-security-automation-manager' ); ?></p>
	<?php else : ?>
	<table class="widefat striped wp-sam-readiness-table" style="margin-top: 1em;">
		<thead>
			<tr>
				<th scope="col"><?php esc_html_e( 'Taken', 'vcns-security-automation-manager' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Migration', 'vcns-security-automation-manager' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Restorable now', 'vcns-security-automation-manager' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Action', 'vcns-security-automation-manager' ); ?></th>
			</tr>
		</thead>
		<tbody>
			<?php foreach ( $rollback_snapshots as $snapshot ) : ?>
			<tr>
				<td><?php echo esc_html( $snapshot['created_at'] ); ?></td>
				<td><?php echo esc_html( sprintf( 'v%1$d -> v%2$d', $snapshot['from_version'], $snapshot['to_version'] ) ); ?></td>
				<td>
					<?php if ( $snapshot['restorable'] ) : ?>
						<?php esc_html_e( 'Yes', 'vcns-security-automation-manager' ); ?>
					<?php else : ?>
						<?php esc_html_e( 'No -- schema has moved on since', 'vcns-security-automation-manager' ); ?>
					<?php endif; ?>
				</td>
				<td>
					<?php if ( $snapshot['restorable'] ) : ?>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:flex;align-items:center;gap:.5em;">
						<?php wp_nonce_field( 'wp_sam_restore_snapshot' ); ?>
						<input type="hidden" name="action" value="wp_sam_restore_snapshot">
						<input type="hidden" name="wp_sam_snapshot_id" value="<?php echo esc_attr( (string) $snapshot['id'] ); ?>">
						<label>
							<input type="checkbox" name="wp_sam_restore_confirmation" value="1" required>
							<?php esc_html_e( 'Confirm', 'vcns-security-automation-manager' ); ?>
						</label>
						<?php submit_button( __( 'Restore this snapshot', 'vcns-security-automation-manager' ), 'secondary small', '', false ); ?>
					</form>
					<?php else : ?>
						&mdash;
					<?php endif; ?>
				</td>
			</tr>
			<?php endforeach; ?>
		</tbody>
	</table>
	<?php endif; ?>

	<hr>

	<hr>

	<h2 id="wp-sam-portability"><?php esc_html_e( 'Export and Import Configuration', 'vcns-security-automation-manager' ); ?></h2>
	<p>
		<?php esc_html_e( 'Move administrator-authored configuration -- policy profiles, source/hash approvals, other pillar profiles, dependency classifications, certificate settings, and automation/reporting options -- to another site, or archive it outside the database. Never includes secrets, credentials, private key material, the audit log, or violation history.', 'vcns-security-automation-manager' ); ?>
	</p>

	<h3><?php esc_html_e( 'Export', 'vcns-security-automation-manager' ); ?></h3>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
		<?php wp_nonce_field( 'wp_sam_export_config' ); ?>
		<input type="hidden" name="action" value="wp_sam_export_config">
		<?php submit_button( __( 'Download configuration export', 'vcns-security-automation-manager' ), 'secondary', '', false ); ?>
	</form>

	<h3 style="margin-top: 1.5em;"><?php esc_html_e( 'Import', 'vcns-security-automation-manager' ); ?></h3>
	<p class="description">
		<?php esc_html_e( 'Importing replaces the current contents of every table covered by the export (see above) and overwrites the matching options. This cannot be undone by this feature -- take a configuration export of the current site first if you may want to go back.', 'vcns-security-automation-manager' ); ?>
	</p>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" enctype="multipart/form-data">
		<?php wp_nonce_field( 'wp_sam_import_config' ); ?>
		<input type="hidden" name="action" value="wp_sam_import_config">
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row">
					<label for="wp_sam_import_file"><?php esc_html_e( 'Configuration file', 'vcns-security-automation-manager' ); ?></label>
				</th>
				<td>
					<input type="file" id="wp_sam_import_file" name="wp_sam_import_file" accept="application/json" required>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Confirmation', 'vcns-security-automation-manager' ); ?></th>
				<td>
					<label>
						<input type="checkbox" name="wp_sam_import_confirmation" value="1" required>
						<?php esc_html_e( 'I understand this overwrites the matching configuration tables and options on this site.', 'vcns-security-automation-manager' ); ?>
					</label>
				</td>
			</tr>
		</table>
		<?php submit_button( __( 'Import configuration', 'vcns-security-automation-manager' ), 'delete' ); ?>
	</form>

	<hr>

	<h2 id="wp-sam-reset"><?php esc_html_e( 'Reset Plugin Data', 'vcns-security-automation-manager' ); ?></h2>
	<p>
		<?php esc_html_e( 'This clears every Security Automation Manager custom-table row and plugin-owned runtime option across the entire plugin -- not just CSP -- then reseeds the default policy profiles needed for a clean start.', 'vcns-security-automation-manager' ); ?>
	</p>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="wp-sam-reset-form">
		<?php wp_nonce_field( 'wp_sam_reset_data' ); ?>
		<input type="hidden" name="action" value="wp_sam_reset_data">
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row">
					<label for="wp_sam_current_password"><?php esc_html_e( 'Current password', 'vcns-security-automation-manager' ); ?></label>
				</th>
				<td>
					<input type="password" id="wp_sam_current_password" name="wp_sam_current_password" class="regular-text" autocomplete="current-password" required>
					<p class="description"><?php esc_html_e( 'Required to re-authenticate the currently logged-in administrator before destructive reset.', 'vcns-security-automation-manager' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row">
					<label for="wp_sam_reset_confirmation"><?php esc_html_e( 'Confirmation', 'vcns-security-automation-manager' ); ?></label>
				</th>
				<td>
					<input type="text" id="wp_sam_reset_confirmation" name="wp_sam_reset_confirmation" class="regular-text" pattern="RESET SAM PLUGIN DATA" required>
					<p class="description"><?php esc_html_e( 'Type RESET SAM PLUGIN DATA to wipe the entire plugin -- all pillars, not just CSP -- and start from a blank canvas.', 'vcns-security-automation-manager' ); ?></p>
				</td>
			</tr>
		</table>
		<?php submit_button( __( 'Reset Plugin Data', 'vcns-security-automation-manager' ), 'delete' ); ?>
	</form>

	<?php elseif ( 'updates' === $tab ) : ?>

		<?php
		$is_github_channel = 'github' === WP_SAM_DISTRIBUTION_CHANNEL;
		?>

	<table class="widefat striped wp-sam-readiness-table" style="margin-top: 1em;">
		<tbody>
			<tr>
				<th scope="row"><?php esc_html_e( 'Installed version', 'vcns-security-automation-manager' ); ?></th>
				<td><?php echo esc_html( WP_SAM_VERSION ); ?></td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Build channel', 'vcns-security-automation-manager' ); ?></th>
				<td>
					<?php
					if ( $is_github_channel ) {
						esc_html_e( 'VCNS GitHub', 'vcns-security-automation-manager' );
					} elseif ( 'wordpress-org' === WP_SAM_DISTRIBUTION_CHANNEL ) {
						esc_html_e( 'WordPress.org', 'vcns-security-automation-manager' );
					} else {
						esc_html_e( 'Development or unknown', 'vcns-security-automation-manager' );
					}
					?>
				</td>
			</tr>
		</tbody>
	</table>

		<?php if ( ! $is_github_channel ) : ?>

	<p class="description">
			<?php esc_html_e( 'This install updates through the WordPress.org plugin directory, the same mechanism as any other WordPress.org plugin. No custom updater runs in this build, and it never contacts any VCNS-operated update service.', 'vcns-security-automation-manager' ); ?>
	</p>

	<?php else : ?>

		<?php
		$updates_diagnostics = get_option( 'wp_sam_update_diagnostics', array() );
		$updates_diagnostics = is_array( $updates_diagnostics ) ? $updates_diagnostics : array();

		$updates_check_result_labels    = array(
			'success'          => __( 'Valid', 'vcns-security-automation-manager' ),
			'http_error'       => __( 'Failed -- could not reach the update endpoint', 'vcns-security-automation-manager' ),
			'invalid_manifest' => __( 'Failed -- manifest rejected (slug, version, host, or checksum format invalid)', 'vcns-security-automation-manager' ),
		);
		$updates_checksum_result_labels = array(
			'verified' => __( 'Verified', 'vcns-security-automation-manager' ),
			'mismatch' => __( 'Failed -- downloaded package did not match the declared checksum', 'vcns-security-automation-manager' ),
			'missing'  => __( 'Failed -- manifest did not declare a valid checksum', 'vcns-security-automation-manager' ),
		);
		$updates_applied_result_labels  = array(
			'success' => __( 'Succeeded', 'vcns-security-automation-manager' ),
			'failure' => __( 'Failed', 'vcns-security-automation-manager' ),
		);

		$updates_never             = __( 'Never', 'vcns-security-automation-manager' );
		$updates_none_recorded     = __( 'None recorded', 'vcns-security-automation-manager' );
		$updates_not_yet_attempted = __( 'Not yet attempted', 'vcns-security-automation-manager' );
		$updates_no_update_applied = __( 'No update applied yet', 'vcns-security-automation-manager' );

		$updates_kill_switch_defined = defined( 'WP_SAM_DISABLE_AUTO_UPDATE' );
		$updates_kill_switch_engaged = $updates_kill_switch_defined && (bool) constant( 'WP_SAM_DISABLE_AUTO_UPDATE' );

		$updates_available_version = (string) ( $updates_diagnostics['available_version'] ?? '' );
		$updates_pending           = '' !== $updates_available_version && version_compare( WP_SAM_VERSION, $updates_available_version, '<' );
		?>

	<table class="widefat striped wp-sam-readiness-table" style="margin-top: 1.5em;">
		<tbody>
			<tr>
				<th scope="row"><?php esc_html_e( 'Update manifest URL', 'vcns-security-automation-manager' ); ?></th>
				<td><code><?php echo esc_html( defined( 'WP_SAM_UPDATE_MANIFEST_URL' ) ? WP_SAM_UPDATE_MANIFEST_URL : '' ); ?></code></td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Available version', 'vcns-security-automation-manager' ); ?></th>
				<td>
					<?php if ( '' === $updates_available_version ) : ?>
						<?php esc_html_e( 'Unknown -- no successful check yet', 'vcns-security-automation-manager' ); ?>
					<?php elseif ( $updates_pending ) : ?>
						<?php echo esc_html( $updates_available_version ); ?> <strong>(<?php esc_html_e( 'update available', 'vcns-security-automation-manager' ); ?>)</strong>
					<?php else : ?>
						<?php echo esc_html( $updates_available_version ); ?> (<?php esc_html_e( 'up to date', 'vcns-security-automation-manager' ); ?>)
					<?php endif; ?>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Last successful update check', 'vcns-security-automation-manager' ); ?></th>
				<td><?php echo esc_html( (string) ( $updates_diagnostics['last_check_success_at'] ?? $updates_never ) ); ?></td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Last failed update check', 'vcns-security-automation-manager' ); ?></th>
				<td><?php echo esc_html( (string) ( $updates_diagnostics['last_check_failure_at'] ?? $updates_none_recorded ) ); ?></td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Manifest validation status', 'vcns-security-automation-manager' ); ?></th>
				<td><?php echo esc_html( $updates_check_result_labels[ $updates_diagnostics['last_check_result'] ?? '' ] ?? $updates_never ); ?></td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Package checksum verification status', 'vcns-security-automation-manager' ); ?></th>
				<td>
					<?php echo esc_html( $updates_checksum_result_labels[ $updates_diagnostics['last_checksum_result'] ?? '' ] ?? $updates_not_yet_attempted ); ?>
					<?php if ( ! empty( $updates_diagnostics['last_checksum_at'] ) ) : ?>
						<span class="description"> (<?php echo esc_html( (string) $updates_diagnostics['last_checksum_at'] ); ?>)</span>
					<?php endif; ?>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Last update result', 'vcns-security-automation-manager' ); ?></th>
				<td>
					<?php echo esc_html( $updates_applied_result_labels[ $updates_diagnostics['last_applied_result'] ?? '' ] ?? $updates_no_update_applied ); ?>
					<?php if ( ! empty( $updates_diagnostics['last_applied_at'] ) ) : ?>
						<span class="description"> (<?php echo esc_html( (string) $updates_diagnostics['last_applied_at'] ); ?>)</span>
					<?php endif; ?>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'WP_SAM_DISABLE_AUTO_UPDATE defined', 'vcns-security-automation-manager' ); ?></th>
				<td>
					<?php
					if ( ! $updates_kill_switch_defined ) {
						esc_html_e( 'No', 'vcns-security-automation-manager' );
					} elseif ( $updates_kill_switch_engaged ) {
						esc_html_e( 'Yes -- true', 'vcns-security-automation-manager' );
					} else {
						esc_html_e( 'Yes -- false', 'vcns-security-automation-manager' );
					}
					?>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Background updates', 'vcns-security-automation-manager' ); ?></th>
				<td>
					<?php
					if ( $updates_kill_switch_engaged ) {
						esc_html_e( 'Blocked by WP_SAM_DISABLE_AUTO_UPDATE.', 'vcns-security-automation-manager' );
					} else {
						esc_html_e( "Not blocked by this plugin. Still subject to WordPress' own per-plugin auto-update setting on the Plugins screen.", 'vcns-security-automation-manager' );
					}
					?>
				</td>
			</tr>
		</tbody>
	</table>

	<p class="description" style="margin-top: 1em;">
		<?php esc_html_e( 'This updater never transmits or stores any credential or secret -- the manifest above is a public JSON file, and package integrity is verified with a SHA-256 checksum published in that same public manifest.', 'vcns-security-automation-manager' ); ?>
	</p>

	<?php endif; ?>

	<?php else /* about */ : ?>

	<div class="wp-sam-about" style="margin-top: 1em;">
		<p>
			<?php esc_html_e( 'Security Automation Manager is built and maintained by VCNS Tech Ltd.', 'vcns-security-automation-manager' ); ?>
		</p>

		<h2><?php esc_html_e( 'Why we built this', 'vcns-security-automation-manager' ); ?></h2>
		<p>
			<?php esc_html_e( 'Most WordPress security plugins bundle a firewall, malware scanner, and login hardening -- and treat everything else a browser-facing site needs to lock down as an afterthought, if they touch it at all: Content Security Policy and the other browser security headers, which third-party scripts a site actually trusts, and whether its TLS certificate is even being watched for expiry. Everywhere else on the web these are standard practice; on WordPress they usually mean hand-editing .htaccess or a theme functions file, a manual cPanel certificate renewal reminder, or simply not being done, with no visibility into what actually breaks, no safe way to test before enforcing, and no audit trail of who approved what.', 'vcns-security-automation-manager' ); ?>
		</p>
		<p>
			<?php esc_html_e( 'We built this plugin to close that gap across every layer it covers: report-only rollout by default wherever a report-only mode is possible, browser-submitted violation reports turned into reviewable proposals, a reason-required decision ledger for every change, and automated ACME certificate issuance and renewal alongside it -- all native to WordPress, with no external dashboard or proprietary scanning service required to use the free tier.', 'vcns-security-automation-manager' ); ?>
		</p>

		<h2><?php esc_html_e( 'What this plugin covers', 'vcns-security-automation-manager' ); ?></h2>
		<p>
			<?php esc_html_e( 'This is not a single-purpose plugin -- it manages several largely independent layers under one roof, sharing the same admin, audit log, and reason-required decision workflow:', 'vcns-security-automation-manager' ); ?>
		</p>
		<ul style="list-style: disc; padding-left: 1.5em;">
			<li>
				<strong><?php esc_html_e( 'Content Security Policy', 'vcns-security-automation-manager' ); ?></strong>
				&nbsp;&mdash;
				<?php esc_html_e( 'the most capable pillar: per-surface profiles, nonce injection, automatic source discovery, violation reporting, and a full report-only-to-enforce review workflow.', 'vcns-security-automation-manager' ); ?>
			</li>
			<li>
				<strong><?php esc_html_e( 'Nine further HTTP security headers', 'vcns-security-automation-manager' ); ?></strong>
				&nbsp;&mdash;
				<?php esc_html_e( 'X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Strict-Transport-Security, Cross-Origin-Resource-Policy, Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy, and X-Permitted-Cross-Domain-Policies -- simpler per-surface pillars, two of which (Cross-Origin-Opener-Policy and Cross-Origin-Embedder-Policy) carry their own report-only learning workflow.', 'vcns-security-automation-manager' ); ?>
			</li>
			<li>
				<strong><?php esc_html_e( 'Page-rewrite protections', 'vcns-security-automation-manager' ); ?></strong>
				&nbsp;&mdash;
				<?php esc_html_e( 'Reverse Tabnabbing Protection, External Scripts (third-party script/stylesheet governance with Subresource Integrity), and Internal Script Integrity, which modify the rendered page itself rather than emit a header.', 'vcns-security-automation-manager' ); ?>
			</li>
			<li>
				<strong><?php esc_html_e( 'Certificates', 'vcns-security-automation-manager' ); ?></strong>
				&nbsp;&mdash;
				<?php esc_html_e( 'a free-standing ACME v2 (Let\'s Encrypt) TLS certificate manager: DNS-01 or HTTP-01 issuance, encrypted-at-rest credentials and private keys, and automatic renewal. Unrelated to the header pillars above beyond sharing the same admin and audit plumbing.', 'vcns-security-automation-manager' ); ?>
			</li>
		</ul>

		<h2><?php esc_html_e( 'The gap this fills', 'vcns-security-automation-manager' ); ?></h2>
		<p>
			<?php esc_html_e( 'CSP is widely regarded as one of the most effective defenses against cross-site scripting, but it is also one of the easiest security controls to deploy badly -- an overly strict policy silently breaks a theme or plugin, and an overly loose one defends nothing. The same trade-off shows up in miniature across every layer above: an unreviewed third-party script is a supply-chain risk, a lapsed certificate is a silent outage, and a header enabled without understanding what depends on the behaviour it changes can break a site as easily as it protects one. This plugin exists to make the safe middle path the easy path everywhere it applies: learn what a site actually needs before enforcing anything, automate what is safe to automate outright, and keep every decision reviewable.', 'vcns-security-automation-manager' ); ?>
		</p>

		<h2><?php esc_html_e( 'Learn more', 'vcns-security-automation-manager' ); ?></h2>
		<ul style="list-style: disc; padding-left: 1.5em;">
			<li>
				<a href="https://vcns.github.io/security-automation-manager/" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Help site', 'vcns-security-automation-manager' ); ?></a>
				&nbsp;&mdash;
				<?php esc_html_e( 'overview, getting started, and how the dashboard works', 'vcns-security-automation-manager' ); ?>
			</li>
			<li>
				<a href="https://vcns.github.io/security-automation-manager/user-guide.html" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'User guide', 'vcns-security-automation-manager' ); ?></a>
				&nbsp;&mdash;
				<?php esc_html_e( 'the full walkthrough: report-only rollout, reviewing proposals, and promoting to enforce', 'vcns-security-automation-manager' ); ?>
			</li>
			<li>
				<a href="https://vcns.github.io/security-automation-manager/faq.html" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'FAQ', 'vcns-security-automation-manager' ); ?></a>
			</li>
			<li>
				<a href="https://github.com/vcns/security-automation-manager" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'GitHub repository', 'vcns-security-automation-manager' ); ?></a>
				&nbsp;&mdash;
				<?php esc_html_e( 'source code, releases, and issue tracker', 'vcns-security-automation-manager' ); ?>
			</li>
			<li>
				<a href="https://vcns.tech" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'VCNS Tech Ltd', 'vcns-security-automation-manager' ); ?></a>
			</li>
		</ul>
	</div>

	<?php endif; ?>
</div>
