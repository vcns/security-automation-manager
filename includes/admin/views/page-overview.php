<?php
/**
 * Admin view: Security Automation Manager overview.
 * Landing page for the top-level menu. Tabs: Overview (per-pillar status
 * summary, the default), Getting Started (a suggested-order setup checklist
 * for a new install, live status per step, Phase 4G), Security Health (a
 * plain-language outcomes summary plus evidence export), Readiness
 * (plugin-specific schema/runtime checks only), Recovery (schema-downgrade
 * status, configuration snapshot restore, full data reset, and
 * configuration export/import), Exceptions (time-bound control
 * weakenings), Updates (installed version, active build channel,
 * manifest/checksum/applied-update diagnostics), and About (who built this
 * and why, with links to the public help site).
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
use WP_SAM\Intelligence\Baseline_Store;
use WP_SAM\Intelligence\Detector_Registry;
use WP_SAM\Intelligence\Recommendation_Engine;
use WP_SAM\Intelligence\Security_Health;
use WP_SAM\Intelligence\Traffic_Policy_Store;
use WP_SAM\Rollback_Guard;

global $wpdb;

// Current tab.
$tab          = isset( $_GET['tab'] ) ? sanitize_text_field( wp_unslash( $_GET['tab'] ) ) : 'overview';
$allowed_tabs = array( 'overview', 'getting-started', 'health', 'recommendations', 'readiness', 'recovery', 'exceptions', 'updates', 'about' );
if ( ! in_array( $tab, $allowed_tabs, true ) ) {
	$tab = 'overview';
}

$base_url = admin_url( 'admin.php?page=security-automation-manager' );
$tab_help = array(
	'overview'        => array(
		'label'       => __( 'Overview', 'vcns-security-automation-manager' ),
		'description' => __( 'At-a-glance status for every pillar this plugin manages, and a link to configure each one.', 'vcns-security-automation-manager' ),
	),
	'getting-started' => array(
		'label'       => __( 'Getting Started', 'vcns-security-automation-manager' ),
		'description' => __( 'A short, recommended-order checklist for a new install -- what to set up first, and why, with a live status for each step.', 'vcns-security-automation-manager' ),
	),
	'health'          => array(
		'label'       => __( 'Security Health', 'vcns-security-automation-manager' ),
		'description' => __( 'A plain-language summary of security outcomes -- enforcement, drift, certificates, dependencies, and open exceptions -- plus an evidence export for reviews and audits.', 'vcns-security-automation-manager' ),
	),
	'recommendations' => array(
		'label'       => __( 'Recommendations', 'vcns-security-automation-manager' ),
		'description' => __( 'Prioritised, evidence-backed suggestions drawn from what this plugin already observes -- what to review or consider changing, and why, never applied automatically.', 'vcns-security-automation-manager' ),
	),
	'readiness'       => array(
		'label'       => __( 'Readiness', 'vcns-security-automation-manager' ),
		'description' => __( 'Plugin-specific checks for schema, runtime defaults, and reporting configuration.', 'vcns-security-automation-manager' ),
	),
	'recovery'        => array(
		'label'       => __( 'Recovery', 'vcns-security-automation-manager' ),
		'description' => __( 'Schema-downgrade status, configuration snapshot restore, full data reset, and configuration export/import.', 'vcns-security-automation-manager' ),
	),
	'exceptions'      => array(
		'label'       => __( 'Exceptions', 'vcns-security-automation-manager' ),
		'description' => __( 'Controlled, time-bound weakenings of a control or surface -- each one requires a reason, an owner, and an expiry date, is auditable, and can be revoked immediately.', 'vcns-security-automation-manager' ),
	),
	'updates'         => array(
		'label'       => __( 'Updates', 'vcns-security-automation-manager' ),
		'description' => __( 'Installed version, active build channel, and (GitHub-channel builds only) manifest, checksum, and applied-update diagnostics.', 'vcns-security-automation-manager' ),
	),
	'about'           => array(
		'label'       => __( 'About', 'vcns-security-automation-manager' ),
		'description' => __( 'Who built this plugin, why, and where to find the full documentation.', 'vcns-security-automation-manager' ),
	),
);

// ── Health tab data ──────────────────────────────────────────────────────────
if ( 'health' === $tab ) {
	$security_health = ( new Security_Health() )->get_report();
}

// ── Recommendations tab data (Phase 4F) ─────────────────────────────────────
if ( 'recommendations' === $tab ) {
	$recommendations = ( new Recommendation_Engine() )->get_recommendations();
}

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

	// Continuous Intelligence (Layer 3) -- the Request Observation Framework
	// observes every request regardless of whether any detector is
	// registered; the count here only reflects whether anything is actually
	// evaluated against what it observes. Detector_Registry::
	// register_defaults() registers every core detector family by default;
	// this is 0 only on a build that skips that call.
	$intelligence_detector_count = count( Detector_Registry::keys() );
}

// ── Getting Started tab data ────────────────────────────────────────────────
// Each step's "done" signal reuses the same stores the relevant page itself
// reads from -- nothing new is computed or persisted here, and nothing on
// this tab changes what those stores actually decide (Observe/Enforce,
// enabled/disabled). This is read-only status, same as the Overview tab
// above; there is no dismiss/hide state to persist, so the checklist simply
// reflects live configuration on every page load.
if ( 'getting-started' === $tab ) {
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	$gs_csp_active_count = (int) $wpdb->get_var(
		"SELECT COUNT(*) FROM {$wpdb->prefix}csp_policy_profiles WHERE mode != 'disabled'"
	);

	$gs_pillar_rows   = Pillar_Registry::fetch_rows();
	$gs_any_pillar_on = false;
	foreach ( $gs_pillar_rows as $gs_pillar_surfaces ) {
		foreach ( $gs_pillar_surfaces as $gs_pillar_surface_row ) {
			if ( ! empty( $gs_pillar_surface_row['enabled'] ) ) {
				$gs_any_pillar_on = true;
				break 2;
			}
		}
	}

	$gs_traffic_policies      = ( new Traffic_Policy_Store() )->all();
	$gs_any_surface_enforcing = false;
	foreach ( $gs_traffic_policies as $gs_policy ) {
		if ( 'enforce' === $gs_policy['mode'] ) {
			$gs_any_surface_enforcing = true;
			break;
		}
	}

	$gs_baseline_captured  = null !== ( new Baseline_Store() )->get_current();
	$gs_certificate_issued = null !== ( new Certificate_Store() )->latest_certificate();
}

// ── Recovery tab data ────────────────────────────────────────────────────────
$reset_result       = sanitize_text_field( wp_unslash( $_GET['wp_sam_reset'] ?? '' ) );
$restore_result     = sanitize_text_field( wp_unslash( $_GET['wp_sam_restore'] ?? '' ) );
$restore_reason     = rawurldecode( sanitize_text_field( wp_unslash( $_GET['wp_sam_restore_reason'] ?? '' ) ) );
$import_result      = sanitize_text_field( wp_unslash( $_GET['wp_sam_import'] ?? '' ) );
$import_reason      = rawurldecode( sanitize_text_field( wp_unslash( $_GET['wp_sam_import_reason'] ?? '' ) ) );
$downgrade_flag     = get_option( Rollback_Guard::DOWNGRADE_OPTION, array() );
$rollback_snapshots = Rollback_Guard::list_snapshots();
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

	<p>
		<?php esc_html_e( "Everything below is organised into five layers, roughly ordered from foundational to visible: whether the plugin itself is healthy, how much it's trusted to act on your behalf, what it's watching for right now, what it tells visitors' browsers to do, and whether the connection to your site can be trusted in the first place. A problem in an earlier layer can undermine every layer listed after it -- if something here looks wrong, it's usually worth checking the layers above it first.", 'vcns-security-automation-manager' ); ?>
	</p>

	<h2><?php esc_html_e( 'Layer 1: Governance and Operations', 'vcns-security-automation-manager' ); ?></h2>
	<p class="description">
		<?php esc_html_e( "This is a check on the plugin itself, not on your site. It confirms the database matches what the running code expects, the environment meets requirements, and no schema rollback is stuck half-finished. Treat every other layer's status with suspicion until a Fail here is resolved -- they all read from the same tables this layer is verifying.", 'vcns-security-automation-manager' ); ?>
	</p>
	<table class="widefat striped wp-sam-readiness-table">
		<thead>
			<tr>
				<th><?php esc_html_e( 'Area', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Status', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Manage', 'vcns-security-automation-manager' ); ?></th>
			</tr>
		</thead>
		<tbody>
			<tr>
				<td><strong><?php esc_html_e( 'Readiness', 'vcns-security-automation-manager' ); ?></strong></td>
				<td>
					<?php
					$layer1_readiness_items  = array_merge( $readiness['plugin'], $readiness['schema'], $readiness['health'] );
					$layer1_readiness_status = 'pass';
					foreach ( $layer1_readiness_items as $layer1_item ) {
						if ( 'fail' === $layer1_item['status'] ) {
							$layer1_readiness_status = 'fail';
							break;
						}
						if ( 'warning' === $layer1_item['status'] ) {
							$layer1_readiness_status = 'warning';
						}
					}
					echo Status_Badge::render_outcome( $layer1_readiness_status ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Status_Badge::render_outcome() returns pre-escaped HTML.
					?>
				</td>
				<td>
					<a href="<?php echo esc_url( add_query_arg( 'tab', 'readiness', $base_url ) ); ?>">
						<?php esc_html_e( 'View Readiness', 'vcns-security-automation-manager' ); ?>
					</a>
				</td>
			</tr>
			<tr>
				<td><strong><?php esc_html_e( 'Recovery', 'vcns-security-automation-manager' ); ?></strong></td>
				<td><?php echo Status_Badge::render_outcome( empty( $downgrade_flag ) ? 'pass' : 'fail' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></td>
				<td>
					<a href="<?php echo esc_url( add_query_arg( 'tab', 'recovery', $base_url ) ); ?>">
						<?php esc_html_e( 'View Recovery', 'vcns-security-automation-manager' ); ?>
					</a>
				</td>
			</tr>
			<tr>
				<td><strong><?php esc_html_e( 'Updates', 'vcns-security-automation-manager' ); ?></strong></td>
				<td>
					<?php
					echo esc_html(
						'github' === WP_SAM_DISTRIBUTION_CHANNEL
							? __( 'GitHub channel', 'vcns-security-automation-manager' )
							: __( 'WordPress.org channel', 'vcns-security-automation-manager' )
					);
					?>
				</td>
				<td>
					<a href="<?php echo esc_url( add_query_arg( 'tab', 'updates', $base_url ) ); ?>">
						<?php esc_html_e( 'View Updates', 'vcns-security-automation-manager' ); ?>
					</a>
				</td>
			</tr>
		</tbody>
	</table>

	<h2><?php esc_html_e( 'Layer 2: Controlled Automation', 'vcns-security-automation-manager' ); ?></h2>
	<p class="description">
		<?php esc_html_e( 'Writing a Content Security Policy by hand means listing every script, style, and font your site is allowed to load -- get it wrong and you either break the site or leave a gap wide open. Deterministic automation builds that list for you from what your site is actually running (its active theme, plugins, and known integrations), worked out separately for each surface below, so a strict policy can exist here without you writing it line by line.', 'vcns-security-automation-manager' ); ?>
	</p>
	<table class="widefat striped wp-sam-readiness-table">
		<thead>
			<tr>
				<th><?php esc_html_e( 'Area', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Status', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Manage', 'vcns-security-automation-manager' ); ?></th>
			</tr>
		</thead>
		<tbody>
			<tr>
				<td><strong><?php esc_html_e( 'CSP Deterministic Automation', 'vcns-security-automation-manager' ); ?></strong></td>
				<td>
					<?php foreach ( $surfaces as $surface ) : ?>
						<?php $automation_mode = $automation_config->for_surface( $surface )['mode']; ?>
						<?php echo Status_Badge::render_automation( ucfirst( $surface ) . ': ' . Automation_Config::mode_label( $automation_mode ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Status_Badge::render_automation() returns pre-escaped HTML. ?>
					<?php endforeach; ?>
				</td>
				<td>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=security-automation-manager-dashboard&tab=settings' ) ); ?>">
						<?php esc_html_e( 'Manage Automation Settings', 'vcns-security-automation-manager' ); ?>
					</a>
				</td>
			</tr>
		</tbody>
	</table>

	<h2><?php esc_html_e( 'Layer 3: Continuous Intelligence', 'vcns-security-automation-manager' ); ?></h2>
	<p class="description">
		<?php esc_html_e( 'Every request your site receives passes through a set of pattern-matching detectors that recognise the signature of common attacks -- SQL injection attempts, path traversal, malicious bots, and more. Each detector can simply watch and record evidence, or actively block, entirely under your control from the Continuous Intelligence page; the row below just shows how many are switched on right now.', 'vcns-security-automation-manager' ); ?>
	</p>
	<table class="widefat striped wp-sam-readiness-table">
		<thead>
			<tr>
				<th><?php esc_html_e( 'Area', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Status', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Manage', 'vcns-security-automation-manager' ); ?></th>
			</tr>
		</thead>
		<tbody>
			<tr>
				<td><strong><?php esc_html_e( 'Request observation, detectors, and traffic intelligence', 'vcns-security-automation-manager' ); ?></strong></td>
				<td>
					<?php if ( $intelligence_detector_count > 0 ) : ?>
						<?php
						echo Status_Badge::render( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- helper escapes internally.
							Status_Badge::STATE_ACTIVE,
							__( 'Observing', 'vcns-security-automation-manager' ),
							sprintf(
								/* translators: %d: number of registered detectors */
								_n( '%d detector registered.', '%d detectors registered.', $intelligence_detector_count, 'vcns-security-automation-manager' ),
								$intelligence_detector_count
							)
						);
						?>
					<?php else : ?>
						<?php
						echo Status_Badge::render( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
							Status_Badge::STATE_ACTIVE,
							__( 'Observing', 'vcns-security-automation-manager' ),
							__( 'Every request is observed and classified; no detectors are registered yet, so nothing is currently evaluated against them.', 'vcns-security-automation-manager' )
						);
						?>
					<?php endif; ?>
				</td>
				<td>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=security-automation-manager-intelligence' ) ); ?>">
						<?php esc_html_e( 'View Continuous Intelligence', 'vcns-security-automation-manager' ); ?>
					</a>
				</td>
			</tr>
		</tbody>
	</table>

	<h2><?php esc_html_e( 'Layer 4: Browser Security Policies', 'vcns-security-automation-manager' ); ?></h2>
	<p class="description">
		<?php esc_html_e( "These are instructions sent to every visitor's browser, telling it how to defend your site on their end -- for example, refusing to run a script you haven't approved, or refusing to let another site frame your pages inside a hidden iframe for a clickjacking attack. Content Security Policy is the most capable of these; the rest are narrower, single-purpose headers. Most can run in report-only mode first, so you can see what would have been blocked before anything actually is.", 'vcns-security-automation-manager' ); ?>
	</p>
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
	<p class="description">
		<?php esc_html_e( 'Every layer above assumes visitors reach your site over a trusted, encrypted connection -- this is where that trust comes from. If a TLS certificate expires or was never issued, browsers show visitors a warning page before any of your other protections get a chance to matter.', 'vcns-security-automation-manager' ); ?>
	</p>
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

	<?php elseif ( 'getting-started' === $tab ) : ?>

	<p>
		<?php esc_html_e( "This is a suggested order, not a requirement -- nothing here is enforced by the plugin, and skipping a step or doing them in a different order won't break anything. It exists because this plugin covers a lot of ground (five different kinds of protection, thirty-plus admin screens), and a brand-new install with everything still at its default is a reasonable place to feel lost about where to start.", 'vcns-security-automation-manager' ); ?>
	</p>
	<p class="description">
		<?php esc_html_e( "Continuous Intelligence (request observation and detector classification) needs no setup at all -- it's already watching every request in the background from the moment this plugin activates, purely in Observe mode, so there's nothing to turn on for it below. The steps here are the parts that genuinely need a decision from you.", 'vcns-security-automation-manager' ); ?>
	</p>

	<table class="widefat striped wp-sam-readiness-table" style="margin-top: 1.5em;">
		<thead>
			<tr>
				<th style="width:32%"><?php esc_html_e( 'Step', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Status', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Go there', 'vcns-security-automation-manager' ); ?></th>
			</tr>
		</thead>
		<tbody>
			<tr>
				<td>
					<strong><?php esc_html_e( '1. Configure Content Security Policy', 'vcns-security-automation-manager' ); ?></strong>
					<p class="description" style="margin:0.3em 0 0;">
						<?php esc_html_e( 'The most capable protection this plugin offers, and the one most worth setting up first. It starts in report-only mode, learning what your site actually loads before it ever blocks anything.', 'vcns-security-automation-manager' ); ?>
					</p>
				</td>
				<td>
					<?php echo Status_Badge::render( $gs_csp_active_count > 0 ? Status_Badge::STATE_ACTIVE : Status_Badge::STATE_NOT_CONFIGURED, $gs_csp_active_count > 0 ? __( 'In progress or active', 'vcns-security-automation-manager' ) : __( 'Not started', 'vcns-security-automation-manager' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Status_Badge::render() returns pre-escaped HTML. ?>
				</td>
				<td>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=security-automation-manager-dashboard' ) ); ?>">
						<?php esc_html_e( 'CSP Dashboard', 'vcns-security-automation-manager' ); ?>
					</a>
				</td>
			</tr>
			<tr>
				<td>
					<strong><?php esc_html_e( '2. Turn on the other header pillars', 'vcns-security-automation-manager' ); ?></strong>
					<p class="description" style="margin:0.3em 0 0;">
						<?php esc_html_e( 'Fourteen further headers, each an independent on/off switch per surface. Unlike CSP, most need no learning period, so most are safe to switch on straight away -- see the Layer 4 table on the Overview tab for the full list and current status of each.', 'vcns-security-automation-manager' ); ?>
					</p>
				</td>
				<td>
					<?php echo Status_Badge::render( $gs_any_pillar_on ? Status_Badge::STATE_ACTIVE : Status_Badge::STATE_NOT_CONFIGURED, $gs_any_pillar_on ? __( 'At least one enabled', 'vcns-security-automation-manager' ) : __( 'None enabled yet', 'vcns-security-automation-manager' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Status_Badge::render() returns pre-escaped HTML. ?>
				</td>
				<td>
					<a href="<?php echo esc_url( add_query_arg( 'tab', 'overview', $base_url ) ); ?>">
						<?php esc_html_e( 'Overview -- Layer 4', 'vcns-security-automation-manager' ); ?>
					</a>
				</td>
			</tr>
			<tr>
				<td>
					<strong><?php esc_html_e( '3. Review Traffic Controls', 'vcns-security-automation-manager' ); ?></strong>
					<p class="description" style="margin:0.3em 0 0;">
						<?php esc_html_e( 'Rate limiting and progressive blocking are already observing every request on every surface, same as Continuous Intelligence -- nothing is actually blocked until you promote a surface from Observe to Enforce.', 'vcns-security-automation-manager' ); ?>
					</p>
				</td>
				<td>
					<?php echo Status_Badge::render( $gs_any_surface_enforcing ? Status_Badge::STATE_ACTIVE : Status_Badge::STATE_NOT_CONFIGURED, $gs_any_surface_enforcing ? __( 'At least one surface enforcing', 'vcns-security-automation-manager' ) : __( 'Every surface still Observe', 'vcns-security-automation-manager' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Status_Badge::render() returns pre-escaped HTML. ?>
				</td>
				<td>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=security-automation-manager-traffic' ) ); ?>">
						<?php esc_html_e( 'Traffic Controls', 'vcns-security-automation-manager' ); ?>
					</a>
				</td>
			</tr>
			<tr>
				<td>
					<strong><?php esc_html_e( '4. Capture a security baseline', 'vcns-security-automation-manager' ); ?></strong>
					<p class="description" style="margin:0.3em 0 0;">
						<?php esc_html_e( "Answers \"what changed?\" from this point forward. Worth doing once you're happy with the configuration from the first three steps, so later drift has something real to compare against.", 'vcns-security-automation-manager' ); ?>
					</p>
				</td>
				<td>
					<?php echo Status_Badge::render( $gs_baseline_captured ? Status_Badge::STATE_ACTIVE : Status_Badge::STATE_NOT_CONFIGURED, $gs_baseline_captured ? __( 'Captured', 'vcns-security-automation-manager' ) : __( 'Not captured yet', 'vcns-security-automation-manager' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Status_Badge::render() returns pre-escaped HTML. ?>
				</td>
				<td>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=security-automation-manager-baseline' ) ); ?>">
						<?php esc_html_e( 'Baseline & Drift', 'vcns-security-automation-manager' ); ?>
					</a>
				</td>
			</tr>
			<tr>
				<td>
					<strong><?php esc_html_e( '5. Issue a free TLS certificate (optional)', 'vcns-security-automation-manager' ); ?></strong>
					<p class="description" style="margin:0.3em 0 0;">
						<?php esc_html_e( "Skip this one if your host already provides HTTPS some other way -- it's only relevant if you want this plugin itself to issue and renew the certificate.", 'vcns-security-automation-manager' ); ?>
					</p>
				</td>
				<td>
					<?php echo Status_Badge::render( $gs_certificate_issued ? Status_Badge::STATE_ACTIVE : Status_Badge::STATE_NOT_CONFIGURED, $gs_certificate_issued ? __( 'Issued', 'vcns-security-automation-manager' ) : __( 'Not configured', 'vcns-security-automation-manager' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Status_Badge::render() returns pre-escaped HTML. ?>
				</td>
				<td>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=security-automation-manager-certificates' ) ); ?>">
						<?php esc_html_e( 'Certificates', 'vcns-security-automation-manager' ); ?>
					</a>
				</td>
			</tr>
		</tbody>
	</table>

	<?php elseif ( 'readiness' === $tab ) : ?>

	<p>
		<?php esc_html_e( "These checks are about the plugin itself, not your site's security posture -- they confirm the database schema is current, required tables exist, and the runtime environment (PHP version, required extensions, WordPress version) meets what this plugin needs to run correctly. A Fail here means something needs fixing before the rest of this plugin can be trusted; a Warning is usually safe to leave for now, but worth understanding.", 'vcns-security-automation-manager' ); ?>
	</p>

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
					<td><?php echo Status_Badge::render_outcome( $item['status'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Status_Badge::render_outcome() returns pre-escaped HTML. ?></td>
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
					<td><?php echo Status_Badge::render_outcome( $item['status'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Status_Badge::render_outcome() returns pre-escaped HTML. ?></td>
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
					<td><?php echo Status_Badge::render_outcome( $item['status'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Status_Badge::render_outcome() returns pre-escaped HTML. ?></td>
				</tr>
			<?php endforeach; ?>
		</tbody>
	</table>

	<?php elseif ( 'health' === $tab ) : ?>

	<p>
		<?php esc_html_e( 'This is the plain-language version of everything else in this plugin: are your defenses actually enforcing, is anything drifting away from your known-good baseline, are certificates on track to renew, and are there any open exceptions somebody still needs to review? Hover the info icon next to a row for the detail behind its status.', 'vcns-security-automation-manager' ); ?>
	</p>
	<p class="description">
		<?php
		printf(
			/* translators: %d: health-model version number */
			esc_html__( 'Health model version %d.', 'vcns-security-automation-manager' ),
			(int) Security_Health::MODEL_VERSION
		);
		?>
	</p>

	<table class="widefat striped wp-sam-readiness-table">
		<thead>
			<tr>
				<th scope="col"><?php esc_html_e( 'Check', 'vcns-security-automation-manager' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Value', 'vcns-security-automation-manager' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Status', 'vcns-security-automation-manager' ); ?></th>
			</tr>
		</thead>
		<tbody>
			<?php foreach ( $security_health as $item ) : ?>
				<tr>
					<th scope="row">
						<?php echo esc_html( $item['label'] ); ?>
						<?php if ( '' !== $item['detail'] ) : ?>
						<span class="dashicons dashicons-info-outline wp-sam-meta-icon" tabindex="0">
							<span class="wp-sam-meta-popover" role="tooltip"><?php echo esc_html( $item['detail'] ); ?></span>
						</span>
						<?php endif; ?>
					</th>
					<td><?php echo esc_html( (string) $item['value'] ); ?></td>
					<td><?php echo Status_Badge::render_outcome( $item['status'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Status_Badge::render_outcome() returns pre-escaped HTML. ?></td>
				</tr>
			<?php endforeach; ?>
		</tbody>
	</table>

	<h2 style="margin-top:2em"><?php esc_html_e( 'Evidence Export', 'vcns-security-automation-manager' ); ?></h2>
	<p class="description">
		<?php esc_html_e( 'Downloads a JSON snapshot of currently-configured controls, open exceptions, certificate state, baseline/drift status, and recent audit history -- useful for a security review, an MSP report, or audit preparation. This is evidence to support a review, not a compliance certification. The export includes a checksum so later alteration can be detected.', 'vcns-security-automation-manager' ); ?>
	</p>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
		<?php wp_nonce_field( 'wp_sam_export_evidence' ); ?>
		<input type="hidden" name="action" value="wp_sam_export_evidence" />
		<p>
			<label for="wp_sam_evidence_period_from"><?php esc_html_e( 'Reporting period (optional):', 'vcns-security-automation-manager' ); ?></label>
			<input type="date" id="wp_sam_evidence_period_from" name="period_from">
			<?php esc_html_e( 'to', 'vcns-security-automation-manager' ); ?>
			<input type="date" name="period_to">
			<span class="description"><?php esc_html_e( 'Bounds only the recent-audit-history section; every other section is a snapshot of current configuration, which has no date range to narrow. Leave both blank for the full audit history.', 'vcns-security-automation-manager' ); ?></span>
		</p>
		<?php submit_button( __( 'Download Evidence Export', 'vcns-security-automation-manager' ), 'primary', '', false ); ?>
	</form>

	<?php elseif ( 'recommendations' === $tab ) : ?>

	<p>
		<?php esc_html_e( 'Each suggestion below is generated from evidence this plugin already collects elsewhere -- nothing here is a new signal source. Acting on one always means going to the relevant page yourself; nothing is ever applied automatically. A recommendation you dismiss stays hidden until the evidence behind it actually changes.', 'vcns-security-automation-manager' ); ?>
	</p>

		<?php if ( empty( $recommendations ) ) : ?>
	<p class="description"><?php esc_html_e( 'Nothing to suggest right now -- either everything already looks reasonable, or this build\'s rule catalogue doesn\'t cover your current configuration yet. This grows over time as more rules are added.', 'vcns-security-automation-manager' ); ?></p>
	<?php else : ?>
	<table class="widefat striped wp-sam-readiness-table">
		<thead>
			<tr>
				<th><?php esc_html_e( 'Recommendation', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Risk', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Affected area', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Action', 'vcns-security-automation-manager' ); ?></th>
			</tr>
		</thead>
		<tbody>
			<?php
			$recommendation_risk_status = array(
				'critical' => 'fail',
				'high'     => 'warning',
				'medium'   => 'warning',
				'low'      => 'info',
			);
			$recommendation_risk_label  = array(
				'critical' => __( 'Critical risk', 'vcns-security-automation-manager' ),
				'high'     => __( 'High risk', 'vcns-security-automation-manager' ),
				'medium'   => __( 'Medium risk', 'vcns-security-automation-manager' ),
				'low'      => __( 'Low risk', 'vcns-security-automation-manager' ),
			);
			?>
			<?php foreach ( $recommendations as $recommendation ) : ?>
			<tr>
				<td>
					<strong><?php echo esc_html( $recommendation['observed'] ); ?></strong>
					<p class="description" style="margin:0.3em 0 0;"><?php echo esc_html( $recommendation['why_it_matters'] ); ?></p>
					<p class="description" style="margin:0.3em 0 0;">
						<?php
						echo esc_html(
							sprintf(
								/* translators: 1: recommended action, 2: rollback position */
								__( 'Suggested: %1$s. %2$s', 'vcns-security-automation-manager' ),
								$recommendation['recommended_action'],
								$recommendation['rollback_position']
							)
						);
						?>
					</p>
				</td>
				<td>
					<?php
					$risk = (string) $recommendation['risk'];
					echo Status_Badge::render_outcome( $recommendation_risk_status[ $risk ] ?? 'info', $recommendation_risk_label[ $risk ] ?? ucfirst( $risk ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Status_Badge::render_outcome() returns pre-escaped HTML.
					?>
				</td>
				<td>
					<?php
					echo esc_html(
						implode(
							' / ',
							array_filter( array( $recommendation['layer'], $recommendation['pillar'] ?? null, $recommendation['surface'] ?? null ) )
						)
					);
					?>
				</td>
				<td>
					<a href="<?php echo esc_url( $recommendation['cta_url'] ); ?>"><?php esc_html_e( 'Go there', 'vcns-security-automation-manager' ); ?></a>
					<?php if ( ! empty( $recommendation['dismissible'] ) ) : ?>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:0.5em;display:flex;gap:0.3em;align-items:center;">
						<?php wp_nonce_field( 'wp_sam_dismiss_recommendation' ); ?>
						<input type="hidden" name="action" value="wp_sam_dismiss_recommendation" />
						<input type="hidden" name="recommendation_key" value="<?php echo esc_attr( (string) $recommendation['key'] ); ?>" />
						<input type="text" name="reason" placeholder="<?php esc_attr_e( 'Reason (required)', 'vcns-security-automation-manager' ); ?>" required style="width:14em;" />
						<?php submit_button( __( 'Dismiss', 'vcns-security-automation-manager' ), 'secondary small', '', false ); ?>
					</form>
					<?php endif; ?>
				</td>
			</tr>
			<?php endforeach; ?>
		</tbody>
	</table>
	<?php endif; ?>

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
	<?php elseif ( 'partial' === $restore_result ) : ?>
	<div class="notice notice-warning is-dismissible">
		<p>
			<?php esc_html_e( 'Snapshot restored, but one or more tables in it were missing from the live database and could not be restored:', 'vcns-security-automation-manager' ); ?>
			<?php echo '' !== $restore_reason ? esc_html( $restore_reason ) : ''; ?>
		</p>
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
				__( 'Snapshots cover policy profiles, source/hash approvals, other pillar profiles, dependency classifications, certificate records, time-bound exceptions, and the automation-posture option -- never the audit log, violation history, or policy-change decision ledger, which are append-only and never overwritten. For anything beyond what\'s here, including swapping plugin code itself, see %s.', 'vcns-security-automation-manager' ),
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
						<?php $snapshot_contents = Rollback_Guard::snapshot_contents( $snapshot['id'] ); ?>
						<?php if ( ! empty( $snapshot_contents ) ) : ?>
					<details style="margin-bottom:.5em">
						<summary style="cursor:pointer"><?php esc_html_e( 'Preview what this would overwrite', 'vcns-security-automation-manager' ); ?></summary>
						<ul style="margin:.5em 0 0 1.5em;list-style:disc">
							<?php foreach ( $snapshot_contents['tables'] as $table_suffix => $row_count ) : ?>
							<li>
								<?php
								printf(
									/* translators: 1: table name, 2: number of rows */
									esc_html( _n( '%1$s: %2$d row', '%1$s: %2$d rows', $row_count, 'vcns-security-automation-manager' ) ),
									esc_html( $table_suffix ),
									(int) $row_count
								);
								?>
							</li>
							<?php endforeach; ?>
							<?php if ( ! empty( $snapshot_contents['options'] ) ) : ?>
							<li><?php echo esc_html( sprintf( /* translators: %s: comma-separated option names */ __( 'Options: %s', 'vcns-security-automation-manager' ), implode( ', ', $snapshot_contents['options'] ) ) ); ?></li>
							<?php endif; ?>
						</ul>
					</details>
					<?php endif; ?>
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

	<?php elseif ( 'exceptions' === $tab ) : ?>

		<?php
		$exception_store = new \WP_SAM\Intelligence\Exception_Store();
		$exceptions      = $exception_store->all();

		$exception_errors = get_transient( 'wp_sam_exception_errors_' . get_current_user_id() );
		$exception_errors = is_array( $exception_errors ) ? $exception_errors : array();
		$exception_input  = get_transient( 'wp_sam_exception_input_' . get_current_user_id() );
		$exception_input  = is_array( $exception_input ) ? $exception_input : array();
		delete_transient( 'wp_sam_exception_errors_' . get_current_user_id() );
		delete_transient( 'wp_sam_exception_input_' . get_current_user_id() );

		$exception_form = array_merge(
			array(
				'control'                 => '',
				'surface'                 => '',
				'weaker_value'            => '',
				'business_justification'  => '',
				'technical_justification' => '',
				'owner'                   => '',
				'approver'                => '',
				'compensating_control'    => '',
				'risk_classification'     => 'medium',
				'reference'               => '',
				'is_privileged_override'  => false,
				'expiry_date'             => '',
			),
			$exception_input
		);

		$exception_risk_labels   = array(
			'low'    => __( 'Low', 'vcns-security-automation-manager' ),
			'medium' => __( 'Medium', 'vcns-security-automation-manager' ),
			'high'   => __( 'High', 'vcns-security-automation-manager' ),
		);
		$exception_status_labels = array(
			'active'  => __( 'Active', 'vcns-security-automation-manager' ),
			'expired' => __( 'Expired', 'vcns-security-automation-manager' ),
			'revoked' => __( 'Revoked', 'vcns-security-automation-manager' ),
		);
		?>

		<p class="description">
			<?php esc_html_e( 'Sometimes a control genuinely needs to be weakened for a specific surface -- a legacy integration, a third-party embed. Record it here as a controlled, auditable exception rather than a silent override: every exception requires a reason and an owner, expires on its own unless a privileged override is used, and can be revoked immediately. Every creation, extension, and revocation is written to the audit log.', 'vcns-security-automation-manager' ); ?>
		</p>

		<?php if ( ! empty( $exception_errors ) ) : ?>
		<div class="notice notice-error inline" style="padding:12px 16px;margin:1em 0;">
			<p style="margin-top:0"><strong><?php esc_html_e( 'Exception not saved:', 'vcns-security-automation-manager' ); ?></strong></p>
			<ul style="margin-bottom:0;list-style:disc;padding-left:1.5em">
				<?php foreach ( $exception_errors as $exception_error ) : ?>
				<li><?php echo esc_html( $exception_error ); ?></li>
				<?php endforeach; ?>
			</ul>
		</div>
		<?php endif; ?>

		<table class="widefat fixed striped wp-sam-violations-table" style="margin-top:1em">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Control', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Surface', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Owner', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Risk', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Status', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Expires', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Actions', 'vcns-security-automation-manager' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $exceptions as $exception ) : ?>
				<tr>
					<td><?php echo esc_html( (string) $exception['control'] ); ?></td>
					<td><?php echo esc_html( '' !== (string) $exception['surface'] ? ucfirst( (string) $exception['surface'] ) : __( 'All', 'vcns-security-automation-manager' ) ); ?></td>
					<td><?php echo esc_html( (string) $exception['owner'] ); ?></td>
					<td><?php echo esc_html( $exception_risk_labels[ $exception['risk_classification'] ] ?? (string) $exception['risk_classification'] ); ?></td>
					<td><?php echo esc_html( $exception_status_labels[ $exception['review_status'] ] ?? (string) $exception['review_status'] ); ?></td>
					<td><?php echo esc_html( ! empty( $exception['expiry_date'] ) ? (string) $exception['expiry_date'] : __( 'Never (privileged override)', 'vcns-security-automation-manager' ) ); ?></td>
					<td style="white-space:nowrap">
					<?php if ( 'active' === $exception['review_status'] ) : ?>
						<details style="display:inline-block">
							<summary style="cursor:pointer;display:inline"><?php esc_html_e( 'Extend', 'vcns-security-automation-manager' ); ?></summary>
							<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:6px">
								<?php wp_nonce_field( 'wp_sam_exception_extend' ); ?>
								<input type="hidden" name="action" value="wp_sam_exception_extend">
								<input type="hidden" name="exception_id" value="<?php echo esc_attr( (string) $exception['id'] ); ?>">
								<input type="date" name="new_expiry_date" required>
								<input type="text" name="reason" placeholder="<?php esc_attr_e( 'Reason for extending', 'vcns-security-automation-manager' ); ?>" required style="width:100%;max-width:220px">
								<button type="submit" class="button button-small"><?php esc_html_e( 'Extend', 'vcns-security-automation-manager' ); ?></button>
							</form>
						</details>
						<details style="display:inline-block;margin-left:6px">
							<summary style="cursor:pointer;display:inline"><?php esc_html_e( 'Revoke', 'vcns-security-automation-manager' ); ?></summary>
							<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:6px">
								<?php wp_nonce_field( 'wp_sam_exception_revoke' ); ?>
								<input type="hidden" name="action" value="wp_sam_exception_revoke">
								<input type="hidden" name="exception_id" value="<?php echo esc_attr( (string) $exception['id'] ); ?>">
								<input type="text" name="reason" placeholder="<?php esc_attr_e( 'Reason for revoking', 'vcns-security-automation-manager' ); ?>" required style="width:100%;max-width:220px">
								<button type="submit" class="button button-small"><?php esc_html_e( 'Revoke now', 'vcns-security-automation-manager' ); ?></button>
							</form>
						</details>
					<?php else : ?>
						&#8212;
					<?php endif; ?>
					</td>
				</tr>
			<?php endforeach; ?>
			<?php if ( empty( $exceptions ) ) : ?>
				<tr><td colspan="7"><?php esc_html_e( 'No exceptions recorded yet.', 'vcns-security-automation-manager' ); ?></td></tr>
			<?php endif; ?>
			</tbody>
		</table>

		<h2 id="wp-sam-exception-form" style="margin-top:2em"><?php esc_html_e( 'Create a new exception', 'vcns-security-automation-manager' ); ?></h2>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'wp_sam_exception_create' ); ?>
			<input type="hidden" name="action" value="wp_sam_exception_create">
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><label for="wp_sam_exception_control"><?php esc_html_e( 'Affected control', 'vcns-security-automation-manager' ); ?></label></th>
					<td><input type="text" id="wp_sam_exception_control" name="control" class="regular-text" value="<?php echo esc_attr( (string) $exception_form['control'] ); ?>" required></td>
				</tr>
				<tr>
					<th scope="row"><label for="wp_sam_exception_surface"><?php esc_html_e( 'Affected surface', 'vcns-security-automation-manager' ); ?></label></th>
					<td>
						<select id="wp_sam_exception_surface" name="surface">
							<option value="" <?php selected( '', $exception_form['surface'] ); ?>><?php esc_html_e( 'All surfaces', 'vcns-security-automation-manager' ); ?></option>
							<?php foreach ( array( 'frontend', 'admin', 'login', 'api' ) as $exception_surface_option ) : ?>
							<option value="<?php echo esc_attr( $exception_surface_option ); ?>" <?php selected( $exception_surface_option, $exception_form['surface'] ); ?>><?php echo esc_html( ucfirst( $exception_surface_option ) ); ?></option>
							<?php endforeach; ?>
						</select>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="wp_sam_exception_weaker_value"><?php esc_html_e( 'Requested weaker value', 'vcns-security-automation-manager' ); ?></label></th>
					<td><textarea id="wp_sam_exception_weaker_value" name="weaker_value" class="large-text" rows="2" required><?php echo esc_textarea( (string) $exception_form['weaker_value'] ); ?></textarea></td>
				</tr>
				<tr>
					<th scope="row"><label for="wp_sam_exception_business_justification"><?php esc_html_e( 'Business justification (reason)', 'vcns-security-automation-manager' ); ?></label></th>
					<td><textarea id="wp_sam_exception_business_justification" name="business_justification" class="large-text" rows="2" required><?php echo esc_textarea( (string) $exception_form['business_justification'] ); ?></textarea></td>
				</tr>
				<tr>
					<th scope="row"><label for="wp_sam_exception_technical_justification"><?php esc_html_e( 'Technical justification', 'vcns-security-automation-manager' ); ?></label></th>
					<td><textarea id="wp_sam_exception_technical_justification" name="technical_justification" class="large-text" rows="2"><?php echo esc_textarea( (string) $exception_form['technical_justification'] ); ?></textarea></td>
				</tr>
				<tr>
					<th scope="row"><label for="wp_sam_exception_owner"><?php esc_html_e( 'Owner', 'vcns-security-automation-manager' ); ?></label></th>
					<td><input type="text" id="wp_sam_exception_owner" name="owner" class="regular-text" value="<?php echo esc_attr( (string) $exception_form['owner'] ); ?>" required></td>
				</tr>
				<tr>
					<th scope="row"><label for="wp_sam_exception_approver"><?php esc_html_e( 'Approver', 'vcns-security-automation-manager' ); ?></label></th>
					<td><input type="text" id="wp_sam_exception_approver" name="approver" class="regular-text" value="<?php echo esc_attr( (string) $exception_form['approver'] ); ?>"></td>
				</tr>
				<tr>
					<th scope="row"><label for="wp_sam_exception_compensating_control"><?php esc_html_e( 'Compensating control', 'vcns-security-automation-manager' ); ?></label></th>
					<td><textarea id="wp_sam_exception_compensating_control" name="compensating_control" class="large-text" rows="2"><?php echo esc_textarea( (string) $exception_form['compensating_control'] ); ?></textarea></td>
				</tr>
				<tr>
					<th scope="row"><label for="wp_sam_exception_risk_classification"><?php esc_html_e( 'Risk classification', 'vcns-security-automation-manager' ); ?></label></th>
					<td>
						<select id="wp_sam_exception_risk_classification" name="risk_classification">
							<?php foreach ( $exception_risk_labels as $exception_risk_key => $exception_risk_label ) : ?>
							<option value="<?php echo esc_attr( $exception_risk_key ); ?>" <?php selected( $exception_risk_key, $exception_form['risk_classification'] ); ?>><?php echo esc_html( $exception_risk_label ); ?></option>
							<?php endforeach; ?>
						</select>
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="wp_sam_exception_reference"><?php esc_html_e( 'Related ticket or reference', 'vcns-security-automation-manager' ); ?></label></th>
					<td><input type="text" id="wp_sam_exception_reference" name="reference" class="regular-text" value="<?php echo esc_attr( (string) $exception_form['reference'] ); ?>"></td>
				</tr>
				<tr>
					<th scope="row"><label for="wp_sam_exception_expiry_date"><?php esc_html_e( 'Expiry date', 'vcns-security-automation-manager' ); ?></label></th>
					<td>
						<input type="date" id="wp_sam_exception_expiry_date" name="expiry_date" value="<?php echo esc_attr( (string) $exception_form['expiry_date'] ); ?>">
						<p class="description"><?php esc_html_e( 'Required unless a privileged override is used below. You will be notified before this exception expires; it returns to review automatically once it does.', 'vcns-security-automation-manager' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row"><?php esc_html_e( 'Privileged override', 'vcns-security-automation-manager' ); ?></th>
					<td>
						<label>
							<input type="checkbox" name="is_privileged_override" value="1" <?php checked( ! empty( $exception_form['is_privileged_override'] ) ); ?>>
							<?php esc_html_e( 'This exception never expires on its own (skips the expiry-date requirement). Use sparingly.', 'vcns-security-automation-manager' ); ?>
						</label>
					</td>
				</tr>
			</table>
			<?php submit_button( __( 'Create exception', 'vcns-security-automation-manager' ) ); ?>
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

		<?php
		// Built-in only -- excludes one Custom_Rule_Detector instance per
		// admin-authored row, which the Traffic Controls bullet below
		// already covers separately ("plus your own custom ... rules").
		// Computed live rather than hardcoded so this line can't go stale
		// again the next time a detector family ships, the way the fixed
		// "nineteen" this replaced already had.
		$builtin_detector_count = count(
			array_filter(
				Detector_Registry::all(),
				static fn( $detector ) => 'custom' !== $detector->family()
			)
		);
		?>

		<h3><?php esc_html_e( 'Browser & Header Security', 'vcns-security-automation-manager' ); ?></h3>
		<ul style="list-style: disc; padding-left: 1.5em;">
			<li>
				<strong><?php esc_html_e( 'Content Security Policy', 'vcns-security-automation-manager' ); ?></strong>
				&nbsp;&mdash;
				<?php esc_html_e( 'the most capable pillar: per-surface profiles, nonce injection, automatic source discovery, violation reporting, deterministic automation that can build a policy from what the site is actually running without waiting on manual review, and a full report-only-to-enforce workflow either way.', 'vcns-security-automation-manager' ); ?>
			</li>
			<li>
				<strong><?php esc_html_e( 'Eleven further HTTP header pillars', 'vcns-security-automation-manager' ); ?></strong>
				&nbsp;&mdash;
				<?php esc_html_e( 'X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Information Masking, Cache-Control, Permissions-Policy, Strict-Transport-Security, Cross-Origin-Resource-Policy, Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy, and X-Permitted-Cross-Domain-Policies -- simpler per-surface pillars, two of which (Cross-Origin-Opener-Policy and Cross-Origin-Embedder-Policy) carry their own report-only learning workflow.', 'vcns-security-automation-manager' ); ?>
			</li>
			<li>
				<strong><?php esc_html_e( 'Page-rewrite protections', 'vcns-security-automation-manager' ); ?></strong>
				&nbsp;&mdash;
				<?php esc_html_e( 'Reverse Tabnabbing Protection, External Scripts (third-party script/stylesheet governance with Subresource Integrity), and Internal Script Integrity, which modify the rendered page itself rather than emit a header.', 'vcns-security-automation-manager' ); ?>
			</li>
		</ul>

		<h3><?php esc_html_e( 'Threat Detection & Traffic Control', 'vcns-security-automation-manager' ); ?></h3>
		<ul style="list-style: disc; padding-left: 1.5em;">
			<li>
				<strong><?php esc_html_e( 'Continuous Intelligence', 'vcns-security-automation-manager' ); ?></strong>
				&nbsp;&mdash;
				<?php esc_html_e( 'the record behind every detector below: every request is logged, and known bots, crawlers, and scanners are recognised against a maintained vendor catalogue and distinguished from unrecognised traffic, without ever assuming "unrecognised" means "hostile" -- recognition is never automatic authorisation.', 'vcns-security-automation-manager' ); ?>
			</li>
			<li>
				<strong><?php esc_html_e( 'Traffic Controls & Network Intelligence', 'vcns-security-automation-manager' ); ?></strong>
				&nbsp;&mdash;
				<?php
				printf(
					/* translators: %d: number of built-in attack detectors, computed live */
					esc_html__( 'rate limiting and progressive response (warn, throttle, temporary block, extended block) per surface; an explicit IP, ASN, and country allow/block list; %d built-in attack detectors (SQL injection, path traversal, webshell probes, credential stuffing, and more) plus your own custom fail2ban-style regex rules; and Tor exit, ASN, Geo-IP, and well-known-file (robots.txt, security.txt, ads.txt, and more) awareness. All observe-only until you explicitly promote a surface to enforce.', 'vcns-security-automation-manager' ),
					$builtin_detector_count
				); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- esc_html__() escapes the translated string; %d is an integer.
				?>
			</li>
		</ul>

		<h3><?php esc_html_e( 'Site Integrity & Recovery', 'vcns-security-automation-manager' ); ?></h3>
		<ul style="list-style: disc; padding-left: 1.5em;">
			<li>
				<strong><?php esc_html_e( 'Advanced Intelligence', 'vcns-security-automation-manager' ); ?></strong>
				&nbsp;&mdash;
				<?php esc_html_e( 'coordinated-campaign detection across related sources, configurable honeypath decoys that flag any request to a path no legitimate visitor should ever hit, and declared change windows that distinguish an expected deployment from unexplained drift.', 'vcns-security-automation-manager' ); ?>
			</li>
			<li>
				<strong><?php esc_html_e( 'Baseline & Drift', 'vcns-security-automation-manager' ); ?></strong>
				&nbsp;&mdash;
				<?php esc_html_e( "snapshots the site's theme, plugin, and core file state, then flags what changed between snapshots -- so an unexpected file modification doesn't go unnoticed between the deployments you actually meant to make.", 'vcns-security-automation-manager' ); ?>
			</li>
		</ul>

		<h3><?php esc_html_e( 'Certificates', 'vcns-security-automation-manager' ); ?></h3>
		<p>
			<?php esc_html_e( 'A free-standing ACME v2 (Let\'s Encrypt) TLS certificate manager: DNS-01 or HTTP-01 issuance, encrypted-at-rest credentials and private keys, and automatic renewal. Unrelated to the pillars above beyond sharing the same admin and audit plumbing.', 'vcns-security-automation-manager' ); ?>
		</p>

		<h2><?php esc_html_e( 'The gap this fills', 'vcns-security-automation-manager' ); ?></h2>
		<p>
			<?php esc_html_e( 'CSP is widely regarded as one of the most effective defenses against cross-site scripting, but it is also one of the easiest security controls to deploy badly -- an overly strict policy silently breaks a theme or plugin, and an overly loose one defends nothing. The same trade-off shows up in miniature across every layer above: an unreviewed third-party script is a supply-chain risk, a lapsed certificate is a silent outage, an unnoticed file change is a compromise nobody caught, and a header enabled without understanding what depends on the behaviour it changes can break a site as easily as it protects one. This plugin exists to make the safe middle path the easy path everywhere it applies: learn what a site actually needs before enforcing anything, automate what is safe to automate outright, and keep every decision reviewable.', 'vcns-security-automation-manager' ); ?>
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
