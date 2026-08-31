<?php
/**
 * Admin view: CSP dashboard.
 * Shows per-surface policy profiles, source inventory, violations, scan log.
 * Rendered by Admin_UI::render_dashboard().
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WP_SAM\Admin\Csp_Header_Formatter;
use WP_SAM\Admin\Table_Query;
use WP_SAM\Admin\Policy_Events_Builder;
use WP_SAM\Admin\Risk_Badge;
use WP_SAM\Admin\Known_Source_Badge;

global $wpdb;

// Current tab.
$tab          = isset( $_GET['tab'] ) ? sanitize_text_field( wp_unslash( $_GET['tab'] ) ) : 'start-here';
$allowed_tabs = array( 'start-here', 'profiles', 'violations', 'sources', 'policy-changes', 'policy-audit', 'scan-log', 'settings' );
if ( ! in_array( $tab, $allowed_tabs, true ) ) {
	$tab = 'start-here';
}

$base_url = admin_url( 'admin.php?page=security-automation-manager-dashboard' );
$tab_help = array(
	'start-here'     => array(
		'label'       => __( 'Start Here', 'vcns-security-automation-manager' ),
		'description' => __( 'A short guide to how this plugin works: report-only, the learning window, and promoting a surface to enforce mode.', 'vcns-security-automation-manager' ),
	),
	'profiles'       => array(
		'label'       => __( 'Profiles', 'vcns-security-automation-manager' ),
		'description' => __( 'Configure the CSP mode for each site surface. Use report-only while learning, enforce only after the surface is stable, or disabled when this plugin should not emit CSP for that surface.', 'vcns-security-automation-manager' ),
	),
	'violations'     => array(
		'label'       => __( 'Violations', 'vcns-security-automation-manager' ),
		'description' => __( 'Review browser-submitted CSP reports. Use these reports to identify required sources before promoting a surface from report-only to enforce mode.', 'vcns-security-automation-manager' ),
	),
	'sources'        => array(
		'label'       => __( 'For Review', 'vcns-security-automation-manager' ),
		'description' => __( 'Review discovered source candidates and decide whether each source belongs in the policy. Discovery adds review items; approvals, rejections, reversions, and undo actions require a reason and are written to the decision ledger.', 'vcns-security-automation-manager' ),
	),
	'policy-changes' => array(
		'label'       => __( 'Policy Changes', 'vcns-security-automation-manager' ),
		'description' => __( 'Inspect policy activity across discovered proposals, administrator or automation decisions, and immutable policy snapshots.', 'vcns-security-automation-manager' ),
	),
	'policy-audit'   => array(
		'label'       => __( 'Policy Audit', 'vcns-security-automation-manager' ),
		'description' => __( 'At-a-glance effective policy for every surface: mode, automation level, policy version, and pending/high-risk counts. For the pending review queue see For Review, and for the full decision ledger see Policy Changes.', 'vcns-security-automation-manager' ),
	),
	'scan-log'       => array(
		'label'       => __( 'Scan Log', 'vcns-security-automation-manager' ),
		'description' => __( 'Check manual and scheduled scan runs, policy-change counts, warnings, and completion status after site, theme, plugin, or content changes.', 'vcns-security-automation-manager' ),
	),
	'settings'       => array(
		'label'       => __( 'Settings', 'vcns-security-automation-manager' ),
		'description' => __( 'Promotion gates, deterministic automation, proxy header emission, report endpoint learning, and scan schedule.', 'vcns-security-automation-manager' ),
	),
);

// ── Data queries ──────────────────────────────────────────────────────────────
// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
$profiles_raw      = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}csp_policy_profiles ORDER BY surface", ARRAY_A );
$profiles          = ! empty( $profiles_raw ) ? $profiles_raw : array();
$surfaces          = array( 'frontend', 'admin', 'login', 'api' );
$automation_config = ( new \WP_SAM\CSP\Automation_Config() )->all();
$automation_labels = \WP_SAM\CSP\Automation_Config::mode_labels();

// True when at least one registered automation mode is currently
// unavailable (e.g. a paid mode without an active entitlement) -- used to
// decide whether an "Upgrade to unlock" affordance has anything to point
// at. On a build where no such mode is ever registered at all (the
// WordPress.org channel), $automation_labels never contains one, so this
// is always false there -- not merely hidden, nothing to compute.
$wp_sam_has_unavailable_mode = false;
foreach ( array_keys( $automation_labels ) as $wp_sam_mode_key ) {
	if ( ! \WP_SAM\CSP\Automation_Mode_Registry::is_available( $wp_sam_mode_key ) ) {
		$wp_sam_has_unavailable_mode = true;
		break;
	}
}
unset( $wp_sam_mode_key );

// Shared pagination defaults.
$per_page = 20;
$page_num = max( 1, (int) ( isset( $_GET['paged'] ) ? $_GET['paged'] : 1 ) );
$offset   = ( $page_num - 1 ) * $per_page;

// Violations – last 50.
// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
$violations_raw = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}csp_violation_reports ORDER BY reported_at DESC LIMIT 50", ARRAY_A );
$violations     = ! empty( $violations_raw ) ? $violations_raw : array();

// Recent competing-CSP-header findings (persistent banner below, visible on
// every tab). Conflict_Detector's header/htaccess/probe checks and
// Violation_Reporter's disposition-mismatch check both log to the same
// 'conflict_detector' audit component, throttled at the source. Findings age
// out of the banner after 48 hours, and the banner's Dismiss button hides
// everything logged before the dismissal moment (recorded by
// Admin_UI::handle_dismiss_conflicts()) without touching the audit log
// itself; only a finding NEWER than the dismissal re-opens the banner.
$conflict_cutoff       = gmdate( 'Y-m-d H:i:s', time() - ( 48 * HOUR_IN_SECONDS ) );
$conflict_dismissed_at = (string) get_option( 'wp_sam_conflict_dismissed_at', '' );
if ( $conflict_dismissed_at > $conflict_cutoff ) { // Lexicographic compare is chronological for this fixed datetime format.
	$conflict_cutoff = $conflict_dismissed_at;
}
// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
$conflict_notices_raw = $wpdb->get_results(
	$wpdb->prepare(
		"SELECT detail, created_at FROM {$wpdb->prefix}sam_audit_log
			WHERE component = %s AND severity = %s AND created_at > %s
			ORDER BY created_at DESC LIMIT 5",
		'conflict_detector',
		'warning',
		$conflict_cutoff
	),
	ARRAY_A
);
$conflict_notices     = ! empty( $conflict_notices_raw ) ? $conflict_notices_raw : array();

// Scan log – last 20 runs.
// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
$scan_logs_raw = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}sam_scan_logs ORDER BY started_at DESC LIMIT 20", ARRAY_A );
$scan_logs     = ! empty( $scan_logs_raw ) ? $scan_logs_raw : array();
?>
<div class="wrap wp-sam-wrap">
	<h1><?php esc_html_e( 'CSP', 'vcns-security-automation-manager' ); ?></h1>

	<!-- ── Top action bar ────────────────────────────────────────────────── -->
	<p>
		<button type="button" id="wp-sam-manual-scan" class="button button-primary">
			<?php esc_html_e( 'Run Manual Scan', 'vcns-security-automation-manager' ); ?>
		</button>
		<span id="wp-sam-scan-status" style="margin-left:10px;display:none"></span>
	</p>

	<!-- ── Tabs ──────────────────────────────────────────────────────────── -->
	<nav class="nav-tab-wrapper wp-sam-tab-wrapper" role="tablist" aria-label="<?php esc_attr_e( 'CSP dashboard sections', 'vcns-security-automation-manager' ); ?>">
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

	<?php if ( ! empty( $conflict_notices ) ) : ?>
	<div class="notice notice-warning wp-sam-conflict-banner">
		<p>
			<strong><?php esc_html_e( 'Possible competing Content-Security-Policy source detected.', 'vcns-security-automation-manager' ); ?></strong>
			<?php esc_html_e( 'Another source (server configuration, a different plugin, or a stale cached response) may be emitting its own CSP header alongside this plugin\'s. Check your server config and any other security plugins for a competing header.', 'vcns-security-automation-manager' ); ?>
		</p>
		<ul>
			<?php foreach ( $conflict_notices as $conflict_notice ) : ?>
			<li><code><?php echo esc_html( $conflict_notice['created_at'] ); ?></code> - <?php echo esc_html( $conflict_notice['detail'] ); ?></li>
			<?php endforeach; ?>
		</ul>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'wp_sam_dismiss_conflicts' ); ?>
			<input type="hidden" name="action" value="wp_sam_dismiss_conflicts" />
			<input type="hidden" name="wp_sam_return_tab" value="<?php echo esc_attr( $tab ); ?>" />
			<p>
				<button type="submit" class="button"><?php esc_html_e( 'Dismiss these findings', 'vcns-security-automation-manager' ); ?></button>
				<span class="description"><?php esc_html_e( 'Hides the findings above without deleting them from the audit log. The banner returns automatically if a new competing-header signal is detected.', 'vcns-security-automation-manager' ); ?></span>
			</p>
		</form>
	</div>
	<?php endif; ?>

	<div class="tab-content" style="margin-top:1em">

	<?php if ( 'start-here' === $tab ) : ?>
	<!-- ── Start Here tab ─────────────────────────────────────────────────── -->
	<h2 class="title"><?php esc_html_e( 'What this plugin does', 'vcns-security-automation-manager' ); ?></h2>
	<p class="description">
		<?php esc_html_e( 'This plugin builds a Content-Security-Policy (CSP) for your site by watching what your site actually loads - scripts, styles, images, fonts, connections, and frames - and letting you decide which of those sources belong in the policy. It manages this separately for four surfaces: the public frontend, wp-admin, the login screen, and the REST API.', 'vcns-security-automation-manager' ); ?>
	</p>
	<p class="description">
		<?php esc_html_e( 'Nothing is blocked or enforced until you deliberately turn it on. The whole workflow below is designed so you can see exactly what a policy would do before it does it.', 'vcns-security-automation-manager' ); ?>
	</p>

	<h2 class="title"><?php esc_html_e( 'How it works', 'vcns-security-automation-manager' ); ?></h2>
	<ol>
		<li>
			<strong><?php esc_html_e( 'Report-only mode.', 'vcns-security-automation-manager' ); ?></strong>
			<?php esc_html_e( 'Each surface starts in report-only mode: browsers evaluate the policy and send a report for anything that would have been blocked, but nothing is actually blocked. Reports arrive at this plugin\'s own endpoint (shown on the Settings tab, under Report Endpoint Learning) and appear in the Violations tab.', 'vcns-security-automation-manager' ); ?>
		</li>
		<li>
			<strong><?php esc_html_e( 'The learning window.', 'vcns-security-automation-manager' ); ?></strong>
			<?php esc_html_e( 'While the learning window is open (48 hours after the last material change to the site by default - a page, post, plugin, or theme edit - adjustable on the Settings tab), validated violation reports and scan discoveries add candidate sources to the For Review queue instead of just being logged. Once the window locks, new discoveries stop being added automatically until another material change reopens it.', 'vcns-security-automation-manager' ); ?>
		</li>
		<li>
			<strong><?php esc_html_e( 'Review.', 'vcns-security-automation-manager' ); ?></strong>
			<?php esc_html_e( 'Every discovered source lands in For Review with a risk rating and a reason. Approve the ones that belong, reject the ones that don\'t - every decision needs a short reason and is written to a permanent decision ledger (visible on the Policy Changes tab). Depending on the Automation Level you\'ve set for a surface, low-risk sources can be approved automatically instead of waiting on you; see Configuration below.', 'vcns-security-automation-manager' ); ?>
		</li>
		<li>
			<strong><?php esc_html_e( 'Manual promotion to enforce mode.', 'vcns-security-automation-manager' ); ?></strong>
			<?php esc_html_e( 'When you\'re confident the policy is complete, promote a surface to enforce mode yourself from the Profiles tab - this is never done automatically. Promotion is gated: it requires at least one approved source or hash, no violations within a configurable window (24 hours by default, set on the Settings tab), and no active temporary override.', 'vcns-security-automation-manager' ); ?>
		</li>
		<li>
			<strong><?php esc_html_e( 'Policy revision.', 'vcns-security-automation-manager' ); ?></strong>
			<?php esc_html_e( 'Enforce mode isn\'t a finish line. A new plugin, a theme change, or a new page can introduce sources the policy doesn\'t cover yet. Treat each material change as a prompt to reopen the learning window, review what\'s new in For Review, and revise the policy - the same report-only-then-promote cycle applies to every revision.', 'vcns-security-automation-manager' ); ?>
		</li>
	</ol>

	<h2 class="title"><?php esc_html_e( 'Configuration', 'vcns-security-automation-manager' ); ?></h2>
	<p class="description">
		<?php esc_html_e( 'The most important setting is Automation Level, set per surface from the Profiles tab dropdown or the Settings tab: Manual, Automatic (medium+high approvals), Automatic (high approvals only), or Fully automatic. This controls which risk tiers of discovered sources, if any, can be approved without you. Manual is always the safe starting point - nothing is auto-approved until you deliberately raise a surface\'s level. The rest of the Settings tab covers promotion gates, proxy header emission, report endpoint learning, and the scan schedule.', 'vcns-security-automation-manager' ); ?>
	</p>

	<h2 class="title"><?php esc_html_e( 'Readiness and Policy Audit', 'vcns-security-automation-manager' ); ?></h2>
	<p class="description">
		<?php esc_html_e( 'The Readiness page (in the sidebar) runs plugin and database health checks - schema integrity, table health, and operational checks. The Recovery page (also in the sidebar) covers schema-downgrade status, configuration snapshot restore, configuration export/import, and a destructive full plugin data reset if you need to start over.', 'vcns-security-automation-manager' ); ?>
	</p>
	<p class="description">
		<?php esc_html_e( 'The Policy Audit tab above shows the current effective policy for every surface at a glance - mode, automation level, policy version, and pending/high-risk counts. For the pending review queue see For Review, and for the full, immutable decision ledger - who approved, rejected, or reverted each source, and why - see Policy Changes.', 'vcns-security-automation-manager' ); ?>
	</p>

	<?php elseif ( 'profiles' === $tab ) : ?>
	<!-- ── Profiles tab ───────────────────────────────────────────────────── -->
		<?php
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- No user input; only $wpdb->prefix used in query.
		$profiles_raw = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}csp_policy_profiles ORDER BY surface", ARRAY_A );
		$profiles     = ! empty( $profiles_raw ) ? $profiles_raw : array();

		// Violation counts for the (directive, blocked_uri) pairs the Bypass
		// Best Practices catalog covers, so each toggle can show "why" -- these
		// are the same rows already visible on the Violations tab, grouped per
		// catalog entry. Built from BYPASS_CATALOG rather than hardcoded so a
		// future catalog entry doesn't silently show a zero count here.
		$bypass_violation_counts = array();
		$bypass_conditions       = array();
		foreach ( \WP_SAM\CSP\Policy_Builder::BYPASS_CATALOG as $bypass_entry ) {
			$bypass_conditions[] = $wpdb->prepare(
				'( violated_directive = %s AND blocked_uri = %s )',
				$bypass_entry['directive'],
				$bypass_entry['violation_blocked_uri']
			);
		}
		if ( ! empty( $bypass_conditions ) ) {
			$bypass_where = implode( ' OR ', $bypass_conditions );
			// Each OR clause above is individually built via $wpdb->prepare(); this
			// is just their concatenation, not raw interpolation of external input.
			$bypass_violation_rows = $wpdb->get_results(
				"SELECT profile_surface, violated_directive, blocked_uri, occurrence_count FROM {$wpdb->prefix}csp_violation_reports WHERE {$bypass_where}", // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				ARRAY_A
			);
			foreach ( (array) $bypass_violation_rows as $row ) {
				$key                             = $row['profile_surface'] . '|' . $row['violated_directive'] . '|' . $row['blocked_uri'];
				$bypass_violation_counts[ $key ] = ( $bypass_violation_counts[ $key ] ?? 0 ) + (int) $row['occurrence_count'];
			}
		}
		?>
	<table class="widefat fixed striped wp-sam-profiles-table">
		<thead>
			<tr>
				<th><?php esc_html_e( 'Surface', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Mode', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Automation', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Experimental', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Bypass Best Practices', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Last Updated', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Actions', 'vcns-security-automation-manager' ); ?></th>
			</tr>
		</thead>
		<tbody>
		<?php foreach ( $profiles as $profile ) : ?>
		<tr>
			<td><?php echo esc_html( ucfirst( $profile['surface'] ) ); ?></td>
			<td>
				<span class="wp-sam-mode-badge mode-<?php echo esc_attr( $profile['mode'] ); ?>">
					<?php echo esc_html( $profile['mode'] ); ?>
				</span>
			</td>
			<td>
				<?php
				$surface          = (string) $profile['surface'];
				$surface_config   = $automation_config[ $surface ] ?? \WP_SAM\CSP\Automation_Config::DEFAULT_SURFACE_CONFIG;
				$automation_mode  = (string) ( $surface_config['mode'] ?? \WP_SAM\CSP\Automation_Config::MODE_MANUAL );
				$automation_title = sprintf(
					/* translators: %s: current automation mode label */
					__( 'Automation posture: %s', 'vcns-security-automation-manager' ),
					\WP_SAM\CSP\Automation_Config::mode_label( $automation_mode )
				);
				?>
				<label class="screen-reader-text" for="wp-sam-automation-mode-<?php echo esc_attr( $surface ); ?>">
					<?php echo esc_html( $automation_title ); ?>
				</label>
				<select id="wp-sam-automation-mode-<?php echo esc_attr( $surface ); ?>"
					class="wp-sam-automation-mode"
					data-surface="<?php echo esc_attr( $surface ); ?>"
					title="<?php echo esc_attr( $automation_title ); ?>">
					<?php foreach ( $automation_labels as $mode => $label ) : ?>
					<option value="<?php echo esc_attr( $mode ); ?>" <?php selected( $automation_mode, $mode ); ?>
						<?php disabled( ! \WP_SAM\CSP\Automation_Mode_Registry::is_available( $mode ) ); ?>>
						<?php
						echo esc_html( $label );
						if ( ! \WP_SAM\CSP\Automation_Mode_Registry::is_available( $mode ) ) {
							echo ' ' . esc_html__( '(requires upgrade)', 'vcns-security-automation-manager' );
						}
						?>
					</option>
					<?php endforeach; ?>
				</select>
				<?php if ( $wp_sam_has_unavailable_mode ) : ?>
				<br /><a href="<?php echo esc_url( admin_url( 'admin.php?page=security-automation-manager-dashboard&tab=settings#wp-sam-upgrade' ) ); ?>" style="font-size:0.85em;"><?php esc_html_e( 'Upgrade to unlock →', 'vcns-security-automation-manager' ); ?></a>
				<?php endif; ?>
			</td>
			<td>
				<label>
					<input
						type="checkbox"
						class="wp-sam-trusted-types-toggle"
						data-surface="<?php echo esc_attr( $profile['surface'] ); ?>"
						<?php checked( ! empty( $profile['trusted_types'] ) ); ?>
					/>
					<code>require-trusted-types-for: 'script'</code>
					<?php
					$trusted_types_note = __( "Trusted Types. Pinned to report-only; enforcing it needs application code most WordPress sites don't have yet.", 'vcns-security-automation-manager' );
					echo Risk_Badge::render( 'report-only', $trusted_types_note ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- helper escapes internally.
					?>
				</label>
			</td>
			<td>
				<?php
				$bypass_enabled_flags = json_decode( (string) ( $profile['bypass_flags'] ?? '' ), true );
				$bypass_enabled_flags = is_array( $bypass_enabled_flags ) ? $bypass_enabled_flags : array();
				$bypass_shown_any     = false;
				?>
				<?php foreach ( \WP_SAM\CSP\Policy_Builder::BYPASS_CATALOG as $bypass_flag => $bypass_entry ) : ?>
					<?php
					$bypass_is_enabled = in_array( $bypass_flag, $bypass_enabled_flags, true );
					$bypass_key        = $profile['surface'] . '|' . $bypass_entry['directive'] . '|' . $bypass_entry['violation_blocked_uri'];
					$bypass_count      = $bypass_violation_counts[ $bypass_key ] ?? 0;

					// Only show an entry this surface has actually hit at least
					// once, or one already enabled (so an admin can still find
					// and turn off a toggle whose triggering content is gone) --
					// a full, uncustomised catalog is dozens of entries, and
					// showing every one regardless of relevance to this specific
					// surface is noise, not a menu.
					if ( 0 === $bypass_count && ! $bypass_is_enabled ) {
						continue;
					}
					$bypass_shown_any = true;
					?>
				<label style="display:block;margin-bottom:6px;">
					<input
						type="checkbox"
						class="wp-sam-bypass-flag-toggle"
						data-surface="<?php echo esc_attr( $profile['surface'] ); ?>"
						data-flag="<?php echo esc_attr( $bypass_flag ); ?>"
						<?php checked( $bypass_is_enabled ); ?>
					/>
					<code><?php echo esc_html( $bypass_entry['directive'] . ': ' . $bypass_entry['token'] ); ?></code>
					<?php
					$bypass_note = $bypass_entry['label'] . ' ' . $bypass_entry['risk_note'];
					if ( $bypass_count > 0 ) {
						$bypass_note .= ' ' . sprintf(
							/* translators: %s: formatted violation occurrence count */
							__( '%s violations observed on this surface.', 'vcns-security-automation-manager' ),
							number_format( $bypass_count )
						);
					}
					echo Risk_Badge::render( $bypass_entry['risk_level'], $bypass_note ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- helper escapes internally.
					?>
				</label>
				<?php endforeach; ?>
				<?php if ( ! $bypass_shown_any ) : ?>
				<p class="description" style="margin:0;"><?php esc_html_e( 'No relevant options for this surface yet -- entries appear here once this surface has actually triggered them.', 'vcns-security-automation-manager' ); ?></p>
				<?php endif; ?>
			</td>
			<td><?php echo esc_html( $profile['updated_at'] ); ?></td>
			<td>
				<?php foreach ( array( 'report-only', 'enforce', 'disabled' ) as $m ) : ?>
					<?php if ( $m !== $profile['mode'] ) : ?>
					<button type="button"
						class="button button-small wp-sam-toggle-mode"
						data-surface="<?php echo esc_attr( $profile['surface'] ); ?>"
						data-mode="<?php echo esc_attr( $m ); ?>">
						<?php echo esc_html( ucwords( str_replace( '-', ' ', $m ) ) ); ?>
					</button>
					<?php endif; ?>
				<?php endforeach; ?>
			</td>
		</tr>
		<?php endforeach; ?>
		<?php if ( empty( $profiles ) ) : ?>
		<tr><td colspan="7"><?php esc_html_e( 'No profiles found. Deactivate and reactivate the plugin to seed defaults.', 'vcns-security-automation-manager' ); ?></td></tr>
		<?php endif; ?>
		</tbody>
	</table>

	<?php elseif ( 'sources' === $tab ) : ?>
	<!-- ── Sources tab ────────────────────────────────────────────────────── -->
		<?php
		$src_surface      = Table_Query::text_param( 'src_surface' );
		$src_state        = Table_Query::multi_param( 'src_state' );
		$src_risk         = Table_Query::multi_param( 'src_risk' );
		$src_directive    = Table_Query::text_param( 'src_directive' );
		$src_host         = Table_Query::text_param( 'src_host' );
		$src_evidence_min = Table_Query::int_param( 'src_evidence_min' );
		$src_seen_from    = Table_Query::text_param( 'src_seen_from' );
		$src_seen_to      = Table_Query::text_param( 'src_seen_to' );
		$src_id           = Table_Query::int_param( 'src_id' );

		$src_where = array( '1=1' );
		$src_args  = array();
		foreach (
			array(
				Table_Query::equals_where( 'surface', $src_surface ),
				Table_Query::multi_select_where( 'approval_state', $src_state ),
				Table_Query::multi_select_where( 'risk_level', $src_risk ),
				Table_Query::like_where( $wpdb, 'directive', $src_directive ),
				Table_Query::like_where( $wpdb, 'source_host', $src_host ),
				Table_Query::numeric_gte_where( 'evidence_count', $src_evidence_min ),
				Table_Query::date_range_where( 'last_seen_at', $src_seen_from, $src_seen_to ),
			) as $src_fragment
		) {
			if ( null === $src_fragment ) {
				continue;
			}
			$src_where[] = $src_fragment['sql'];
			array_push( $src_args, ...$src_fragment['args'] );
		}
		if ( null !== $src_id ) {
			$src_where[] = 'id = %d';
			$src_args[]  = $src_id;
		}

		$src_where_sql = implode( ' AND ', $src_where );

		$src_sort_whitelist = array(
			'id'        => array(
				'expr'        => 'id',
				'default_dir' => 'desc',
			),
			'surface'   => array(
				'expr'        => 'surface',
				'default_dir' => 'asc',
			),
			'directive' => array(
				'expr'        => 'directive',
				'default_dir' => 'asc',
			),
			'host'      => array(
				'expr'        => 'source_host',
				'default_dir' => 'asc',
			),
			'risk'      => array(
				'expr'        => "CASE risk_level WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END",
				'default_dir' => 'asc',
			),
			'state'     => array(
				'expr'        => 'approval_state',
				'default_dir' => 'asc',
			),
			'evidence'  => array(
				'expr'        => 'evidence_count',
				'default_dir' => 'desc',
			),
			'last_seen' => array(
				'expr'        => 'last_seen_at',
				'default_dir' => 'desc',
			),
		);
		$src_sort           = Table_Query::resolve_sort(
			$src_sort_whitelist,
			'last_seen',
			isset( $_GET['sort'] ) ? sanitize_text_field( wp_unslash( $_GET['sort'] ) ) : null, // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			isset( $_GET['dir'] ) ? sanitize_text_field( wp_unslash( $_GET['dir'] ) ) : null // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		);

		$src_state_args = array_filter(
			array(
				'tab'              => 'sources',
				'sort'             => $src_sort['key'],
				'dir'              => strtolower( $src_sort['dir'] ),
				'src_surface'      => $src_surface,
				'src_state'        => $src_state,
				'src_risk'         => $src_risk,
				'src_directive'    => $src_directive,
				'src_host'         => $src_host,
				'src_evidence_min' => $src_evidence_min,
				'src_seen_from'    => $src_seen_from,
				'src_seen_to'      => $src_seen_to,
				'src_id'           => $src_id,
			)
		);

		$count_sql = "SELECT COUNT(*) FROM {$wpdb->prefix}csp_source_inventory WHERE {$src_where_sql}";
		if ( ! empty( $src_args ) ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$count_sql = $wpdb->prepare( $count_sql, ...$src_args );
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$src_total = (int) $wpdb->get_var( $count_sql );

		$src_pages = max( 1, (int) ceil( $src_total / $per_page ) );
		$page_num  = min( max( 1, (int) ( isset( $_GET['paged'] ) ? $_GET['paged'] : 1 ) ), $src_pages );
		$offset    = ( $page_num - 1 ) * $per_page;

		$query_args = array_merge( $src_args, array( $per_page, $offset ) );
		$data_sql   = "SELECT * FROM {$wpdb->prefix}csp_source_inventory WHERE {$src_where_sql} " . Table_Query::order_by_sql( $src_sort ) . ' LIMIT %d OFFSET %d';
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$data_sql = $wpdb->prepare( $data_sql, ...$query_args );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$sources_raw = $wpdb->get_results( $data_sql, ARRAY_A );
		$sources     = ! empty( $sources_raw ) ? $sources_raw : array();
		?>
	<details class="wp-sam-filter-form">
		<summary><?php esc_html_e( 'Filters', 'vcns-security-automation-manager' ); ?></summary>
		<form method="get" action="">
			<input type="hidden" name="page" value="security-automation-manager-dashboard" />
			<input type="hidden" name="tab"  value="sources" />
			<label>
				<?php esc_html_e( 'Surface', 'vcns-security-automation-manager' ); ?>
				<select name="src_surface">
					<option value=""><?php esc_html_e( 'Any', 'vcns-security-automation-manager' ); ?></option>
					<?php foreach ( $surfaces as $s ) : ?>
					<option value="<?php echo esc_attr( $s ); ?>" <?php selected( $src_surface, $s ); ?>><?php echo esc_html( ucfirst( $s ) ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
			<label>
				<?php esc_html_e( 'State', 'vcns-security-automation-manager' ); ?>
				<select name="src_state[]" multiple size="3">
					<?php foreach ( array( 'pending', 'approved', 'denied' ) as $st ) : ?>
					<option value="<?php echo esc_attr( $st ); ?>" <?php echo in_array( $st, $src_state, true ) ? 'selected' : ''; ?>><?php echo esc_html( ucfirst( $st ) ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
			<label>
				<?php esc_html_e( 'Risk', 'vcns-security-automation-manager' ); ?>
				<select name="src_risk[]" multiple size="3">
					<?php foreach ( array( 'high', 'medium', 'low' ) as $risk ) : ?>
					<option value="<?php echo esc_attr( $risk ); ?>" <?php echo in_array( $risk, $src_risk, true ) ? 'selected' : ''; ?>><?php echo esc_html( ucfirst( $risk ) ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
			<label>
				<?php esc_html_e( 'Directive', 'vcns-security-automation-manager' ); ?>
				<input type="text" name="src_directive" placeholder="<?php esc_attr_e( 'e.g. script-src', 'vcns-security-automation-manager' ); ?>" value="<?php echo esc_attr( $src_directive ); ?>" />
			</label>
			<label>
				<?php esc_html_e( 'Host contains', 'vcns-security-automation-manager' ); ?>
				<input type="text" name="src_host" value="<?php echo esc_attr( $src_host ); ?>" />
			</label>
			<label>
				<?php esc_html_e( 'ID', 'vcns-security-automation-manager' ); ?>
				<input type="number" min="1" name="src_id" style="width:80px" value="<?php echo esc_attr( null !== $src_id ? (string) $src_id : '' ); ?>" />
			</label>
			<label>
				<?php esc_html_e( 'Evidence at least', 'vcns-security-automation-manager' ); ?>
				<input type="number" min="0" name="src_evidence_min" style="width:80px" value="<?php echo esc_attr( null !== $src_evidence_min ? (string) $src_evidence_min : '' ); ?>" />
			</label>
			<label>
				<?php esc_html_e( 'Last seen from', 'vcns-security-automation-manager' ); ?>
				<input type="datetime-local" name="src_seen_from" value="<?php echo esc_attr( $src_seen_from ); ?>" />
			</label>
			<label>
				<?php esc_html_e( 'to', 'vcns-security-automation-manager' ); ?>
				<input type="datetime-local" name="src_seen_to" value="<?php echo esc_attr( $src_seen_to ); ?>" />
			</label>
			<?php submit_button( __( 'Filter', 'vcns-security-automation-manager' ), 'secondary', 'filter_sources', false ); ?>
		</form>
	</details>

	<table class="widefat fixed striped wp-sam-sources-table" style="margin-top:1em">
		<thead>
			<tr>
				<?php
				echo Table_Query::sort_header( __( 'ID', 'vcns-security-automation-manager' ), 'id', $src_sort_whitelist, $src_sort, $src_state_args, $base_url ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- helper escapes internally.
				echo Table_Query::sort_header( __( 'Surface', 'vcns-security-automation-manager' ), 'surface', $src_sort_whitelist, $src_sort, $src_state_args, $base_url ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'Directive', 'vcns-security-automation-manager' ), 'directive', $src_sort_whitelist, $src_sort, $src_state_args, $base_url ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'Host', 'vcns-security-automation-manager' ), 'host', $src_sort_whitelist, $src_sort, $src_state_args, $base_url ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'Risk', 'vcns-security-automation-manager' ), 'risk', $src_sort_whitelist, $src_sort, $src_state_args, $base_url ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'State', 'vcns-security-automation-manager' ), 'state', $src_sort_whitelist, $src_sort, $src_state_args, $base_url ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'Evidence', 'vcns-security-automation-manager' ), 'evidence', $src_sort_whitelist, $src_sort, $src_state_args, $base_url ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'Last Seen', 'vcns-security-automation-manager' ), 'last_seen', $src_sort_whitelist, $src_sort, $src_state_args, $base_url ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				?>
				<th><?php esc_html_e( 'Actions', 'vcns-security-automation-manager' ); ?></th>
			</tr>
		</thead>
		<tbody>
		<?php foreach ( $sources as $src ) : ?>
		<tr>
			<td><?php echo esc_html( $src['id'] ); ?></td>
			<td><?php echo esc_html( $src['surface'] ); ?></td>
			<td><code><?php echo esc_html( $src['directive'] ); ?></code></td>
			<td>
				<code><?php echo esc_html( $src['source_host'] ); ?></code>
				<?php echo Known_Source_Badge::render( (string) $src['source_host'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- helper escapes internally. ?>
			</td>
			<td>
				<?php echo Risk_Badge::render( (string) ( $src['risk_level'] ?? 'low' ), (string) ( $src['risk_reason'] ?? '' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- helper escapes internally. ?>
			</td>
			<td>
				<span class="wp-sam-state-badge state-<?php echo esc_attr( $src['approval_state'] ); ?>">
					<?php echo esc_html( ucfirst( $src['approval_state'] ) ); ?>
				</span>
			</td>
			<td><?php echo esc_html( number_format( (int) ( $src['evidence_count'] ?? 1 ) ) ); ?></td>
			<td><?php echo esc_html( $src['last_seen_at'] ); ?></td>
			<td class="wp-sam-source-actions">
				<?php if ( 'pending' === $src['approval_state'] || 'denied' === $src['approval_state'] ) : ?>
				<button type="button" class="button button-small wp-sam-approve-source" data-id="<?php echo esc_attr( $src['id'] ); ?>">
					<?php esc_html_e( 'Approve', 'vcns-security-automation-manager' ); ?>
				</button>
				<?php endif; ?>
				<?php if ( 'pending' === $src['approval_state'] || 'approved' === $src['approval_state'] ) : ?>
				<button type="button" class="button button-small wp-sam-deny-source" data-id="<?php echo esc_attr( $src['id'] ); ?>">
					<?php esc_html_e( 'Reject', 'vcns-security-automation-manager' ); ?>
				</button>
				<?php endif; ?>
				<?php if ( 'approved' === $src['approval_state'] ) : ?>
				<button type="button" class="button button-small wp-sam-revert-source" data-id="<?php echo esc_attr( $src['id'] ); ?>">
					<?php esc_html_e( 'Revert', 'vcns-security-automation-manager' ); ?>
				</button>
				<?php endif; ?>
				<?php if ( in_array( $src['last_decision'] ?? '', array( 'approved', 'auto_approved', 'rejected' ), true ) ) : ?>
				<button type="button" class="button button-small wp-sam-undo-source-decision" data-id="<?php echo esc_attr( $src['id'] ); ?>">
					<?php esc_html_e( 'Undo', 'vcns-security-automation-manager' ); ?>
				</button>
				<?php endif; ?>
			</td>
		</tr>
		<?php endforeach; ?>
		<?php if ( empty( $sources ) ) : ?>
		<tr><td colspan="9"><?php esc_html_e( 'No sources discovered yet. Run a scan to populate this table.', 'vcns-security-automation-manager' ); ?></td></tr>
		<?php endif; ?>
		</tbody>
	</table>

		<?php echo Table_Query::pagination( $page_num, $src_pages, $src_state_args, $base_url ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>

	<?php elseif ( 'policy-changes' === $tab ) : ?>
	<!-- Policy Changes tab -->
		<?php
		$pc_type        = Table_Query::multi_param( 'pc_type' );
		$pc_event       = Table_Query::multi_param( 'pc_event' );
		$pc_surface     = Table_Query::multi_param( 'pc_surface' );
		$pc_directive   = Table_Query::multi_param( 'pc_directive' );
		$pc_host        = Table_Query::text_param( 'pc_host' );
		$pc_risk        = Table_Query::multi_param( 'pc_risk' );
		$pc_policy_ver  = Table_Query::text_param( 'pc_policy_version' );
		$pc_suppression = Table_Query::text_param( 'pc_suppression' );
		$pc_actor       = Table_Query::multi_param( 'pc_actor' );
		$pc_detail      = Table_Query::text_param( 'pc_detail' );
		$pc_when_from   = Table_Query::text_param( 'pc_when_from' );
		$pc_when_to     = Table_Query::text_param( 'pc_when_to' );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- No user input; only $wpdb->prefix used in query.
		$pc_directive_options = $wpdb->get_col( "SELECT DISTINCT directive FROM {$wpdb->prefix}sam_policy_change_decisions ORDER BY directive" );
		$pc_directive_options = ! empty( $pc_directive_options ) ? $pc_directive_options : array();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- No user input; only $wpdb->prefix used in query.
		$pc_actor_from_decisions = $wpdb->get_col( "SELECT DISTINCT actor_type FROM {$wpdb->prefix}sam_policy_change_decisions" );
		$pc_actor_from_decisions = ! empty( $pc_actor_from_decisions ) ? $pc_actor_from_decisions : array();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- No user input; only $wpdb->prefix used in query.
		$pc_actor_from_versions = $wpdb->get_col( "SELECT DISTINCT trigger_type FROM {$wpdb->prefix}sam_policy_versions" );
		$pc_actor_from_versions = ! empty( $pc_actor_from_versions ) ? $pc_actor_from_versions : array();
		$pc_actor_from_versions = array_map(
			static function ( string $trigger_type ): string {
				return 'decision' === $trigger_type ? __( 'system', 'vcns-security-automation-manager' ) : $trigger_type;
			},
			$pc_actor_from_versions
		);
		$pc_actor_options       = array_values(
			array_unique(
				array_merge(
					$pc_actor_from_decisions,
					$pc_actor_from_versions,
					array( __( 'system', 'vcns-security-automation-manager' ), __( 'administrator', 'vcns-security-automation-manager' ) )
				)
			)
		);
		sort( $pc_actor_options );

		$pc_type_options  = array(
			__( 'Decision', 'vcns-security-automation-manager' ),
			__( 'Policy version', 'vcns-security-automation-manager' ),
			__( 'Discovery', 'vcns-security-automation-manager' ),
		);
		$pc_event_options = array(
			__( 'Approved', 'vcns-security-automation-manager' ),
			__( 'Rejected', 'vcns-security-automation-manager' ),
			__( 'Reverted', 'vcns-security-automation-manager' ),
			__( 'Undone', 'vcns-security-automation-manager' ),
			__( 'Snapshot', 'vcns-security-automation-manager' ),
			__( 'Proposed source', 'vcns-security-automation-manager' ),
			__( 'Suppressed proposal', 'vcns-security-automation-manager' ),
		);

		$pc_result = Policy_Events_Builder::fetch(
			$wpdb,
			array(
				'type'           => $pc_type,
				'event'          => $pc_event,
				'surface'        => $pc_surface,
				'directive'      => $pc_directive,
				'host'           => $pc_host,
				'risk'           => $pc_risk,
				'policy_version' => $pc_policy_ver,
				'suppression'    => $pc_suppression,
				'actor'          => $pc_actor,
				'detail'         => $pc_detail,
				'when_from'      => $pc_when_from,
				'when_to'        => $pc_when_to,
			)
		);

		$pc_sort_whitelist = array(
			'when'           => array(
				'expr'        => 'created_at',
				'default_dir' => 'desc',
			),
			'event'          => array(
				'expr'        => 'event',
				'default_dir' => 'asc',
			),
			'type'           => array(
				'expr'        => 'type',
				'default_dir' => 'asc',
			),
			'actor'          => array(
				'expr'        => 'actor',
				'default_dir' => 'asc',
			),
			'surface'        => array(
				'expr'        => 'surface',
				'default_dir' => 'asc',
			),
			'directive'      => array(
				'expr'        => 'directive',
				'default_dir' => 'asc',
			),
			'host'           => array(
				'expr'        => 'source',
				'default_dir' => 'asc',
			),
			'risk'           => array(
				'expr'        => 'risk_level',
				'default_dir' => 'asc',
			),
			'policy_version' => array(
				'expr'        => 'policy_version',
				'default_dir' => 'asc',
			),
			'suppression'    => array(
				'expr'        => 'suppression',
				'default_dir' => 'asc',
			),
			'detail'         => array(
				'expr'        => 'detail',
				'default_dir' => 'asc',
			),
		);
		$pc_sort           = Table_Query::resolve_sort(
			$pc_sort_whitelist,
			'when',
			isset( $_GET['sort'] ) ? sanitize_text_field( wp_unslash( $_GET['sort'] ) ) : null, // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			isset( $_GET['dir'] ) ? sanitize_text_field( wp_unslash( $_GET['dir'] ) ) : null // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		);

		$policy_events_sorted = Policy_Events_Builder::sort( $pc_result['events'], $pc_sort['key'], $pc_sort['dir'] );

		$pc_total      = count( $policy_events_sorted );
		$pc_pages      = max( 1, (int) ceil( $pc_total / $per_page ) );
		$pc_page_num   = min( max( 1, (int) ( isset( $_GET['pc_paged'] ) ? $_GET['pc_paged'] : 1 ) ), $pc_pages );
		$pc_offset     = ( $pc_page_num - 1 ) * $per_page;
		$policy_events = array_slice( $policy_events_sorted, $pc_offset, $per_page );

		$pc_state_args = array_filter(
			array(
				'tab'               => 'policy-changes',
				'sort'              => $pc_sort['key'],
				'dir'               => strtolower( $pc_sort['dir'] ),
				'pc_type'           => $pc_type,
				'pc_event'          => $pc_event,
				'pc_surface'        => $pc_surface,
				'pc_directive'      => $pc_directive,
				'pc_host'           => $pc_host,
				'pc_risk'           => $pc_risk,
				'pc_policy_version' => $pc_policy_ver,
				'pc_suppression'    => $pc_suppression,
				'pc_actor'          => $pc_actor,
				'pc_detail'         => $pc_detail,
				'pc_when_from'      => $pc_when_from,
				'pc_when_to'        => $pc_when_to,
			)
		);
		?>
	<p class="description">
		<?php esc_html_e( 'Discovered candidates appear in For Review first. This timeline shows proposal activity, administrator or automation decisions, suppression state, and the policy snapshots created after material changes.', 'vcns-security-automation-manager' ); ?>
	</p>
		<?php if ( $pc_result['truncated'] ) : ?>
	<div class="notice notice-warning inline">
		<p><?php esc_html_e( 'Showing results from up to 5,000 recent records per activity type. Narrow your filters (Type, Surface, Directive, or a date range) to see the full, correctly-sorted result set.', 'vcns-security-automation-manager' ); ?></p>
	</div>
	<?php endif; ?>
	<details class="wp-sam-filter-form">
		<summary><?php esc_html_e( 'Filters', 'vcns-security-automation-manager' ); ?></summary>
		<form method="get" action="">
			<input type="hidden" name="page" value="security-automation-manager-dashboard" />
			<input type="hidden" name="tab"  value="policy-changes" />
			<label>
				<?php esc_html_e( 'Type', 'vcns-security-automation-manager' ); ?>
				<select name="pc_type[]" multiple size="3">
					<?php foreach ( $pc_type_options as $opt ) : ?>
					<option value="<?php echo esc_attr( $opt ); ?>" <?php echo in_array( $opt, $pc_type, true ) ? 'selected' : ''; ?>><?php echo esc_html( $opt ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
			<label>
				<?php esc_html_e( 'Event', 'vcns-security-automation-manager' ); ?>
				<select name="pc_event[]" multiple size="4">
					<?php foreach ( $pc_event_options as $opt ) : ?>
					<option value="<?php echo esc_attr( $opt ); ?>" <?php echo in_array( $opt, $pc_event, true ) ? 'selected' : ''; ?>><?php echo esc_html( $opt ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
			<label>
				<?php esc_html_e( 'Surface', 'vcns-security-automation-manager' ); ?>
				<select name="pc_surface[]" multiple size="4">
					<?php foreach ( $surfaces as $s ) : ?>
					<option value="<?php echo esc_attr( $s ); ?>" <?php echo in_array( $s, $pc_surface, true ) ? 'selected' : ''; ?>><?php echo esc_html( ucfirst( $s ) ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
			<label>
				<?php esc_html_e( 'Directive', 'vcns-security-automation-manager' ); ?>
				<select name="pc_directive[]" multiple size="4">
					<?php foreach ( $pc_directive_options as $d ) : ?>
					<option value="<?php echo esc_attr( $d ); ?>" <?php echo in_array( $d, $pc_directive, true ) ? 'selected' : ''; ?>><?php echo esc_html( $d ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
			<label>
				<?php esc_html_e( 'Host contains', 'vcns-security-automation-manager' ); ?>
				<input type="text" name="pc_host" value="<?php echo esc_attr( $pc_host ); ?>" />
			</label>
			<label>
				<?php esc_html_e( 'Risk', 'vcns-security-automation-manager' ); ?>
				<select name="pc_risk[]" multiple size="3">
					<?php foreach ( array( 'high', 'medium', 'low' ) as $risk ) : ?>
					<option value="<?php echo esc_attr( $risk ); ?>" <?php echo in_array( $risk, $pc_risk, true ) ? 'selected' : ''; ?>><?php echo esc_html( ucfirst( $risk ) ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
			<label>
				<?php esc_html_e( 'Policy version contains', 'vcns-security-automation-manager' ); ?>
				<input type="text" name="pc_policy_version" value="<?php echo esc_attr( $pc_policy_ver ); ?>" />
			</label>
			<label>
				<?php esc_html_e( 'Suppression', 'vcns-security-automation-manager' ); ?>
				<select name="pc_suppression">
					<option value=""><?php esc_html_e( 'Any', 'vcns-security-automation-manager' ); ?></option>
					<option value="active" <?php selected( $pc_suppression, 'active' ); ?>><?php esc_html_e( 'Active only', 'vcns-security-automation-manager' ); ?></option>
				</select>
			</label>
			<label>
				<?php esc_html_e( 'Actor', 'vcns-security-automation-manager' ); ?>
				<select name="pc_actor[]" multiple size="4">
					<?php foreach ( $pc_actor_options as $a ) : ?>
					<option value="<?php echo esc_attr( $a ); ?>" <?php echo in_array( $a, $pc_actor, true ) ? 'selected' : ''; ?>><?php echo esc_html( $a ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
			<label>
				<?php esc_html_e( 'Detail contains', 'vcns-security-automation-manager' ); ?>
				<input type="text" name="pc_detail" value="<?php echo esc_attr( $pc_detail ); ?>" />
			</label>
			<label>
				<?php esc_html_e( 'When from', 'vcns-security-automation-manager' ); ?>
				<input type="date" name="pc_when_from" value="<?php echo esc_attr( $pc_when_from ); ?>" />
			</label>
			<label>
				<?php esc_html_e( 'to', 'vcns-security-automation-manager' ); ?>
				<input type="date" name="pc_when_to" value="<?php echo esc_attr( $pc_when_to ); ?>" />
			</label>
			<?php submit_button( __( 'Filter', 'vcns-security-automation-manager' ), 'secondary', 'filter_policy_changes', false ); ?>
		</form>
	</details>
	<table class="widefat fixed striped" style="margin-top:1em">
		<thead>
			<tr>
				<?php
				echo Table_Query::sort_header( __( 'When', 'vcns-security-automation-manager' ), 'when', $pc_sort_whitelist, $pc_sort, $pc_state_args, $base_url, 'pc_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- helper escapes internally.
				echo Table_Query::sort_header( __( 'Event', 'vcns-security-automation-manager' ), 'event', $pc_sort_whitelist, $pc_sort, $pc_state_args, $base_url, 'pc_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'Type', 'vcns-security-automation-manager' ), 'type', $pc_sort_whitelist, $pc_sort, $pc_state_args, $base_url, 'pc_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'Actor', 'vcns-security-automation-manager' ), 'actor', $pc_sort_whitelist, $pc_sort, $pc_state_args, $base_url, 'pc_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'Surface', 'vcns-security-automation-manager' ), 'surface', $pc_sort_whitelist, $pc_sort, $pc_state_args, $base_url, 'pc_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'Directive', 'vcns-security-automation-manager' ), 'directive', $pc_sort_whitelist, $pc_sort, $pc_state_args, $base_url, 'pc_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'Host', 'vcns-security-automation-manager' ), 'host', $pc_sort_whitelist, $pc_sort, $pc_state_args, $base_url, 'pc_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'Risk', 'vcns-security-automation-manager' ), 'risk', $pc_sort_whitelist, $pc_sort, $pc_state_args, $base_url, 'pc_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'Policy Version', 'vcns-security-automation-manager' ), 'policy_version', $pc_sort_whitelist, $pc_sort, $pc_state_args, $base_url, 'pc_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'Suppression', 'vcns-security-automation-manager' ), 'suppression', $pc_sort_whitelist, $pc_sort, $pc_state_args, $base_url, 'pc_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'Detail', 'vcns-security-automation-manager' ), 'detail', $pc_sort_whitelist, $pc_sort, $pc_state_args, $base_url, 'pc_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				?>
			</tr>
		</thead>
		<tbody>
		<?php foreach ( $policy_events as $event ) : ?>
		<tr>
			<td><?php echo esc_html( $event['created_at'] ); ?></td>
			<td><?php echo esc_html( $event['event'] ); ?></td>
			<td><?php echo esc_html( $event['type'] ); ?></td>
			<td><?php echo esc_html( $event['actor'] ); ?></td>
			<td><?php echo '' !== $event['surface'] ? esc_html( $event['surface'] ) : '&mdash;'; ?></td>
			<td>
				<?php if ( '' !== $event['directive'] ) : ?>
					<code><?php echo esc_html( $event['directive'] ); ?></code>
				<?php else : ?>
					&mdash;
				<?php endif; ?>
			</td>
			<td>
				<?php if ( '' !== $event['source'] ) : ?>
					<code><?php echo esc_html( $event['source'] ); ?></code>
				<?php else : ?>
					&mdash;
				<?php endif; ?>
			</td>
			<td>
				<?php echo '' !== $event['risk_level'] ? Risk_Badge::render( $event['risk_level'], $event['risk_reason'] ) : '&mdash;'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Risk_Badge::render() escapes internally; the literal &mdash; needs no escaping. ?>
			</td>
			<td><?php echo '' !== $event['policy_version'] ? esc_html( $event['policy_version'] ) : '&mdash;'; ?></td>
			<td>
				<?php echo '' !== $event['suppression'] ? esc_html( $event['suppression'] ) : '&mdash;'; ?>
			</td>
			<td><?php echo esc_html( $event['detail'] ); ?></td>
		</tr>
		<?php endforeach; ?>
		<?php if ( empty( $policy_events ) ) : ?>
		<tr><td colspan="11"><?php esc_html_e( 'No policy activity has been recorded yet.', 'vcns-security-automation-manager' ); ?></td></tr>
		<?php endif; ?>
		</tbody>
	</table>

		<?php echo Table_Query::pagination( $pc_page_num, $pc_pages, $pc_state_args, $base_url, 'pc_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>

	<?php elseif ( 'policy-audit' === $tab ) : ?>
	<!-- ── Policy Audit tab ───────────────────────────────────────────────── -->
		<?php
		$audit_versions_table = $wpdb->prefix . 'sam_policy_versions';
		$audit_pending_table  = $wpdb->prefix . 'csp_source_inventory';
		$profiles_by_surface  = array_column( $profiles, null, 'surface' );
		?>
	<table class="widefat striped wp-sam-audit-table">
		<thead>
			<tr>
				<th><?php esc_html_e( 'Surface', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Mode', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Automation', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Policy Version', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Pending', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'High Risk', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Effective Header', 'vcns-security-automation-manager' ); ?></th>
			</tr>
		</thead>
		<tbody>
			<?php foreach ( $surfaces as $surface ) : ?>
				<?php
				$audit_latest = $wpdb->get_row(
					$wpdb->prepare(
						// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
						"SELECT * FROM {$audit_versions_table} WHERE surface = %s ORDER BY version_number DESC LIMIT 1",
						$surface
					),
					ARRAY_A
				);
				$audit_pending_count = (int) $wpdb->get_var(
					$wpdb->prepare(
						// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
						"SELECT COUNT(*) FROM {$audit_pending_table} WHERE surface = %s AND approval_state = 'pending'",
						$surface
					)
				);
				$audit_high_count = (int) $wpdb->get_var(
					$wpdb->prepare(
						// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
						"SELECT COUNT(*) FROM {$audit_pending_table} WHERE surface = %s AND approval_state = 'pending' AND risk_level IN ('critical','high','unknown')",
						$surface
					)
				);
				$audit_profile = $profiles_by_surface[ $surface ] ?? array();
				?>
				<tr>
					<td><strong><?php echo esc_html( ucfirst( $surface ) ); ?></strong></td>
					<td><?php echo esc_html( $audit_profile['mode'] ?? 'unknown' ); ?></td>
					<td><?php echo esc_html( $automation_config[ $surface ]['mode'] ?? 'manual' ); ?></td>
					<td><?php echo isset( $audit_latest['version_number'] ) ? esc_html( (string) $audit_latest['version_number'] ) : esc_html__( 'Not captured yet', 'vcns-security-automation-manager' ); ?></td>
					<td><?php echo esc_html( (string) $audit_pending_count ); ?></td>
					<td><?php echo esc_html( (string) $audit_high_count ); ?></td>
					<td><code><?php echo Csp_Header_Formatter::render( (string) ( $audit_latest['effective_header'] ?? '' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- pre-escaped HTML, see Csp_Header_Formatter::render() ?></code></td>
				</tr>
			<?php endforeach; ?>
		</tbody>
	</table>
	<p class="description" style="margin-top:1em">
		<?php esc_html_e( 'For the pending review queue, see For Review. For the full, immutable decision ledger -- who approved, rejected, or reverted each source, and why -- see Policy Changes.', 'vcns-security-automation-manager' ); ?>
	</p>

	<?php elseif ( 'violations' === $tab ) : ?>
	<!-- ── Violations tab ─────────────────────────────────────────────────── -->
		<?php
		$report_endpoint_url = (string) get_option( 'wp_sam_report_endpoint_url', '' );
		if ( '' === trim( $report_endpoint_url ) ) {
			$report_endpoint_url = rest_url( 'sam/v1/report' );
		}

		$v_surface   = Table_Query::text_param( 'v_surface' );
		$v_directive = Table_Query::text_param( 'v_directive' );
		$v_blocked   = Table_Query::text_param( 'v_blocked' );
		$v_occ_min   = Table_Query::int_param( 'v_occ_min' );
		$v_seen_from = Table_Query::text_param( 'v_seen_from' );
		$v_seen_to   = Table_Query::text_param( 'v_seen_to' );

		$viol_where = array( '1=1' );
		$viol_args  = array();
		foreach (
			array(
				Table_Query::equals_where( 'profile_surface', $v_surface ),
				Table_Query::like_where( $wpdb, 'violated_directive', $v_directive ),
				Table_Query::like_where_any( $wpdb, array( 'blocked_host', 'blocked_uri' ), $v_blocked ),
				Table_Query::numeric_gte_where( 'occurrence_count', $v_occ_min ),
				Table_Query::date_range_where( 'reported_at', $v_seen_from, $v_seen_to ),
			) as $viol_fragment
		) {
			if ( null === $viol_fragment ) {
				continue;
			}
			$viol_where[] = $viol_fragment['sql'];
			array_push( $viol_args, ...$viol_fragment['args'] );
		}
		$viol_where_sql = implode( ' AND ', $viol_where );

		$viol_sort_whitelist = array(
			'surface'     => array(
				'expr'        => 'profile_surface',
				'default_dir' => 'asc',
			),
			'blocked_uri' => array(
				'expr'        => 'COALESCE(blocked_host, blocked_uri)',
				'default_dir' => 'asc',
			),
			'directive'   => array(
				'expr'        => 'violated_directive',
				'default_dir' => 'asc',
			),
			'occurrences' => array(
				'expr'        => 'occurrence_count',
				'default_dir' => 'desc',
			),
			'last_seen'   => array(
				'expr'        => 'reported_at',
				'default_dir' => 'desc',
			),
			'disposition' => array(
				'expr'        => 'disposition',
				'default_dir' => 'asc',
			),
		);
		$viol_sort           = Table_Query::resolve_sort(
			$viol_sort_whitelist,
			'last_seen',
			isset( $_GET['sort'] ) ? sanitize_text_field( wp_unslash( $_GET['sort'] ) ) : null, // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			isset( $_GET['dir'] ) ? sanitize_text_field( wp_unslash( $_GET['dir'] ) ) : null // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		);

		$viol_state_args = array_filter(
			array(
				'tab'         => 'violations',
				'sort'        => $viol_sort['key'],
				'dir'         => strtolower( $viol_sort['dir'] ),
				'v_surface'   => $v_surface,
				'v_directive' => $v_directive,
				'v_blocked'   => $v_blocked,
				'v_occ_min'   => $v_occ_min,
				'v_seen_from' => $v_seen_from,
				'v_seen_to'   => $v_seen_to,
			)
		);

		$viol_count_sql = "SELECT COUNT(*) FROM {$wpdb->prefix}csp_violation_reports WHERE {$viol_where_sql}";
		if ( ! empty( $viol_args ) ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$viol_count_sql = $wpdb->prepare( $viol_count_sql, ...$viol_args );
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$viol_total = (int) $wpdb->get_var( $viol_count_sql );

		$viol_pages    = max( 1, (int) ceil( $viol_total / $per_page ) );
		$viol_page_num = min( max( 1, (int) ( isset( $_GET['v_paged'] ) ? $_GET['v_paged'] : 1 ) ), $viol_pages );
		$viol_offset   = ( $viol_page_num - 1 ) * $per_page;

		$viol_data_args = array_merge( $viol_args, array( $per_page, $viol_offset ) );
		$viol_data_sql  = "SELECT * FROM {$wpdb->prefix}csp_violation_reports WHERE {$viol_where_sql} " . Table_Query::order_by_sql( $viol_sort ) . ' LIMIT %d OFFSET %d';
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$viol_data_sql = $wpdb->prepare( $viol_data_sql, ...$viol_data_args );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$violations_raw = $wpdb->get_results( $viol_data_sql, ARRAY_A );
		$violations     = ! empty( $violations_raw ) ? $violations_raw : array();

		// Quick range buttons: set "Last seen from" to now-minus-N and leave the
		// upper bound open, matching current_time( 'mysql', true ) (UTC), the
		// same basis reported_at is stored under -- so these line up with what's
		// actually in the database regardless of the site's display timezone.
		$viol_quick_ranges = array(
			'1h'  => array( 1, __( 'Last hour', 'vcns-security-automation-manager' ) ),
			'6h'  => array( 6, __( 'Last 6 hours', 'vcns-security-automation-manager' ) ),
			'24h' => array( 24, __( 'Last day', 'vcns-security-automation-manager' ) ),
			'7d'  => array( 24 * 7, __( 'Last 7 days', 'vcns-security-automation-manager' ) ),
		);
		?>
	<p class="wp-sam-quick-ranges">
		<?php foreach ( $viol_quick_ranges as [ $viol_range_hours_ago, $viol_range_label ] ) : ?>
			<?php
			$viol_range_from = gmdate( 'Y-m-d\TH:i', time() - ( $viol_range_hours_ago * HOUR_IN_SECONDS ) );
			$viol_range_url  = add_query_arg(
				array_merge(
					$viol_state_args,
					array(
						'v_seen_from' => $viol_range_from,
						'v_seen_to'   => '',
						'v_paged'     => 1,
					)
				),
				$base_url
			);
			?>
		<a href="<?php echo esc_url( $viol_range_url ); ?>" class="button"><?php echo esc_html( $viol_range_label ); ?></a>
		<?php endforeach; ?>
	</p>
	<details class="wp-sam-filter-form">
		<summary><?php esc_html_e( 'Filters', 'vcns-security-automation-manager' ); ?></summary>
		<form method="get" action="">
			<input type="hidden" name="page" value="security-automation-manager-dashboard" />
			<input type="hidden" name="tab" value="violations" />
			<label>
				<?php esc_html_e( 'Surface', 'vcns-security-automation-manager' ); ?>
				<select name="v_surface">
					<option value=""><?php esc_html_e( 'Any', 'vcns-security-automation-manager' ); ?></option>
					<?php foreach ( $surfaces as $s ) : ?>
					<option value="<?php echo esc_attr( $s ); ?>" <?php selected( $v_surface, $s ); ?>><?php echo esc_html( ucfirst( $s ) ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
			<label>
				<?php esc_html_e( 'Directive', 'vcns-security-automation-manager' ); ?>
				<input type="text" name="v_directive" placeholder="<?php esc_attr_e( 'e.g. script-src', 'vcns-security-automation-manager' ); ?>" value="<?php echo esc_attr( $v_directive ); ?>" />
			</label>
			<label>
				<?php esc_html_e( 'Blocked URI contains', 'vcns-security-automation-manager' ); ?>
				<input type="text" name="v_blocked" value="<?php echo esc_attr( $v_blocked ); ?>" />
			</label>
			<label>
				<?php esc_html_e( 'Occurrences at least', 'vcns-security-automation-manager' ); ?>
				<input type="number" min="0" name="v_occ_min" style="width:80px" value="<?php echo esc_attr( null !== $v_occ_min ? (string) $v_occ_min : '' ); ?>" />
			</label>
			<label>
				<?php esc_html_e( 'Last seen from', 'vcns-security-automation-manager' ); ?>
				<input type="datetime-local" name="v_seen_from" value="<?php echo esc_attr( $v_seen_from ); ?>" />
			</label>
			<label>
				<?php esc_html_e( 'to', 'vcns-security-automation-manager' ); ?>
				<input type="datetime-local" name="v_seen_to" value="<?php echo esc_attr( $v_seen_to ); ?>" />
			</label>
			<?php submit_button( __( 'Filter', 'vcns-security-automation-manager' ), 'secondary', 'filter_violations', false ); ?>
		</form>
	</details>
	<table class="widefat fixed striped wp-sam-violations-table" style="margin-top:1em">
		<thead>
			<tr>
				<?php
				echo Table_Query::sort_header( __( 'Surface', 'vcns-security-automation-manager' ), 'surface', $viol_sort_whitelist, $viol_sort, $viol_state_args, $base_url, 'v_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- helper escapes internally.
				echo Table_Query::sort_header( __( 'Blocked URI', 'vcns-security-automation-manager' ), 'blocked_uri', $viol_sort_whitelist, $viol_sort, $viol_state_args, $base_url, 'v_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'Directive', 'vcns-security-automation-manager' ), 'directive', $viol_sort_whitelist, $viol_sort, $viol_state_args, $base_url, 'v_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'Occurrences (lifetime)', 'vcns-security-automation-manager' ), 'occurrences', $viol_sort_whitelist, $viol_sort, $viol_state_args, $base_url, 'v_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- count never resets; the seen-range filter only affects which rows are *shown*, not this total.
				echo Table_Query::sort_header( __( 'Last Seen', 'vcns-security-automation-manager' ), 'last_seen', $viol_sort_whitelist, $viol_sort, $viol_state_args, $base_url, 'v_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'Disposition', 'vcns-security-automation-manager' ), 'disposition', $viol_sort_whitelist, $viol_sort, $viol_state_args, $base_url, 'v_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				?>
				<th><?php esc_html_e( 'Details', 'vcns-security-automation-manager' ); ?></th>
			</tr>
		</thead>
		<tbody>
		<?php foreach ( $violations as $v ) : ?>
		<tr>
			<td><?php echo esc_html( $v['profile_surface'] ); ?></td>
			<td><code style="word-break:break-all"><?php echo esc_html( ! empty( $v['blocked_host'] ) ? $v['blocked_host'] : $v['blocked_uri'] ); ?></code></td>
			<td><code><?php echo esc_html( $v['violated_directive'] ); ?></code></td>
			<td><?php echo esc_html( number_format( (int) $v['occurrence_count'] ) ); ?></td>
			<td><?php echo esc_html( $v['reported_at'] ); ?></td>
			<td><?php echo esc_html( $v['disposition'] ); ?></td>
			<td>
				<?php
				$meta_fields = array();
				if ( ! empty( $v['first_reported_at'] ) ) {
					$meta_fields[ __( 'First seen', 'vcns-security-automation-manager' ) ] = (string) $v['first_reported_at'];
				}
				if ( 0 === strpos( (string) $v['blocked_uri'], 'data:' ) ) {
					$meta_fields[ __( 'Data URI payload', 'vcns-security-automation-manager' ) ] = mb_substr( (string) $v['blocked_uri'], 0, 200 );
				} elseif ( ! empty( $v['blocked_host'] ) ) {
					$meta_fields[ __( 'Last seen URL', 'vcns-security-automation-manager' ) ] = (string) $v['blocked_uri'];
				}
				if ( ! empty( $v['document_uri'] ) ) {
					$meta_fields[ __( 'Page URL', 'vcns-security-automation-manager' ) ] = (string) $v['document_uri'];
				}
				if ( ! empty( $v['source_file'] ) ) {
					$location = (string) $v['source_file'];
					if ( '' !== (string) ( $v['line_number'] ?? '' ) ) {
						$location .= ':' . $v['line_number'];
						if ( '' !== (string) ( $v['column_number'] ?? '' ) ) {
							$location .= ':' . $v['column_number'];
						}
					}
					$meta_fields[ __( 'Source file', 'vcns-security-automation-manager' ) ] = $location;
				}
				if ( ! empty( $v['referrer'] ) ) {
					$meta_fields[ __( 'Referrer', 'vcns-security-automation-manager' ) ] = (string) $v['referrer'];
				}
				if ( ! empty( $v['user_agent'] ) ) {
					$meta_fields[ __( 'User agent', 'vcns-security-automation-manager' ) ] = (string) $v['user_agent'];
				}
				if ( ! empty( $v['sample'] ) ) {
					$meta_fields[ __( 'Sample', 'vcns-security-automation-manager' ) ] = (string) $v['sample'];
				}
				if ( empty( $v['blocked_host'] ) ) {
					// blocked_uri values with no host (inline, eval, data:, etc.) fingerprint
					// on the literal token itself -- every distinct inline block matching
					// this surface+directive combination collapses into this one row, so
					// occurrence_count is not a count of distinct blocks. Point admins at
					// the actual per-block record instead of leaving this undercount silent.
					$meta_fields[ __( 'Note', 'vcns-security-automation-manager' ) ] = __( 'This row aggregates every occurrence of this directive with this blocked-uri token (e.g. "inline"), not distinct content blocks -- a page with many different inline scripts/styles still shows as one row here. Check the Scripts (Internal Script Integrity) tab for individually captured content hashes awaiting review.', 'vcns-security-automation-manager' );
				}

				$has_meta = ! empty( $meta_fields );
				?>
				<?php if ( $has_meta ) : ?>
				<span class="dashicons dashicons-info-outline wp-sam-meta-icon" tabindex="0">
					<span class="wp-sam-meta-popover" role="tooltip">
						<?php foreach ( $meta_fields as $meta_label => $meta_value ) : ?>
						<div class="wp-sam-meta-row">
							<strong><?php echo esc_html( $meta_label ); ?>:</strong>
							<code><?php echo esc_html( $meta_value ); ?></code>
						</div>
						<?php endforeach; ?>
					</span>
				</span>
				<?php else : ?>
				<span class="dashicons dashicons-info-outline wp-sam-meta-icon wp-sam-meta-icon--empty" title="<?php esc_attr_e( 'No metadata captured for this violation', 'vcns-security-automation-manager' ); ?>"></span>
				<?php endif; ?>
			</td>
		</tr>
		<?php endforeach; ?>
		<?php if ( empty( $violations ) ) : ?>
		<tr>
			<td colspan="7">
				<p><?php esc_html_e( 'No browser violation reports have been recorded yet.', 'vcns-security-automation-manager' ); ?></p>
				<p>
					<?php esc_html_e( 'Manual scans discover candidate sources, but they do not create violation reports. To collect violations, browse the live site while the relevant surface emits this plugin\'s report-only or enforce CSP header with reporting directives.', 'vcns-security-automation-manager' ); ?>
				</p>
				<p>
					<?php esc_html_e( 'Expected reporting endpoint:', 'vcns-security-automation-manager' ); ?>
					<code><?php echo esc_html( esc_url_raw( $report_endpoint_url ) ); ?></code>
				</p>
			</td>
		</tr>
		<?php endif; ?>
		</tbody>
	</table>

		<?php echo Table_Query::pagination( $viol_page_num, $viol_pages, $viol_state_args, $base_url, 'v_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>

	<?php elseif ( 'scan-log' === $tab ) : ?>
	<!-- ── Scan log tab ───────────────────────────────────────────────────── -->
		<?php
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- No user input; only $wpdb->prefix used in query.
		$scan_logs_raw = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}sam_scan_logs ORDER BY started_at DESC LIMIT 20", ARRAY_A );
		$scan_logs     = ! empty( $scan_logs_raw ) ? $scan_logs_raw : array();
		?>
	<table class="widefat fixed striped">
		<thead>
			<tr>
				<th><?php esc_html_e( 'Trigger', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Status', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Sources +/-', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Hashes +/-', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Policy Changed', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Started', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Duration', 'vcns-security-automation-manager' ); ?></th>
			</tr>
		</thead>
		<tbody>
		<?php foreach ( $scan_logs as $log ) : ?>
			<?php
			$duration = '';
			if ( $log['completed_at'] && $log['started_at'] ) {
				$diff     = strtotime( $log['completed_at'] ) - strtotime( $log['started_at'] );
				$duration = $diff . 's';
			}
			?>
		<tr>
			<td><?php echo esc_html( ucfirst( $log['trigger_type'] ) ); ?></td>
			<td><?php echo esc_html( ucfirst( $log['status'] ) ); ?></td>
			<td>+<?php echo esc_html( $log['sources_added'] ); ?> / -<?php echo esc_html( $log['sources_removed'] ); ?></td>
			<td>+<?php echo esc_html( $log['hashes_added'] ); ?> / -<?php echo esc_html( $log['hashes_removed'] ); ?></td>
			<td><?php echo $log['policy_changed'] ? esc_html__( 'Yes', 'vcns-security-automation-manager' ) : '&mdash;'; ?></td>
			<td><?php echo esc_html( $log['started_at'] ); ?></td>
			<td><?php echo esc_html( $duration ); ?></td>
		</tr>
		<?php endforeach; ?>
		<?php if ( empty( $scan_logs ) ) : ?>
		<tr><td colspan="7"><?php esc_html_e( 'No scans run yet.', 'vcns-security-automation-manager' ); ?></td></tr>
		<?php endif; ?>
		</tbody>
	</table>

	<?php elseif ( 'settings' === $tab ) : ?>
	<!-- ── Settings tab ───────────────────────────────────────────────────── -->
		<?php
		$learning_window            = new \WP_SAM\CSP\Learning_Window();
		$learning_status            = $learning_window->is_open() ? __( 'Open', 'vcns-security-automation-manager' ) : __( 'Locked', 'vcns-security-automation-manager' );
		$current_report_endpoint    = esc_url_raw( rest_url( 'sam/v1/report' ) );
		$configured_report_endpoint = (string) get_option( 'wp_sam_report_endpoint_url', '' );
		$configured_policy_header   = (string) get_option( 'wp_sam_policy_header_name', '' );
		$reporting_transport        = \WP_SAM\CSP\Policy_Builder::sanitize_reporting_transport( get_option( 'wp_sam_reporting_transport', 'report-uri' ) );
		$settings_automation_config = ( new \WP_SAM\CSP\Automation_Config( $this->plugin->gate ) )->all();
		$automation_mode_labels     = \WP_SAM\CSP\Automation_Config::mode_labels();
		$automation_directives      = array( 'default-src', 'img-src', 'font-src', 'media-src', 'manifest-src' );
		$automation_schemes         = array( 'https', 'wss' );
		?>
	<form method="post" action="options.php">
		<?php settings_fields( 'wp_sam_settings_group' ); ?>

		<!-- ── Promotion gates ───────────────────────────────────────────── -->
		<h2 class="title"><?php esc_html_e( 'Promotion Gates', 'vcns-security-automation-manager' ); ?></h2>
		<p class="description">
			<?php esc_html_e( 'These settings control the conditions that must be met before a surface can be promoted from report-only to enforce mode.', 'vcns-security-automation-manager' ); ?>
		</p>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row">
					<label for="wp_sam_enforce_gate_violation_window">
						<?php esc_html_e( 'Violation-free window (hours)', 'vcns-security-automation-manager' ); ?>
					</label>
				</th>
				<td>
					<input type="number" id="wp_sam_enforce_gate_violation_window"
						name="wp_sam_enforce_gate_violation_window"
						value="<?php echo esc_attr( get_option( 'wp_sam_enforce_gate_violation_window', 24 ) ); ?>"
						min="1" max="720" class="small-text" />
					<p class="description">
						<?php esc_html_e( 'Number of hours without any CSP violations required before a surface can be promoted to enforce mode. Default: 24. Increase this for production sites to ensure stability.', 'vcns-security-automation-manager' ); ?>
					</p>
				</td>
			</tr>
		</table>

		<h2 class="title"><?php esc_html_e( 'Deterministic Automation', 'vcns-security-automation-manager' ); ?></h2>
		<p class="description">
			<?php esc_html_e( 'Configure how far the deterministic engine may go without administrator approval. Manual mode remains the default; hard-excluded, critical, unknown, and insufficient-evidence proposals always require review.', 'vcns-security-automation-manager' ); ?>
		</p>
		<?php
		/**
		 * Any paid automation mode's own upsell presentation (and, in its
		 * own further hook if it needs one, its own payment-provider
		 * settings UI) is rendered by whichever extension registers that
		 * mode (see includes/extensions/, physically absent from the
		 * WordPress.org build) -- this file has no knowledge of any
		 * payment provider, checkout mechanism, specific paid mode name,
		 * or its copy. Passes $wp_sam_has_unavailable_mode so a listening
		 * extension can skip rendering anything if its own mode is already
		 * available (entitled).
		 */
		do_action( 'wp_sam_automation_upgrade_notice', $wp_sam_has_unavailable_mode );
		?>

		<table class="widefat striped" role="presentation">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Surface', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Mode', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Maximum per run', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Directive scope', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Allowed schemes', 'vcns-security-automation-manager' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $surfaces as $surface ) : ?>
				<?php $surface_config = $settings_automation_config[ $surface ] ?? \WP_SAM\CSP\Automation_Config::DEFAULT_SURFACE_CONFIG; ?>
				<tr>
					<td><strong><?php echo esc_html( ucfirst( $surface ) ); ?></strong></td>
					<td>
						<select name="wp_sam_automation_config[<?php echo esc_attr( $surface ); ?>][mode]">
							<?php foreach ( $automation_mode_labels as $mode => $label ) : ?>
							<option value="<?php echo esc_attr( $mode ); ?>" <?php selected( $surface_config['mode'], $mode ); ?>
								<?php disabled( ! \WP_SAM\CSP\Automation_Mode_Registry::is_available( $mode ) ); ?>>
								<?php
								echo esc_html( $label );
								if ( ! \WP_SAM\CSP\Automation_Mode_Registry::is_available( $mode ) ) {
									echo ' ' . esc_html__( '(requires upgrade)', 'vcns-security-automation-manager' );
								}
								?>
							</option>
							<?php endforeach; ?>
						</select>
					</td>
					<td>
						<input type="number" class="small-text" min="0" max="50" name="wp_sam_automation_config[<?php echo esc_attr( $surface ); ?>][max_automatic_changes_per_scan]" value="<?php echo esc_attr( (string) ( $surface_config['max_automatic_changes_per_scan'] ?? 0 ) ); ?>" />
					</td>
					<td>
						<?php foreach ( $automation_directives as $directive ) : ?>
							<label style="display:block">
								<input type="checkbox" name="wp_sam_automation_config[<?php echo esc_attr( $surface ); ?>][enabled_directives][]" value="<?php echo esc_attr( $directive ); ?>" <?php checked( in_array( $directive, $surface_config['enabled_directives'] ?? array(), true ) ); ?> />
								<code><?php echo esc_html( $directive ); ?></code>
							</label>
						<?php endforeach; ?>
						<p class="description"><?php esc_html_e( 'Leave all unchecked to permit any directive that is inside the selected automation posture and not hard-excluded by the deterministic engine.', 'vcns-security-automation-manager' ); ?></p>
					</td>
					<td>
						<?php foreach ( $automation_schemes as $scheme ) : ?>
							<label style="display:block">
								<input type="checkbox" name="wp_sam_automation_config[<?php echo esc_attr( $surface ); ?>][allowed_source_schemes][]" value="<?php echo esc_attr( $scheme ); ?>" <?php checked( in_array( $scheme, $surface_config['allowed_source_schemes'] ?? array(), true ) ); ?> />
								<code><?php echo esc_html( $scheme ); ?></code>
							</label>
						<?php endforeach; ?>
					</td>
				</tr>
			<?php endforeach; ?>
			</tbody>
		</table>
		<p class="description">
			<?php esc_html_e( 'Automatic decisions are recorded with actor automation_engine and can be reverted from the review queue like administrator approvals.', 'vcns-security-automation-manager' ); ?>
		</p>

		<h2 class="title"><?php esc_html_e( 'Proxy Header Emission', 'vcns-security-automation-manager' ); ?></h2>
		<p class="description">
			<?php esc_html_e( 'Use this when WordPress is the origin behind Cloudflare, a CDN, or another edge proxy that needs to copy an origin-only header into the browser-facing CSP header.', 'vcns-security-automation-manager' ); ?>
		</p>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><label for="wp_sam_policy_header_name"><?php esc_html_e( 'Policy header name', 'vcns-security-automation-manager' ); ?></label></th>
				<td>
					<input type="text" id="wp_sam_policy_header_name" name="wp_sam_policy_header_name"
						value="<?php echo esc_attr( $configured_policy_header ); ?>"
						placeholder="<?php echo esc_attr( 'X-Origin-CSP-Policy' ); ?>"
						class="regular-text code" />
					<p class="description">
						<?php esc_html_e( 'Leave blank for the plugin to emit the normal mode-aware headers: Content-Security-Policy-Report-Only in report-only mode and Content-Security-Policy in enforce mode. Set a custom HTTP field name to emit the policy under that exact origin header instead, then configure the proxy to copy it back to the appropriate browser-facing CSP header.', 'vcns-security-automation-manager' ); ?>
					</p>
					<p class="description">
						<?php esc_html_e( 'Only valid HTTP header field names are accepted. Hop-by-hop and cookie headers are rejected.', 'vcns-security-automation-manager' ); ?>
					</p>
				</td>
			</tr>
		</table>

		<h2 class="title"><?php esc_html_e( 'Report Endpoint Learning', 'vcns-security-automation-manager' ); ?></h2>
		<p class="description">
			<?php esc_html_e( 'Validated CSP reports can add pending source candidates while the site is inside the material-change learning window.', 'vcns-security-automation-manager' ); ?>
		</p>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><label for="wp_sam_report_endpoint_url"><?php esc_html_e( 'Reporting server URL', 'vcns-security-automation-manager' ); ?></label></th>
				<td>
					<input type="url" id="wp_sam_report_endpoint_url" name="wp_sam_report_endpoint_url"
						value="<?php echo esc_attr( $configured_report_endpoint ); ?>"
						placeholder="<?php echo esc_attr( $current_report_endpoint ); ?>"
						class="regular-text code" />
					<button type="button" class="button wp-sam-use-current-report-endpoint" data-report-endpoint="<?php echo esc_attr( $current_report_endpoint ); ?>">
						<?php esc_html_e( 'Use current site endpoint', 'vcns-security-automation-manager' ); ?>
					</button>
					<p class="description">
						<?php esc_html_e( 'Leave blank to use the current WordPress REST endpoint shown below. Set an absolute public URL when visitors reach the site through a proxy, CDN, load balancer, or different HTTPS host. The URL should still resolve to this plugin report endpoint if you want local report learning.', 'vcns-security-automation-manager' ); ?>
					</p>
					<p class="description">
						<?php esc_html_e( 'Detected current endpoint:', 'vcns-security-automation-manager' ); ?>
						<code><?php echo esc_html( $current_report_endpoint ); ?></code>
					</p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="wp_sam_reporting_transport"><?php esc_html_e( 'Reporting transport', 'vcns-security-automation-manager' ); ?></label></th>
				<td>
					<select id="wp_sam_reporting_transport" name="wp_sam_reporting_transport">
						<option value="report-uri" <?php selected( $reporting_transport, 'report-uri' ); ?>>
							<?php esc_html_e( 'Direct report-uri (recommended)', 'vcns-security-automation-manager' ); ?>
						</option>
						<option value="both" <?php selected( $reporting_transport, 'both' ); ?>>
							<?php esc_html_e( 'Direct report-uri plus Reporting API', 'vcns-security-automation-manager' ); ?>
						</option>
						<option value="report-to" <?php selected( $reporting_transport, 'report-to' ); ?>>
							<?php esc_html_e( 'Reporting API only', 'vcns-security-automation-manager' ); ?>
						</option>
					</select>
					<p class="description">
						<?php esc_html_e( 'Use direct report-uri while learning so browser reports arrive promptly in the Violations tab. Reporting API delivery can be queued or delayed by the browser, and browsers that use report-to may ignore report-uri.', 'vcns-security-automation-manager' ); ?>
					</p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="wp_sam_learning_window_hours"><?php esc_html_e( 'Learning window (hours)', 'vcns-security-automation-manager' ); ?></label></th>
				<td>
					<input type="number" id="wp_sam_learning_window_hours" name="wp_sam_learning_window_hours"
						value="<?php echo esc_attr( get_option( 'wp_sam_learning_window_hours', 48 ) ); ?>"
						min="1" max="720" class="small-text" />
					<p class="description">
						<?php esc_html_e( 'Default: 48. The report endpoint stops creating or updating source candidates after this many hours from the latest page, post, or plugin change.', 'vcns-security-automation-manager' ); ?>
					</p>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Learning status', 'vcns-security-automation-manager' ); ?></th>
				<td>
					<p>
						<?php
						printf(
							/* translators: 1: status, 2: last material change time, 3: lock time */
							esc_html__( '%1$s. Last material change: %2$s. Locks at: %3$s UTC.', 'vcns-security-automation-manager' ),
							'<strong>' . esc_html( $learning_status ) . '</strong>',
							esc_html( $learning_window->last_material_change_at() ),
							esc_html( $learning_window->locks_at() )
						);
						?>
					</p>
				</td>
			</tr>
		</table>

		<!-- ── Scan schedule ─────────────────────────────────────────────── -->
		<h2 class="title"><?php esc_html_e( 'Scan Schedule', 'vcns-security-automation-manager' ); ?></h2>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><label for="wp_sam_cron_hour"><?php esc_html_e( 'Daily Scan Hour (0–23, UTC)', 'vcns-security-automation-manager' ); ?></label></th>
				<td>
					<input type="number" id="wp_sam_cron_hour" name="wp_sam_cron_hour"
						value="<?php echo esc_attr( get_option( 'wp_sam_cron_hour', 2 ) ); ?>"
						min="0" max="23" class="small-text" />
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="wp_sam_notify_email"><?php esc_html_e( 'Notification Email', 'vcns-security-automation-manager' ); ?></label></th>
				<td>
					<input type="email" id="wp_sam_notify_email" name="wp_sam_notify_email"
						value="<?php echo esc_attr( get_option( 'wp_sam_notify_email', get_option( 'admin_email' ) ) ); ?>"
						class="regular-text" />
					<p class="description"><?php esc_html_e( 'Receive an email when the policy changes after a scheduled scan.', 'vcns-security-automation-manager' ); ?></p>
				</td>
			</tr>
		</table>

		<?php submit_button(); ?>
	</form>
	<?php endif; ?>

	</div><!-- .tab-content -->
</div><!-- .wp-sam-wrap -->
