<?php
/**
 * Admin view: CSP dashboard.
 * Shows per-surface policy profiles, source inventory, violations, scan log.
 * Rendered by Admin_UI::render_dashboard().
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WP_SAM\Admin\Table_Query;
use WP_SAM\Admin\Policy_Events_Builder;

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
		'label'       => __( 'Start Here', 'security-automation-manager' ),
		'description' => __( 'A short guide to how this plugin works: report-only, the learning window, and promoting a surface to enforce mode.', 'security-automation-manager' ),
	),
	'profiles'       => array(
		'label'       => __( 'Profiles', 'security-automation-manager' ),
		'description' => __( 'Configure the CSP mode for each site surface. Use report-only while learning, enforce only after the surface is stable, or disabled when this plugin should not emit CSP for that surface.', 'security-automation-manager' ),
	),
	'violations'     => array(
		'label'       => __( 'Violations', 'security-automation-manager' ),
		'description' => __( 'Review browser-submitted CSP reports. Use these reports to identify required sources before promoting a surface from report-only to enforce mode.', 'security-automation-manager' ),
	),
	'sources'        => array(
		'label'       => __( 'For Review', 'security-automation-manager' ),
		'description' => __( 'Review discovered source candidates and decide whether each source belongs in the policy. Discovery adds review items; approvals, rejections, reversions, and undo actions require a reason and are written to the decision ledger.', 'security-automation-manager' ),
	),
	'policy-changes' => array(
		'label'       => __( 'Policy Changes', 'security-automation-manager' ),
		'description' => __( 'Inspect policy activity across discovered proposals, administrator or automation decisions, and immutable policy snapshots.', 'security-automation-manager' ),
	),
	'policy-audit'   => array(
		'label'       => __( 'Policy Audit', 'security-automation-manager' ),
		'description' => __( 'At-a-glance effective policy for every surface: mode, automation level, policy version, and pending/high-risk counts. For the pending review queue see For Review, and for the full decision ledger see Policy Changes.', 'security-automation-manager' ),
	),
	'scan-log'       => array(
		'label'       => __( 'Scan Log', 'security-automation-manager' ),
		'description' => __( 'Check manual and scheduled scan runs, policy-change counts, warnings, and completion status after site, theme, plugin, or content changes.', 'security-automation-manager' ),
	),
	'settings'       => array(
		'label'       => __( 'Settings', 'security-automation-manager' ),
		'description' => __( 'Promotion gates, deterministic automation, proxy header emission, report endpoint learning, and scan schedule.', 'security-automation-manager' ),
	),
);

// ── Data queries ──────────────────────────────────────────────────────────────
// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
$profiles_raw      = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}csp_policy_profiles ORDER BY surface", ARRAY_A );
$profiles          = ! empty( $profiles_raw ) ? $profiles_raw : array();
$surfaces          = array( 'frontend', 'admin', 'login', 'api' );
$automation_config = ( new \WP_SAM\CSP\Automation_Config( $this->plugin->gate ) )->all();
$automation_labels = \WP_SAM\CSP\Automation_Config::mode_labels();
$wp_sam_is_pro     = $this->plugin->gate->is_allowed( 'fully_automatic' );

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
// 'conflict_detector' audit component, throttled at the source, so this is
// safe to show without an admin having to notice or keep a dismissible
// wp-admin notice around.
// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQL.NotPrepared
$conflict_notices_raw = $wpdb->get_results(
	$wpdb->prepare(
		"SELECT detail, created_at FROM {$wpdb->prefix}sam_audit_log
			WHERE component = %s AND severity = %s AND created_at >= %s
			ORDER BY created_at DESC LIMIT 5",
		'conflict_detector',
		'warning',
		gmdate( 'Y-m-d H:i:s', time() - ( 48 * HOUR_IN_SECONDS ) )
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
	<h1><?php esc_html_e( 'CSP', 'security-automation-manager' ); ?></h1>

	<!-- ── Top action bar ────────────────────────────────────────────────── -->
	<p>
		<button type="button" id="wp-sam-manual-scan" class="button button-primary">
			<?php esc_html_e( 'Run Manual Scan', 'security-automation-manager' ); ?>
		</button>
		<span id="wp-sam-scan-status" style="margin-left:10px;display:none"></span>
	</p>

	<!-- ── Tabs ──────────────────────────────────────────────────────────── -->
	<nav class="nav-tab-wrapper wp-sam-tab-wrapper" role="tablist" aria-label="<?php esc_attr_e( 'CSP dashboard sections', 'security-automation-manager' ); ?>">
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
			<strong><?php esc_html_e( 'Possible competing Content-Security-Policy source detected.', 'security-automation-manager' ); ?></strong>
			<?php esc_html_e( 'Another source (server configuration, a different plugin, or a stale cached response) may be emitting its own CSP header alongside this plugin\'s. Check your server config and any other security plugins for a competing header.', 'security-automation-manager' ); ?>
		</p>
		<ul>
			<?php foreach ( $conflict_notices as $conflict_notice ) : ?>
			<li><code><?php echo esc_html( $conflict_notice['created_at'] ); ?></code> — <?php echo esc_html( $conflict_notice['detail'] ); ?></li>
			<?php endforeach; ?>
		</ul>
	</div>
	<?php endif; ?>

	<div class="tab-content" style="margin-top:1em">

	<?php if ( 'start-here' === $tab ) : ?>
	<!-- ── Start Here tab ─────────────────────────────────────────────────── -->
	<h2 class="title"><?php esc_html_e( 'What this plugin does', 'security-automation-manager' ); ?></h2>
	<p class="description">
		<?php esc_html_e( 'This plugin builds a Content-Security-Policy (CSP) for your site by watching what your site actually loads — scripts, styles, images, fonts, connections, and frames — and letting you decide which of those sources belong in the policy. It manages this separately for four surfaces: the public frontend, wp-admin, the login screen, and the REST API.', 'security-automation-manager' ); ?>
	</p>
	<p class="description">
		<?php esc_html_e( 'Nothing is blocked or enforced until you deliberately turn it on. The whole workflow below is designed so you can see exactly what a policy would do before it does it.', 'security-automation-manager' ); ?>
	</p>

	<h2 class="title"><?php esc_html_e( 'How it works', 'security-automation-manager' ); ?></h2>
	<ol>
		<li>
			<strong><?php esc_html_e( 'Report-only mode.', 'security-automation-manager' ); ?></strong>
			<?php esc_html_e( 'Each surface starts in report-only mode: browsers evaluate the policy and send a report for anything that would have been blocked, but nothing is actually blocked. Reports arrive at this plugin\'s own endpoint (shown on the Settings tab, under Report Endpoint Learning) and appear in the Violations tab.', 'security-automation-manager' ); ?>
		</li>
		<li>
			<strong><?php esc_html_e( 'The learning window.', 'security-automation-manager' ); ?></strong>
			<?php esc_html_e( 'While the learning window is open (48 hours after the last material change to the site by default — a page, post, plugin, or theme edit — adjustable on the Settings tab), validated violation reports and scan discoveries add candidate sources to the For Review queue instead of just being logged. Once the window locks, new discoveries stop being added automatically until another material change reopens it.', 'security-automation-manager' ); ?>
		</li>
		<li>
			<strong><?php esc_html_e( 'Review.', 'security-automation-manager' ); ?></strong>
			<?php esc_html_e( 'Every discovered source lands in For Review with a risk rating and a reason. Approve the ones that belong, reject the ones that don\'t — every decision needs a short reason and is written to a permanent decision ledger (visible on the Policy Changes tab). Depending on the Automation Level you\'ve set for a surface, low-risk sources can be approved automatically instead of waiting on you; see Configuration below.', 'security-automation-manager' ); ?>
		</li>
		<li>
			<strong><?php esc_html_e( 'Manual promotion to enforce mode.', 'security-automation-manager' ); ?></strong>
			<?php esc_html_e( 'When you\'re confident the policy is complete, promote a surface to enforce mode yourself from the Profiles tab — this is never done automatically. Promotion is gated: it requires at least one approved source or hash, no violations within a configurable window (24 hours by default, set on the Settings tab), and no active temporary override.', 'security-automation-manager' ); ?>
		</li>
		<li>
			<strong><?php esc_html_e( 'Policy revision.', 'security-automation-manager' ); ?></strong>
			<?php esc_html_e( 'Enforce mode isn\'t a finish line. A new plugin, a theme change, or a new page can introduce sources the policy doesn\'t cover yet. Treat each material change as a prompt to reopen the learning window, review what\'s new in For Review, and revise the policy — the same report-only-then-promote cycle applies to every revision.', 'security-automation-manager' ); ?>
		</li>
	</ol>

	<h2 class="title"><?php esc_html_e( 'Configuration', 'security-automation-manager' ); ?></h2>
	<p class="description">
		<?php esc_html_e( 'The most important setting is Automation Level, set per surface from the Profiles tab dropdown or the Settings tab: Manual, Automatic (medium+high approvals), Automatic (high approvals only), or Fully automatic. This controls which risk tiers of discovered sources, if any, can be approved without you. Manual is always the safe starting point — nothing is auto-approved until you deliberately raise a surface\'s level. The rest of the Settings tab covers promotion gates, proxy header emission, report endpoint learning, and the scan schedule.', 'security-automation-manager' ); ?>
	</p>

	<h2 class="title"><?php esc_html_e( 'Readiness and Policy Audit', 'security-automation-manager' ); ?></h2>
	<p class="description">
		<?php esc_html_e( 'The Readiness page (in the sidebar) runs plugin and database health checks — schema integrity, table health, and operational checks — and, separately, offers a destructive full data reset if you need to start over.', 'security-automation-manager' ); ?>
	</p>
	<p class="description">
		<?php esc_html_e( 'The Policy Audit tab above shows the current effective policy for every surface at a glance — mode, automation level, policy version, and pending/high-risk counts. For the pending review queue see For Review, and for the full, immutable decision ledger — who approved, rejected, or reverted each source, and why — see Policy Changes.', 'security-automation-manager' ); ?>
	</p>

	<?php elseif ( 'profiles' === $tab ) : ?>
	<!-- ── Profiles tab ───────────────────────────────────────────────────── -->
		<?php
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- No user input; only $wpdb->prefix used in query.
		$profiles_raw = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}csp_policy_profiles ORDER BY surface", ARRAY_A );
		$profiles     = ! empty( $profiles_raw ) ? $profiles_raw : array();

		// Violation counts for the specific (surface, directive) pairs the Bypass
		// Best Practices catalog covers, so the toggle can show "why" -- these are
		// the same rows already visible on the Violations tab, not a new query
		// concept, just grouped for this catalog's two entries specifically.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- no user input; only $wpdb->prefix and a fixed directive list used in the query.
		$bypass_violation_rows   = $wpdb->get_results(
			"SELECT profile_surface, violated_directive, occurrence_count FROM {$wpdb->prefix}csp_violation_reports
			 WHERE blocked_uri = 'data' AND violated_directive IN ( 'img-src', 'font-src' )",
			ARRAY_A
		);
		$bypass_violation_counts = array();
		foreach ( (array) $bypass_violation_rows as $row ) {
			$key                             = $row['profile_surface'] . '|' . $row['violated_directive'];
			$bypass_violation_counts[ $key ] = ( $bypass_violation_counts[ $key ] ?? 0 ) + (int) $row['occurrence_count'];
		}
		?>
	<table class="widefat fixed striped wp-sam-profiles-table">
		<thead>
			<tr>
				<th><?php esc_html_e( 'Surface', 'security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Mode', 'security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Automation', 'security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Experimental', 'security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Bypass Best Practices', 'security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Last Updated', 'security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Actions', 'security-automation-manager' ); ?></th>
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
					__( 'Automation posture: %s', 'security-automation-manager' ),
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
						<?php disabled( \WP_SAM\CSP\Automation_Config::MODE_FULLY_AUTOMATIC === $mode && ! $wp_sam_is_pro ); ?>>
						<?php
						echo esc_html( $label );
						if ( \WP_SAM\CSP\Automation_Config::MODE_FULLY_AUTOMATIC === $mode && ! $wp_sam_is_pro ) {
							echo ' ' . esc_html__( '(requires upgrade)', 'security-automation-manager' );
						}
						?>
					</option>
					<?php endforeach; ?>
				</select>
				<?php if ( ! $wp_sam_is_pro ) : ?>
				<br /><a href="<?php echo esc_url( admin_url( 'admin.php?page=security-automation-manager-dashboard&tab=settings#wp-sam-upgrade' ) ); ?>" style="font-size:0.85em;"><?php esc_html_e( 'Upgrade to unlock →', 'security-automation-manager' ); ?></a>
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
					<?php esc_html_e( 'Trusted Types', 'security-automation-manager' ); ?>
				</label>
				<p class="description" style="margin:4px 0 0;">
					<?php esc_html_e( "require-trusted-types-for 'script' -- pinned to report-only; enforcing it needs application code most WordPress sites don't have yet.", 'security-automation-manager' ); ?>
				</p>
			</td>
			<td>
				<?php foreach ( \WP_SAM\CSP\Policy_Builder::BYPASS_CATALOG as $bypass_flag => $bypass_entry ) : ?>
				<label style="display:block;margin-bottom:6px;">
					<input
						type="checkbox"
						class="wp-sam-bypass-flag-toggle"
						data-surface="<?php echo esc_attr( $profile['surface'] ); ?>"
						data-flag="<?php echo esc_attr( $bypass_flag ); ?>"
						<?php checked( ! empty( $profile[ $bypass_entry['column'] ] ) ); ?>
					/>
					<?php echo esc_html( $bypass_entry['label'] ); ?>
				</label>
				<p class="description" style="margin:0 0 8px;">
					<?php echo esc_html( $bypass_entry['risk_note'] ); ?>
					<?php
					$bypass_count = $bypass_violation_counts[ $profile['surface'] . '|' . $bypass_entry['directive'] ] ?? 0;
					if ( $bypass_count > 0 ) :
						?>
					<br />
						<?php
						printf(
						/* translators: %s: formatted violation occurrence count */
							esc_html__( '%s violations observed on this surface.', 'security-automation-manager' ),
							esc_html( number_format( $bypass_count ) )
						);
						?>
					<?php endif; ?>
				</p>
				<?php endforeach; ?>
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
		<tr><td colspan="7"><?php esc_html_e( 'No profiles found. Deactivate and reactivate the plugin to seed defaults.', 'security-automation-manager' ); ?></td></tr>
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
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			$count_sql = $wpdb->prepare( $count_sql, ...$src_args );
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.NotPrepared
		$src_total = (int) $wpdb->get_var( $count_sql );

		$src_pages = max( 1, (int) ceil( $src_total / $per_page ) );
		$page_num  = min( max( 1, (int) ( isset( $_GET['paged'] ) ? $_GET['paged'] : 1 ) ), $src_pages );
		$offset    = ( $page_num - 1 ) * $per_page;

		$query_args = array_merge( $src_args, array( $per_page, $offset ) );
		$data_sql   = "SELECT * FROM {$wpdb->prefix}csp_source_inventory WHERE {$src_where_sql} " . Table_Query::order_by_sql( $src_sort ) . ' LIMIT %d OFFSET %d';
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		$data_sql = $wpdb->prepare( $data_sql, ...$query_args );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.NotPrepared
		$sources_raw = $wpdb->get_results( $data_sql, ARRAY_A );
		$sources     = ! empty( $sources_raw ) ? $sources_raw : array();
		?>
	<details class="wp-sam-filter-form">
		<summary><?php esc_html_e( 'Filters', 'security-automation-manager' ); ?></summary>
		<form method="get" action="">
			<input type="hidden" name="page" value="security-automation-manager-dashboard" />
			<input type="hidden" name="tab"  value="sources" />
			<label>
				<?php esc_html_e( 'Surface', 'security-automation-manager' ); ?>
				<select name="src_surface">
					<option value=""><?php esc_html_e( 'Any', 'security-automation-manager' ); ?></option>
					<?php foreach ( $surfaces as $s ) : ?>
					<option value="<?php echo esc_attr( $s ); ?>" <?php selected( $src_surface, $s ); ?>><?php echo esc_html( ucfirst( $s ) ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
			<label>
				<?php esc_html_e( 'State', 'security-automation-manager' ); ?>
				<select name="src_state[]" multiple size="3">
					<?php foreach ( array( 'pending', 'approved', 'denied' ) as $st ) : ?>
					<option value="<?php echo esc_attr( $st ); ?>" <?php echo in_array( $st, $src_state, true ) ? 'selected' : ''; ?>><?php echo esc_html( ucfirst( $st ) ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
			<label>
				<?php esc_html_e( 'Risk', 'security-automation-manager' ); ?>
				<select name="src_risk[]" multiple size="3">
					<?php foreach ( array( 'high', 'medium', 'low' ) as $risk ) : ?>
					<option value="<?php echo esc_attr( $risk ); ?>" <?php echo in_array( $risk, $src_risk, true ) ? 'selected' : ''; ?>><?php echo esc_html( ucfirst( $risk ) ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
			<label>
				<?php esc_html_e( 'Directive', 'security-automation-manager' ); ?>
				<input type="text" name="src_directive" placeholder="<?php esc_attr_e( 'e.g. script-src', 'security-automation-manager' ); ?>" value="<?php echo esc_attr( $src_directive ); ?>" />
			</label>
			<label>
				<?php esc_html_e( 'Host contains', 'security-automation-manager' ); ?>
				<input type="text" name="src_host" value="<?php echo esc_attr( $src_host ); ?>" />
			</label>
			<label>
				<?php esc_html_e( 'ID', 'security-automation-manager' ); ?>
				<input type="number" min="1" name="src_id" style="width:80px" value="<?php echo esc_attr( null !== $src_id ? (string) $src_id : '' ); ?>" />
			</label>
			<label>
				<?php esc_html_e( 'Evidence at least', 'security-automation-manager' ); ?>
				<input type="number" min="0" name="src_evidence_min" style="width:80px" value="<?php echo esc_attr( null !== $src_evidence_min ? (string) $src_evidence_min : '' ); ?>" />
			</label>
			<label>
				<?php esc_html_e( 'Last seen from', 'security-automation-manager' ); ?>
				<input type="datetime-local" name="src_seen_from" value="<?php echo esc_attr( $src_seen_from ); ?>" />
			</label>
			<label>
				<?php esc_html_e( 'to', 'security-automation-manager' ); ?>
				<input type="datetime-local" name="src_seen_to" value="<?php echo esc_attr( $src_seen_to ); ?>" />
			</label>
			<?php submit_button( __( 'Filter', 'security-automation-manager' ), 'secondary', 'filter_sources', false ); ?>
		</form>
	</details>

	<table class="widefat fixed striped" style="margin-top:1em">
		<thead>
			<tr>
				<?php
				echo Table_Query::sort_header( __( 'ID', 'security-automation-manager' ), 'id', $src_sort_whitelist, $src_sort, $src_state_args, $base_url ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- helper escapes internally.
				echo Table_Query::sort_header( __( 'Surface', 'security-automation-manager' ), 'surface', $src_sort_whitelist, $src_sort, $src_state_args, $base_url ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'Directive', 'security-automation-manager' ), 'directive', $src_sort_whitelist, $src_sort, $src_state_args, $base_url ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'Host', 'security-automation-manager' ), 'host', $src_sort_whitelist, $src_sort, $src_state_args, $base_url ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'Risk', 'security-automation-manager' ), 'risk', $src_sort_whitelist, $src_sort, $src_state_args, $base_url ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'State', 'security-automation-manager' ), 'state', $src_sort_whitelist, $src_sort, $src_state_args, $base_url ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'Evidence', 'security-automation-manager' ), 'evidence', $src_sort_whitelist, $src_sort, $src_state_args, $base_url ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'Last Seen', 'security-automation-manager' ), 'last_seen', $src_sort_whitelist, $src_sort, $src_state_args, $base_url ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				?>
				<th><?php esc_html_e( 'Actions', 'security-automation-manager' ); ?></th>
			</tr>
		</thead>
		<tbody>
		<?php foreach ( $sources as $src ) : ?>
		<tr>
			<td><?php echo esc_html( $src['id'] ); ?></td>
			<td><?php echo esc_html( $src['surface'] ); ?></td>
			<td><code><?php echo esc_html( $src['directive'] ); ?></code></td>
			<td><code><?php echo esc_html( $src['source_host'] ); ?></code></td>
			<td>
				<span class="wp-sam-risk-badge risk-<?php echo esc_attr( $src['risk_level'] ?? 'low' ); ?>" title="<?php echo esc_attr( $src['risk_reason'] ?? '' ); ?>">
					<?php echo esc_html( ucfirst( $src['risk_level'] ?? 'low' ) ); ?>
				</span>
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
					<?php esc_html_e( 'Approve', 'security-automation-manager' ); ?>
				</button>
				<?php endif; ?>
				<?php if ( 'pending' === $src['approval_state'] || 'approved' === $src['approval_state'] ) : ?>
				<button type="button" class="button button-small wp-sam-deny-source" data-id="<?php echo esc_attr( $src['id'] ); ?>">
					<?php esc_html_e( 'Reject', 'security-automation-manager' ); ?>
				</button>
				<?php endif; ?>
				<?php if ( 'approved' === $src['approval_state'] ) : ?>
				<button type="button" class="button button-small wp-sam-revert-source" data-id="<?php echo esc_attr( $src['id'] ); ?>">
					<?php esc_html_e( 'Revert', 'security-automation-manager' ); ?>
				</button>
				<?php endif; ?>
				<?php if ( in_array( $src['last_decision'] ?? '', array( 'approved', 'auto_approved', 'rejected' ), true ) ) : ?>
				<button type="button" class="button button-small wp-sam-undo-source-decision" data-id="<?php echo esc_attr( $src['id'] ); ?>">
					<?php esc_html_e( 'Undo', 'security-automation-manager' ); ?>
				</button>
				<?php endif; ?>
			</td>
		</tr>
		<?php endforeach; ?>
		<?php if ( empty( $sources ) ) : ?>
		<tr><td colspan="9"><?php esc_html_e( 'No sources discovered yet. Run a scan to populate this table.', 'security-automation-manager' ); ?></td></tr>
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
				return 'decision' === $trigger_type ? __( 'system', 'security-automation-manager' ) : $trigger_type;
			},
			$pc_actor_from_versions
		);
		$pc_actor_options       = array_values(
			array_unique(
				array_merge(
					$pc_actor_from_decisions,
					$pc_actor_from_versions,
					array( __( 'system', 'security-automation-manager' ), __( 'administrator', 'security-automation-manager' ) )
				)
			)
		);
		sort( $pc_actor_options );

		$pc_type_options  = array(
			__( 'Decision', 'security-automation-manager' ),
			__( 'Policy version', 'security-automation-manager' ),
			__( 'Discovery', 'security-automation-manager' ),
		);
		$pc_event_options = array(
			__( 'Approved', 'security-automation-manager' ),
			__( 'Rejected', 'security-automation-manager' ),
			__( 'Reverted', 'security-automation-manager' ),
			__( 'Undone', 'security-automation-manager' ),
			__( 'Snapshot', 'security-automation-manager' ),
			__( 'Proposed source', 'security-automation-manager' ),
			__( 'Suppressed proposal', 'security-automation-manager' ),
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
		<?php esc_html_e( 'Discovered candidates appear in For Review first. This timeline shows proposal activity, administrator or automation decisions, suppression state, and the policy snapshots created after material changes.', 'security-automation-manager' ); ?>
	</p>
		<?php if ( $pc_result['truncated'] ) : ?>
	<div class="notice notice-warning inline">
		<p><?php esc_html_e( 'Showing results from up to 5,000 recent records per activity type. Narrow your filters (Type, Surface, Directive, or a date range) to see the full, correctly-sorted result set.', 'security-automation-manager' ); ?></p>
	</div>
	<?php endif; ?>
	<details class="wp-sam-filter-form">
		<summary><?php esc_html_e( 'Filters', 'security-automation-manager' ); ?></summary>
		<form method="get" action="">
			<input type="hidden" name="page" value="security-automation-manager-dashboard" />
			<input type="hidden" name="tab"  value="policy-changes" />
			<label>
				<?php esc_html_e( 'Type', 'security-automation-manager' ); ?>
				<select name="pc_type[]" multiple size="3">
					<?php foreach ( $pc_type_options as $opt ) : ?>
					<option value="<?php echo esc_attr( $opt ); ?>" <?php echo in_array( $opt, $pc_type, true ) ? 'selected' : ''; ?>><?php echo esc_html( $opt ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
			<label>
				<?php esc_html_e( 'Event', 'security-automation-manager' ); ?>
				<select name="pc_event[]" multiple size="4">
					<?php foreach ( $pc_event_options as $opt ) : ?>
					<option value="<?php echo esc_attr( $opt ); ?>" <?php echo in_array( $opt, $pc_event, true ) ? 'selected' : ''; ?>><?php echo esc_html( $opt ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
			<label>
				<?php esc_html_e( 'Surface', 'security-automation-manager' ); ?>
				<select name="pc_surface[]" multiple size="4">
					<?php foreach ( $surfaces as $s ) : ?>
					<option value="<?php echo esc_attr( $s ); ?>" <?php echo in_array( $s, $pc_surface, true ) ? 'selected' : ''; ?>><?php echo esc_html( ucfirst( $s ) ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
			<label>
				<?php esc_html_e( 'Directive', 'security-automation-manager' ); ?>
				<select name="pc_directive[]" multiple size="4">
					<?php foreach ( $pc_directive_options as $d ) : ?>
					<option value="<?php echo esc_attr( $d ); ?>" <?php echo in_array( $d, $pc_directive, true ) ? 'selected' : ''; ?>><?php echo esc_html( $d ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
			<label>
				<?php esc_html_e( 'Host contains', 'security-automation-manager' ); ?>
				<input type="text" name="pc_host" value="<?php echo esc_attr( $pc_host ); ?>" />
			</label>
			<label>
				<?php esc_html_e( 'Risk', 'security-automation-manager' ); ?>
				<select name="pc_risk[]" multiple size="3">
					<?php foreach ( array( 'high', 'medium', 'low' ) as $risk ) : ?>
					<option value="<?php echo esc_attr( $risk ); ?>" <?php echo in_array( $risk, $pc_risk, true ) ? 'selected' : ''; ?>><?php echo esc_html( ucfirst( $risk ) ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
			<label>
				<?php esc_html_e( 'Policy version contains', 'security-automation-manager' ); ?>
				<input type="text" name="pc_policy_version" value="<?php echo esc_attr( $pc_policy_ver ); ?>" />
			</label>
			<label>
				<?php esc_html_e( 'Suppression', 'security-automation-manager' ); ?>
				<select name="pc_suppression">
					<option value=""><?php esc_html_e( 'Any', 'security-automation-manager' ); ?></option>
					<option value="active" <?php selected( $pc_suppression, 'active' ); ?>><?php esc_html_e( 'Active only', 'security-automation-manager' ); ?></option>
				</select>
			</label>
			<label>
				<?php esc_html_e( 'Actor', 'security-automation-manager' ); ?>
				<select name="pc_actor[]" multiple size="4">
					<?php foreach ( $pc_actor_options as $a ) : ?>
					<option value="<?php echo esc_attr( $a ); ?>" <?php echo in_array( $a, $pc_actor, true ) ? 'selected' : ''; ?>><?php echo esc_html( $a ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
			<label>
				<?php esc_html_e( 'Detail contains', 'security-automation-manager' ); ?>
				<input type="text" name="pc_detail" value="<?php echo esc_attr( $pc_detail ); ?>" />
			</label>
			<label>
				<?php esc_html_e( 'When from', 'security-automation-manager' ); ?>
				<input type="date" name="pc_when_from" value="<?php echo esc_attr( $pc_when_from ); ?>" />
			</label>
			<label>
				<?php esc_html_e( 'to', 'security-automation-manager' ); ?>
				<input type="date" name="pc_when_to" value="<?php echo esc_attr( $pc_when_to ); ?>" />
			</label>
			<?php submit_button( __( 'Filter', 'security-automation-manager' ), 'secondary', 'filter_policy_changes', false ); ?>
		</form>
	</details>
	<table class="widefat fixed striped" style="margin-top:1em">
		<thead>
			<tr>
				<?php
				echo Table_Query::sort_header( __( 'When', 'security-automation-manager' ), 'when', $pc_sort_whitelist, $pc_sort, $pc_state_args, $base_url, 'pc_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- helper escapes internally.
				echo Table_Query::sort_header( __( 'Event', 'security-automation-manager' ), 'event', $pc_sort_whitelist, $pc_sort, $pc_state_args, $base_url, 'pc_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'Type', 'security-automation-manager' ), 'type', $pc_sort_whitelist, $pc_sort, $pc_state_args, $base_url, 'pc_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'Actor', 'security-automation-manager' ), 'actor', $pc_sort_whitelist, $pc_sort, $pc_state_args, $base_url, 'pc_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'Surface', 'security-automation-manager' ), 'surface', $pc_sort_whitelist, $pc_sort, $pc_state_args, $base_url, 'pc_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'Directive', 'security-automation-manager' ), 'directive', $pc_sort_whitelist, $pc_sort, $pc_state_args, $base_url, 'pc_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'Host', 'security-automation-manager' ), 'host', $pc_sort_whitelist, $pc_sort, $pc_state_args, $base_url, 'pc_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'Risk', 'security-automation-manager' ), 'risk', $pc_sort_whitelist, $pc_sort, $pc_state_args, $base_url, 'pc_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'Policy Version', 'security-automation-manager' ), 'policy_version', $pc_sort_whitelist, $pc_sort, $pc_state_args, $base_url, 'pc_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'Suppression', 'security-automation-manager' ), 'suppression', $pc_sort_whitelist, $pc_sort, $pc_state_args, $base_url, 'pc_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'Detail', 'security-automation-manager' ), 'detail', $pc_sort_whitelist, $pc_sort, $pc_state_args, $base_url, 'pc_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
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
				<?php if ( '' !== $event['risk_level'] ) : ?>
				<span class="wp-sam-risk-badge risk-<?php echo esc_attr( $event['risk_level'] ); ?>" title="<?php echo esc_attr( $event['risk_reason'] ); ?>">
					<?php echo esc_html( ucfirst( $event['risk_level'] ) ); ?>
				</span>
				<?php else : ?>
					&mdash;
				<?php endif; ?>
			</td>
			<td><?php echo '' !== $event['policy_version'] ? esc_html( $event['policy_version'] ) : '&mdash;'; ?></td>
			<td>
				<?php echo '' !== $event['suppression'] ? esc_html( $event['suppression'] ) : '&mdash;'; ?>
			</td>
			<td><?php echo esc_html( $event['detail'] ); ?></td>
		</tr>
		<?php endforeach; ?>
		<?php if ( empty( $policy_events ) ) : ?>
		<tr><td colspan="11"><?php esc_html_e( 'No policy activity has been recorded yet.', 'security-automation-manager' ); ?></td></tr>
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
				<th><?php esc_html_e( 'Surface', 'security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Mode', 'security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Automation', 'security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Policy Version', 'security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Pending', 'security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'High Risk', 'security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Effective Header', 'security-automation-manager' ); ?></th>
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
					<td><?php echo isset( $audit_latest['version_number'] ) ? esc_html( (string) $audit_latest['version_number'] ) : esc_html__( 'Not captured yet', 'security-automation-manager' ); ?></td>
					<td><?php echo esc_html( (string) $audit_pending_count ); ?></td>
					<td><?php echo esc_html( (string) $audit_high_count ); ?></td>
					<td><code><?php echo esc_html( $audit_latest['effective_header'] ?? '' ); ?></code></td>
				</tr>
			<?php endforeach; ?>
		</tbody>
	</table>
	<p class="description" style="margin-top:1em">
		<?php esc_html_e( 'For the pending review queue, see For Review. For the full, immutable decision ledger -- who approved, rejected, or reverted each source, and why -- see Policy Changes.', 'security-automation-manager' ); ?>
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
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			$viol_count_sql = $wpdb->prepare( $viol_count_sql, ...$viol_args );
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.NotPrepared
		$viol_total = (int) $wpdb->get_var( $viol_count_sql );

		$viol_pages    = max( 1, (int) ceil( $viol_total / $per_page ) );
		$viol_page_num = min( max( 1, (int) ( isset( $_GET['v_paged'] ) ? $_GET['v_paged'] : 1 ) ), $viol_pages );
		$viol_offset   = ( $viol_page_num - 1 ) * $per_page;

		$viol_data_args = array_merge( $viol_args, array( $per_page, $viol_offset ) );
		$viol_data_sql  = "SELECT * FROM {$wpdb->prefix}csp_violation_reports WHERE {$viol_where_sql} " . Table_Query::order_by_sql( $viol_sort ) . ' LIMIT %d OFFSET %d';
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		$viol_data_sql = $wpdb->prepare( $viol_data_sql, ...$viol_data_args );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.NotPrepared
		$violations_raw = $wpdb->get_results( $viol_data_sql, ARRAY_A );
		$violations     = ! empty( $violations_raw ) ? $violations_raw : array();

		// Quick range buttons: set "Last seen from" to now-minus-N and leave the
		// upper bound open, matching current_time( 'mysql', true ) (UTC), the
		// same basis reported_at is stored under -- so these line up with what's
		// actually in the database regardless of the site's display timezone.
		$viol_quick_ranges = array(
			'1h'  => array( 1, __( 'Last hour', 'security-automation-manager' ) ),
			'6h'  => array( 6, __( 'Last 6 hours', 'security-automation-manager' ) ),
			'24h' => array( 24, __( 'Last day', 'security-automation-manager' ) ),
			'7d'  => array( 24 * 7, __( 'Last 7 days', 'security-automation-manager' ) ),
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
		<summary><?php esc_html_e( 'Filters', 'security-automation-manager' ); ?></summary>
		<form method="get" action="">
			<input type="hidden" name="page" value="security-automation-manager-dashboard" />
			<input type="hidden" name="tab" value="violations" />
			<label>
				<?php esc_html_e( 'Surface', 'security-automation-manager' ); ?>
				<select name="v_surface">
					<option value=""><?php esc_html_e( 'Any', 'security-automation-manager' ); ?></option>
					<?php foreach ( $surfaces as $s ) : ?>
					<option value="<?php echo esc_attr( $s ); ?>" <?php selected( $v_surface, $s ); ?>><?php echo esc_html( ucfirst( $s ) ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
			<label>
				<?php esc_html_e( 'Directive', 'security-automation-manager' ); ?>
				<input type="text" name="v_directive" placeholder="<?php esc_attr_e( 'e.g. script-src', 'security-automation-manager' ); ?>" value="<?php echo esc_attr( $v_directive ); ?>" />
			</label>
			<label>
				<?php esc_html_e( 'Blocked URI contains', 'security-automation-manager' ); ?>
				<input type="text" name="v_blocked" value="<?php echo esc_attr( $v_blocked ); ?>" />
			</label>
			<label>
				<?php esc_html_e( 'Occurrences at least', 'security-automation-manager' ); ?>
				<input type="number" min="0" name="v_occ_min" style="width:80px" value="<?php echo esc_attr( null !== $v_occ_min ? (string) $v_occ_min : '' ); ?>" />
			</label>
			<label>
				<?php esc_html_e( 'Last seen from', 'security-automation-manager' ); ?>
				<input type="datetime-local" name="v_seen_from" value="<?php echo esc_attr( $v_seen_from ); ?>" />
			</label>
			<label>
				<?php esc_html_e( 'to', 'security-automation-manager' ); ?>
				<input type="datetime-local" name="v_seen_to" value="<?php echo esc_attr( $v_seen_to ); ?>" />
			</label>
			<?php submit_button( __( 'Filter', 'security-automation-manager' ), 'secondary', 'filter_violations', false ); ?>
		</form>
	</details>
	<table class="widefat fixed striped wp-sam-violations-table" style="margin-top:1em">
		<thead>
			<tr>
				<?php
				echo Table_Query::sort_header( __( 'Surface', 'security-automation-manager' ), 'surface', $viol_sort_whitelist, $viol_sort, $viol_state_args, $base_url, 'v_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- helper escapes internally.
				echo Table_Query::sort_header( __( 'Blocked URI', 'security-automation-manager' ), 'blocked_uri', $viol_sort_whitelist, $viol_sort, $viol_state_args, $base_url, 'v_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'Directive', 'security-automation-manager' ), 'directive', $viol_sort_whitelist, $viol_sort, $viol_state_args, $base_url, 'v_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'Occurrences (lifetime)', 'security-automation-manager' ), 'occurrences', $viol_sort_whitelist, $viol_sort, $viol_state_args, $base_url, 'v_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- count never resets; the seen-range filter only affects which rows are *shown*, not this total.
				echo Table_Query::sort_header( __( 'Last Seen', 'security-automation-manager' ), 'last_seen', $viol_sort_whitelist, $viol_sort, $viol_state_args, $base_url, 'v_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'Disposition', 'security-automation-manager' ), 'disposition', $viol_sort_whitelist, $viol_sort, $viol_state_args, $base_url, 'v_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				?>
				<th><?php esc_html_e( 'Details', 'security-automation-manager' ); ?></th>
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
					$meta_fields[ __( 'First seen', 'security-automation-manager' ) ] = (string) $v['first_reported_at'];
				}
				if ( 0 === strpos( (string) $v['blocked_uri'], 'data:' ) ) {
					$meta_fields[ __( 'Data URI payload', 'security-automation-manager' ) ] = mb_substr( (string) $v['blocked_uri'], 0, 200 );
				} elseif ( ! empty( $v['blocked_host'] ) ) {
					$meta_fields[ __( 'Last seen URL', 'security-automation-manager' ) ] = (string) $v['blocked_uri'];
				}
				if ( ! empty( $v['document_uri'] ) ) {
					$meta_fields[ __( 'Page URL', 'security-automation-manager' ) ] = (string) $v['document_uri'];
				}
				if ( ! empty( $v['source_file'] ) ) {
					$location = (string) $v['source_file'];
					if ( '' !== (string) ( $v['line_number'] ?? '' ) ) {
						$location .= ':' . $v['line_number'];
						if ( '' !== (string) ( $v['column_number'] ?? '' ) ) {
							$location .= ':' . $v['column_number'];
						}
					}
					$meta_fields[ __( 'Source file', 'security-automation-manager' ) ] = $location;
				}
				if ( ! empty( $v['referrer'] ) ) {
					$meta_fields[ __( 'Referrer', 'security-automation-manager' ) ] = (string) $v['referrer'];
				}
				if ( ! empty( $v['user_agent'] ) ) {
					$meta_fields[ __( 'User agent', 'security-automation-manager' ) ] = (string) $v['user_agent'];
				}
				if ( ! empty( $v['sample'] ) ) {
					$meta_fields[ __( 'Sample', 'security-automation-manager' ) ] = (string) $v['sample'];
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
				<span class="dashicons dashicons-info-outline wp-sam-meta-icon wp-sam-meta-icon--empty" title="<?php esc_attr_e( 'No metadata captured for this violation', 'security-automation-manager' ); ?>"></span>
				<?php endif; ?>
			</td>
		</tr>
		<?php endforeach; ?>
		<?php if ( empty( $violations ) ) : ?>
		<tr>
			<td colspan="7">
				<p><?php esc_html_e( 'No browser violation reports have been recorded yet.', 'security-automation-manager' ); ?></p>
				<p>
					<?php esc_html_e( 'Manual scans discover candidate sources, but they do not create violation reports. To collect violations, browse the live site while the relevant surface emits this plugin\'s report-only or enforce CSP header with reporting directives.', 'security-automation-manager' ); ?>
				</p>
				<p>
					<?php esc_html_e( 'Expected reporting endpoint:', 'security-automation-manager' ); ?>
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
				<th><?php esc_html_e( 'Trigger', 'security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Status', 'security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Sources +/-', 'security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Hashes +/-', 'security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Policy Changed', 'security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Started', 'security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Duration', 'security-automation-manager' ); ?></th>
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
			<td><?php echo $log['policy_changed'] ? esc_html__( 'Yes', 'security-automation-manager' ) : '&mdash;'; ?></td>
			<td><?php echo esc_html( $log['started_at'] ); ?></td>
			<td><?php echo esc_html( $duration ); ?></td>
		</tr>
		<?php endforeach; ?>
		<?php if ( empty( $scan_logs ) ) : ?>
		<tr><td colspan="7"><?php esc_html_e( 'No scans run yet.', 'security-automation-manager' ); ?></td></tr>
		<?php endif; ?>
		</tbody>
	</table>

	<?php elseif ( 'settings' === $tab ) : ?>
	<!-- ── Settings tab ───────────────────────────────────────────────────── -->
		<?php
		$learning_window            = new \WP_SAM\CSP\Learning_Window();
		$learning_status            = $learning_window->is_open() ? __( 'Open', 'security-automation-manager' ) : __( 'Locked', 'security-automation-manager' );
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
		<h2 class="title"><?php esc_html_e( 'Promotion Gates', 'security-automation-manager' ); ?></h2>
		<p class="description">
			<?php esc_html_e( 'These settings control the conditions that must be met before a surface can be promoted from report-only to enforce mode.', 'security-automation-manager' ); ?>
		</p>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row">
					<label for="wp_sam_enforce_gate_violation_window">
						<?php esc_html_e( 'Violation-free window (hours)', 'security-automation-manager' ); ?>
					</label>
				</th>
				<td>
					<input type="number" id="wp_sam_enforce_gate_violation_window"
						name="wp_sam_enforce_gate_violation_window"
						value="<?php echo esc_attr( get_option( 'wp_sam_enforce_gate_violation_window', 24 ) ); ?>"
						min="1" max="720" class="small-text" />
					<p class="description">
						<?php esc_html_e( 'Number of hours without any CSP violations required before a surface can be promoted to enforce mode. Default: 24. Increase this for production sites to ensure stability.', 'security-automation-manager' ); ?>
					</p>
				</td>
			</tr>
		</table>

		<h2 class="title"><?php esc_html_e( 'Deterministic Automation', 'security-automation-manager' ); ?></h2>
		<p class="description">
			<?php esc_html_e( 'Configure how far the deterministic engine may go without administrator approval. Manual mode remains the default; hard-excluded, critical, unknown, and insufficient-evidence proposals always require review.', 'security-automation-manager' ); ?>
		</p>
		<?php if ( ! $wp_sam_is_pro ) : ?>
		<div id="wp-sam-upgrade" class="notice notice-info inline" style="padding:16px 20px;margin:1em 0;">
			<h3 style="margin-top:0;"><?php esc_html_e( 'Unlock Fully Automatic', 'security-automation-manager' ); ?></h3>
			<p><?php esc_html_e( 'Fully Automatic auto-applies low, medium, and high-risk proposals within the hard safety exclusions the deterministic engine already enforces -- zero manual review. Every other automation mode, and every other pillar, stays free.', 'security-automation-manager' ); ?></p>
			<?php if ( null !== $this->plugin->checkout ) : ?>
			<div class="wp-sam-product-cards">
				<div class="wp-sam-product-card">
					<h3><?php esc_html_e( 'Monthly', 'security-automation-manager' ); ?></h3>
					<p class="wp-sam-price">&pound;1.99<span style="font-size:0.4em;font-weight:normal;">/mo</span></p>
					<button type="button" class="button button-primary wp-sam-upgrade-button" data-interval="monthly"><?php esc_html_e( 'Subscribe monthly', 'security-automation-manager' ); ?></button>
				</div>
				<div class="wp-sam-product-card">
					<h3><?php esc_html_e( 'Annual', 'security-automation-manager' ); ?></h3>
					<p class="wp-sam-price">&pound;19.99<span style="font-size:0.4em;font-weight:normal;">/yr</span></p>
					<button type="button" class="button button-primary wp-sam-upgrade-button" data-interval="annual"><?php esc_html_e( 'Subscribe annually', 'security-automation-manager' ); ?></button>
				</div>
			</div>
			<p><span id="wp-sam-upgrade-status" role="status"></span></p>
			<?php else : ?>
			<p class="description"><?php esc_html_e( 'Upgrading is not available in this build of the plugin.', 'security-automation-manager' ); ?></p>
			<?php endif; ?>
		</div>
		<?php endif; ?>

		<?php if ( null !== $this->plugin->checkout ) : ?>
		<h2 class="title"><?php esc_html_e( 'Stripe Configuration', 'security-automation-manager' ); ?></h2>
		<p class="description">
			<?php esc_html_e( 'This site calls the Stripe API directly to create checkout sessions -- no external proxy is involved. Create one Product with a recurring Monthly and Annual Price in your Stripe dashboard, then paste the resulting IDs below.', 'security-automation-manager' ); ?>
		</p>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><label for="wp_sam_stripe_mode"><?php esc_html_e( 'Mode', 'security-automation-manager' ); ?></label></th>
				<td>
					<select id="wp_sam_stripe_mode" name="wp_sam_stripe_mode">
						<option value="test" <?php selected( get_option( 'wp_sam_stripe_mode', 'test' ), 'test' ); ?>><?php esc_html_e( 'Test', 'security-automation-manager' ); ?></option>
						<option value="live" <?php selected( get_option( 'wp_sam_stripe_mode', 'test' ), 'live' ); ?>><?php esc_html_e( 'Live', 'security-automation-manager' ); ?></option>
					</select>
					<p class="description"><?php esc_html_e( 'Which key/price pair below is actually used for checkout. Test everything in Test mode first.', 'security-automation-manager' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="wp_sam_stripe_secret_key_test"><?php esc_html_e( 'Test Secret Key', 'security-automation-manager' ); ?></label></th>
				<td><input type="password" id="wp_sam_stripe_secret_key_test" name="wp_sam_stripe_secret_key_test" value="<?php echo esc_attr( get_option( 'wp_sam_stripe_secret_key_test', '' ) ); ?>" class="regular-text" autocomplete="off" placeholder="sk_test_…" /></td>
			</tr>
			<tr>
				<th scope="row"><label for="wp_sam_stripe_secret_key_live"><?php esc_html_e( 'Live Secret Key', 'security-automation-manager' ); ?></label></th>
				<td><input type="password" id="wp_sam_stripe_secret_key_live" name="wp_sam_stripe_secret_key_live" value="<?php echo esc_attr( get_option( 'wp_sam_stripe_secret_key_live', '' ) ); ?>" class="regular-text" autocomplete="off" placeholder="sk_live_…" /></td>
			</tr>
			<tr>
				<th scope="row"><label for="wp_sam_stripe_price_id_monthly_test"><?php esc_html_e( 'Test Price ID (Monthly)', 'security-automation-manager' ); ?></label></th>
				<td><input type="text" id="wp_sam_stripe_price_id_monthly_test" name="wp_sam_stripe_price_id_monthly_test" value="<?php echo esc_attr( get_option( 'wp_sam_stripe_price_id_monthly_test', '' ) ); ?>" class="regular-text" placeholder="price_…" /></td>
			</tr>
			<tr>
				<th scope="row"><label for="wp_sam_stripe_price_id_annual_test"><?php esc_html_e( 'Test Price ID (Annual)', 'security-automation-manager' ); ?></label></th>
				<td><input type="text" id="wp_sam_stripe_price_id_annual_test" name="wp_sam_stripe_price_id_annual_test" value="<?php echo esc_attr( get_option( 'wp_sam_stripe_price_id_annual_test', '' ) ); ?>" class="regular-text" placeholder="price_…" /></td>
			</tr>
			<tr>
				<th scope="row"><label for="wp_sam_stripe_price_id_monthly_live"><?php esc_html_e( 'Live Price ID (Monthly)', 'security-automation-manager' ); ?></label></th>
				<td><input type="text" id="wp_sam_stripe_price_id_monthly_live" name="wp_sam_stripe_price_id_monthly_live" value="<?php echo esc_attr( get_option( 'wp_sam_stripe_price_id_monthly_live', '' ) ); ?>" class="regular-text" placeholder="price_…" /></td>
			</tr>
			<tr>
				<th scope="row"><label for="wp_sam_stripe_price_id_annual_live"><?php esc_html_e( 'Live Price ID (Annual)', 'security-automation-manager' ); ?></label></th>
				<td><input type="text" id="wp_sam_stripe_price_id_annual_live" name="wp_sam_stripe_price_id_annual_live" value="<?php echo esc_attr( get_option( 'wp_sam_stripe_price_id_annual_live', '' ) ); ?>" class="regular-text" placeholder="price_…" /></td>
			</tr>
			<tr>
				<th scope="row"><label for="wp_sam_webhook_secret"><?php esc_html_e( 'Webhook Signing Secret', 'security-automation-manager' ); ?></label></th>
				<td>
					<input type="password" id="wp_sam_webhook_secret" name="wp_sam_webhook_secret" value="<?php echo esc_attr( get_option( 'wp_sam_webhook_secret', '' ) ); ?>" class="regular-text" autocomplete="off" placeholder="whsec_…" />
					<p class="description">
						<?php
						echo wp_kses_post(
							sprintf(
								/* translators: %s: the webhook URL to register in the Stripe dashboard */
								__( 'In the Stripe dashboard, add a webhook endpoint at %s listening for checkout.session.completed and checkout.session.async_payment_succeeded, then paste its signing secret here. One endpoint covers both Test and Live mode.', 'security-automation-manager' ),
								'<code>' . esc_html( rest_url( 'sam/v1/webhook/stripe' ) ) . '</code>'
							)
						);
						?>
					</p>
				</td>
			</tr>
		</table>
		<?php endif; ?>

		<table class="widefat striped" role="presentation">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Surface', 'security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Mode', 'security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Maximum per run', 'security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Directive scope', 'security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Allowed schemes', 'security-automation-manager' ); ?></th>
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
								<?php disabled( \WP_SAM\CSP\Automation_Config::MODE_FULLY_AUTOMATIC === $mode && ! $wp_sam_is_pro ); ?>>
								<?php
								echo esc_html( $label );
								if ( \WP_SAM\CSP\Automation_Config::MODE_FULLY_AUTOMATIC === $mode && ! $wp_sam_is_pro ) {
									echo ' ' . esc_html__( '(requires upgrade)', 'security-automation-manager' );
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
						<p class="description"><?php esc_html_e( 'Leave all unchecked to permit any directive that is inside the selected automation posture and not hard-excluded by the deterministic engine.', 'security-automation-manager' ); ?></p>
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
			<?php esc_html_e( 'Automatic decisions are recorded with actor automation_engine and can be reverted from the review queue like administrator approvals.', 'security-automation-manager' ); ?>
		</p>

		<h2 class="title"><?php esc_html_e( 'Proxy Header Emission', 'security-automation-manager' ); ?></h2>
		<p class="description">
			<?php esc_html_e( 'Use this when WordPress is the origin behind Cloudflare, a CDN, or another edge proxy that needs to copy an origin-only header into the browser-facing CSP header.', 'security-automation-manager' ); ?>
		</p>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><label for="wp_sam_policy_header_name"><?php esc_html_e( 'Policy header name', 'security-automation-manager' ); ?></label></th>
				<td>
					<input type="text" id="wp_sam_policy_header_name" name="wp_sam_policy_header_name"
						value="<?php echo esc_attr( $configured_policy_header ); ?>"
						placeholder="<?php echo esc_attr( 'X-Origin-CSP-Policy' ); ?>"
						class="regular-text code" />
					<p class="description">
						<?php esc_html_e( 'Leave blank for the plugin to emit the normal mode-aware headers: Content-Security-Policy-Report-Only in report-only mode and Content-Security-Policy in enforce mode. Set a custom HTTP field name to emit the policy under that exact origin header instead, then configure the proxy to copy it back to the appropriate browser-facing CSP header.', 'security-automation-manager' ); ?>
					</p>
					<p class="description">
						<?php esc_html_e( 'Only valid HTTP header field names are accepted. Hop-by-hop and cookie headers are rejected.', 'security-automation-manager' ); ?>
					</p>
				</td>
			</tr>
		</table>

		<h2 class="title"><?php esc_html_e( 'Report Endpoint Learning', 'security-automation-manager' ); ?></h2>
		<p class="description">
			<?php esc_html_e( 'Validated CSP reports can add pending source candidates while the site is inside the material-change learning window.', 'security-automation-manager' ); ?>
		</p>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><label for="wp_sam_report_endpoint_url"><?php esc_html_e( 'Reporting server URL', 'security-automation-manager' ); ?></label></th>
				<td>
					<input type="url" id="wp_sam_report_endpoint_url" name="wp_sam_report_endpoint_url"
						value="<?php echo esc_attr( $configured_report_endpoint ); ?>"
						placeholder="<?php echo esc_attr( $current_report_endpoint ); ?>"
						class="regular-text code" />
					<button type="button" class="button wp-sam-use-current-report-endpoint" data-report-endpoint="<?php echo esc_attr( $current_report_endpoint ); ?>">
						<?php esc_html_e( 'Use current site endpoint', 'security-automation-manager' ); ?>
					</button>
					<p class="description">
						<?php esc_html_e( 'Leave blank to use the current WordPress REST endpoint shown below. Set an absolute public URL when visitors reach the site through a proxy, CDN, load balancer, or different HTTPS host. The URL should still resolve to this plugin report endpoint if you want local report learning.', 'security-automation-manager' ); ?>
					</p>
					<p class="description">
						<?php esc_html_e( 'Detected current endpoint:', 'security-automation-manager' ); ?>
						<code><?php echo esc_html( $current_report_endpoint ); ?></code>
					</p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="wp_sam_reporting_transport"><?php esc_html_e( 'Reporting transport', 'security-automation-manager' ); ?></label></th>
				<td>
					<select id="wp_sam_reporting_transport" name="wp_sam_reporting_transport">
						<option value="report-uri" <?php selected( $reporting_transport, 'report-uri' ); ?>>
							<?php esc_html_e( 'Direct report-uri (recommended)', 'security-automation-manager' ); ?>
						</option>
						<option value="both" <?php selected( $reporting_transport, 'both' ); ?>>
							<?php esc_html_e( 'Direct report-uri plus Reporting API', 'security-automation-manager' ); ?>
						</option>
						<option value="report-to" <?php selected( $reporting_transport, 'report-to' ); ?>>
							<?php esc_html_e( 'Reporting API only', 'security-automation-manager' ); ?>
						</option>
					</select>
					<p class="description">
						<?php esc_html_e( 'Use direct report-uri while learning so browser reports arrive promptly in the Violations tab. Reporting API delivery can be queued or delayed by the browser, and browsers that use report-to may ignore report-uri.', 'security-automation-manager' ); ?>
					</p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="wp_sam_learning_window_hours"><?php esc_html_e( 'Learning window (hours)', 'security-automation-manager' ); ?></label></th>
				<td>
					<input type="number" id="wp_sam_learning_window_hours" name="wp_sam_learning_window_hours"
						value="<?php echo esc_attr( get_option( 'wp_sam_learning_window_hours', 48 ) ); ?>"
						min="1" max="720" class="small-text" />
					<p class="description">
						<?php esc_html_e( 'Default: 48. The report endpoint stops creating or updating source candidates after this many hours from the latest page, post, or plugin change.', 'security-automation-manager' ); ?>
					</p>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Learning status', 'security-automation-manager' ); ?></th>
				<td>
					<p>
						<?php
						printf(
							/* translators: 1: status, 2: last material change time, 3: lock time */
							esc_html__( '%1$s. Last material change: %2$s. Locks at: %3$s UTC.', 'security-automation-manager' ),
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
		<h2 class="title"><?php esc_html_e( 'Scan Schedule', 'security-automation-manager' ); ?></h2>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><label for="wp_sam_cron_hour"><?php esc_html_e( 'Daily Scan Hour (0–23, UTC)', 'security-automation-manager' ); ?></label></th>
				<td>
					<input type="number" id="wp_sam_cron_hour" name="wp_sam_cron_hour"
						value="<?php echo esc_attr( get_option( 'wp_sam_cron_hour', 2 ) ); ?>"
						min="0" max="23" class="small-text" />
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="wp_sam_notify_email"><?php esc_html_e( 'Notification Email', 'security-automation-manager' ); ?></label></th>
				<td>
					<input type="email" id="wp_sam_notify_email" name="wp_sam_notify_email"
						value="<?php echo esc_attr( get_option( 'wp_sam_notify_email', get_option( 'admin_email' ) ) ); ?>"
						class="regular-text" />
					<p class="description"><?php esc_html_e( 'Receive an email when the policy changes after a scheduled scan.', 'security-automation-manager' ); ?></p>
				</td>
			</tr>
		</table>

		<?php submit_button(); ?>
	</form>
	<?php endif; ?>

	</div><!-- .tab-content -->
</div><!-- .wp-sam-wrap -->
