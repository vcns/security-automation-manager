<?php
/**
 * Admin view: Cross-Origin Policies -- consolidates the four cross-origin/
 * legacy header pillars (Cross-Origin-Resource-Policy,
 * X-Permitted-Cross-Domain-Policies, Cross-Origin-Opener-Policy,
 * Cross-Origin-Embedder-Policy) that previously each had their own separate
 * submenu page, onto one page with a tab per pillar -- same tab pattern as
 * the CSP dashboard.
 *
 * Cross-Origin-Resource-Policy and X-Permitted-Cross-Domain-Policies reuse
 * the plain per-surface enable+value table page-pillar-simple.php uses for
 * the other simple pillars, since neither has a report-only or Reporting
 * API mechanism to learn from.
 *
 * Cross-Origin-Opener-Policy and Cross-Origin-Embedder-Policy are the only
 * two pillars in this group with a browser-native report-only + Reporting
 * API delivery mechanism (Chromium only), so their tabs render a richer
 * per-surface mode selector (Disabled / Report-Only / Enforce) in place of
 * the plain enabled checkbox, plus a Report-Only Evidence table below --
 * same Table_Query sort/filter/pagination conventions as the CSP Violations
 * tab -- showing what's actually been observed for that surface.
 *
 * Rendered by Admin_UI::render_cross_origin().
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WP_SAM\Admin\Table_Query;
use WP_SAM\Security\Cross_Origin_Resource_Policy_Builder;
use WP_SAM\Security\X_Permitted_Cross_Domain_Policies_Builder;
use WP_SAM\Security\Cross_Origin_Opener_Policy_Builder;
use WP_SAM\Security\Cross_Origin_Embedder_Policy_Builder;

global $wpdb;

$mode_options = array(
	'disabled'    => __( 'Disabled -- header not sent', 'vcns-security-automation-manager' ),
	'report-only' => __( 'Report-Only -- observe without blocking', 'vcns-security-automation-manager' ),
	'enforce'     => __( 'Enforce -- header sent and blocking', 'vcns-security-automation-manager' ),
);

$tabs = array(
	'coep'  => array(
		'label'          => __( 'Cross-Origin-Embedder-Policy', 'vcns-security-automation-manager' ),
		'pillar_key'     => Cross_Origin_Embedder_Policy_Builder::PILLAR_KEY,
		'header_name'    => 'Cross-Origin-Embedder-Policy',
		'intro_html'     => '<p>' . esc_html__( 'Required for cross-origin isolation (SharedArrayBuffer, high-resolution timers, and similar browser APIs). Most WordPress sites do not need this at all.', 'vcns-security-automation-manager' ) . '</p>',
		'value_options'  => array(
			'unsafe-none'    => __( 'unsafe-none -- no restriction (browser default)', 'vcns-security-automation-manager' ),
			'credentialless' => __( 'credentialless -- cross-origin resources load without credentials instead of being blocked', 'vcns-security-automation-manager' ),
			'require-corp'   => __( 'require-corp -- every cross-origin resource must explicitly opt in, or it is blocked', 'vcns-security-automation-manager' ),
		),
		'warning_html'   => '<p style="margin-top:0;margin-bottom:0;">' . esc_html__( 'The highest-risk header this plugin manages. "require-corp" blocks every cross-origin subresource (fonts, images, iframes, scripts) that does not explicitly opt in via a matching Cross-Origin-Resource-Policy header or CORS -- most third-party embeds and CDN-hosted fonts, including Google Fonts, do not opt in by default. Start with Report-Only, and give it at least two weeks of real traffic covering a full content cycle before enforcing -- a page or feature visited only occasionally can easily go unrepresented in a shorter window. You can shorten that wait with deliberate testing: visit every page template, embed, and font source this site uses yourself while Report-Only is active, so you are not relying on organic traffic alone to surface a rare page. The Report-Only Evidence table below only reflects visits from Chromium-based browsers (Chrome, Edge, Opera and similar) -- it cannot show a break a Safari or Firefox visitor would hit, since neither sends these reports yet, so also check the site manually in both before enforcing.', 'vcns-security-automation-manager' ) . '</p>',
		'supports_mode'  => true,
		'mode_extractor' => array( Cross_Origin_Embedder_Policy_Builder::class, 'extract_mode' ),
	),
	'coop'  => array(
		'label'          => __( 'Cross-Origin-Opener-Policy', 'vcns-security-automation-manager' ),
		'pillar_key'     => Cross_Origin_Opener_Policy_Builder::PILLAR_KEY,
		'header_name'    => 'Cross-Origin-Opener-Policy',
		'intro_html'     => '<p>' . esc_html__( 'Isolates this site\'s browsing context group from cross-origin windows it opens or is opened by, closing off cross-window/Spectre-style leaks.', 'vcns-security-automation-manager' ) . '</p>',
		'value_options'  => array(
			'unsafe-none'              => __( 'unsafe-none -- no isolation (browser default)', 'vcns-security-automation-manager' ),
			'same-origin-allow-popups' => __( 'same-origin-allow-popups -- isolate, but let popups keep a restricted opener reference', 'vcns-security-automation-manager' ),
			'same-origin'              => __( 'same-origin -- full isolation', 'vcns-security-automation-manager' ),
		),
		'warning_html'   => '<p style="margin-top:0;margin-bottom:0;">' . esc_html__( '"same-origin" severs window.opener access from any cross-origin popup this site opens or is opened by -- including popup-based OAuth/SSO and payment flows. Start with Report-Only, and give it at least two weeks of real traffic covering a full content cycle before enforcing -- a login or checkout flow used only occasionally can easily go unrepresented in a shorter window. You can shorten that wait with deliberate testing: walk through every popup-based sign-in, sharing, or payment flow this site uses yourself while Report-Only is active. The Report-Only Evidence table below only reflects visits from Chromium-based browsers (Chrome, Edge, Opera and similar) -- it cannot show a break a Safari or Firefox visitor would hit, since neither sends these reports yet, so also check the site manually in both before enforcing.', 'vcns-security-automation-manager' ) . '</p>',
		'supports_mode'  => true,
		'mode_extractor' => array( Cross_Origin_Opener_Policy_Builder::class, 'extract_mode' ),
	),
	'corp'  => array(
		'label'         => __( 'Cross-Origin-Resource-Policy', 'vcns-security-automation-manager' ),
		'pillar_key'    => Cross_Origin_Resource_Policy_Builder::PILLAR_KEY,
		'header_name'   => 'Cross-Origin-Resource-Policy',
		'intro_html'    => '<p>' . esc_html__( 'Controls whether other origins may load this site\'s own resources (scripts, images, fonts) via image tags, script tags, fetch(), and similar. The lowest-risk of the cross-origin headers to enable: a misconfiguration can stop a legitimate third party from loading this site\'s own resource, but it never breaks resources this site itself loads from elsewhere.', 'vcns-security-automation-manager' ) . '</p>',
		'value_options' => array(
			'same-site'    => __( 'same-site -- allow same-site origins only', 'vcns-security-automation-manager' ),
			'same-origin'  => __( 'same-origin -- allow only this exact origin', 'vcns-security-automation-manager' ),
			'cross-origin' => __( 'cross-origin -- allow any origin', 'vcns-security-automation-manager' ),
		),
		'warning_html'  => '',
		'supports_mode' => false,
	),
	'xpcdp' => array(
		'label'         => __( 'X-Permitted-Cross-Domain-Policies', 'vcns-security-automation-manager' ),
		'pillar_key'    => X_Permitted_Cross_Domain_Policies_Builder::PILLAR_KEY,
		'header_name'   => 'X-Permitted-Cross-Domain-Policies',
		'intro_html'    => '<p>' . esc_html__( 'A legacy header from the Adobe Flash/Acrobat era, controlling whether Flash and PDF plugins may load a cross-domain policy file from this site. Flash is dead, so "none" is almost always the correct value -- this closes a legacy attack surface that would otherwise sit at its permissive browser default.', 'vcns-security-automation-manager' ) . '</p>',
		'value_options' => array(
			'none'            => __( 'none -- no policy files allowed (recommended)', 'vcns-security-automation-manager' ),
			'master-only'     => __( 'master-only -- only the root crossdomain.xml', 'vcns-security-automation-manager' ),
			'by-content-type' => __( 'by-content-type', 'vcns-security-automation-manager' ),
			'all'             => __( 'all -- any policy file, anywhere (not recommended)', 'vcns-security-automation-manager' ),
		),
		'warning_html'  => '',
		'supports_mode' => false,
	),
);

$tab = isset( $_GET['tab'] ) ? sanitize_text_field( wp_unslash( $_GET['tab'] ) ) : 'coep';
if ( ! isset( $tabs[ $tab ] ) ) {
	$tab = 'coep';
}
$active = $tabs[ $tab ];

$base_url = admin_url( 'admin.php?page=security-automation-manager-cross-origin' );

$surfaces = array( 'frontend', 'admin', 'login', 'api' );

$profiles_raw = $wpdb->get_results(
	$wpdb->prepare(
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		"SELECT surface, enabled, payload FROM {$wpdb->prefix}sam_pillar_profiles WHERE pillar = %s",
		$active['pillar_key']
	),
	ARRAY_A
);

$profiles_by_surface = array();
foreach ( ! empty( $profiles_raw ) ? $profiles_raw : array() as $row ) {
	$payload                                = json_decode( (string) $row['payload'], true );
	$profiles_by_surface[ $row['surface'] ] = array(
		'enabled' => ! empty( $row['enabled'] ),
		'value'   => is_array( $payload ) ? (string) ( $payload['value'] ?? '' ) : '',
		'mode'    => $active['supports_mode'] ? call_user_func( $active['mode_extractor'], $row ) : '',
	);
}
?>
<div class="wrap wp-sam-wrap">
	<h1><?php esc_html_e( 'Cross-Origin Policies', 'vcns-security-automation-manager' ); ?></h1>

	<!-- ── Tabs ──────────────────────────────────────────────────────────── -->
	<nav class="nav-tab-wrapper wp-sam-tab-wrapper" role="tablist" aria-label="<?php esc_attr_e( 'Cross-origin policy pillars', 'vcns-security-automation-manager' ); ?>">
		<?php foreach ( $tabs as $tab_key => $tab_data ) : ?>
		<a class="nav-tab<?php echo $tab_key === $tab ? ' nav-tab-active' : ''; ?>"
			href="<?php echo esc_url( add_query_arg( 'tab', $tab_key, $base_url ) ); ?>"
			role="tab"
			<?php echo $tab_key === $tab ? 'aria-selected="true" aria-current="page"' : 'aria-selected="false"'; ?>>
			<?php echo esc_html( $tab_data['label'] ); ?>
		</a>
		<?php endforeach; ?>
	</nav>

	<?php if ( ! empty( $active['warning_html'] ) ) : ?>
	<div class="notice notice-warning inline" style="padding:12px 16px;margin:1em 0;">
		<?php echo wp_kses_post( $active['warning_html'] ); ?>
	</div>
	<?php endif; ?>

	<?php echo wp_kses_post( $active['intro_html'] ); ?>

	<table class="widefat striped wp-sam-readiness-table" style="margin-top: 1em;">
		<thead>
			<tr>
				<th><?php esc_html_e( 'Surface', 'vcns-security-automation-manager' ); ?></th>
				<?php if ( $active['supports_mode'] ) : ?>
					<th><?php esc_html_e( 'Mode', 'vcns-security-automation-manager' ); ?></th>
				<?php else : ?>
					<th><?php esc_html_e( 'Enabled', 'vcns-security-automation-manager' ); ?></th>
				<?php endif; ?>
				<th><?php esc_html_e( 'Value', 'vcns-security-automation-manager' ); ?></th>
			</tr>
		</thead>
		<tbody>
			<?php foreach ( $surfaces as $surface ) : ?>
				<?php
				$current = $profiles_by_surface[ $surface ] ?? array(
					'enabled' => false,
					'value'   => '',
					'mode'    => 'enforce',
				);
				?>
				<tr>
					<td><?php echo esc_html( ucfirst( $surface ) ); ?></td>
					<?php if ( $active['supports_mode'] ) : ?>
						<td>
							<select
								class="wp-sam-pillar-mode"
								data-pillar="<?php echo esc_attr( $active['pillar_key'] ); ?>"
								data-surface="<?php echo esc_attr( $surface ); ?>"
							>
								<?php foreach ( $mode_options as $mode_value => $mode_label ) : ?>
									<option value="<?php echo esc_attr( $mode_value ); ?>" <?php selected( $current['enabled'] ? $current['mode'] : 'disabled', $mode_value ); ?>>
										<?php echo esc_html( $mode_label ); ?>
									</option>
								<?php endforeach; ?>
							</select>
						</td>
					<?php else : ?>
						<td>
							<input
								type="checkbox"
								class="wp-sam-pillar-enabled"
								data-pillar="<?php echo esc_attr( $active['pillar_key'] ); ?>"
								data-surface="<?php echo esc_attr( $surface ); ?>"
								<?php checked( $current['enabled'] ); ?>
							/>
						</td>
					<?php endif; ?>
					<td>
						<select
							class="wp-sam-pillar-value"
							data-pillar="<?php echo esc_attr( $active['pillar_key'] ); ?>"
							data-surface="<?php echo esc_attr( $surface ); ?>"
						>
							<?php foreach ( $active['value_options'] as $value => $label ) : ?>
								<option value="<?php echo esc_attr( $value ); ?>" <?php selected( $current['value'], $value ); ?>>
									<?php echo esc_html( $label ); ?>
								</option>
							<?php endforeach; ?>
						</select>
					</td>
				</tr>
			<?php endforeach; ?>
		</tbody>
	</table>

	<?php if ( $active['supports_mode'] ) : ?>
	<p class="description" style="margin-top: 1em;">
		<?php
		echo wp_kses_post(
			sprintf(
			/* translators: %s: HTTP header name, e.g. "Cross-Origin-Opener-Policy" */
				__( 'Report-Only sends %s-Report-Only and records what would have been blocked below, without blocking anything. Promoting a surface to Enforce is always a deliberate, manual choice -- nothing here is auto-promoted.', 'vcns-security-automation-manager' ),
				'<code>' . esc_html( $active['header_name'] ) . '</code>'
			)
		);
		?>
	</p>

		<?php
		// ── Report-Only Evidence ─────────────────────────────────────────────
		$per_page = 20;

		$e_surface   = Table_Query::text_param( 'e_surface' );
		$e_type      = Table_Query::text_param( 'e_type' );
		$e_occ_min   = Table_Query::int_param( 'e_occ_min' );
		$e_seen_from = Table_Query::text_param( 'e_seen_from' );
		$e_seen_to   = Table_Query::text_param( 'e_seen_to' );

		$evid_where = array( 'pillar = %s' );
		$evid_args  = array( $active['pillar_key'] );
		foreach (
		array(
			Table_Query::equals_where( 'surface', $e_surface ),
			Table_Query::like_where( $wpdb, 'report_type', $e_type ),
			Table_Query::numeric_gte_where( 'occurrence_count', $e_occ_min ),
			Table_Query::date_range_where( 'last_seen_at', $e_seen_from, $e_seen_to ),
		) as $evid_fragment
		) {
			if ( null === $evid_fragment ) {
				continue;
			}
			$evid_where[] = $evid_fragment['sql'];
			array_push( $evid_args, ...$evid_fragment['args'] );
		}
		$evid_where_sql = implode( ' AND ', $evid_where );

		$evid_sort_whitelist = array(
			'surface'     => array(
				'expr'        => 'surface',
				'default_dir' => 'asc',
			),
			'type'        => array(
				'expr'        => 'report_type',
				'default_dir' => 'asc',
			),
			'disposition' => array(
				'expr'        => 'disposition',
				'default_dir' => 'asc',
			),
			'occurrences' => array(
				'expr'        => 'occurrence_count',
				'default_dir' => 'desc',
			),
			'first_seen'  => array(
				'expr'        => 'first_seen_at',
				'default_dir' => 'desc',
			),
			'last_seen'   => array(
				'expr'        => 'last_seen_at',
				'default_dir' => 'desc',
			),
		);
		$evid_sort           = Table_Query::resolve_sort(
			$evid_sort_whitelist,
			'last_seen',
			isset( $_GET['esort'] ) ? sanitize_text_field( wp_unslash( $_GET['esort'] ) ) : null, // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			isset( $_GET['edir'] ) ? sanitize_text_field( wp_unslash( $_GET['edir'] ) ) : null // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		);

		$evid_state_args = array_filter(
			array(
				'tab'         => $tab,
				'esort'       => $evid_sort['key'],
				'edir'        => strtolower( $evid_sort['dir'] ),
				'e_surface'   => $e_surface,
				'e_type'      => $e_type,
				'e_occ_min'   => $e_occ_min,
				'e_seen_from' => $e_seen_from,
				'e_seen_to'   => $e_seen_to,
			)
		);

		$evid_count_sql = "SELECT COUNT(*) FROM {$wpdb->prefix}sam_pillar_violation_reports WHERE {$evid_where_sql}";
	// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$evid_count_sql = $wpdb->prepare( $evid_count_sql, ...$evid_args );
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$evid_total = (int) $wpdb->get_var( $evid_count_sql );

		$evid_pages    = max( 1, (int) ceil( $evid_total / $per_page ) );
		$evid_page_num = min( max( 1, (int) ( isset( $_GET['e_paged'] ) ? $_GET['e_paged'] : 1 ) ), $evid_pages );
		$evid_offset   = ( $evid_page_num - 1 ) * $per_page;

		$evid_data_args = array_merge( $evid_args, array( $per_page, $evid_offset ) );
		$evid_data_sql  = "SELECT * FROM {$wpdb->prefix}sam_pillar_violation_reports WHERE {$evid_where_sql} " . Table_Query::order_by_sql( $evid_sort ) . ' LIMIT %d OFFSET %d';
	// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$evid_data_sql = $wpdb->prepare( $evid_data_sql, ...$evid_data_args );
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$evidence_raw = $wpdb->get_results( $evid_data_sql, ARRAY_A );
		$evidence     = ! empty( $evidence_raw ) ? $evidence_raw : array();

		// Simple at-a-glance signal, same spirit as CSP's promotion gate -- purely
		// informational, never blocking or auto-triggering a mode change.
	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$evid_recent_count = (int) $wpdb->get_var(
			$wpdb->prepare(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT COUNT(*) FROM {$wpdb->prefix}sam_pillar_violation_reports WHERE pillar = %s AND last_seen_at >= %s",
				$active['pillar_key'],
				gmdate( 'Y-m-d H:i:s', time() - ( 7 * DAY_IN_SECONDS ) )
			)
		);
		?>

	<h2><?php esc_html_e( 'Report-Only Evidence', 'vcns-security-automation-manager' ); ?></h2>
	<p>
		<?php
		if ( $evid_recent_count > 0 ) {
			echo esc_html(
				sprintf(
					/* translators: %d: number of distinct violation fingerprints */
					_n(
						'%d distinct violation in the last 7 days.',
						'%d distinct violations in the last 7 days.',
						$evid_recent_count,
						'vcns-security-automation-manager'
					),
					$evid_recent_count
				)
			);
		} else {
			esc_html_e( 'No violations in the last 7 days.', 'vcns-security-automation-manager' );
		}
		?>
	</p>

	<details class="wp-sam-filter-form">
		<summary><?php esc_html_e( 'Filters', 'vcns-security-automation-manager' ); ?></summary>
		<form method="get" action="">
			<input type="hidden" name="page" value="security-automation-manager-cross-origin" />
			<input type="hidden" name="tab" value="<?php echo esc_attr( $tab ); ?>" />
			<label>
				<?php esc_html_e( 'Surface', 'vcns-security-automation-manager' ); ?>
				<select name="e_surface">
					<option value=""><?php esc_html_e( 'Any', 'vcns-security-automation-manager' ); ?></option>
					<?php foreach ( $surfaces as $s ) : ?>
					<option value="<?php echo esc_attr( $s ); ?>" <?php selected( $e_surface, $s ); ?>><?php echo esc_html( ucfirst( $s ) ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
			<label>
				<?php esc_html_e( 'Report type contains', 'vcns-security-automation-manager' ); ?>
				<input type="text" name="e_type" value="<?php echo esc_attr( $e_type ); ?>" />
			</label>
			<label>
				<?php esc_html_e( 'Occurrences at least', 'vcns-security-automation-manager' ); ?>
				<input type="number" min="0" name="e_occ_min" style="width:80px" value="<?php echo esc_attr( null !== $e_occ_min ? (string) $e_occ_min : '' ); ?>" />
			</label>
			<label>
				<?php esc_html_e( 'Last seen from', 'vcns-security-automation-manager' ); ?>
				<input type="datetime-local" name="e_seen_from" value="<?php echo esc_attr( $e_seen_from ); ?>" />
			</label>
			<label>
				<?php esc_html_e( 'to', 'vcns-security-automation-manager' ); ?>
				<input type="datetime-local" name="e_seen_to" value="<?php echo esc_attr( $e_seen_to ); ?>" />
			</label>
			<?php submit_button( __( 'Filter', 'vcns-security-automation-manager' ), 'secondary', 'filter_evidence', false ); ?>
		</form>
	</details>

	<table class="widefat fixed striped wp-sam-violations-table" style="margin-top:1em">
		<thead>
			<tr>
				<?php
				echo Table_Query::sort_header( __( 'Surface', 'vcns-security-automation-manager' ), 'surface', $evid_sort_whitelist, $evid_sort, $evid_state_args, $base_url, 'e_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- helper escapes internally.
				echo Table_Query::sort_header( __( 'Report Type', 'vcns-security-automation-manager' ), 'type', $evid_sort_whitelist, $evid_sort, $evid_state_args, $base_url, 'e_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'Disposition', 'vcns-security-automation-manager' ), 'disposition', $evid_sort_whitelist, $evid_sort, $evid_state_args, $base_url, 'e_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'Occurrences', 'vcns-security-automation-manager' ), 'occurrences', $evid_sort_whitelist, $evid_sort, $evid_state_args, $base_url, 'e_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'First Seen', 'vcns-security-automation-manager' ), 'first_seen', $evid_sort_whitelist, $evid_sort, $evid_state_args, $base_url, 'e_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				echo Table_Query::sort_header( __( 'Last Seen', 'vcns-security-automation-manager' ), 'last_seen', $evid_sort_whitelist, $evid_sort, $evid_state_args, $base_url, 'e_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
				?>
				<th><?php esc_html_e( 'Details', 'vcns-security-automation-manager' ); ?></th>
			</tr>
		</thead>
		<tbody>
		<?php foreach ( $evidence as $e ) : ?>
		<tr>
			<td><?php echo esc_html( ucfirst( (string) $e['surface'] ) ); ?></td>
			<td><code><?php echo esc_html( (string) $e['report_type'] ); ?></code></td>
			<td><?php echo esc_html( (string) $e['disposition'] ); ?></td>
			<td><?php echo esc_html( number_format( (int) $e['occurrence_count'] ) ); ?></td>
			<td><?php echo esc_html( (string) $e['first_seen_at'] ); ?></td>
			<td><?php echo esc_html( (string) $e['last_seen_at'] ); ?></td>
			<td>
				<?php
				$e_detail    = json_decode( (string) $e['detail'], true );
				$meta_fields = is_array( $e_detail ) ? $e_detail : array();
				$has_meta    = ! empty( $meta_fields );
				?>
				<?php if ( $has_meta ) : ?>
				<span class="dashicons dashicons-info-outline wp-sam-meta-icon" tabindex="0">
					<span class="wp-sam-meta-popover" role="tooltip">
						<?php foreach ( $meta_fields as $meta_label => $meta_value ) : ?>
						<div class="wp-sam-meta-row">
							<strong><?php echo esc_html( (string) $meta_label ); ?>:</strong>
							<code><?php echo esc_html( is_scalar( $meta_value ) ? (string) $meta_value : wp_json_encode( $meta_value ) ); ?></code>
						</div>
						<?php endforeach; ?>
					</span>
				</span>
				<?php else : ?>
				<span class="dashicons dashicons-info-outline wp-sam-meta-icon wp-sam-meta-icon--empty" title="<?php esc_attr_e( 'No metadata captured for this report', 'vcns-security-automation-manager' ); ?>"></span>
				<?php endif; ?>
			</td>
		</tr>
		<?php endforeach; ?>
		<?php if ( empty( $evidence ) ) : ?>
		<tr>
			<td colspan="7">
				<p><?php esc_html_e( 'No report-only evidence recorded yet.', 'vcns-security-automation-manager' ); ?></p>
				<p><?php esc_html_e( 'Set a surface above to Report-Only, then browse the live site with a Chromium-based browser -- only Chromium currently sends these reports. Evidence appears here as violations are observed.', 'vcns-security-automation-manager' ); ?></p>
			</td>
		</tr>
		<?php endif; ?>
		</tbody>
	</table>

		<?php echo Table_Query::pagination( $evid_page_num, $evid_pages, $evid_state_args, $base_url, 'e_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>

	<?php else : ?>
	<p class="description" style="margin-top: 1em;">
		<?php
		echo wp_kses_post(
			sprintf(
			/* translators: %s: HTTP header name, e.g. "Cross-Origin-Resource-Policy" */
				__( 'Changes apply immediately -- there is no report-only mode, discovery workflow, or automation for this pillar. The %s header is either sent exactly as configured, or not sent at all.', 'vcns-security-automation-manager' ),
				'<code>' . esc_html( $active['header_name'] ) . '</code>'
			)
		);
		?>
	</p>
	<?php endif; ?>
</div>
