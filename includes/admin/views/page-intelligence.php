<?php
/**
 * Admin view: Continuous Intelligence -- Layer 3 of the roadmap's five
 * protection layers. Three tabs:
 *
 * - Events: whatever the Request Observation Framework has recorded in
 *   sam_request_events (Phase 3B/3C), using the same Table_Query sort/
 *   filter/pagination conventions as the CSP Violations and Cross-Origin
 *   Report-Only Evidence tabs.
 * - Identities: resolved request identities from sam_scanner_identities
 *   (Phase 3D). Recognition (automatic) is shown distinctly from
 *   authorisation (an explicit administrator decision) -- see
 *   Intelligence\Scanner_Identity_Store's docblock for why the two can
 *   never be conflated.
 * - Vendors: the known-identity catalogue (sam_scanner_vendors,
 *   Phase 3D) Identity_Resolver matches claimed identities against.
 *   Built-in rows are editable but not deletable.
 *
 * Rendered by Admin_UI::render_intelligence().
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WP_SAM\Admin\Table_Query;
use WP_SAM\Intelligence\Scanner_Identity_Store;
use WP_SAM\Intelligence\Scanner_Vendor_Store;

global $wpdb;

$base_url     = admin_url( 'admin.php?page=security-automation-manager-intelligence' );
$tab          = isset( $_GET['tab'] ) ? sanitize_text_field( wp_unslash( $_GET['tab'] ) ) : 'events'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
$allowed_tabs = array( 'events', 'identities', 'vendors' );
if ( ! in_array( $tab, $allowed_tabs, true ) ) {
	$tab = 'events';
}

$tab_help = array(
	'events'     => array(
		'label'       => __( 'Events', 'vcns-security-automation-manager' ),
		'description' => __( 'Requests matched by a registered detector family.', 'vcns-security-automation-manager' ),
	),
	'identities' => array(
		'label'       => __( 'Identities', 'vcns-security-automation-manager' ),
		'description' => __( 'Claimed identities resolved from real traffic. Recognition is automatic; authorisation is always an explicit decision below.', 'vcns-security-automation-manager' ),
	),
	'vendors'    => array(
		'label'       => __( 'Vendors', 'vcns-security-automation-manager' ),
		'description' => __( 'The known-identity catalogue new traffic is matched against. Add your own verified commercial scanner vendors here.', 'vcns-security-automation-manager' ),
	),
);
?>
<div class="wrap wp-sam-wrap">
	<h1><?php esc_html_e( 'Continuous Intelligence', 'vcns-security-automation-manager' ); ?></h1>

	<p>
		<?php esc_html_e( 'Layer 3 of this plugin\'s protection model: request observation and classification, independent of the enforced header policies above.', 'vcns-security-automation-manager' ); ?>
	</p>

	<nav class="nav-tab-wrapper wp-sam-tab-wrapper" role="tablist" aria-label="<?php esc_attr_e( 'Continuous Intelligence sections', 'vcns-security-automation-manager' ); ?>">
		<?php foreach ( $tab_help as $tab_key => $tab_data ) : ?>
		<a class="nav-tab<?php echo $tab_key === $tab ? ' nav-tab-active' : ''; ?>"
			href="<?php echo esc_url( add_query_arg( 'tab', $tab_key, $base_url ) ); ?>"
			role="tab"
			title="<?php echo esc_attr( $tab_data['description'] ); ?>"
			<?php echo $tab_key === $tab ? 'aria-selected="true" aria-current="page"' : 'aria-selected="false"'; ?>>
			<?php echo esc_html( $tab_data['label'] ); ?>
		</a>
		<?php endforeach; ?>
	</nav>
	<div class="wp-sam-tab-help" role="note">
		<strong><?php echo esc_html( $tab_help[ $tab ]['label'] ); ?>:</strong>
		<?php echo esc_html( $tab_help[ $tab ]['description'] ); ?>
	</div>

	<?php if ( 'events' === $tab ) : ?>

		<?php
		$surfaces   = array( 'frontend', 'admin', 'login', 'api' );
		$severities = array( 'low', 'medium', 'high', 'critical', 'unknown' );
		$per_page   = 20;

		$i_surface   = Table_Query::text_param( 'i_surface' );
		$i_severity  = Table_Query::text_param( 'i_severity' );
		$i_detector  = Table_Query::text_param( 'i_detector' );
		$i_occ_min   = Table_Query::int_param( 'i_occ_min' );
		$i_seen_from = Table_Query::text_param( 'i_seen_from' );
		$i_seen_to   = Table_Query::text_param( 'i_seen_to' );

		$where = array( '1=1' );
		$args  = array();
		foreach (
			array(
				Table_Query::equals_where( 'surface', $i_surface ),
				Table_Query::equals_where( 'severity', $i_severity ),
				Table_Query::like_where_any( $wpdb, array( 'detector_id', 'detector_family' ), $i_detector ),
				Table_Query::numeric_gte_where( 'occurrence_count', $i_occ_min ),
				Table_Query::date_range_where( 'last_seen_at', $i_seen_from, $i_seen_to ),
			) as $fragment
		) {
			if ( null === $fragment ) {
				continue;
			}
			$where[] = $fragment['sql'];
			array_push( $args, ...$fragment['args'] );
		}
		$where_sql = implode( ' AND ', $where );

		$sort_whitelist = array(
			'surface'     => array(
				'expr'        => 'surface',
				'default_dir' => 'asc',
			),
			'detector'    => array(
				'expr'        => 'detector_id',
				'default_dir' => 'asc',
			),
			'family'      => array(
				'expr'        => 'detector_family',
				'default_dir' => 'asc',
			),
			'severity'    => array(
				'expr'        => 'severity',
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
		$sort           = Table_Query::resolve_sort(
			$sort_whitelist,
			'last_seen',
			isset( $_GET['sort'] ) ? sanitize_text_field( wp_unslash( $_GET['sort'] ) ) : null, // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			isset( $_GET['dir'] ) ? sanitize_text_field( wp_unslash( $_GET['dir'] ) ) : null // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		);

		$state_args = array_filter(
			array(
				'tab'         => 'events',
				'sort'        => $sort['key'],
				'dir'         => strtolower( $sort['dir'] ),
				'i_surface'   => $i_surface,
				'i_severity'  => $i_severity,
				'i_detector'  => $i_detector,
				'i_occ_min'   => $i_occ_min,
				'i_seen_from' => $i_seen_from,
				'i_seen_to'   => $i_seen_to,
			)
		);

		$count_sql = "SELECT COUNT(*) FROM {$wpdb->prefix}sam_request_events WHERE {$where_sql}";
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$count_sql = $wpdb->prepare( $count_sql, ...$args );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$total = (int) $wpdb->get_var( $count_sql );

		$pages    = max( 1, (int) ceil( $total / $per_page ) );
		$page_num = min( max( 1, (int) ( isset( $_GET['i_paged'] ) ? $_GET['i_paged'] : 1 ) ), $pages ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$offset   = ( $page_num - 1 ) * $per_page;

		$data_args = array_merge( $args, array( $per_page, $offset ) );
		$data_sql  = "SELECT * FROM {$wpdb->prefix}sam_request_events WHERE {$where_sql} " . Table_Query::order_by_sql( $sort ) . ' LIMIT %d OFFSET %d';
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$data_sql = $wpdb->prepare( $data_sql, ...$data_args );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$events_raw = $wpdb->get_results( $data_sql, ARRAY_A );
		$events     = ! empty( $events_raw ) ? $events_raw : array();

		$detector_count = count( \WP_SAM\Intelligence\Detector_Registry::keys() );
		?>

		<?php if ( 0 === $detector_count ) : ?>
		<div class="notice notice-info inline" style="padding:12px 16px;margin:1em 0;">
			<p style="margin-top:0;">
				<?php esc_html_e( 'No detectors are registered yet. Requests are observed and classified, but nothing is currently evaluated against them, so this table stays empty.', 'vcns-security-automation-manager' ); ?>
			</p>
		</div>
		<?php endif; ?>

		<details class="wp-sam-filter-form">
			<summary><?php esc_html_e( 'Filters', 'vcns-security-automation-manager' ); ?></summary>
			<form method="get" action="">
				<input type="hidden" name="page" value="security-automation-manager-intelligence" />
				<input type="hidden" name="tab" value="events" />
				<label>
					<?php esc_html_e( 'Surface', 'vcns-security-automation-manager' ); ?>
					<select name="i_surface">
						<option value=""><?php esc_html_e( 'Any', 'vcns-security-automation-manager' ); ?></option>
						<?php foreach ( $surfaces as $s ) : ?>
						<option value="<?php echo esc_attr( $s ); ?>" <?php selected( $i_surface, $s ); ?>><?php echo esc_html( ucfirst( $s ) ); ?></option>
						<?php endforeach; ?>
					</select>
				</label>
				<label>
					<?php esc_html_e( 'Severity', 'vcns-security-automation-manager' ); ?>
					<select name="i_severity">
						<option value=""><?php esc_html_e( 'Any', 'vcns-security-automation-manager' ); ?></option>
						<?php foreach ( $severities as $sev ) : ?>
						<option value="<?php echo esc_attr( $sev ); ?>" <?php selected( $i_severity, $sev ); ?>><?php echo esc_html( ucfirst( $sev ) ); ?></option>
						<?php endforeach; ?>
					</select>
				</label>
				<label>
					<?php esc_html_e( 'Detector contains', 'vcns-security-automation-manager' ); ?>
					<input type="text" name="i_detector" value="<?php echo esc_attr( $i_detector ); ?>" />
				</label>
				<label>
					<?php esc_html_e( 'Occurrences at least', 'vcns-security-automation-manager' ); ?>
					<input type="number" min="0" name="i_occ_min" style="width:80px" value="<?php echo esc_attr( null !== $i_occ_min ? (string) $i_occ_min : '' ); ?>" />
				</label>
				<label>
					<?php esc_html_e( 'Last seen from', 'vcns-security-automation-manager' ); ?>
					<input type="datetime-local" name="i_seen_from" value="<?php echo esc_attr( $i_seen_from ); ?>" />
				</label>
				<label>
					<?php esc_html_e( 'to', 'vcns-security-automation-manager' ); ?>
					<input type="datetime-local" name="i_seen_to" value="<?php echo esc_attr( $i_seen_to ); ?>" />
				</label>
				<?php submit_button( __( 'Filter', 'vcns-security-automation-manager' ), 'secondary', 'filter_events', false ); ?>
			</form>
		</details>

		<table class="widefat fixed striped wp-sam-violations-table" style="margin-top:1em">
			<thead>
				<tr>
					<?php
					echo Table_Query::sort_header( __( 'Surface', 'vcns-security-automation-manager' ), 'surface', $sort_whitelist, $sort, $state_args, $base_url, 'i_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- helper escapes internally.
					echo Table_Query::sort_header( __( 'Detector', 'vcns-security-automation-manager' ), 'detector', $sort_whitelist, $sort, $state_args, $base_url, 'i_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
					echo Table_Query::sort_header( __( 'Family', 'vcns-security-automation-manager' ), 'family', $sort_whitelist, $sort, $state_args, $base_url, 'i_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
					echo Table_Query::sort_header( __( 'Severity', 'vcns-security-automation-manager' ), 'severity', $sort_whitelist, $sort, $state_args, $base_url, 'i_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
					echo Table_Query::sort_header( __( 'Occurrences', 'vcns-security-automation-manager' ), 'occurrences', $sort_whitelist, $sort, $state_args, $base_url, 'i_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
					echo Table_Query::sort_header( __( 'First Seen', 'vcns-security-automation-manager' ), 'first_seen', $sort_whitelist, $sort, $state_args, $base_url, 'i_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
					echo Table_Query::sort_header( __( 'Last Seen', 'vcns-security-automation-manager' ), 'last_seen', $sort_whitelist, $sort, $state_args, $base_url, 'i_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
					?>
					<th><?php esc_html_e( 'Details', 'vcns-security-automation-manager' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $events as $event ) : ?>
			<tr>
				<td><?php echo esc_html( ucfirst( (string) $event['surface'] ) ); ?></td>
				<td><code><?php echo esc_html( (string) $event['detector_id'] ); ?></code></td>
				<td><?php echo esc_html( (string) $event['detector_family'] ); ?></td>
				<td><?php echo esc_html( ucfirst( (string) $event['severity'] ) ); ?></td>
				<td><?php echo esc_html( number_format( (int) $event['occurrence_count'] ) ); ?></td>
				<td><?php echo esc_html( (string) $event['first_seen_at'] ); ?></td>
				<td><?php echo esc_html( (string) $event['last_seen_at'] ); ?></td>
				<td>
					<?php
					$event_detail = json_decode( (string) $event['detail'], true );
					$meta_fields  = is_array( $event_detail ) ? $event_detail : array();
					$has_meta     = ! empty( $meta_fields );
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
					<span class="dashicons dashicons-info-outline wp-sam-meta-icon wp-sam-meta-icon--empty" title="<?php esc_attr_e( 'No metadata captured for this event', 'vcns-security-automation-manager' ); ?>"></span>
					<?php endif; ?>
				</td>
			</tr>
			<?php endforeach; ?>
			<?php if ( empty( $events ) ) : ?>
			<tr>
				<td colspan="8">
					<?php if ( $detector_count > 0 ) : ?>
					<p><?php esc_html_e( 'No events recorded yet.', 'vcns-security-automation-manager' ); ?></p>
					<?php else : ?>
					<p><?php esc_html_e( 'No events recorded -- no detectors are registered yet.', 'vcns-security-automation-manager' ); ?></p>
					<?php endif; ?>
				</td>
			</tr>
			<?php endif; ?>
			</tbody>
		</table>

		<?php echo Table_Query::pagination( $page_num, $pages, $state_args, $base_url, 'i_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>

	<?php elseif ( 'identities' === $tab ) : ?>

		<?php
		$surfaces = array( 'frontend', 'admin', 'login', 'api' );
		$states   = array_merge( Scanner_Identity_Store::AUTOMATIC_STATES, Scanner_Identity_Store::DECISION_STATES );
		$per_page = 20;

		$id_surface = Table_Query::text_param( 'id_surface' );
		$id_state   = Table_Query::text_param( 'id_state' );
		$id_ip      = Table_Query::text_param( 'id_ip' );

		$where = array( '1=1' );
		$args  = array();
		foreach (
			array(
				Table_Query::equals_where( 'surface', $id_surface ),
				Table_Query::equals_where( 'verification_state', $id_state ),
				Table_Query::like_where_any( $wpdb, array( 'ip' ), $id_ip ),
			) as $fragment
		) {
			if ( null === $fragment ) {
				continue;
			}
			$where[] = $fragment['sql'];
			array_push( $args, ...$fragment['args'] );
		}
		$where_sql = implode( ' AND ', $where );

		$sort_whitelist = array(
			'identity'    => array(
				'expr'        => 'claimed_identity',
				'default_dir' => 'asc',
			),
			'state'       => array(
				'expr'        => 'verification_state',
				'default_dir' => 'asc',
			),
			'occurrences' => array(
				'expr'        => 'occurrence_count',
				'default_dir' => 'desc',
			),
			'last_seen'   => array(
				'expr'        => 'last_seen_at',
				'default_dir' => 'desc',
			),
		);
		$sort           = Table_Query::resolve_sort(
			$sort_whitelist,
			'last_seen',
			isset( $_GET['sort'] ) ? sanitize_text_field( wp_unslash( $_GET['sort'] ) ) : null, // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			isset( $_GET['dir'] ) ? sanitize_text_field( wp_unslash( $_GET['dir'] ) ) : null // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		);

		$state_args = array_filter(
			array(
				'tab'        => 'identities',
				'sort'       => $sort['key'],
				'dir'        => strtolower( $sort['dir'] ),
				'id_surface' => $id_surface,
				'id_state'   => $id_state,
				'id_ip'      => $id_ip,
			)
		);

		$identities_table = $wpdb->prefix . 'sam_scanner_identities';
		$count_sql        = "SELECT COUNT(*) FROM {$identities_table} WHERE {$where_sql}";
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$count_sql = $wpdb->prepare( $count_sql, ...$args );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$total = (int) $wpdb->get_var( $count_sql );

		$pages    = max( 1, (int) ceil( $total / $per_page ) );
		$page_num = min( max( 1, (int) ( isset( $_GET['id_paged'] ) ? $_GET['id_paged'] : 1 ) ), $pages ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$offset   = ( $page_num - 1 ) * $per_page;

		$data_args = array_merge( $args, array( $per_page, $offset ) );
		$data_sql  = "SELECT * FROM {$identities_table} WHERE {$where_sql} " . Table_Query::order_by_sql( $sort ) . ' LIMIT %d OFFSET %d';
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$data_sql = $wpdb->prepare( $data_sql, ...$data_args );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$identities_raw = $wpdb->get_results( $data_sql, ARRAY_A );
		$identities     = ! empty( $identities_raw ) ? $identities_raw : array();

		$vendor_store   = new Scanner_Vendor_Store();
		$vendors_by_key = array();
		foreach ( $vendor_store->all() as $v ) {
			$vendors_by_key[ $v['vendor_key'] ] = $v;
		}

		$state_labels = array(
			'unknown'                       => __( 'Unknown', 'vcns-security-automation-manager' ),
			'known_commercial_scanner'      => __( 'Known commercial scanner', 'vcns-security-automation-manager' ),
			'known_research_scanner'        => __( 'Known research scanner', 'vcns-security-automation-manager' ),
			'known_crawler'                 => __( 'Known crawler', 'vcns-security-automation-manager' ),
			'identity_conflict'             => __( 'Identity conflict', 'vcns-security-automation-manager' ),
			'customer_authorised'           => __( 'Authorised', 'vcns-security-automation-manager' ),
			'explicitly_denied'             => __( 'Denied', 'vcns-security-automation-manager' ),
			'previously_authorised_expired' => __( 'Authorisation expired', 'vcns-security-automation-manager' ),
		);
		?>

		<div class="notice notice-info inline" style="padding:12px 16px;margin:1em 0;">
			<p style="margin-top:0;">
				<?php esc_html_e( 'Recognition is not authorisation. A source matching a known vendor pattern is only ever a recognition signal -- it does not bypass any control until you explicitly authorise it below.', 'vcns-security-automation-manager' ); ?>
			</p>
		</div>

		<details class="wp-sam-filter-form">
			<summary><?php esc_html_e( 'Filters', 'vcns-security-automation-manager' ); ?></summary>
			<form method="get" action="">
				<input type="hidden" name="page" value="security-automation-manager-intelligence" />
				<input type="hidden" name="tab" value="identities" />
				<label>
					<?php esc_html_e( 'Surface', 'vcns-security-automation-manager' ); ?>
					<select name="id_surface">
						<option value=""><?php esc_html_e( 'Any', 'vcns-security-automation-manager' ); ?></option>
						<?php foreach ( $surfaces as $s ) : ?>
						<option value="<?php echo esc_attr( $s ); ?>" <?php selected( $id_surface, $s ); ?>><?php echo esc_html( ucfirst( $s ) ); ?></option>
						<?php endforeach; ?>
					</select>
				</label>
				<label>
					<?php esc_html_e( 'State', 'vcns-security-automation-manager' ); ?>
					<select name="id_state">
						<option value=""><?php esc_html_e( 'Any', 'vcns-security-automation-manager' ); ?></option>
						<?php foreach ( $states as $st ) : ?>
						<option value="<?php echo esc_attr( $st ); ?>" <?php selected( $id_state, $st ); ?>><?php echo esc_html( $state_labels[ $st ] ?? $st ); ?></option>
						<?php endforeach; ?>
					</select>
				</label>
				<label>
					<?php esc_html_e( 'IP contains', 'vcns-security-automation-manager' ); ?>
					<input type="text" name="id_ip" value="<?php echo esc_attr( $id_ip ); ?>" />
				</label>
				<?php submit_button( __( 'Filter', 'vcns-security-automation-manager' ), 'secondary', 'filter_identities', false ); ?>
			</form>
		</details>

		<table class="widefat fixed striped wp-sam-violations-table" style="margin-top:1em">
			<thead>
				<tr>
					<?php
					echo Table_Query::sort_header( __( 'Claimed Identity', 'vcns-security-automation-manager' ), 'identity', $sort_whitelist, $sort, $state_args, $base_url, 'id_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
					?>
					<th><?php esc_html_e( 'IP', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Surface', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Vendor Source', 'vcns-security-automation-manager' ); ?></th>
					<?php
					echo Table_Query::sort_header( __( 'State', 'vcns-security-automation-manager' ), 'state', $sort_whitelist, $sort, $state_args, $base_url, 'id_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
					echo Table_Query::sort_header( __( 'Occurrences', 'vcns-security-automation-manager' ), 'occurrences', $sort_whitelist, $sort, $state_args, $base_url, 'id_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
					echo Table_Query::sort_header( __( 'Last Seen', 'vcns-security-automation-manager' ), 'last_seen', $sort_whitelist, $sort, $state_args, $base_url, 'id_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
					?>
					<th><?php esc_html_e( 'Decision', 'vcns-security-automation-manager' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $identities as $row ) : ?>
				<?php
				$vendor_key = (string) $row['vendor_key'];
				$vendor     = $vendors_by_key[ $vendor_key ] ?? null;
				$state      = (string) $row['verification_state'];
				$is_decided = in_array( $state, Scanner_Identity_Store::DECISION_STATES, true );
				?>
			<tr>
				<td><?php echo esc_html( '' !== (string) $row['claimed_identity'] ? (string) $row['claimed_identity'] : __( '(unrecognised)', 'vcns-security-automation-manager' ) ); ?></td>
				<td><code><?php echo esc_html( (string) $row['ip'] ); ?></code></td>
				<td><?php echo esc_html( ucfirst( (string) $row['surface'] ) ); ?></td>
				<td>
					<?php if ( null !== $vendor && '' !== (string) $vendor['source_url'] ) : ?>
						<a href="<?php echo esc_url( (string) $vendor['source_url'] ); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Source', 'vcns-security-automation-manager' ); ?></a>
					<?php else : ?>
						&mdash;
					<?php endif; ?>
				</td>
				<td><?php echo esc_html( $state_labels[ $state ] ?? $state ); ?></td>
				<td><?php echo esc_html( number_format( (int) $row['occurrence_count'] ) ); ?></td>
				<td><?php echo esc_html( (string) $row['last_seen_at'] ); ?></td>
				<td>
					<?php if ( $is_decided ) : ?>
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline">
							<?php wp_nonce_field( 'wp_sam_scanner_identity_decide' ); ?>
							<input type="hidden" name="action" value="wp_sam_scanner_identity_decide" />
							<input type="hidden" name="identity_id" value="<?php echo esc_attr( (string) $row['id'] ); ?>" />
							<input type="hidden" name="decision" value="clear" />
							<input type="hidden" name="wp_sam_return_tab" value="identities" />
							<input type="text" name="note" placeholder="<?php esc_attr_e( 'Reason', 'vcns-security-automation-manager' ); ?>" required style="width:110px" />
							<?php submit_button( __( 'Clear decision', 'vcns-security-automation-manager' ), 'secondary small', '', false ); ?>
						</form>
					<?php else : ?>
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline-block">
							<?php wp_nonce_field( 'wp_sam_scanner_identity_decide' ); ?>
							<input type="hidden" name="action" value="wp_sam_scanner_identity_decide" />
							<input type="hidden" name="identity_id" value="<?php echo esc_attr( (string) $row['id'] ); ?>" />
							<input type="hidden" name="wp_sam_return_tab" value="identities" />
							<input type="text" name="note" placeholder="<?php esc_attr_e( 'Reason', 'vcns-security-automation-manager' ); ?>" required style="width:110px" />
							<button type="submit" name="decision" value="authorise" class="button button-primary button-small"><?php esc_html_e( 'Authorise', 'vcns-security-automation-manager' ); ?></button>
							<button type="submit" name="decision" value="deny" class="button button-small"><?php esc_html_e( 'Deny', 'vcns-security-automation-manager' ); ?></button>
						</form>
					<?php endif; ?>
				</td>
			</tr>
			<?php endforeach; ?>
			<?php if ( empty( $identities ) ) : ?>
			<tr>
				<td colspan="8"><p><?php esc_html_e( 'No identities recorded yet.', 'vcns-security-automation-manager' ); ?></p></td>
			</tr>
			<?php endif; ?>
			</tbody>
		</table>

		<?php echo Table_Query::pagination( $page_num, $pages, $state_args, $base_url, 'id_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>

	<?php elseif ( 'vendors' === $tab ) : ?>

		<?php
		$vendor_store    = new Scanner_Vendor_Store();
		$vendors         = $vendor_store->all();
		$category_labels = array(
			'known_commercial_scanner' => __( 'Known commercial scanner', 'vcns-security-automation-manager' ),
			'known_research_scanner'   => __( 'Known research scanner', 'vcns-security-automation-manager' ),
			'known_crawler'            => __( 'Known crawler', 'vcns-security-automation-manager' ),
			'custom'                   => __( 'Custom', 'vcns-security-automation-manager' ),
		);
		?>

		<table class="widefat fixed striped wp-sam-violations-table" style="margin-top:1em">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Vendor', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Category', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'UA pattern', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Verification', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Source', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Actions', 'vcns-security-automation-manager' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $vendors as $vendor ) : ?>
			<tr>
				<td>
					<?php echo esc_html( (string) $vendor['vendor_name'] ); ?>
					<?php if ( ! empty( $vendor['is_builtin'] ) ) : ?>
						<span class="description">(<?php esc_html_e( 'built-in', 'vcns-security-automation-manager' ); ?>)</span>
					<?php endif; ?>
				</td>
				<td><?php echo esc_html( $category_labels[ (string) $vendor['category'] ] ?? (string) $vendor['category'] ); ?></td>
				<td><code><?php echo esc_html( (string) $vendor['ua_pattern'] ); ?></code></td>
				<td><?php echo esc_html( (string) $vendor['verification_method'] ); ?></td>
				<td>
					<?php if ( '' !== (string) $vendor['source_url'] ) : ?>
						<a href="<?php echo esc_url( (string) $vendor['source_url'] ); ?>" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Link', 'vcns-security-automation-manager' ); ?></a>
					<?php else : ?>
						&mdash;
					<?php endif; ?>
				</td>
				<td>
					<?php if ( empty( $vendor['is_builtin'] ) ) : ?>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline">
						<?php wp_nonce_field( 'wp_sam_scanner_vendor_delete' ); ?>
						<input type="hidden" name="action" value="wp_sam_scanner_vendor_delete" />
						<input type="hidden" name="vendor_key" value="<?php echo esc_attr( (string) $vendor['vendor_key'] ); ?>" />
						<?php submit_button( __( 'Delete', 'vcns-security-automation-manager' ), 'link-delete small', '', false ); ?>
					</form>
					<?php else : ?>
						&mdash;
					<?php endif; ?>
				</td>
			</tr>
			<?php endforeach; ?>
			</tbody>
		</table>

		<h2 style="margin-top:2em"><?php esc_html_e( 'Add a vendor', 'vcns-security-automation-manager' ); ?></h2>
		<p class="description"><?php esc_html_e( 'A source URL is required so the record stays traceable to where the verification method came from.', 'vcns-security-automation-manager' ); ?></p>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="wp-sam-vendor-form">
			<?php wp_nonce_field( 'wp_sam_scanner_vendor_upsert' ); ?>
			<input type="hidden" name="action" value="wp_sam_scanner_vendor_upsert" />
			<table class="form-table">
				<tr>
					<th><label for="vendor_key"><?php esc_html_e( 'Key', 'vcns-security-automation-manager' ); ?></label></th>
					<td><input type="text" id="vendor_key" name="vendor_key" required pattern="[a-z0-9_-]+" placeholder="qualys" /></td>
				</tr>
				<tr>
					<th><label for="vendor_name"><?php esc_html_e( 'Name', 'vcns-security-automation-manager' ); ?></label></th>
					<td><input type="text" id="vendor_name" name="vendor_name" required placeholder="Qualys" /></td>
				</tr>
				<tr>
					<th><label for="category"><?php esc_html_e( 'Category', 'vcns-security-automation-manager' ); ?></label></th>
					<td>
						<select id="category" name="category">
							<?php foreach ( $category_labels as $cat_key => $cat_label ) : ?>
							<option value="<?php echo esc_attr( $cat_key ); ?>"><?php echo esc_html( $cat_label ); ?></option>
							<?php endforeach; ?>
						</select>
					</td>
				</tr>
				<tr>
					<th><label for="ua_pattern"><?php esc_html_e( 'User-Agent contains', 'vcns-security-automation-manager' ); ?></label></th>
					<td><input type="text" id="ua_pattern" name="ua_pattern" placeholder="QualysGuard" /></td>
				</tr>
				<tr>
					<th><label for="verification_method"><?php esc_html_e( 'Verification method', 'vcns-security-automation-manager' ); ?></label></th>
					<td>
						<select id="verification_method" name="verification_method">
							<option value="none"><?php esc_html_e( 'None', 'vcns-security-automation-manager' ); ?></option>
							<option value="cidr"><?php esc_html_e( 'Published CIDR ranges', 'vcns-security-automation-manager' ); ?></option>
							<option value="fcrdns"><?php esc_html_e( 'Forward-confirmed reverse DNS', 'vcns-security-automation-manager' ); ?></option>
						</select>
					</td>
				</tr>
				<tr>
					<th><label for="cidr_ranges"><?php esc_html_e( 'CIDR ranges (one per line)', 'vcns-security-automation-manager' ); ?></label></th>
					<td><textarea id="cidr_ranges" name="cidr_ranges" rows="3" style="width:100%;max-width:400px" placeholder="64.39.96.0/20"></textarea></td>
				</tr>
				<tr>
					<th><label for="rdns_suffixes"><?php esc_html_e( 'rDNS hostname suffixes (one per line)', 'vcns-security-automation-manager' ); ?></label></th>
					<td><textarea id="rdns_suffixes" name="rdns_suffixes" rows="3" style="width:100%;max-width:400px" placeholder="qualys.com"></textarea></td>
				</tr>
				<tr>
					<th><label for="source_url"><?php esc_html_e( 'Source URL', 'vcns-security-automation-manager' ); ?></label></th>
					<td><input type="url" id="source_url" name="source_url" required style="width:100%;max-width:400px" placeholder="https://..." /></td>
				</tr>
				<tr>
					<th><label for="notes"><?php esc_html_e( 'Notes', 'vcns-security-automation-manager' ); ?></label></th>
					<td><textarea id="notes" name="notes" rows="2" style="width:100%;max-width:400px"></textarea></td>
				</tr>
			</table>
			<?php submit_button( __( 'Add vendor', 'vcns-security-automation-manager' ) ); ?>
		</form>

	<?php endif; ?>
</div>
