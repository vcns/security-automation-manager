<?php
/**
 * Admin view: Continuous Intelligence -- Layer 3 of the roadmap's five
 * protection layers. Shows whatever the Request Observation Framework has
 * recorded in sam_request_events, using the same Table_Query sort/filter/
 * pagination conventions as the CSP Violations and Cross-Origin Report-Only
 * Evidence tabs.
 *
 * Phase 3B ships the observation/classification skeleton only -- no
 * detector is registered in this build (see Detector_Registry's own
 * docblock), so this page's table is empty on every fresh install and stays
 * that way until Phase 3C (or an extension) registers a real detector. The
 * empty state says so plainly rather than implying something is broken.
 *
 * Rendered by Admin_UI::render_intelligence().
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WP_SAM\Admin\Table_Query;

global $wpdb;

$base_url   = admin_url( 'admin.php?page=security-automation-manager-intelligence' );
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
	isset( $_GET['isort'] ) ? sanitize_text_field( wp_unslash( $_GET['isort'] ) ) : null, // phpcs:ignore WordPress.Security.NonceVerification.Recommended
	isset( $_GET['idir'] ) ? sanitize_text_field( wp_unslash( $_GET['idir'] ) ) : null // phpcs:ignore WordPress.Security.NonceVerification.Recommended
);

$state_args = array_filter(
	array(
		'isort'       => $sort['key'],
		'idir'        => strtolower( $sort['dir'] ),
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
<div class="wrap wp-sam-wrap">
	<h1><?php esc_html_e( 'Continuous Intelligence', 'vcns-security-automation-manager' ); ?></h1>

	<p>
		<?php esc_html_e( 'Layer 3 of this plugin\'s protection model: request observation and classification, independent of the enforced header policies above.', 'vcns-security-automation-manager' ); ?>
	</p>

	<?php if ( 0 === $detector_count ) : ?>
	<div class="notice notice-info inline" style="padding:12px 16px;margin:1em 0;">
		<p style="margin-top:0;">
			<?php esc_html_e( 'No detectors are registered yet. Requests are observed and classified, but nothing is currently evaluated against them, so this table stays empty. Detector families are planned for a future phase.', 'vcns-security-automation-manager' ); ?>
		</p>
	</div>
	<?php endif; ?>

	<details class="wp-sam-filter-form">
		<summary><?php esc_html_e( 'Filters', 'vcns-security-automation-manager' ); ?></summary>
		<form method="get" action="">
			<input type="hidden" name="page" value="security-automation-manager-intelligence" />
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
				<p><?php esc_html_e( 'No events recorded -- no detectors are registered yet. Planned for a future phase.', 'vcns-security-automation-manager' ); ?></p>
				<?php endif; ?>
			</td>
		</tr>
		<?php endif; ?>
		</tbody>
	</table>

	<?php echo Table_Query::pagination( $page_num, $pages, $state_args, $base_url, 'i_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
</div>
