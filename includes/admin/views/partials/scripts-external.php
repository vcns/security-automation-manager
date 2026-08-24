<?php
/**
 * "External" tab of the Scripts page -- third-party <script>/<link
 * rel=stylesheet> origin inventory, classification, and Subresource
 * Integrity. Formerly the standalone page-external-scripts.php.
 *
 * Included by page-scripts.php; $wpdb and $surfaces are already in scope.
 * Note: PHP `use` imports are per-file, not inherited through require() --
 * page-scripts.php's own `use` statements do not extend to this file, so it
 * needs its own.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WP_SAM\Admin\Table_Query;
use WP_SAM\Security\Dependency_Governance_Builder;

// ── Per-surface enabled + mode ──────────────────────────────────────────────
$profiles_raw = $wpdb->get_results(
	$wpdb->prepare(
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		"SELECT surface, enabled, payload FROM {$wpdb->prefix}sam_pillar_profiles WHERE pillar = %s",
		Dependency_Governance_Builder::PILLAR_KEY
	),
	ARRAY_A
);

$state_by_surface = array();
foreach ( ! empty( $profiles_raw ) ? $profiles_raw : array() as $row ) {
	$state_by_surface[ $row['surface'] ] = array(
		'enabled' => ! empty( $row['enabled'] ),
		'mode'    => Dependency_Governance_Builder::extract_mode( $row ),
	);
}

// ── Inventory filters, sort, pagination ─────────────────────────────────────
$ext_surface        = Table_Query::text_param( 'ext_surface' );
$ext_type           = Table_Query::text_param( 'ext_type' );
$ext_classification = Table_Query::text_param( 'ext_classification' );
$ext_origin         = Table_Query::text_param( 'ext_origin' );

$ext_where = array( '1=1' );
$ext_args  = array();
foreach (
	array(
		Table_Query::equals_where( 'surface', $ext_surface ),
		Table_Query::equals_where( 'resource_type', $ext_type ),
		Table_Query::equals_where( 'classification', $ext_classification ),
		Table_Query::like_where( $wpdb, 'origin', $ext_origin ),
	) as $fragment
) {
	if ( null !== $fragment ) {
		$ext_where[] = $fragment['sql'];
		$ext_args    = array_merge( $ext_args, $fragment['args'] );
	}
}

$ext_sort_whitelist = array(
	'last_seen' => array(
		'expr'        => 'last_seen_at',
		'default_dir' => 'desc',
	),
	'evidence'  => array(
		'expr'        => 'evidence_count',
		'default_dir' => 'desc',
	),
	'origin'    => array(
		'expr'        => 'origin',
		'default_dir' => 'asc',
	),
);
$ext_sort           = Table_Query::resolve_sort(
	$ext_sort_whitelist,
	'last_seen',
	isset( $_GET['ext_sort'] ) ? sanitize_text_field( wp_unslash( $_GET['ext_sort'] ) ) : null,
	isset( $_GET['ext_dir'] ) ? sanitize_text_field( wp_unslash( $_GET['ext_dir'] ) ) : null
);

$ext_per_page = 20;
$ext_page_num = max( 1, (int) ( $_GET['ext_paged'] ?? 1 ) );
$ext_offset   = ( $ext_page_num - 1 ) * $ext_per_page;

$ext_table     = $wpdb->prefix . 'sam_dependency_inventory';
$ext_where_sql = implode( ' AND ', $ext_where );

$ext_count_sql = "SELECT COUNT(*) FROM {$ext_table} WHERE {$ext_where_sql}";
if ( ! empty( $ext_args ) ) {
	// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	$ext_count_sql = $wpdb->prepare( $ext_count_sql, ...$ext_args );
}
// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
$ext_total = (int) $wpdb->get_var( $ext_count_sql );
$ext_pages = max( 1, (int) ceil( $ext_total / $ext_per_page ) );

$ext_data_args = array_merge( $ext_args, array( $ext_per_page, $ext_offset ) );
$ext_data_sql  = "SELECT * FROM {$ext_table} WHERE {$ext_where_sql} " . Table_Query::order_by_sql( $ext_sort ) . ' LIMIT %d OFFSET %d';
// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
$ext_data_sql = $wpdb->prepare( $ext_data_sql, ...$ext_data_args );
// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
$inventory_raw = $wpdb->get_results( $ext_data_sql, ARRAY_A );
$inventory     = ! empty( $inventory_raw ) ? $inventory_raw : array();

$ext_state_args = array_filter(
	array(
		'tab'                => 'external',
		'sort'               => $ext_sort['key'],
		'dir'                => strtolower( $ext_sort['dir'] ),
		'ext_surface'        => $ext_surface,
		'ext_type'           => $ext_type,
		'ext_classification' => $ext_classification,
		'ext_origin'         => $ext_origin,
	)
);

$ext_base_url = admin_url( 'admin.php?page=security-automation-manager-scripts' );

// 'first_party' is deliberately excluded: it's never stored in the inventory
// at all (the builder skips first-party origins before they're recorded), so
// it's not a classification an administrator ever needs to pick or filter by.
$classification_labels = array(
	'unclassified'     => __( 'Unclassified', 'vcns-security-automation-manager' ),
	'immutable_pinned' => __( 'Approved -- immutable (SRI)', 'vcns-security-automation-manager' ),
	'mutable_provider' => __( 'Approved -- mutable provider (no SRI)', 'vcns-security-automation-manager' ),
	'exception'        => __( 'Exception', 'vcns-security-automation-manager' ),
	'prohibited'       => __( 'Blocked', 'vcns-security-automation-manager' ),
);
?>
<div class="notice notice-warning inline" style="padding:12px 16px;margin:1em 0;">
	<p style="margin-top:0;">
		<?php esc_html_e( 'This plugin never fabricates a Subresource Integrity hash. "Approved -- immutable" only ever compares against a hash you paste in yourself -- from a local copy of the file you already trust, or the vendor\'s own published hash -- never one computed by fetching the remote URL.', 'vcns-security-automation-manager' ); ?>
	</p>
	<p style="margin-bottom:0;">
		<?php esc_html_e( 'Report mode (the default) never removes anything -- it only builds the inventory below. Enforce mode still only ever removes an origin you explicitly marked Blocked, or an "immutable" origin whose SRI hash no longer matches what the page actually served; an Unclassified origin is never silently blocked, even in enforce mode.', 'vcns-security-automation-manager' ); ?>
	</p>
</div>

<table class="widefat striped wp-sam-readiness-table" style="margin-top: 1em;">
	<thead>
		<tr>
			<th><?php esc_html_e( 'Surface', 'vcns-security-automation-manager' ); ?></th>
			<th><?php esc_html_e( 'Enabled', 'vcns-security-automation-manager' ); ?></th>
			<th><?php esc_html_e( 'Mode', 'vcns-security-automation-manager' ); ?></th>
		</tr>
	</thead>
	<tbody>
		<?php foreach ( $surfaces as $surface ) : ?>
			<?php
			$current = $state_by_surface[ $surface ] ?? array(
				'enabled' => false,
				'mode'    => 'report',
			);
			?>
			<tr>
				<td><?php echo esc_html( ucfirst( $surface ) ); ?></td>
				<td>
					<input
						type="checkbox"
						class="wp-sam-dependency-enabled"
						data-surface="<?php echo esc_attr( $surface ); ?>"
						<?php checked( $current['enabled'] ); ?>
					/>
				</td>
				<td>
					<select class="wp-sam-dependency-mode" data-surface="<?php echo esc_attr( $surface ); ?>">
						<option value="report" <?php selected( $current['mode'], 'report' ); ?>><?php esc_html_e( 'Report only', 'vcns-security-automation-manager' ); ?></option>
						<option value="enforce" <?php selected( $current['mode'], 'enforce' ); ?>><?php esc_html_e( 'Enforce', 'vcns-security-automation-manager' ); ?></option>
					</select>
				</td>
			</tr>
		<?php endforeach; ?>
	</tbody>
</table>

<h2 class="title" style="margin-top:1.5em"><?php esc_html_e( 'Inventory', 'vcns-security-automation-manager' ); ?></h2>

<details class="wp-sam-filter-form">
	<summary><?php esc_html_e( 'Filters', 'vcns-security-automation-manager' ); ?></summary>
	<form method="get" action="">
		<input type="hidden" name="page" value="security-automation-manager-scripts" />
		<input type="hidden" name="tab" value="external" />
		<label>
			<?php esc_html_e( 'Surface', 'vcns-security-automation-manager' ); ?>
			<select name="ext_surface">
				<option value=""><?php esc_html_e( 'Any', 'vcns-security-automation-manager' ); ?></option>
				<?php foreach ( $surfaces as $s ) : ?>
				<option value="<?php echo esc_attr( $s ); ?>" <?php selected( $ext_surface, $s ); ?>><?php echo esc_html( ucfirst( $s ) ); ?></option>
				<?php endforeach; ?>
			</select>
		</label>
		<label>
			<?php esc_html_e( 'Type', 'vcns-security-automation-manager' ); ?>
			<select name="ext_type">
				<option value=""><?php esc_html_e( 'Any', 'vcns-security-automation-manager' ); ?></option>
				<option value="script" <?php selected( $ext_type, 'script' ); ?>><?php esc_html_e( 'Script', 'vcns-security-automation-manager' ); ?></option>
				<option value="style" <?php selected( $ext_type, 'style' ); ?>><?php esc_html_e( 'Stylesheet', 'vcns-security-automation-manager' ); ?></option>
			</select>
		</label>
		<label>
			<?php esc_html_e( 'Classification', 'vcns-security-automation-manager' ); ?>
			<select name="ext_classification">
				<option value=""><?php esc_html_e( 'Any', 'vcns-security-automation-manager' ); ?></option>
				<?php foreach ( $classification_labels as $value => $label ) : ?>
				<option value="<?php echo esc_attr( $value ); ?>" <?php selected( $ext_classification, $value ); ?>><?php echo esc_html( $label ); ?></option>
				<?php endforeach; ?>
			</select>
		</label>
		<label>
			<?php esc_html_e( 'Origin contains', 'vcns-security-automation-manager' ); ?>
			<input type="text" name="ext_origin" placeholder="<?php esc_attr_e( 'e.g. googletagmanager.com', 'vcns-security-automation-manager' ); ?>" value="<?php echo esc_attr( $ext_origin ); ?>" />
		</label>
		<?php submit_button( __( 'Filter', 'vcns-security-automation-manager' ), 'secondary', 'filter_external_scripts', false ); ?>
	</form>
</details>

<table class="widefat fixed striped wp-sam-dependency-inventory-table" style="margin-top:1em">
	<thead>
		<tr>
			<th><?php esc_html_e( 'Surface', 'vcns-security-automation-manager' ); ?></th>
			<th><?php esc_html_e( 'Type', 'vcns-security-automation-manager' ); ?></th>
			<?php echo Table_Query::sort_header( __( 'Origin', 'vcns-security-automation-manager' ), 'origin', $ext_sort_whitelist, $ext_sort, $ext_state_args, $ext_base_url, 'ext_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
			<th><?php esc_html_e( 'Classification', 'vcns-security-automation-manager' ); ?></th>
			<th><?php esc_html_e( 'Expected SRI', 'vcns-security-automation-manager' ); ?></th>
			<?php echo Table_Query::sort_header( __( 'Evidence', 'vcns-security-automation-manager' ), 'evidence', $ext_sort_whitelist, $ext_sort, $ext_state_args, $ext_base_url, 'ext_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
			<?php echo Table_Query::sort_header( __( 'Last Seen', 'vcns-security-automation-manager' ), 'last_seen', $ext_sort_whitelist, $ext_sort, $ext_state_args, $ext_base_url, 'ext_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
		</tr>
	</thead>
	<tbody>
		<?php foreach ( $inventory as $item ) : ?>
			<tr data-id="<?php echo esc_attr( (string) $item['id'] ); ?>">
				<td><?php echo esc_html( ucfirst( $item['surface'] ) ); ?></td>
				<td><?php echo esc_html( 'script' === $item['resource_type'] ? __( 'Script', 'vcns-security-automation-manager' ) : __( 'Stylesheet', 'vcns-security-automation-manager' ) ); ?></td>
				<td>
					<code><?php echo esc_html( $item['origin'] ); ?></code>
					<?php if ( ! empty( $item['last_seen_url'] ) ) : ?>
					<span class="dashicons dashicons-info-outline wp-sam-meta-icon" tabindex="0">
						<span class="wp-sam-meta-popover" role="tooltip">
							<div class="wp-sam-meta-row">
								<strong><?php esc_html_e( 'Last seen URL', 'vcns-security-automation-manager' ); ?>:</strong>
								<code><?php echo esc_html( (string) $item['last_seen_url'] ); ?></code>
							</div>
						</span>
					</span>
					<?php endif; ?>
				</td>
				<td>
					<select class="wp-sam-dependency-classification" data-id="<?php echo esc_attr( (string) $item['id'] ); ?>">
						<?php foreach ( $classification_labels as $value => $label ) : ?>
						<option value="<?php echo esc_attr( $value ); ?>" <?php selected( $item['classification'], $value ); ?>><?php echo esc_html( $label ); ?></option>
						<?php endforeach; ?>
					</select>
				</td>
				<td>
					<input
						type="text"
						class="wp-sam-dependency-sri"
						data-id="<?php echo esc_attr( (string) $item['id'] ); ?>"
						placeholder="sha384-…"
						style="width:100%"
						value="<?php echo esc_attr( $item['expected_sri'] ?? '' ); ?>"
						<?php disabled( 'immutable_pinned' !== $item['classification'] ); ?>
					/>
					<div class="wp-sam-dependency-suggest" style="margin-top:4px;display:flex;gap:4px;">
						<input
							type="url"
							class="wp-sam-dependency-suggest-url"
							placeholder="<?php esc_attr_e( 'https://exact/script/url to hash & pin', 'vcns-security-automation-manager' ); ?>"
							style="flex:1;font-size:11px"
							value="<?php echo esc_attr( (string) ( $item['last_seen_url'] ?? '' ) ); ?>"
							<?php disabled( 'immutable_pinned' !== $item['classification'] ); ?>
						/>
						<button
							type="button"
							class="button button-small wp-sam-dependency-suggest-button"
							data-id="<?php echo esc_attr( (string) $item['id'] ); ?>"
							<?php disabled( 'immutable_pinned' !== $item['classification'] ); ?>
						><?php esc_html_e( 'Suggest', 'vcns-security-automation-manager' ); ?></button>
					</div>
				</td>
				<td><?php echo esc_html( (string) $item['evidence_count'] ); ?></td>
				<td><?php echo esc_html( $item['last_seen_at'] ); ?></td>
			</tr>
		<?php endforeach; ?>
		<?php if ( empty( $inventory ) ) : ?>
		<tr>
			<td colspan="7"><?php esc_html_e( 'No third-party scripts or stylesheets have been observed yet. Enable a surface above and browse the live site to build the inventory.', 'vcns-security-automation-manager' ); ?></td>
		</tr>
		<?php endif; ?>
	</tbody>
</table>

<?php echo Table_Query::pagination( $ext_page_num, $ext_pages, $ext_state_args, $ext_base_url, 'ext_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
