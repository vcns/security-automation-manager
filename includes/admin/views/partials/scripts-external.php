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
use WP_SAM\Security\Dependency_Sri_Fetcher;
use WP_SAM\Security\Known_Vendor_Profiles;

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

// Cap at $ext_pages (not just floored at 1) -- every other Table_Query-driven
// table in this codebase clamps its page number the same way; this one didn't,
// so ?ext_paged=9999 against a 3-page result set rendered "Page 9999 of 3"
// instead of serving (and reporting) the real last page.
$ext_page_num = min( max( 1, (int) ( $_GET['ext_paged'] ?? 1 ) ), $ext_pages );
$ext_offset   = ( $ext_page_num - 1 ) * $ext_per_page;

$ext_data_args = array_merge( $ext_args, array( $ext_per_page, $ext_offset ) );
// A pinned file that changed at its source is already failing for
// visitors, so drifted rows always sort to the top of the first page --
// that is where the drift recommendation and admin notice send people.
$ext_order_sql = str_replace( 'ORDER BY ', "ORDER BY ( classification = 'immutable_pinned' AND drift_detected_at IS NOT NULL ) DESC, ", Table_Query::order_by_sql( $ext_sort ) );
$ext_data_sql  = "SELECT * FROM {$ext_table} WHERE {$ext_where_sql} {$ext_order_sql} LIMIT %d OFFSET %d";
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

$check_error_labels = array(
	Dependency_Sri_Fetcher::ERROR_NO_URL          => __( 'no URL recorded for this file', 'vcns-security-automation-manager' ),
	Dependency_Sri_Fetcher::ERROR_NOT_HTTPS       => __( 'not an https:// URL', 'vcns-security-automation-manager' ),
	Dependency_Sri_Fetcher::ERROR_ORIGIN_MISMATCH => __( 'URL is not on this row\'s origin', 'vcns-security-automation-manager' ),
	Dependency_Sri_Fetcher::ERROR_FETCH_FAILED    => __( 'request failed', 'vcns-security-automation-manager' ),
	Dependency_Sri_Fetcher::ERROR_HTTP_STATUS     => __( 'server did not return 200 OK', 'vcns-security-automation-manager' ),
	Dependency_Sri_Fetcher::ERROR_EMPTY_OR_LARGE  => __( 'empty or larger than 5 MB', 'vcns-security-automation-manager' ),
);
?>
<div class="notice notice-warning inline" style="padding:12px 16px;margin:1em 0;">
	<p style="margin-top:0;">
		<?php esc_html_e( 'Nothing is pinned without your click. "Approved -- immutable" compares against a hash you choose: one you paste in (from a local copy of the file you trust, or the vendor\'s published hash), or one "Suggest" computes by fetching the exact URL you confirm. SAM also re-fetches each pinned file once a day and compares it with your hash; if the vendor has changed the file, this table flags it for you to re-approve or allow by host instead. A fetched hash is only ever suggested or compared, never approved on its own.', 'vcns-security-automation-manager' ); ?>
	</p>
	<p>
		<?php esc_html_e( 'SAM never adds an integrity attribute to your pages. The integrity attribute that browsers enforce comes from the theme or plugin markup that loads the file, so when a pinned hash changes, that markup has to be updated to the same value.', 'vcns-security-automation-manager' ); ?>
	</p>
	<p style="margin-bottom:0;">
		<?php esc_html_e( 'Report mode (the default) never removes anything -- it only builds the inventory below. Enforce mode still only ever removes an origin you explicitly marked Blocked, or an "immutable" origin whose SRI hash no longer matches what the page actually served; an Unclassified origin is never silently blocked, even in enforce mode.', 'vcns-security-automation-manager' ); ?>
	</p>
</div>

<div class="wp-sam-table-wrap">
<table class="widefat striped wp-sam-table wp-sam-readiness-table" style="margin-top: 1em;">
	<thead>
		<tr>
			<th class="wp-sam-col-surface"><?php esc_html_e( 'Surface', 'vcns-security-automation-manager' ); ?></th>
			<th class="wp-sam-col-status"><?php esc_html_e( 'Enabled', 'vcns-security-automation-manager' ); ?></th>
			<th class="wp-sam-col-technical"><?php esc_html_e( 'Mode', 'vcns-security-automation-manager' ); ?></th>
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
				<td class="wp-sam-col-surface"><?php echo esc_html( ucfirst( $surface ) ); ?></td>
				<td class="wp-sam-col-status">
					<input
						type="checkbox"
						class="wp-sam-dependency-enabled"
						data-surface="<?php echo esc_attr( $surface ); ?>"
						<?php checked( $current['enabled'] ); ?>
					/>
				</td>
				<td class="wp-sam-col-technical">
					<select class="wp-sam-dependency-mode" data-surface="<?php echo esc_attr( $surface ); ?>">
						<option value="report" <?php selected( $current['mode'], 'report' ); ?>><?php esc_html_e( 'Report only', 'vcns-security-automation-manager' ); ?></option>
						<option value="enforce" <?php selected( $current['mode'], 'enforce' ); ?>><?php esc_html_e( 'Enforce', 'vcns-security-automation-manager' ); ?></option>
					</select>
				</td>
			</tr>
		<?php endforeach; ?>
	</tbody>
</table>
</div>

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

<div class="wp-sam-table-wrap">
<table class="widefat striped wp-sam-table wp-sam-dependency-inventory-table" style="margin-top:1em">
	<thead>
		<tr>
			<th class="wp-sam-col-surface"><?php esc_html_e( 'Surface', 'vcns-security-automation-manager' ); ?></th>
			<th class="wp-sam-col-compact"><?php esc_html_e( 'Type', 'vcns-security-automation-manager' ); ?></th>
			<?php echo Table_Query::sort_header( __( 'Origin', 'vcns-security-automation-manager' ), 'origin', $ext_sort_whitelist, $ext_sort, $ext_state_args, $ext_base_url, 'ext_paged', 'wp-sam-col-technical' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
			<th class="wp-sam-col-status"><?php esc_html_e( 'Classification', 'vcns-security-automation-manager' ); ?></th>
			<th class="wp-sam-col-technical"><?php esc_html_e( 'Expected SRI', 'vcns-security-automation-manager' ); ?></th>
			<?php echo Table_Query::sort_header( __( 'Evidence', 'vcns-security-automation-manager' ), 'evidence', $ext_sort_whitelist, $ext_sort, $ext_state_args, $ext_base_url, 'ext_paged', 'wp-sam-col-count' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
			<?php echo Table_Query::sort_header( __( 'Last Seen', 'vcns-security-automation-manager' ), 'last_seen', $ext_sort_whitelist, $ext_sort, $ext_state_args, $ext_base_url, 'ext_paged', 'wp-sam-col-datetime' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
		</tr>
	</thead>
	<tbody>
		<?php foreach ( $inventory as $item ) : ?>
			<?php
			$vendor     = Known_Vendor_Profiles::match( (string) $item['origin'], (string) ( $item['last_seen_url'] ?? '' ), (string) $item['resource_type'] );
			$is_pinned  = 'immutable_pinned' === $item['classification'];
			$is_drifted = $is_pinned && ! empty( $item['drift_detected_at'] ) && ! empty( $item['drift_observed_sri'] );
			?>
			<tr data-id="<?php echo esc_attr( (string) $item['id'] ); ?>"<?php echo $is_drifted ? ' class="wp-sam-dependency-drifted"' : ''; ?>>
				<td class="wp-sam-col-surface"><?php echo esc_html( ucfirst( $item['surface'] ) ); ?></td>
				<td class="wp-sam-col-compact"><?php echo esc_html( 'script' === $item['resource_type'] ? __( 'Script', 'vcns-security-automation-manager' ) : __( 'Stylesheet', 'vcns-security-automation-manager' ) ); ?></td>
				<td class="wp-sam-col-technical">
					<code><?php echo esc_html( $item['origin'] ); ?></code>
					<?php if ( ! empty( $item['last_seen_url'] ) ) : ?>
					<span class="wp-sam-meta-icon" tabindex="0"><span class="dashicons dashicons-info-outline" aria-hidden="true"></span>
						<span class="wp-sam-meta-popover" role="tooltip">
							<div class="wp-sam-meta-row">
								<strong><?php esc_html_e( 'Last seen URL', 'vcns-security-automation-manager' ); ?>:</strong>
								<code><?php echo esc_html( (string) $item['last_seen_url'] ); ?></code>
							</div>
						</span>
					</span>
					<?php endif; ?>
					<?php if ( null !== $vendor ) : ?>
					<span class="wp-sam-known-source-badge" tabindex="0">
						<?php
						printf(
							/* translators: %s: vendor name, e.g. "Google Tag Manager" */
							esc_html__( 'Known vendor: %s -- allowed by host, not hash', 'vcns-security-automation-manager' ),
							esc_html( $vendor['vendor'] )
						);
						?>
						<span class="wp-sam-meta-popover" role="tooltip"><?php echo esc_html( $vendor['reason'] ); ?></span>
					</span>
						<?php if ( 'immutable_pinned' === $item['classification'] ) : ?>
					<p class="description" style="color:#996800;margin:4px 0 0;">
							<?php esc_html_e( 'This vendor changes its files routinely, so a pinned hash will keep breaking. Consider "Approved -- mutable provider" instead.', 'vcns-security-automation-manager' ); ?>
							<button type="button" class="button button-small wp-sam-dependency-allow-host"><?php esc_html_e( 'Allow by host', 'vcns-security-automation-manager' ); ?></button>
					</p>
						<?php elseif ( 'unclassified' === $item['classification'] ) : ?>
					<p class="description" style="margin:4px 0 0;">
							<?php esc_html_e( 'Recommended: "Approved -- mutable provider".', 'vcns-security-automation-manager' ); ?>
							<button type="button" class="button button-small wp-sam-dependency-allow-host"><?php esc_html_e( 'Allow by host', 'vcns-security-automation-manager' ); ?></button>
					</p>
						<?php endif; ?>
					<?php endif; ?>
				</td>
				<td class="wp-sam-col-status">
					<select class="wp-sam-dependency-classification" data-id="<?php echo esc_attr( (string) $item['id'] ); ?>">
						<?php foreach ( $classification_labels as $value => $label ) : ?>
						<option value="<?php echo esc_attr( $value ); ?>" <?php selected( $item['classification'], $value ); ?>><?php echo esc_html( $label ); ?></option>
						<?php endforeach; ?>
					</select>
				</td>
				<td class="wp-sam-col-technical">
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
					<?php if ( $is_drifted ) : ?>
					<div class="notice notice-error inline wp-sam-dependency-drift" style="margin:8px 0 0;padding:8px 10px;">
						<p style="margin:0 0 4px;"><strong><?php esc_html_e( 'This file has changed at its source.', 'vcns-security-automation-manager' ); ?></strong>
						<?php
						printf(
							/* translators: %s: date/time (UTC) the change was first detected */
							esc_html__( 'First detected %s UTC. Browsers enforcing the integrity attribute are refusing to load it.', 'vcns-security-automation-manager' ),
							esc_html( (string) $item['drift_detected_at'] )
						);
						?>
						</p>
						<p style="margin:0;font-size:11px;"><?php esc_html_e( 'Pinned:', 'vcns-security-automation-manager' ); ?> <code style="word-break:break-all;"><?php echo esc_html( (string) $item['expected_sri'] ); ?></code></p>
						<p style="margin:0;font-size:11px;"><?php esc_html_e( 'Now served:', 'vcns-security-automation-manager' ); ?> <code style="word-break:break-all;"><?php echo esc_html( (string) $item['drift_observed_sri'] ); ?></code>
							<button type="button" class="button button-small wp-sam-copy-value" data-value="<?php echo esc_attr( (string) $item['drift_observed_sri'] ); ?>" data-copied-label="<?php esc_attr_e( 'Copied', 'vcns-security-automation-manager' ); ?>"><?php esc_html_e( 'Copy', 'vcns-security-automation-manager' ); ?></button>
						</p>
						<?php if ( ! empty( $item['pinned_url'] ) ) : ?>
						<p style="margin:0;font-size:11px;"><?php esc_html_e( 'File checked:', 'vcns-security-automation-manager' ); ?> <code style="word-break:break-all;"><?php echo esc_html( (string) $item['pinned_url'] ); ?></code></p>
						<?php endif; ?>
						<p class="description" style="margin:6px 0;">
							<?php esc_html_e( 'Re-approving updates the hash SAM expects. You also need to change the integrity attribute in the theme or plugin markup that loads this file to the new value above, or browsers will keep blocking it.', 'vcns-security-automation-manager' ); ?>
							<?php if ( null !== $vendor ) : ?>
								<?php
								printf(
									/* translators: %s: vendor name */
									esc_html__( '%s changes this file routinely, so allowing it by host is usually the better fix.', 'vcns-security-automation-manager' ),
									esc_html( $vendor['vendor'] )
								);
								?>
							<?php endif; ?>
						</p>
						<p class="wp-sam-dependency-drift-actions" style="margin:0;display:flex;gap:6px;flex-wrap:wrap;">
							<button type="button" class="button button-primary button-small wp-sam-dependency-reapprove" data-id="<?php echo esc_attr( (string) $item['id'] ); ?>"><?php esc_html_e( 'Re-approve new hash', 'vcns-security-automation-manager' ); ?></button>
							<button type="button" class="button button-small wp-sam-dependency-allow-host"><?php esc_html_e( 'Allow by host instead', 'vcns-security-automation-manager' ); ?></button>
						</p>
						<p class="wp-sam-dependency-drift-done" hidden style="margin:6px 0 0;">
							<strong><?php esc_html_e( 'New hash approved in SAM.', 'vcns-security-automation-manager' ); ?></strong>
							<?php esc_html_e( 'Now update the integrity attribute in your markup to the value above.', 'vcns-security-automation-manager' ); ?>
						</p>
					</div>
					<?php elseif ( $is_pinned && ! empty( $item['integrity_check_error'] ) ) : ?>
					<p class="description" style="margin:6px 0 0;">
						<?php
						printf(
							/* translators: 1: date/time (UTC) of the last attempt, 2: short reason code */
							esc_html__( 'Daily check could not fetch this file (last tried %1$s UTC: %2$s). This is not treated as a change.', 'vcns-security-automation-manager' ),
							esc_html( (string) $item['integrity_attempted_at'] ),
							esc_html( $check_error_labels[ (string) $item['integrity_check_error'] ] ?? (string) $item['integrity_check_error'] )
						);
						?>
					</p>
					<?php elseif ( $is_pinned && ! empty( $item['integrity_checked_at'] ) ) : ?>
					<p class="description" style="margin:6px 0 0;">
						<?php
						printf(
							/* translators: %s: date/time (UTC) of the last successful check */
							esc_html__( 'File still matches this hash (checked %s UTC).', 'vcns-security-automation-manager' ),
							esc_html( (string) $item['integrity_checked_at'] )
						);
						?>
					</p>
					<?php endif; ?>
				</td>
				<td class="wp-sam-col-count"><?php echo esc_html( (string) $item['evidence_count'] ); ?></td>
				<td class="wp-sam-col-datetime"><?php echo esc_html( $item['last_seen_at'] ); ?></td>
			</tr>
		<?php endforeach; ?>
		<?php if ( empty( $inventory ) ) : ?>
		<tr>
			<td colspan="7"><?php esc_html_e( 'No third-party scripts or stylesheets have been observed yet. Enable a surface above and browse the live site to build the inventory.', 'vcns-security-automation-manager' ); ?></td>
		</tr>
		<?php endif; ?>
	</tbody>
</table>
</div>

<?php echo Table_Query::pagination( $ext_page_num, $ext_pages, $ext_state_args, $ext_base_url, 'ext_paged' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
