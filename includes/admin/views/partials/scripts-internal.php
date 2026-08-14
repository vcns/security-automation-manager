<?php
/**
 * "Internal" tab of the Scripts page -- per-surface on/off for first-party
 * Subresource Integrity, and a read-only inventory of what's currently being
 * hashed. There is nothing to classify or approve here (unlike External):
 * the hash is always freshly computed from the exact file being served, so
 * it can never legitimately drift from what's on disk the way an
 * admin-declared third-party hash can.
 *
 * Included by page-scripts.php; $wpdb and $surfaces are already in scope.
 * Note: PHP `use` imports are per-file, not inherited through require() --
 * page-scripts.php's own `use` statements do not extend to this file, so it
 * needs its own.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WP_SAM\Security\Internal_Script_Integrity_Builder;

// ── Per-surface enabled ──────────────────────────────────────────────────────
$int_profiles_raw = $wpdb->get_results(
	$wpdb->prepare(
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		"SELECT surface, enabled FROM {$wpdb->prefix}sam_pillar_profiles WHERE pillar = %s",
		Internal_Script_Integrity_Builder::PILLAR_KEY
	),
	ARRAY_A
);

$int_enabled_by_surface = array();
foreach ( ! empty( $int_profiles_raw ) ? $int_profiles_raw : array() as $row ) {
	$int_enabled_by_surface[ $row['surface'] ] = ! empty( $row['enabled'] );
}

// ── Inventory (sorted most-recently-seen first; no filters -- this is a
//     diagnostic view, not a workflow queue with a backlog to triage) ────────
$int_table = $wpdb->prefix . 'sam_internal_asset_inventory';
// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
$int_inventory_raw = $wpdb->get_results( "SELECT * FROM {$int_table} ORDER BY last_seen_at DESC LIMIT 200", ARRAY_A );
$int_inventory     = ! empty( $int_inventory_raw ) ? $int_inventory_raw : array();
?>
<table class="widefat striped wp-sam-readiness-table" style="margin-top: 1em;">
	<thead>
		<tr>
			<th><?php esc_html_e( 'Surface', 'security-automation-manager' ); ?></th>
			<th><?php esc_html_e( 'Enabled', 'security-automation-manager' ); ?></th>
		</tr>
	</thead>
	<tbody>
		<?php foreach ( $surfaces as $surface ) : ?>
			<tr>
				<td><?php echo esc_html( ucfirst( $surface ) ); ?></td>
				<td>
					<input
						type="checkbox"
						class="wp-sam-pillar-enabled"
						data-pillar="<?php echo esc_attr( Internal_Script_Integrity_Builder::PILLAR_KEY ); ?>"
						data-surface="<?php echo esc_attr( $surface ); ?>"
						<?php checked( $int_enabled_by_surface[ $surface ] ?? false ); ?>
					/>
				</td>
			</tr>
		<?php endforeach; ?>
	</tbody>
</table>

<h2 class="title" style="margin-top:1.5em"><?php esc_html_e( 'Hash inventory', 'security-automation-manager' ); ?></h2>
<p class="description">
	<?php esc_html_e( 'Read-only: every first-party script/stylesheet currently getting an integrity attribute, on a surface where this is enabled. Recalculated automatically whenever a file\'s size or modified time changes -- nothing to approve or classify.', 'security-automation-manager' ); ?>
</p>

<table class="widefat fixed striped" style="margin-top:1em">
	<thead>
		<tr>
			<th><?php esc_html_e( 'Surface', 'security-automation-manager' ); ?></th>
			<th><?php esc_html_e( 'Type', 'security-automation-manager' ); ?></th>
			<th><?php esc_html_e( 'Handle', 'security-automation-manager' ); ?></th>
			<th><?php esc_html_e( 'URL', 'security-automation-manager' ); ?></th>
			<th><?php esc_html_e( 'Hash', 'security-automation-manager' ); ?></th>
			<th><?php esc_html_e( 'File Size', 'security-automation-manager' ); ?></th>
			<th><?php esc_html_e( 'Last Seen', 'security-automation-manager' ); ?></th>
		</tr>
	</thead>
	<tbody>
		<?php foreach ( $int_inventory as $item ) : ?>
			<tr>
				<td><?php echo esc_html( ucfirst( $item['surface'] ) ); ?></td>
				<td><?php echo esc_html( 'script' === $item['resource_type'] ? __( 'Script', 'security-automation-manager' ) : __( 'Stylesheet', 'security-automation-manager' ) ); ?></td>
				<td><code><?php echo esc_html( $item['handle'] ); ?></code></td>
				<td><code style="word-break:break-all;"><?php echo esc_html( $item['url'] ); ?></code></td>
				<td><code style="word-break:break-all;font-size:11px;"><?php echo esc_html( $item['hash'] ); ?></code></td>
				<td><?php echo esc_html( size_format( (int) $item['file_size'] ) ); ?></td>
				<td><?php echo esc_html( $item['last_seen_at'] ); ?></td>
			</tr>
		<?php endforeach; ?>
		<?php if ( empty( $int_inventory ) ) : ?>
		<tr>
			<td colspan="7"><?php esc_html_e( 'No first-party scripts or stylesheets have been hashed yet. Enable a surface above and browse the live site to build the inventory.', 'security-automation-manager' ); ?></td>
		</tr>
		<?php endif; ?>
	</tbody>
</table>
