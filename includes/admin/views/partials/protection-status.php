<?php
/**
 * Admin partial: the outcome-oriented Protection Status section (Customer-
 * Centred Administration Experience spec §10). One row per protection
 * area, using the fixed six-state vocabulary rendered by
 * Status_Badge::render_protection_state().
 *
 * @var array<int, array{area:string, state:string, summary:string}> $wp_sam_protection_areas
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WP_SAM\Admin\Status_Badge;
?>
<div id="wp-sam-protection-status" class="wp-sam-protection-status">
	<h2><?php esc_html_e( 'Protection status', 'vcns-security-automation-manager' ); ?></h2>
	<table class="widefat striped wp-sam-readiness-table">
		<thead>
			<tr>
				<th><?php esc_html_e( 'Protection area', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Status', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Summary', 'vcns-security-automation-manager' ); ?></th>
			</tr>
		</thead>
		<tbody>
			<?php foreach ( $wp_sam_protection_areas as $wp_sam_area ) : ?>
			<tr>
				<td><strong><?php echo esc_html( $wp_sam_area['area'] ); ?></strong></td>
				<td><?php echo Status_Badge::render_protection_state( $wp_sam_area['state'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- helper escapes internally. ?></td>
				<td><?php echo esc_html( $wp_sam_area['summary'] ); ?></td>
			</tr>
			<?php endforeach; ?>
		</tbody>
	</table>
</div>
