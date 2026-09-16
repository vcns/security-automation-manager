<?php
/**
 * Admin partial: the outcome-oriented Protection Status section (Customer-
 * Centred Administration Experience spec §10). One row per protection
 * area, using the fixed six-state vocabulary rendered by
 * Status_Badge::render_protection_state().
 *
 * Progressive disclosure (spec §12): the plain-English area name is always
 * shown; the recognised technical name sits alongside it, de-emphasised in
 * Simple/Balanced and prominent in Technical (CSS only -- the name is
 * always in the markup, never removed, per spec's explicit "Simple means
 * less technical presentation, not less visibility"); the technical_detail
 * evidence string lives inside a <details> element, open by default only
 * when the current user's presentation depth is Technical.
 *
 * @var array<int, array{area:string, state:string, summary:string, technical_name:string, technical_detail:string}> $wp_sam_protection_areas
 * @var array{presentation_depth:string, security_familiarity:string} $wp_sam_home_prefs
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WP_SAM\Admin\Status_Badge;

$wp_sam_technical_open = 'technical' === $wp_sam_home_prefs['presentation_depth'];
?>
<div id="wp-sam-protection-status" class="wp-sam-protection-status wp-sam-depth-<?php echo esc_attr( $wp_sam_home_prefs['presentation_depth'] ); ?>">
	<h2><?php esc_html_e( 'Protection status', 'vcns-security-automation-manager' ); ?></h2>
	<?php if ( 'new' === $wp_sam_home_prefs['security_familiarity'] ) : ?>
	<p class="description"><?php esc_html_e( "New to this? Each row below is an automated check SAM already runs for you. You don't need to do anything unless a row says \"Needs attention.\"", 'vcns-security-automation-manager' ); ?></p>
	<?php endif; ?>
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
				<td>
					<strong><?php echo esc_html( $wp_sam_area['area'] ); ?></strong>
					<span class="wp-sam-technical-name">(<?php echo esc_html( $wp_sam_area['technical_name'] ); ?>)</span>
				</td>
				<td><?php echo Status_Badge::render_protection_state( $wp_sam_area['state'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- helper escapes internally. ?></td>
				<td>
					<?php echo esc_html( $wp_sam_area['summary'] ); ?>
					<details<?php echo $wp_sam_technical_open ? ' open="open"' : ''; ?>>
						<summary><?php esc_html_e( 'Technical details', 'vcns-security-automation-manager' ); ?></summary>
						<code><?php echo esc_html( $wp_sam_area['technical_detail'] ); ?></code>
					</details>
				</td>
			</tr>
			<?php endforeach; ?>
		</tbody>
	</table>
</div>
