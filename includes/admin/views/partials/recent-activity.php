<?php
/**
 * Admin partial: the recent-activity statistics strip (Customer-Centred
 * Administration Experience spec §9). Reuses the existing
 * .wp-sam-stat-row/.wp-sam-stat pattern from Network Intelligence's own
 * summary boxes (assets/css/admin.css) rather than introducing a new one.
 *
 * @var array<int, array{label:string, value:int, definition:string}> $wp_sam_activity_metrics
 * @var string $wp_sam_activity_period
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<div class="wp-sam-recent-activity">
	<h2><?php esc_html_e( 'Recent activity', 'vcns-security-automation-manager' ); ?></h2>
	<p class="description"><?php echo esc_html( $wp_sam_activity_period ); ?></p>
	<div class="wp-sam-stat-row">
		<?php foreach ( $wp_sam_activity_metrics as $wp_sam_metric ) : ?>
		<div class="wp-sam-stat">
			<span class="wp-sam-stat-label"><?php echo esc_html( $wp_sam_metric['label'] ); ?></span>
			<span class="wp-sam-stat-value"><?php echo esc_html( number_format( (int) $wp_sam_metric['value'] ) ); ?></span>
			<span class="description"><?php echo esc_html( $wp_sam_metric['definition'] ); ?></span>
		</div>
		<?php endforeach; ?>
	</div>
</div>
