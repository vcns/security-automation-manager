<?php
/**
 * Admin partial: the persistent Protected/Learning/Needs-attention
 * scorecard (Customer-Centred Administration Experience spec §8). Every
 * tile is a real, keyboard-reachable <a> with an accessible name that
 * states the count and what activating it does (spec §17 example: "12
 * protections active. View protected controls.").
 *
 * @var array{protected:int, learning:int, needs_attention:int} $wp_sam_scorecard_counts
 * @var string $wp_sam_action_centre_url
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$wp_sam_protection_anchor = admin_url( 'admin.php?page=security-automation-manager#wp-sam-protection-status' );
$wp_sam_needs_attention   = (int) $wp_sam_scorecard_counts['needs_attention'];
?>
<div class="wp-sam-scorecard" role="group" aria-label="<?php esc_attr_e( 'Security scorecard', 'vcns-security-automation-manager' ); ?>">
	<a class="wp-sam-scorecard-tile wp-sam-scorecard-tile--protected" href="<?php echo esc_url( $wp_sam_protection_anchor ); ?>">
		<span class="wp-sam-scorecard-value"><?php echo esc_html( (string) $wp_sam_scorecard_counts['protected'] ); ?></span>
		<span class="wp-sam-scorecard-label"><?php esc_html_e( 'Protected', 'vcns-security-automation-manager' ); ?></span>
		<span class="screen-reader-text">
			<?php
			printf(
				/* translators: %d: number of protections currently active */
				esc_html__( '%d protections active. View protected controls.', 'vcns-security-automation-manager' ),
				(int) $wp_sam_scorecard_counts['protected']
			);
			?>
		</span>
	</a>
	<a class="wp-sam-scorecard-tile wp-sam-scorecard-tile--learning" href="<?php echo esc_url( $wp_sam_protection_anchor ); ?>">
		<span class="wp-sam-scorecard-value"><?php echo esc_html( (string) $wp_sam_scorecard_counts['learning'] ); ?></span>
		<span class="wp-sam-scorecard-label"><?php esc_html_e( 'Learning', 'vcns-security-automation-manager' ); ?></span>
		<span class="screen-reader-text">
			<?php
			printf(
				/* translators: %d: number of controls currently learning/monitoring */
				esc_html__( '%d controls learning or monitoring. View their status.', 'vcns-security-automation-manager' ),
				(int) $wp_sam_scorecard_counts['learning']
			);
			?>
		</span>
	</a>
	<a class="wp-sam-scorecard-tile wp-sam-scorecard-tile--attention<?php echo $wp_sam_needs_attention > 0 ? ' wp-sam-scorecard-tile--has-items' : ''; ?>" href="<?php echo esc_url( $wp_sam_action_centre_url ); ?>">
		<span class="wp-sam-scorecard-value"><?php echo esc_html( (string) $wp_sam_needs_attention ); ?></span>
		<span class="wp-sam-scorecard-label"><?php esc_html_e( 'Needs attention', 'vcns-security-automation-manager' ); ?></span>
		<span class="screen-reader-text">
			<?php
			printf(
				/* translators: %d: number of items needing review */
				esc_html__( '%d items need your attention. Open the Action Centre.', 'vcns-security-automation-manager' ),
				$wp_sam_needs_attention
			);
			?>
		</span>
	</a>
</div>
