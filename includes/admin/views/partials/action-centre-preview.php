<?php
/**
 * Admin partial: the Action Centre preview (Customer-Centred
 * Administration Experience spec §13.5) -- a short summary shown on the
 * Settings/Overview page, linking to the full Action Centre tab. Never
 * invents an empty-state "task" just to avoid saying nothing is pending
 * (spec: "Do not create artificial tasks merely to avoid an empty state").
 *
 * @var array<int, array{what_found:string, why_it_matters:string, recommended_action:string, what_will_happen:string, evidence_url:string, risk:string, dismissible:bool, key:?string}> $wp_sam_action_items
 * @var string $wp_sam_action_centre_url
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$wp_sam_high_priority = 0;
$wp_sam_routine       = 0;
foreach ( $wp_sam_action_items as $wp_sam_item ) {
	if ( in_array( $wp_sam_item['risk'], array( 'critical', 'high' ), true ) ) {
		++$wp_sam_high_priority;
	} else {
		++$wp_sam_routine;
	}
}
?>
<div class="wp-sam-action-centre-preview">
	<h2><?php esc_html_e( 'Needs your attention', 'vcns-security-automation-manager' ); ?></h2>
	<?php if ( empty( $wp_sam_action_items ) ) : ?>
	<p><?php esc_html_e( 'Nothing currently needs your attention.', 'vcns-security-automation-manager' ); ?></p>
	<?php else : ?>
	<ul>
		<?php if ( $wp_sam_high_priority > 0 ) : ?>
		<li>
			<?php
			printf(
				/* translators: %d: number of high-priority items */
				esc_html( _n( '%d high-priority item', '%d high-priority items', $wp_sam_high_priority, 'vcns-security-automation-manager' ) ),
				(int) $wp_sam_high_priority
			);
			?>
		</li>
		<?php endif; ?>
		<?php if ( $wp_sam_routine > 0 ) : ?>
		<li>
			<?php
			printf(
				/* translators: %d: number of routine review items */
				esc_html( _n( '%d routine review', '%d routine reviews', $wp_sam_routine, 'vcns-security-automation-manager' ) ),
				(int) $wp_sam_routine
			);
			?>
		</li>
		<?php endif; ?>
	</ul>
	<p><a class="button button-primary" href="<?php echo esc_url( $wp_sam_action_centre_url ); ?>"><?php esc_html_e( 'Review now', 'vcns-security-automation-manager' ); ?></a></p>
	<?php endif; ?>
</div>
