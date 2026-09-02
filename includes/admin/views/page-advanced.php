<?php
/**
 * Admin view: Advanced Intelligence (Phase 3J, .roadmap/phase3_early_
 * plan.md §14, §15, §17, §18 -- explicitly optional capabilities the user
 * chose to build ahead of real-world validation). Four tabs: Campaigns
 * (possible coordinated activity), Honey Paths (decoy path configuration),
 * Change Windows (declared-intent workflow around baseline/drift), and
 * Timeline (merged change-attribution view, extending Phase 3F's §17 work).
 *
 * Integrity Monitoring (§16) has no tab of its own here -- its two signals
 * (new administrator accounts, role escalations) write into the same
 * Change_Log_Store the existing Baseline & Drift page's Change Log tab
 * already shows, and into this page's own Timeline tab; a third place to
 * look would just fragment the same data.
 *
 * Rendered by Admin_UI::render_advanced().
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WP_SAM\Admin\Change_Timeline_Builder;
use WP_SAM\Admin\Risk_Badge;
use WP_SAM\Intelligence\Baseline_Store;
use WP_SAM\Intelligence\Campaign_Store;
use WP_SAM\Intelligence\Change_Log_Store;
use WP_SAM\Intelligence\Change_Window_Store;
use WP_SAM\Intelligence\Drift_Store;
use WP_SAM\Intelligence\Honeypath_Store;

$base_url     = admin_url( 'admin.php?page=security-automation-manager-advanced' );
$tab          = isset( $_GET['tab'] ) ? sanitize_text_field( wp_unslash( $_GET['tab'] ) ) : 'campaigns'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
$allowed_tabs = array( 'campaigns', 'honeypaths', 'change-windows', 'timeline' );
if ( ! in_array( $tab, $allowed_tabs, true ) ) {
	$tab = 'campaigns';
}

$tab_help = array(
	'campaigns'      => array(
		'label'       => __( 'Campaigns', 'vcns-security-automation-manager' ),
		'description' => __( 'Possible coordinated activity: many distinct sources triggering the same detector.', 'vcns-security-automation-manager' ),
	),
	'honeypaths'     => array(
		'label'       => __( 'Honey Paths', 'vcns-security-automation-manager' ),
		'description' => __( 'Decoy paths no legitimate visitor ever requests. Disabled until you add one.', 'vcns-security-automation-manager' ),
	),
	'change-windows' => array(
		'label'       => __( 'Change Windows', 'vcns-security-automation-manager' ),
		'description' => __( 'Declare an intentional change in progress, then review what drifted while it was open.', 'vcns-security-automation-manager' ),
	),
	'timeline'       => array(
		'label'       => __( 'Timeline', 'vcns-security-automation-manager' ),
		'description' => __( 'Site changes, security drift, and campaigns merged into one chronological view.', 'vcns-security-automation-manager' ),
	),
);
?>
<div class="wrap wp-sam-wrap">
	<h1><?php esc_html_e( 'Advanced Intelligence', 'vcns-security-automation-manager' ); ?></h1>

	<p>
		<?php esc_html_e( 'Optional capabilities beyond the core observe/decide/control/verify lifecycle. Every capability here observes and records only -- nothing blocks, exposes, or auto-accepts without an explicit action below.', 'vcns-security-automation-manager' ); ?>
	</p>

	<nav class="nav-tab-wrapper wp-sam-tab-wrapper" role="tablist" aria-label="<?php esc_attr_e( 'Advanced Intelligence sections', 'vcns-security-automation-manager' ); ?>">
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

	<?php if ( 'campaigns' === $tab ) : ?>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin:1em 0">
			<?php wp_nonce_field( 'wp_sam_campaign_scan' ); ?>
			<input type="hidden" name="action" value="wp_sam_campaign_scan" />
			<?php submit_button( __( 'Run Campaign Scan', 'vcns-security-automation-manager' ), 'primary', '', false ); ?>
		</form>

		<?php $campaigns = ( new Campaign_Store() )->all(); ?>

		<table class="widefat fixed striped wp-sam-violations-table">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Detector', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Surface', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Participants', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Status', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'First / Last Detected', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Actions', 'vcns-security-automation-manager' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $campaigns as $campaign ) : ?>
			<tr>
				<td><code><?php echo esc_html( (string) $campaign['detector_id'] ); ?></code></td>
				<td><?php echo esc_html( ucfirst( (string) $campaign['surface'] ) ); ?></td>
				<td><?php echo esc_html( (string) $campaign['participant_count'] ); ?> <?php esc_html_e( 'distinct IPs', 'vcns-security-automation-manager' ); ?></td>
				<td><?php echo esc_html( ucfirst( (string) $campaign['status'] ) ); ?></td>
				<td><?php echo esc_html( (string) $campaign['first_detected_at'] . ' / ' . (string) $campaign['last_detected_at'] ); ?></td>
				<td>
					<?php if ( 'detected' === (string) $campaign['status'] ) : ?>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
						<?php wp_nonce_field( 'wp_sam_campaign_disposition' ); ?>
						<input type="hidden" name="action" value="wp_sam_campaign_disposition" />
						<input type="hidden" name="campaign_id" value="<?php echo esc_attr( (string) $campaign['id'] ); ?>" />
						<input type="text" name="note" placeholder="<?php esc_attr_e( 'Reason', 'vcns-security-automation-manager' ); ?>" required style="width:110px" />
						<button type="submit" name="disposition" value="acknowledged" class="button button-small"><?php esc_html_e( 'Acknowledge', 'vcns-security-automation-manager' ); ?></button>
						<button type="submit" name="disposition" value="dismissed" class="button button-small"><?php esc_html_e( 'Dismiss', 'vcns-security-automation-manager' ); ?></button>
					</form>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:4px">
						<?php wp_nonce_field( 'wp_sam_campaign_block' ); ?>
						<input type="hidden" name="action" value="wp_sam_campaign_block" />
						<input type="hidden" name="campaign_id" value="<?php echo esc_attr( (string) $campaign['id'] ); ?>" />
						<input type="text" name="note" placeholder="<?php esc_attr_e( 'Reason (required)', 'vcns-security-automation-manager' ); ?>" required style="width:110px" />
						<button type="submit" class="button button-primary button-small" onclick="return confirm('<?php echo esc_js( __( 'Block every currently-live participant IP? This is an explicit, immediate action.', 'vcns-security-automation-manager' ) ); ?>');"><?php esc_html_e( 'Block Participants', 'vcns-security-automation-manager' ); ?></button>
					</form>
					<?php else : ?>
						<?php echo esc_html( (string) $campaign['disposition_note'] ); ?>
					<?php endif; ?>
				</td>
			</tr>
			<?php endforeach; ?>
			<?php if ( empty( $campaigns ) ) : ?>
			<tr>
				<td colspan="6"><p><?php esc_html_e( 'No campaign detected yet.', 'vcns-security-automation-manager' ); ?></p></td>
			</tr>
			<?php endif; ?>
			</tbody>
		</table>

	<?php elseif ( 'honeypaths' === $tab ) : ?>

		<?php $honeypaths = ( new Honeypath_Store() )->all(); ?>

		<table class="widefat fixed striped wp-sam-violations-table" style="margin-top:1em">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Path', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Description', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Added', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Actions', 'vcns-security-automation-manager' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $honeypaths as $honeypath ) : ?>
			<tr>
				<td><code><?php echo esc_html( (string) $honeypath['path'] ); ?></code></td>
				<td><?php echo esc_html( (string) $honeypath['description'] ); ?></td>
				<td><?php echo esc_html( (string) $honeypath['created_at'] ); ?></td>
				<td>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
						<?php wp_nonce_field( 'wp_sam_honeypath_delete' ); ?>
						<input type="hidden" name="action" value="wp_sam_honeypath_delete" />
						<input type="hidden" name="honeypath_id" value="<?php echo esc_attr( (string) $honeypath['id'] ); ?>" />
						<button type="submit" class="button button-small"><?php esc_html_e( 'Remove', 'vcns-security-automation-manager' ); ?></button>
					</form>
				</td>
			</tr>
			<?php endforeach; ?>
			<?php if ( empty( $honeypaths ) ) : ?>
			<tr>
				<td colspan="4"><p><?php esc_html_e( 'No decoy paths configured. This detector is currently disabled.', 'vcns-security-automation-manager' ); ?></p></td>
			</tr>
			<?php endif; ?>
			</tbody>
		</table>

		<h2 style="margin-top:2em"><?php esc_html_e( 'Add a decoy path', 'vcns-security-automation-manager' ); ?></h2>
		<p class="description"><?php esc_html_e( 'Choose a path no legitimate visitor, link, or integration on your site ever requests -- e.g. a fake admin path or a plausible-looking sensitive filename.', 'vcns-security-automation-manager' ); ?></p>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'wp_sam_honeypath_add' ); ?>
			<input type="hidden" name="action" value="wp_sam_honeypath_add" />
			<p>
				<input type="text" name="path" placeholder="<?php esc_attr_e( '/wp-content/backup.zip', 'vcns-security-automation-manager' ); ?>" style="width:100%;max-width:400px" required />
			</p>
			<p>
				<input type="text" name="description" placeholder="<?php esc_attr_e( 'Optional note', 'vcns-security-automation-manager' ); ?>" style="width:100%;max-width:400px" />
			</p>
			<?php submit_button( __( 'Add Decoy Path', 'vcns-security-automation-manager' ) ); ?>
		</form>

	<?php elseif ( 'change-windows' === $tab ) : ?>

		<?php
		$window_store = new Change_Window_Store();
		$active       = $window_store->get_active();
		$baseline     = new Baseline_Store();
		?>

		<?php if ( null !== $active ) : ?>
		<div class="notice notice-info inline" style="padding:12px 16px;margin:1em 0;">
			<p style="margin-top:0;">
				<strong><?php esc_html_e( 'Change window open:', 'vcns-security-automation-manager' ); ?></strong>
				<?php echo esc_html( (string) $active['description'] ); ?>
				&mdash; <?php echo esc_html( (string) $active['opened_at'] ); ?>
			</p>
		</div>

			<?php
			$since_drifts = array_filter(
				( new Drift_Store() )->all(),
				static fn( array $d ): bool => (string) $d['first_seen_at'] >= (string) $active['opened_at']
			);
			?>
		<p><?php echo esc_html( sprintf( /* translators: %d: number of drift records */ _n( '%d item has drifted since this window opened.', '%d items have drifted since this window opened.', count( $since_drifts ), 'vcns-security-automation-manager' ), count( $since_drifts ) ) ); ?></p>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'wp_sam_change_window_close' ); ?>
			<input type="hidden" name="action" value="wp_sam_change_window_close" />
			<input type="hidden" name="window_id" value="<?php echo esc_attr( (string) $active['id'] ); ?>" />
			<p>
				<textarea name="note" rows="2" style="width:100%;max-width:500px" placeholder="<?php esc_attr_e( 'Resolution note, e.g. what changed and whether it matches expectations', 'vcns-security-automation-manager' ); ?>"></textarea>
			</p>
			<?php submit_button( __( 'Run Drift Scan and Close Window', 'vcns-security-automation-manager' ), 'primary', '', false ); ?>
		</form>
		<p class="description" style="margin-top:1em">
			<?php esc_html_e( 'Closing runs a fresh drift scan for an accurate delta, then closes the window. To accept the new state as the known-good baseline afterwards, use Capture Baseline on the Baseline & Drift page -- that stays a separate, explicit step.', 'vcns-security-automation-manager' ); ?>
		</p>

		<?php else : ?>

		<h2><?php esc_html_e( 'Open a change window', 'vcns-security-automation-manager' ); ?></h2>
		<p class="description"><?php esc_html_e( 'Declare an intentional change (e.g. a plugin upgrade or deployment) in progress. The current baseline is recorded as the rollback reference point.', 'vcns-security-automation-manager' ); ?></p>
			<?php if ( null === $baseline->get_current() ) : ?>
		<p class="description"><em><?php esc_html_e( 'No baseline has been approved yet -- you can still open a window, but there will be no rollback reference point recorded.', 'vcns-security-automation-manager' ); ?></em></p>
			<?php endif; ?>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'wp_sam_change_window_open' ); ?>
			<input type="hidden" name="action" value="wp_sam_change_window_open" />
			<p>
				<input type="text" name="description" placeholder="<?php esc_attr_e( 'e.g. Upgrading Elementor to 3.28', 'vcns-security-automation-manager' ); ?>" style="width:100%;max-width:400px" required />
			</p>
			<p>
				<label>
					<?php esc_html_e( 'Expected duration (hours, optional):', 'vcns-security-automation-manager' ); ?>
					<input type="number" name="duration_hours" min="1" max="168" style="width:80px" />
				</label>
			</p>
			<?php submit_button( __( 'Open Change Window', 'vcns-security-automation-manager' ) ); ?>
		</form>

		<?php endif; ?>

		<h2 style="margin-top:2em"><?php esc_html_e( 'History', 'vcns-security-automation-manager' ); ?></h2>
		<table class="widefat fixed striped wp-sam-violations-table">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Description', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Status', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Opened', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Closed', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Rollback Reference', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Resolution', 'vcns-security-automation-manager' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php $window_history = $window_store->all(); ?>
			<?php foreach ( $window_history as $window ) : ?>
			<tr>
				<td><?php echo esc_html( (string) $window['description'] ); ?></td>
				<td><?php echo esc_html( ucfirst( (string) $window['status'] ) ); ?></td>
				<td><?php echo esc_html( (string) $window['opened_at'] ); ?></td>
				<td><?php echo esc_html( (string) ( $window['closed_at'] ?? '' ) ); ?></td>
				<td><?php echo ! empty( $window['baseline_id_before'] ) ? esc_html( '#' . (string) $window['baseline_id_before'] ) : '&mdash;'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static HTML entity only. ?></td>
				<td><?php echo esc_html( (string) $window['resolution_note'] ); ?></td>
			</tr>
			<?php endforeach; ?>
			<?php if ( empty( $window_history ) ) : ?>
			<tr>
				<td colspan="6"><p><?php esc_html_e( 'No change window opened yet.', 'vcns-security-automation-manager' ); ?></p></td>
			</tr>
			<?php endif; ?>
			</tbody>
		</table>

	<?php elseif ( 'timeline' === $tab ) : ?>

		<?php
		$timeline_events = Change_Timeline_Builder::fetch(
			new Change_Log_Store(),
			new Drift_Store(),
			new Campaign_Store()
		);
		?>

		<table class="widefat fixed striped wp-sam-violations-table" style="margin-top:1em">
			<thead>
				<tr>
					<th><?php esc_html_e( 'When', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Type', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Event', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Risk', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Detail', 'vcns-security-automation-manager' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $timeline_events as $event ) : ?>
			<tr>
				<td><?php echo esc_html( (string) $event['when'] ); ?></td>
				<td><?php echo esc_html( (string) $event['type'] ); ?></td>
				<td><?php echo esc_html( (string) $event['event'] ); ?></td>
				<td><?php echo '' !== (string) $event['risk_level'] ? Risk_Badge::render( (string) $event['risk_level'], '' ) : '&mdash;'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- helper escapes internally; static entity otherwise. ?></td>
				<td><?php echo esc_html( (string) $event['detail'] ); ?></td>
			</tr>
			<?php endforeach; ?>
			<?php if ( empty( $timeline_events ) ) : ?>
			<tr>
				<td colspan="5"><p><?php esc_html_e( 'Nothing recorded yet.', 'vcns-security-automation-manager' ); ?></p></td>
			</tr>
			<?php endif; ?>
			</tbody>
		</table>

	<?php endif; ?>
</div>
