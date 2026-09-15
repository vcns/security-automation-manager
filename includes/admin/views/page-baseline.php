<?php
/**
 * Admin view: Baseline & Drift (Phase 3F, .roadmap/phase3_early_plan.md
 * §19). Three tabs: Drift (differences from the approved baseline, with
 * risk classification, correlation, and administrator disposition),
 * Baseline History (past approved snapshots, and capturing a new one),
 * Change Log (real plugin/theme/core change history, §17 Change
 * Attribution).
 *
 * Rendered by Admin_UI::render_baseline().
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WP_SAM\Admin\Risk_Badge;
use WP_SAM\Intelligence\Baseline_Store;
use WP_SAM\Intelligence\Change_Log_Store;
use WP_SAM\Intelligence\Drift_Store;

$base_url     = admin_url( 'admin.php?page=security-automation-manager-baseline' );
$tab          = isset( $_GET['tab'] ) ? sanitize_text_field( wp_unslash( $_GET['tab'] ) ) : 'drift'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
$allowed_tabs = array( 'drift', 'history', 'change-log' );
if ( ! in_array( $tab, $allowed_tabs, true ) ) {
	$tab = 'drift';
}

$tab_help = array(
	'drift'      => array(
		'label'       => __( 'Drift', 'vcns-security-automation-manager' ),
		'description' => __( 'Differences between the approved baseline and current state.', 'vcns-security-automation-manager' ),
	),
	'history'    => array(
		'label'       => __( 'Baseline History', 'vcns-security-automation-manager' ),
		'description' => __( 'Past approved baselines, and capturing a new one.', 'vcns-security-automation-manager' ),
	),
	'change-log' => array(
		'label'       => __( 'Change Log', 'vcns-security-automation-manager' ),
		'description' => __( 'Real plugin, theme, and core update history, used to correlate drift.', 'vcns-security-automation-manager' ),
	),
);

$baseline_store = new Baseline_Store();
$current        = $baseline_store->get_current();
?>
<div class="wrap wp-sam-wrap">
	<h1><?php esc_html_e( 'Baseline & Drift', 'vcns-security-automation-manager' ); ?></h1>

	<p>
		<?php esc_html_e( 'Answers "what changed?" rather than only "what is configured?". Capture a baseline once you\'re happy with the current configuration, then run scans to see what drifted from it.', 'vcns-security-automation-manager' ); ?>
	</p>
	<p class="description">
		<?php esc_html_e( "A baseline is a snapshot of this site's security-relevant configuration at a moment you choose: TLS certificate state, the effective CSP header for each surface, individual security header toggles, the review classification given to each external script/style source, the integrity hash of every first-party file this site tracks, and the installed version of WordPress core, the active theme, and every active plugin. It only covers what this WordPress install can see about itself -- it doesn't verify anything external, such as DNS records or what a visitor's browser actually receives.", 'vcns-security-automation-manager' ); ?>
	</p>

	<nav class="nav-tab-wrapper wp-sam-tab-wrapper" role="tablist" aria-label="<?php esc_attr_e( 'Baseline and Drift sections', 'vcns-security-automation-manager' ); ?>">
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

	<?php if ( 'drift' === $tab ) : ?>

		<?php if ( null === $current ) : ?>
		<div class="notice notice-info inline" style="padding:12px 16px;margin:1em 0;">
			<p style="margin-top:0;">
				<?php esc_html_e( 'No baseline has been approved yet, so there is nothing to compare against. Capture one from the Baseline History tab once you\'re happy with the current configuration.', 'vcns-security-automation-manager' ); ?>
			</p>
		</div>
		<?php else : ?>

		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin:1em 0">
			<?php wp_nonce_field( 'wp_sam_drift_scan' ); ?>
			<input type="hidden" name="action" value="wp_sam_drift_scan" />
			<?php submit_button( __( 'Run Drift Scan', 'vcns-security-automation-manager' ), 'primary', '', false ); ?>
		</form>

		<p class="description">
			<?php esc_html_e( "A scan compares the state above against your last approved baseline and lists everything that differs, each rated by risk. Low covers routine housekeeping -- a version number changing, or an already-known external source simply being reclassified. Medium covers surface-visible changes -- the effective CSP header or a security header toggle changing, a brand-new external script/style source appearing, or a first-party file this site was tracking no longer being found. High is reserved for the two changes most worth confirming were intentional: a first-party file's integrity hash changing -- confirm you or an update actually touched that file before dismissing it, since this is how a compromised file often first surfaces -- and a certificate's recorded state changing. A high-risk certificate row is very often just this plugin's own automatic renewal running as designed (the expiry date always changes at renewal), but there is no certificate-specific entry in the Change Log to correlate it against, so check the Certificates page directly rather than expecting this row to explain itself.", 'vcns-security-automation-manager' ); ?>
		</p>
		<p class="description">
			<?php esc_html_e( "Correlation only ever reports that a recorded site change happened around the same time as the drift -- never that it caused it -- so treat it as a lead, not a conclusion. Newly-detected drift starts Unexplained. Once you've confirmed a change is fine -- you deliberately updated a plugin, or edited a policy yourself -- Approve it or Mark it Expected; either requires a short reason that is kept for the record, but neither changes what counts as known-good: the next scan still compares against the same baseline. If this is the new normal going forward, capture a new baseline from the Baseline History tab so future scans stop flagging it. An item only becomes Resolved automatically, when it reverts back to matching the baseline on its own.", 'vcns-security-automation-manager' ); ?>
		</p>

			<?php
			$disposition_filter = isset( $_GET['disposition'] ) ? sanitize_key( wp_unslash( $_GET['disposition'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$drifts             = ( new Drift_Store() )->all( $disposition_filter );
			?>

		<p>
			<a href="<?php echo esc_url( $base_url . '&tab=drift' ); ?>" class="button<?php echo '' === $disposition_filter ? ' button-primary' : ''; ?>"><?php esc_html_e( 'All', 'vcns-security-automation-manager' ); ?></a>
			<?php foreach ( array( 'unexplained', 'expected', 'approved', 'resolved' ) as $d ) : ?>
			<a href="
				<?php
				echo esc_url(
					add_query_arg(
						array(
							'tab'         => 'drift',
							'disposition' => $d,
						),
						$base_url
					)
				);
				?>
						" class="button<?php echo $disposition_filter === $d ? ' button-primary' : ''; ?>"><?php echo esc_html( ucfirst( $d ) ); ?></a>
			<?php endforeach; ?>
		</p>

		<table class="widefat fixed striped wp-sam-violations-table wp-sam-drift-table">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Category', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Item', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Risk', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Correlation', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Disposition', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Details', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Actions', 'vcns-security-automation-manager' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $drifts as $drift ) : ?>
			<tr>
				<td><?php echo esc_html( str_replace( '_', ' ', ucfirst( (string) $drift['category'] ) ) ); ?><?php echo '' !== (string) $drift['surface'] ? ' (' . esc_html( ucfirst( (string) $drift['surface'] ) ) . ')' : ''; ?></td>
				<td><code class="wp-sam-drift-item"><?php echo esc_html( (string) $drift['item_key'] ); ?></code></td>
				<td><?php echo Risk_Badge::render( (string) $drift['risk_level'], (string) $drift['risk_reason'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- helper escapes internally. ?></td>
				<td><?php echo esc_html( (string) $drift['correlated_change'] ); ?></td>
				<td><?php echo esc_html( ucfirst( (string) $drift['disposition'] ) ); ?></td>
				<td>
					<span class="dashicons dashicons-info-outline wp-sam-meta-icon" tabindex="0">
						<span class="wp-sam-meta-popover" role="tooltip">
							<div class="wp-sam-meta-row"><strong><?php esc_html_e( 'Baseline said:', 'vcns-security-automation-manager' ); ?></strong> <code><?php echo esc_html( mb_substr( (string) $drift['old_value'], 0, 200 ) ); ?></code></div>
							<div class="wp-sam-meta-row"><strong><?php esc_html_e( 'Currently:', 'vcns-security-automation-manager' ); ?></strong> <code><?php echo esc_html( mb_substr( (string) $drift['new_value'], 0, 200 ) ); ?></code></div>
						</span>
					</span>
				</td>
				<td>
					<?php if ( in_array( (string) $drift['disposition'], array( 'unexplained' ), true ) ) : ?>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
						<?php wp_nonce_field( 'wp_sam_drift_disposition' ); ?>
						<input type="hidden" name="action" value="wp_sam_drift_disposition" />
						<input type="hidden" name="drift_id" value="<?php echo esc_attr( (string) $drift['id'] ); ?>" />
						<input type="text" name="note" placeholder="<?php esc_attr_e( 'Reason', 'vcns-security-automation-manager' ); ?>" required style="width:110px" />
						<button type="submit" name="disposition" value="approved" class="button button-primary button-small"><?php esc_html_e( 'Approve', 'vcns-security-automation-manager' ); ?></button>
						<button type="submit" name="disposition" value="expected" class="button button-small"><?php esc_html_e( 'Mark Expected', 'vcns-security-automation-manager' ); ?></button>
					</form>
					<?php else : ?>
						&mdash;
					<?php endif; ?>
				</td>
			</tr>
			<?php endforeach; ?>
			<?php if ( empty( $drifts ) ) : ?>
			<tr>
				<td colspan="7"><p><?php esc_html_e( 'No drift recorded for this filter.', 'vcns-security-automation-manager' ); ?></p></td>
			</tr>
			<?php endif; ?>
			</tbody>
		</table>

		<?php endif; ?>

	<?php elseif ( 'history' === $tab ) : ?>

		<?php $all_baselines = $baseline_store->all(); ?>

		<p class="description">
			<?php esc_html_e( 'Every approved baseline is kept, not deleted, when you capture a new one -- capturing only changes which version is Current, the one drift scans actually compare against. Capturing is always a deliberate action taken here; nothing is ever baselined automatically, the same never-automatic principle used elsewhere in this plugin (CSP enforcement, traffic blocking), so there is always a known, chosen baseline rather than a moving target.', 'vcns-security-automation-manager' ); ?>
		</p>

		<table class="widefat fixed striped wp-sam-violations-table" style="margin-top:1em">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Version', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Current', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Approved At', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Note', 'vcns-security-automation-manager' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $all_baselines as $baseline ) : ?>
			<tr>
				<td><?php echo esc_html( '#' . (string) $baseline['version_number'] ); ?></td>
				<td><?php echo ! empty( $baseline['is_current'] ) ? '&#10003;' : '&mdash;'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static HTML entities only. ?></td>
				<td><?php echo esc_html( (string) $baseline['approved_at'] ); ?></td>
				<td><?php echo esc_html( (string) $baseline['note'] ); ?></td>
			</tr>
			<?php endforeach; ?>
			<?php if ( empty( $all_baselines ) ) : ?>
			<tr>
				<td colspan="4"><p><?php esc_html_e( 'No baseline captured yet.', 'vcns-security-automation-manager' ); ?></p></td>
			</tr>
			<?php endif; ?>
			</tbody>
		</table>

		<h2 style="margin-top:2em"><?php esc_html_e( 'Capture a new baseline', 'vcns-security-automation-manager' ); ?></h2>
		<p class="description"><?php esc_html_e( 'Snapshots the current configuration as the new known-good state. Future drift scans compare against this instead.', 'vcns-security-automation-manager' ); ?></p>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<?php wp_nonce_field( 'wp_sam_baseline_capture' ); ?>
			<input type="hidden" name="action" value="wp_sam_baseline_capture" />
			<p>
				<textarea name="note" rows="2" style="width:100%;max-width:500px" placeholder="<?php esc_attr_e( 'Optional note, e.g. why this is being captured now', 'vcns-security-automation-manager' ); ?>"></textarea>
			</p>
			<?php submit_button( __( 'Capture Baseline', 'vcns-security-automation-manager' ) ); ?>
		</form>

	<?php elseif ( 'change-log' === $tab ) : ?>

		<?php $change_log_entries = ( new Change_Log_Store() )->all(); ?>

		<p class="description">
			<?php esc_html_e( "Populated automatically as these events happen -- a plugin or theme updating, being activated or deactivated, WordPress core updating, a new administrator account appearing, or a role being granted -- there is nothing to configure here. Its only purpose is giving the Drift tab's Correlation column something concrete to check against; it is not itself an alert or a block on anything.", 'vcns-security-automation-manager' ); ?>
		</p>

		<table class="widefat fixed striped wp-sam-violations-table" style="margin-top:1em">
			<thead>
				<tr>
					<th><?php esc_html_e( 'Type', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Item', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'Version', 'vcns-security-automation-manager' ); ?></th>
					<th><?php esc_html_e( 'When', 'vcns-security-automation-manager' ); ?></th>
				</tr>
			</thead>
			<tbody>
			<?php foreach ( $change_log_entries as $entry ) : ?>
			<tr>
				<td><?php echo esc_html( str_replace( '_', ' ', ucfirst( (string) $entry['change_type'] ) ) ); ?></td>
				<td><code><?php echo esc_html( (string) $entry['item_name'] ); ?></code></td>
				<td>
					<?php if ( '' !== (string) $entry['old_version'] && '' !== (string) $entry['new_version'] ) : ?>
						<?php echo esc_html( (string) $entry['old_version'] . ' → ' . (string) $entry['new_version'] ); ?>
					<?php else : ?>
						<?php echo esc_html( (string) $entry['new_version'] ); ?>
					<?php endif; ?>
				</td>
				<td><?php echo esc_html( (string) $entry['occurred_at'] ); ?></td>
			</tr>
			<?php endforeach; ?>
			<?php if ( empty( $change_log_entries ) ) : ?>
			<tr>
				<td colspan="4"><p><?php esc_html_e( 'No changes recorded yet.', 'vcns-security-automation-manager' ); ?></p></td>
			</tr>
			<?php endif; ?>
			</tbody>
		</table>

	<?php endif; ?>
</div>
