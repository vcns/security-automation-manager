<?php
/**
 * Admin view: Observe -- the first stage of this plugin's operational
 * lifecycle (.roadmap/phase3_early_plan.md §3.1, §6.1): collect evidence
 * without making an enforcement decision. Nothing on this page, or reached
 * from it, blocks or changes anything -- it only shows what's already been
 * observed.
 *
 * A curated set of links into existing evidence views, not a
 * re-implementation of any of them.
 *
 * Rendered by Admin_UI::render_observe().
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WP_SAM\Admin\Status_Badge;
use WP_SAM\Intelligence\Detector_Registry;

$intelligence_detector_count = count( Detector_Registry::keys() );
?>
<div class="wrap wp-sam-wrap">
	<h1><?php esc_html_e( 'Observe', 'vcns-security-automation-manager' ); ?></h1>

	<p>
		<?php esc_html_e( 'Collecting evidence -- request behaviour, browser policy violations, script and certificate changes -- without applying any control. Nothing here blocks or changes anything on its own.', 'vcns-security-automation-manager' ); ?>
	</p>

	<table class="widefat striped wp-sam-readiness-table">
		<thead>
			<tr>
				<th><?php esc_html_e( 'Area', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Status', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'View', 'vcns-security-automation-manager' ); ?></th>
			</tr>
		</thead>
		<tbody>
			<tr>
				<td>
					<strong><?php esc_html_e( 'Continuous Intelligence', 'vcns-security-automation-manager' ); ?></strong>
					<p class="description"><?php esc_html_e( 'Every request to Frontend, Admin, Login and API is observed and classified.', 'vcns-security-automation-manager' ); ?></p>
				</td>
				<td>
					<?php if ( $intelligence_detector_count > 0 ) : ?>
						<?php
						echo Status_Badge::render( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- helper escapes internally.
							Status_Badge::STATE_ACTIVE,
							__( 'Observing', 'vcns-security-automation-manager' ),
							sprintf(
								/* translators: %d: number of registered detectors */
								_n( '%d detector registered.', '%d detectors registered.', $intelligence_detector_count, 'vcns-security-automation-manager' ),
								$intelligence_detector_count
							)
						);
						?>
					<?php else : ?>
						<?php
						echo Status_Badge::render( // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
							Status_Badge::STATE_ACTIVE,
							__( 'Observing', 'vcns-security-automation-manager' ),
							__( 'Every request is observed and classified; no detectors are registered yet, so nothing is currently evaluated against them.', 'vcns-security-automation-manager' )
						);
						?>
					<?php endif; ?>
				</td>
				<td>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=security-automation-manager-intelligence' ) ); ?>">
						<?php esc_html_e( 'View Continuous Intelligence', 'vcns-security-automation-manager' ); ?>
					</a>
				</td>
			</tr>
			<tr>
				<td>
					<strong><?php esc_html_e( 'CSP Violations', 'vcns-security-automation-manager' ); ?></strong>
					<p class="description"><?php esc_html_e( 'Report-only violation reports browsers have sent back for this site\'s Content Security Policy.', 'vcns-security-automation-manager' ); ?></p>
				</td>
				<td>&mdash;</td>
				<td>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=security-automation-manager-dashboard&tab=violations' ) ); ?>">
						<?php esc_html_e( 'View CSP Violations', 'vcns-security-automation-manager' ); ?>
					</a>
				</td>
			</tr>
			<tr>
				<td>
					<strong><?php esc_html_e( 'Scan Log', 'vcns-security-automation-manager' ); ?></strong>
					<p class="description"><?php esc_html_e( 'History of discovery scans, including ones that ran after a theme, plugin, or content change.', 'vcns-security-automation-manager' ); ?></p>
				</td>
				<td>&mdash;</td>
				<td>
					<a href="<?php echo esc_url( admin_url( 'admin.php?page=security-automation-manager-dashboard&tab=scan-log' ) ); ?>">
						<?php esc_html_e( 'View Scan Log', 'vcns-security-automation-manager' ); ?>
					</a>
				</td>
			</tr>
		</tbody>
	</table>

	<p class="description">
		<?php esc_html_e( 'Not yet available: an ongoing baseline/drift feed and certificate-change monitoring as first-class observation are planned for a future phase.', 'vcns-security-automation-manager' ); ?>
	</p>
</div>
