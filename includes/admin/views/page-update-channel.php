<?php
/**
 * Admin view: Update Channel status.
 * Rendered by Admin_UI::render_update_channel().
 *
 * WordPress.org builds must never display or use the GitHub update
 * service. This file branches on WP_SAM_DISTRIBUTION_CHANNEL up front --
 * the WordPress.org branch never references Github_Update_Checker (which
 * isn't even present in that build's ZIP, see release-package.yml) or the
 * diagnostics option it writes, and uses the raw option name string
 * rather than a class constant so nothing here can trigger autoloading a
 * class that doesn't exist on disk in that build.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$is_github_channel = 'github' === WP_SAM_DISTRIBUTION_CHANNEL;
?>
<div class="wrap wp-sam-wrap">
	<h1><?php esc_html_e( 'Update Channel', 'security-automation-manager' ); ?></h1>

	<table class="widefat striped wp-sam-readiness-table" style="margin-top: 1em; max-width: 760px;">
		<tbody>
			<tr>
				<th scope="row"><?php esc_html_e( 'Installed version', 'security-automation-manager' ); ?></th>
				<td><?php echo esc_html( WP_SAM_VERSION ); ?></td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Build channel', 'security-automation-manager' ); ?></th>
				<td>
					<?php
					if ( $is_github_channel ) {
						esc_html_e( 'VCNS GitHub', 'security-automation-manager' );
					} elseif ( 'wordpress-org' === WP_SAM_DISTRIBUTION_CHANNEL ) {
						esc_html_e( 'WordPress.org', 'security-automation-manager' );
					} else {
						esc_html_e( 'Development or unknown', 'security-automation-manager' );
					}
					?>
				</td>
			</tr>
		</tbody>
	</table>

	<?php if ( ! $is_github_channel ) : ?>

	<p class="description" style="max-width: 760px;">
		<?php esc_html_e( 'This install updates through the WordPress.org plugin directory, the same mechanism as any other WordPress.org plugin. No custom updater runs in this build, and it never contacts any VCNS-operated update service.', 'security-automation-manager' ); ?>
	</p>

	<?php else : ?>

		<?php
		$diagnostics = get_option( 'wp_sam_update_diagnostics', array() );
		$diagnostics = is_array( $diagnostics ) ? $diagnostics : array();

		$check_result_labels    = array(
			'success'          => __( 'Valid', 'security-automation-manager' ),
			'http_error'       => __( 'Failed -- could not reach the update endpoint', 'security-automation-manager' ),
			'invalid_manifest' => __( 'Failed -- manifest rejected (slug, version, host, or checksum format invalid)', 'security-automation-manager' ),
		);
		$checksum_result_labels = array(
			'verified' => __( 'Verified', 'security-automation-manager' ),
			'mismatch' => __( 'Failed -- downloaded package did not match the declared checksum', 'security-automation-manager' ),
			'missing'  => __( 'Failed -- manifest did not declare a valid checksum', 'security-automation-manager' ),
		);
		$applied_result_labels  = array(
			'success' => __( 'Succeeded', 'security-automation-manager' ),
			'failure' => __( 'Failed', 'security-automation-manager' ),
		);

		$never             = __( 'Never', 'security-automation-manager' );
		$none_recorded     = __( 'None recorded', 'security-automation-manager' );
		$not_yet_attempted = __( 'Not yet attempted', 'security-automation-manager' );
		$no_update_applied = __( 'No update applied yet', 'security-automation-manager' );

		$kill_switch_defined = defined( 'WP_SAM_DISABLE_AUTO_UPDATE' );
		$kill_switch_engaged = $kill_switch_defined && (bool) constant( 'WP_SAM_DISABLE_AUTO_UPDATE' );

		$available_version = (string) ( $diagnostics['available_version'] ?? '' );
		$update_pending    = '' !== $available_version && version_compare( WP_SAM_VERSION, $available_version, '<' );
		?>

	<table class="widefat striped wp-sam-readiness-table" style="margin-top: 1.5em; max-width: 760px;">
		<tbody>
			<tr>
				<th scope="row"><?php esc_html_e( 'Update manifest URL', 'security-automation-manager' ); ?></th>
				<td><code><?php echo esc_html( defined( 'WP_SAM_UPDATE_MANIFEST_URL' ) ? WP_SAM_UPDATE_MANIFEST_URL : '' ); ?></code></td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Available version', 'security-automation-manager' ); ?></th>
				<td>
					<?php if ( '' === $available_version ) : ?>
						<?php esc_html_e( 'Unknown -- no successful check yet', 'security-automation-manager' ); ?>
					<?php elseif ( $update_pending ) : ?>
						<?php echo esc_html( $available_version ); ?> <strong>(<?php esc_html_e( 'update available', 'security-automation-manager' ); ?>)</strong>
					<?php else : ?>
						<?php echo esc_html( $available_version ); ?> (<?php esc_html_e( 'up to date', 'security-automation-manager' ); ?>)
					<?php endif; ?>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Last successful update check', 'security-automation-manager' ); ?></th>
				<td><?php echo esc_html( (string) ( $diagnostics['last_check_success_at'] ?? $never ) ); ?></td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Last failed update check', 'security-automation-manager' ); ?></th>
				<td><?php echo esc_html( (string) ( $diagnostics['last_check_failure_at'] ?? $none_recorded ) ); ?></td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Manifest validation status', 'security-automation-manager' ); ?></th>
				<td><?php echo esc_html( $check_result_labels[ $diagnostics['last_check_result'] ?? '' ] ?? $never ); ?></td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Package checksum verification status', 'security-automation-manager' ); ?></th>
				<td>
					<?php echo esc_html( $checksum_result_labels[ $diagnostics['last_checksum_result'] ?? '' ] ?? $not_yet_attempted ); ?>
					<?php if ( ! empty( $diagnostics['last_checksum_at'] ) ) : ?>
						<span class="description"> (<?php echo esc_html( (string) $diagnostics['last_checksum_at'] ); ?>)</span>
					<?php endif; ?>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Last update result', 'security-automation-manager' ); ?></th>
				<td>
					<?php echo esc_html( $applied_result_labels[ $diagnostics['last_applied_result'] ?? '' ] ?? $no_update_applied ); ?>
					<?php if ( ! empty( $diagnostics['last_applied_at'] ) ) : ?>
						<span class="description"> (<?php echo esc_html( (string) $diagnostics['last_applied_at'] ); ?>)</span>
					<?php endif; ?>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'WP_SAM_DISABLE_AUTO_UPDATE defined', 'security-automation-manager' ); ?></th>
				<td>
					<?php
					if ( ! $kill_switch_defined ) {
						esc_html_e( 'No', 'security-automation-manager' );
					} elseif ( $kill_switch_engaged ) {
						esc_html_e( 'Yes -- true', 'security-automation-manager' );
					} else {
						esc_html_e( 'Yes -- false', 'security-automation-manager' );
					}
					?>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Background updates', 'security-automation-manager' ); ?></th>
				<td>
					<?php
					if ( $kill_switch_engaged ) {
						esc_html_e( 'Blocked by WP_SAM_DISABLE_AUTO_UPDATE.', 'security-automation-manager' );
					} else {
						esc_html_e( "Not blocked by this plugin. Still subject to WordPress' own per-plugin auto-update setting on the Plugins screen.", 'security-automation-manager' );
					}
					?>
				</td>
			</tr>
		</tbody>
	</table>

	<p class="description" style="max-width: 760px; margin-top: 1em;">
		<?php esc_html_e( 'This updater never transmits or stores any credential or secret -- the manifest above is a public JSON file, and package integrity is verified with a SHA-256 checksum published in that same public manifest.', 'security-automation-manager' ); ?>
	</p>

	<?php endif; ?>
</div>
