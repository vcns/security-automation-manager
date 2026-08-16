<?php
/**
 * Admin view: Permissions-Policy per-surface, per-directive picker.
 * Rendered by Admin_UI::render_permissions_policy().
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WP_SAM\Security\Permissions_Policy_Builder;

global $wpdb;

$surfaces   = array( 'frontend', 'admin', 'login', 'api' );
$directives = Permissions_Policy_Builder::KNOWN_DIRECTIVES;

$profiles_raw = $wpdb->get_results(
	$wpdb->prepare(
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		"SELECT surface, enabled, payload FROM {$wpdb->prefix}sam_pillar_profiles WHERE pillar = %s",
		Permissions_Policy_Builder::PILLAR_KEY
	),
	ARRAY_A
);

$state_by_surface = array();
foreach ( ! empty( $profiles_raw ) ? $profiles_raw : array() as $row ) {
	$state_by_surface[ $row['surface'] ] = array(
		'enabled'    => ! empty( $row['enabled'] ),
		'directives' => Permissions_Policy_Builder::extract_directives( $row ),
	);
}

$token_labels = array(
	''     => __( '(browser default)', 'security-automation-manager' ),
	'none' => __( 'None', 'security-automation-manager' ),
	'self' => __( 'Self', 'security-automation-manager' ),
	'all'  => __( 'All -- any origin, including third-party iframes and embeds (not recommended)', 'security-automation-manager' ),
);
?>
<div class="wrap wp-sam-wrap">
	<h1><?php esc_html_e( 'Permissions-Policy', 'security-automation-manager' ); ?></h1>

	<p>
		<?php esc_html_e( 'Controls which browser features (camera, geolocation, and similar) this site allows, per surface. A directive left at "(browser default)" is not emitted for that surface -- the browser applies its own default policy for that feature.', 'security-automation-manager' ); ?>
	</p>

	<table class="widefat striped wp-sam-readiness-table" style="margin-top: 1em;">
		<thead>
			<tr>
				<th><?php esc_html_e( 'Surface', 'security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Enabled', 'security-automation-manager' ); ?></th>
				<?php foreach ( $directives as $directive ) : ?>
					<th><code><?php echo esc_html( $directive ); ?></code></th>
				<?php endforeach; ?>
			</tr>
		</thead>
		<tbody>
			<?php foreach ( $surfaces as $surface ) : ?>
				<?php
				$current = $state_by_surface[ $surface ] ?? array(
					'enabled'    => false,
					'directives' => array(),
				);
				?>
				<tr>
					<td><?php echo esc_html( ucfirst( $surface ) ); ?></td>
					<td>
						<input
							type="checkbox"
							class="wp-sam-permissions-policy-enabled"
							data-surface="<?php echo esc_attr( $surface ); ?>"
							<?php checked( $current['enabled'] ); ?>
						/>
					</td>
					<?php foreach ( $directives as $directive ) : ?>
						<?php $current_token = $current['directives'][ $directive ] ?? ''; ?>
						<td>
							<select
								class="wp-sam-permissions-policy-directive"
								data-surface="<?php echo esc_attr( $surface ); ?>"
								data-directive="<?php echo esc_attr( $directive ); ?>"
							>
								<?php foreach ( $token_labels as $token => $label ) : ?>
									<option value="<?php echo esc_attr( $token ); ?>" <?php selected( $current_token, $token ); ?>>
										<?php echo esc_html( $label ); ?>
									</option>
								<?php endforeach; ?>
							</select>
						</td>
					<?php endforeach; ?>
				</tr>
			<?php endforeach; ?>
		</tbody>
	</table>

	<p class="description" style="margin-top: 1em;">
		<?php esc_html_e( 'Changes apply immediately. "None" blocks the feature entirely, "Self" allows it for this origin only, "All" allows any origin. There is no report-only mode, discovery workflow, or automation for this pillar.', 'security-automation-manager' ); ?>
	</p>
</div>
