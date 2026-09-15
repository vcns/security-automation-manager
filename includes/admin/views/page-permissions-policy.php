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
	''     => __( '(browser default)', 'vcns-security-automation-manager' ),
	'none' => __( 'None', 'vcns-security-automation-manager' ),
	'self' => __( 'Self', 'vcns-security-automation-manager' ),
	'all'  => __( 'All', 'vcns-security-automation-manager' ),
);
?>
<div class="wrap wp-sam-wrap">
	<h1><?php esc_html_e( 'Permissions-Policy', 'vcns-security-automation-manager' ); ?></h1>

	<p>
		<?php esc_html_e( "Permissions-Policy controls which of the browser's own hardware and sensor features -- camera, microphone, precise location, and similar -- a page, and anything embedded inside it (a third-party ad, an embedded widget), is even allowed to ask the visitor for. It never asks the visitor anything itself: a feature set to None here is refused by the browser before any permission prompt would appear, the same way a locked door doesn't need a receptionist to turn people away.", 'vcns-security-automation-manager' ); ?>
	</p>
	<p>
		<?php esc_html_e( "Most of what runs in wp-admin, on the login screen, or against the REST API has no legitimate reason to touch a camera, a microphone, or a visitor's location -- so locking every directive to None on those surfaces closes off a capability a compromised plugin or an injected script could otherwise try to use, without taking anything away from what an administrator actually does there. The frontend is the surface most likely to need an exception carved out -- a store locator using geolocation, an embedded payment form using the Payment Request API -- which is why each surface and each directive is decided separately rather than all at once. A directive left at \"(browser default)\" is not emitted for that surface -- the browser applies its own default policy for that feature.", 'vcns-security-automation-manager' ); ?>
	</p>

	<table class="widefat striped wp-sam-readiness-table" style="margin-top: 1em;">
		<thead>
			<tr>
				<th><?php esc_html_e( 'Surface', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Enabled', 'vcns-security-automation-manager' ); ?></th>
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
		<?php esc_html_e( 'Changes apply immediately. "(browser default)" emits nothing for that surface, leaving the browser\'s own default policy in place. "None" blocks the feature entirely. "Self" allows it for this origin only. "All" allows any origin, including a third-party iframe or embed running alongside this site\'s own pages -- not just this site\'s own code -- so it is not recommended unless a specific integration genuinely needs it. There is no report-only mode, discovery workflow, or automation for this pillar.', 'vcns-security-automation-manager' ); ?>
	</p>
</div>
