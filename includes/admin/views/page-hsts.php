<?php
/**
 * Admin view: Strict-Transport-Security (HSTS) per-surface configuration.
 * Rendered by Admin_UI::render_hsts().
 *
 * Not the shared page-pillar-simple.php template -- this pillar has three
 * independently-configurable fields per surface (max-age, includeSubDomains,
 * preload), closer in shape to Permissions-Policy than to a single value
 * picker.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WP_SAM\Security\Strict_Transport_Security_Builder;

global $wpdb;

$surfaces = array( 'frontend', 'admin', 'login', 'api' );

$profiles_raw = $wpdb->get_results(
	$wpdb->prepare(
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		"SELECT surface, enabled, payload FROM {$wpdb->prefix}sam_pillar_profiles WHERE pillar = %s",
		Strict_Transport_Security_Builder::PILLAR_KEY
	),
	ARRAY_A
);

$state_by_surface = array();
foreach ( ! empty( $profiles_raw ) ? $profiles_raw : array() as $row ) {
	$state_by_surface[ $row['surface'] ] = array_merge(
		array( 'enabled' => ! empty( $row['enabled'] ) ),
		Strict_Transport_Security_Builder::extract_settings( $row )
	);
}

$max_age_options = array(
	300      => __( '5 minutes (testing only)', 'security-automation-manager' ),
	86400    => __( '1 day', 'security-automation-manager' ),
	604800   => __( '1 week', 'security-automation-manager' ),
	2592000  => __( '30 days', 'security-automation-manager' ),
	15552000 => __( '180 days', 'security-automation-manager' ),
	31536000 => __( '1 year (minimum for preload)', 'security-automation-manager' ),
	63072000 => __( '2 years (recommended for preload)', 'security-automation-manager' ),
);
?>
<div class="wrap wp-sam-wrap">
	<h1><?php esc_html_e( 'Strict-Transport-Security (HSTS)', 'security-automation-manager' ); ?></h1>

	<div class="notice notice-warning inline" style="padding:12px 16px;margin:1em 0;">
		<p style="margin-top:0;">
			<?php esc_html_e( 'Unlike this plugin\'s other headers, HSTS is sticky. Once a browser receives this header, it remembers the Max-Age and refuses plain-HTTP connections to this site for that long -- disabling the header afterward does not undo that for browsers that already cached it. There is no report-only mode to rehearse a rollout with either.', 'security-automation-manager' ); ?>
		</p>
		<p style="margin-bottom:0;">
			<?php esc_html_e( 'Start with a short Max-Age while confirming every surface, subdomain, and asset genuinely works over HTTPS, then increase it once confident. Preload goes further still: submitting this domain to browsers\' built-in preload lists can take months to reverse, so it stays off until Max-Age and Include Subdomains already meet the submission requirements below.', 'security-automation-manager' ); ?>
		</p>
	</div>

	<p>
		<?php esc_html_e( 'This header is only ever sent over an HTTPS connection -- sending it over plain HTTP would have no effect on browsers and would misrepresent the site as HTTPS-only before it actually is.', 'security-automation-manager' ); ?>
	</p>

	<table class="widefat striped wp-sam-readiness-table" style="margin-top: 1em;">
		<thead>
			<tr>
				<th><?php esc_html_e( 'Surface', 'security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Enabled', 'security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Max-Age', 'security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Include Subdomains', 'security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Preload', 'security-automation-manager' ); ?></th>
			</tr>
		</thead>
		<tbody>
			<?php foreach ( $surfaces as $surface ) : ?>
				<?php
				$current          = $state_by_surface[ $surface ] ?? array(
					'enabled'            => false,
					'max_age'            => Strict_Transport_Security_Builder::DEFAULT_MAX_AGE,
					'include_subdomains' => false,
					'preload'            => false,
				);
				$preload_eligible = Strict_Transport_Security_Builder::preload_eligible( $current['max_age'], $current['include_subdomains'] );
				?>
				<tr>
					<td><?php echo esc_html( ucfirst( $surface ) ); ?></td>
					<td>
						<input
							type="checkbox"
							class="wp-sam-hsts-enabled"
							data-surface="<?php echo esc_attr( $surface ); ?>"
							<?php checked( $current['enabled'] ); ?>
						/>
					</td>
					<td>
						<select
							class="wp-sam-hsts-max-age"
							data-surface="<?php echo esc_attr( $surface ); ?>"
						>
							<?php foreach ( $max_age_options as $seconds => $label ) : ?>
								<option value="<?php echo esc_attr( (string) $seconds ); ?>" <?php selected( $current['max_age'], $seconds ); ?>>
									<?php echo esc_html( $label ); ?>
								</option>
							<?php endforeach; ?>
						</select>
					</td>
					<td>
						<input
							type="checkbox"
							class="wp-sam-hsts-include-subdomains"
							data-surface="<?php echo esc_attr( $surface ); ?>"
							<?php checked( $current['include_subdomains'] ); ?>
						/>
					</td>
					<td>
						<input
							type="checkbox"
							class="wp-sam-hsts-preload"
							data-surface="<?php echo esc_attr( $surface ); ?>"
							<?php checked( $current['preload'] ); ?>
							<?php disabled( ! $preload_eligible ); ?>
						/>
					</td>
				</tr>
			<?php endforeach; ?>
		</tbody>
	</table>

	<p class="description" style="margin-top: 1em;">
		<?php esc_html_e( 'Changes apply immediately. Preload is only selectable once Max-Age is at least 1 year and Include Subdomains is on -- the minimum hstspreload.org requires for submission. There is no report-only mode, discovery workflow, or automation for this pillar.', 'security-automation-manager' ); ?>
	</p>
</div>
