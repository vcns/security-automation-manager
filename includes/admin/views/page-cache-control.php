<?php
/**
 * Admin view: Cache-Control -- per-surface enable + preset picker for
 * Cache_Control_Builder, gated by Cache_Control_Conflict_Detector.
 *
 * Not built on the shared page-pillar-simple.php template because this
 * pillar needs conflict-aware behaviour that template has no concept of:
 * GitHub issue #221's own explicit safety requirement that this section
 * "must be disabled/grayed out rather than emit a competing Cache-Control
 * header" when a known caching plugin is active or a CDN has been
 * acknowledged. When blocked, every control below is rendered disabled
 * and a warning notice explains why -- this mirrors the CSP conflict
 * banner's warning-notice visual language, not its literal mechanism
 * (that banner is dismissible and informational; it never disables a
 * control the way this page does).
 *
 * Rendered by Admin_UI::render_cache_control().
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WP_SAM\Security\Cache_Control_Builder;
use WP_SAM\Security\Cache_Control_Conflict_Detector;

global $wpdb;

$surfaces = array( 'frontend', 'admin', 'login', 'api' );

$profiles_raw = $wpdb->get_results(
	$wpdb->prepare(
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		"SELECT surface, enabled, payload FROM {$wpdb->prefix}sam_pillar_profiles WHERE pillar = %s",
		Cache_Control_Builder::PILLAR_KEY
	),
	ARRAY_A
);

$profiles_by_surface = array();
foreach ( ! empty( $profiles_raw ) ? $profiles_raw : array() as $row ) {
	$profiles_by_surface[ $row['surface'] ] = array(
		'enabled' => ! empty( $row['enabled'] ),
		'value'   => Cache_Control_Builder::extract_value( $row ),
	);
}

$value_options = array(
	'no-store'         => __( 'no-store -- never cache (recommended for sensitive surfaces)', 'vcns-security-automation-manager' ),
	'private-no-cache' => __( 'private, no-cache -- may be cached per-visitor, always revalidated', 'vcns-security-automation-manager' ),
	'public-short'     => __( 'public, max-age=300 -- may be cached by any cache for 5 minutes', 'vcns-security-automation-manager' ),
	'public-long'      => __( 'public, max-age=3600 -- may be cached by any cache for 1 hour', 'vcns-security-automation-manager' ),
);

$conflict         = Cache_Control_Conflict_Detector::detect();
$blocked          = $conflict['blocked'];
$cdn_acknowledged = ! empty( get_option( Cache_Control_Conflict_Detector::CDN_ACKNOWLEDGED_OPTION, false ) );
?>
<div class="wrap wp-sam-wrap">
	<h1><?php esc_html_e( 'Cache-Control', 'vcns-security-automation-manager' ); ?></h1>

	<p>
		<?php esc_html_e( 'Sets the Cache-Control header on a per-surface basis. WordPress core already sends its own strict no-cache header on admin, login, and other dynamic pages -- this pillar lets that be made explicit and, optionally, lets the frontend be given an actual caching policy.', 'vcns-security-automation-manager' ); ?>
	</p>

	<?php if ( $blocked ) : ?>
	<div class="notice notice-warning inline" style="padding:12px 16px;margin:1em 0;">
		<p style="margin-top:0">
			<strong><?php esc_html_e( 'This pillar is currently disabled.', 'vcns-security-automation-manager' ); ?></strong>
			<?php echo esc_html( $conflict['detail'] ); ?>
		</p>
		<p style="margin-bottom:0">
			<?php esc_html_e( 'To avoid sending a competing Cache-Control header, no value below will be emitted while this condition is present, even if a surface is shown as enabled.', 'vcns-security-automation-manager' ); ?>
		</p>
	</div>
	<?php endif; ?>

	<table class="widefat striped wp-sam-readiness-table" style="margin-top: 1em;">
		<thead>
			<tr>
				<th><?php esc_html_e( 'Surface', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Enabled', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Value', 'vcns-security-automation-manager' ); ?></th>
			</tr>
		</thead>
		<tbody>
			<?php foreach ( $surfaces as $surface ) : ?>
				<?php
				$current = $profiles_by_surface[ $surface ] ?? array(
					'enabled' => false,
					'value'   => Cache_Control_Builder::DEFAULT_VALUE,
				);
				?>
				<tr>
					<td><?php echo esc_html( ucfirst( $surface ) ); ?></td>
					<td>
						<input
							type="checkbox"
							class="wp-sam-pillar-enabled"
							data-pillar="<?php echo esc_attr( Cache_Control_Builder::PILLAR_KEY ); ?>"
							data-surface="<?php echo esc_attr( $surface ); ?>"
							<?php checked( $current['enabled'] ); ?>
							<?php disabled( $blocked ); ?>
						/>
					</td>
					<td>
						<select
							class="wp-sam-pillar-value"
							data-pillar="<?php echo esc_attr( Cache_Control_Builder::PILLAR_KEY ); ?>"
							data-surface="<?php echo esc_attr( $surface ); ?>"
							<?php disabled( $blocked ); ?>
						>
							<?php $current_value = '' !== $current['value'] ? $current['value'] : Cache_Control_Builder::DEFAULT_VALUE; ?>
							<?php foreach ( $value_options as $value => $label ) : ?>
								<option value="<?php echo esc_attr( $value ); ?>" <?php selected( $current_value, $value ); ?>>
									<?php echo esc_html( $label ); ?>
								</option>
							<?php endforeach; ?>
						</select>
					</td>
				</tr>
			<?php endforeach; ?>
		</tbody>
	</table>

	<p class="description" style="margin-top: 1em;">
		<?php esc_html_e( 'Unlike every other pillar on this page, Cache-Control is not enabled by default on any surface -- it is a caching/performance decision, not a universal security hardening default, and WordPress core already protects admin and login pages on its own.', 'vcns-security-automation-manager' ); ?>
	</p>

	<h2 style="margin-top:2em"><?php esc_html_e( 'CDN / Edge Cache Acknowledgement', 'vcns-security-automation-manager' ); ?></h2>
	<p class="description">
		<?php esc_html_e( 'A CDN or reverse proxy in front of this site manages its own caching in a way this plugin cannot see from a single PHP request, so it cannot be detected automatically. If one is in use, acknowledge it here to keep this pillar from emitting a Cache-Control value that could compete with it.', 'vcns-security-automation-manager' ); ?>
	</p>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:1em">
		<?php wp_nonce_field( 'wp_sam_cache_control_cdn_acknowledge' ); ?>
		<input type="hidden" name="action" value="wp_sam_cache_control_cdn_acknowledge" />
		<label>
			<input type="checkbox" name="cdn_acknowledged" value="1" <?php checked( $cdn_acknowledged ); ?> />
			<?php esc_html_e( 'This site is behind a CDN or edge cache that manages its own caching.', 'vcns-security-automation-manager' ); ?>
		</label>
		<?php submit_button( __( 'Save', 'vcns-security-automation-manager' ), 'secondary', '', false, array( 'style' => 'margin-left:1em' ) ); ?>
	</form>
</div>
