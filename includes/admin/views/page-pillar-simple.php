<?php
/**
 * Admin view: shared per-surface picker for the "simple" header pillars
 * (X-Frame-Options, X-Content-Type-Options, Referrer-Policy) -- pillars with
 * nothing beyond an enable toggle and, optionally, a single value select.
 *
 * Rendered by Admin_UI::render_pillar_page(), which sets:
 *   string      $pillar_key      sam_pillar_profiles.pillar
 *   string      $page_title
 *   string      $header_name     the actual HTTP header name, for display
 *   string      $intro_html      allowed-tags help copy above the table
 *   array|null  $value_options   value => label options, or null for no picker
 *   string      $warning_html    optional allowed-tags warning copy, rendered
 *                                 in a prominent notice box above $intro_html
 *                                 for a pillar with real breakage risk (e.g.
 *                                 Cross-Origin-Opener-Policy,
 *                                 Cross-Origin-Embedder-Policy); '' for none
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

global $wpdb;

$surfaces = array( 'frontend', 'admin', 'login', 'api' );

$profiles_raw = $wpdb->get_results(
	$wpdb->prepare(
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		"SELECT surface, enabled, payload FROM {$wpdb->prefix}sam_pillar_profiles WHERE pillar = %s",
		$pillar_key
	),
	ARRAY_A
);

$profiles_by_surface = array();
foreach ( ! empty( $profiles_raw ) ? $profiles_raw : array() as $row ) {
	$payload                                = json_decode( (string) $row['payload'], true );
	$profiles_by_surface[ $row['surface'] ] = array(
		'enabled' => ! empty( $row['enabled'] ),
		'value'   => is_array( $payload ) ? (string) ( $payload['value'] ?? '' ) : '',
	);
}
?>
<div class="wrap wp-sam-wrap">
	<h1><?php echo esc_html( $page_title ); ?></h1>

	<?php if ( ! empty( $warning_html ) ) : ?>
	<div class="notice notice-warning inline" style="padding:12px 16px;margin:1em 0;">
		<?php echo wp_kses_post( $warning_html ); ?>
	</div>
	<?php endif; ?>

	<?php echo wp_kses_post( $intro_html ); ?>

	<table class="widefat striped wp-sam-readiness-table" style="margin-top: 1em;">
		<thead>
			<tr>
				<th><?php esc_html_e( 'Surface', 'security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Enabled', 'security-automation-manager' ); ?></th>
				<?php if ( null !== $value_options ) : ?>
					<th><?php esc_html_e( 'Value', 'security-automation-manager' ); ?></th>
				<?php endif; ?>
			</tr>
		</thead>
		<tbody>
			<?php foreach ( $surfaces as $surface ) : ?>
				<?php
				$current = $profiles_by_surface[ $surface ] ?? array(
					'enabled' => false,
					'value'   => '',
				);
				?>
				<tr>
					<td><?php echo esc_html( ucfirst( $surface ) ); ?></td>
					<td>
						<input
							type="checkbox"
							class="wp-sam-pillar-enabled"
							data-pillar="<?php echo esc_attr( $pillar_key ); ?>"
							data-surface="<?php echo esc_attr( $surface ); ?>"
							<?php checked( $current['enabled'] ); ?>
						/>
					</td>
					<?php if ( null !== $value_options ) : ?>
						<td>
							<select
								class="wp-sam-pillar-value"
								data-pillar="<?php echo esc_attr( $pillar_key ); ?>"
								data-surface="<?php echo esc_attr( $surface ); ?>"
							>
								<?php foreach ( $value_options as $value => $label ) : ?>
									<option value="<?php echo esc_attr( $value ); ?>" <?php selected( $current['value'], $value ); ?>>
										<?php echo esc_html( $label ); ?>
									</option>
								<?php endforeach; ?>
							</select>
						</td>
					<?php endif; ?>
				</tr>
			<?php endforeach; ?>
		</tbody>
	</table>

	<p class="description" style="margin-top: 1em;">
		<?php
		echo wp_kses_post(
			sprintf(
			/* translators: %s: HTTP header name, e.g. "X-Frame-Options" */
				__( 'Changes apply immediately -- there is no report-only mode, discovery workflow, or automation for this pillar. The %s header is either sent exactly as configured, or not sent at all.', 'security-automation-manager' ),
				'<code>' . esc_html( $header_name ) . '</code>'
			)
		);
		?>
	</p>
</div>
