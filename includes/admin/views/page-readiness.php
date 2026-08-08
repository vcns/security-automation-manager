<?php
/**
 * Plugin readiness and reset page.
 *
 * @var array $readiness Readiness report from Readiness_Checker.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$reset_result = sanitize_text_field( wp_unslash( $_GET['wp_sam_reset'] ?? '' ) );
$status_badge = static function ( string $status ): void {
	$labels = array(
		'pass'    => __( 'Pass', 'security-automation-manager' ),
		'warning' => __( 'Warning', 'security-automation-manager' ),
		'fail'    => __( 'Fail', 'security-automation-manager' ),
	);
	$label  = $labels[ $status ] ?? __( 'Unknown', 'security-automation-manager' );

	printf(
		'<span class="wp-sam-readiness-badge status-%1$s">%2$s</span>',
		esc_attr( $status ),
		esc_html( $label )
	);
};
?>
<div class="wrap wp-sam-wrap">
	<h1><?php esc_html_e( 'Readiness', 'security-automation-manager' ); ?></h1>
	<p class="description">
		<?php esc_html_e( 'Plugin-specific checks for schema, runtime defaults, reporting configuration, and reset readiness.', 'security-automation-manager' ); ?>
	</p>

	<?php if ( 'success' === $reset_result ) : ?>
		<div class="notice notice-success is-dismissible">
			<p><?php esc_html_e( 'Security Automation Manager data has been reset and default profiles have been reseeded.', 'security-automation-manager' ); ?></p>
		</div>
	<?php elseif ( 'partial' === $reset_result ) : ?>
		<div class="notice notice-warning is-dismissible">
			<p><?php esc_html_e( 'Reset completed, but one or more plugin tables could not be cleared. Review schema health below.', 'security-automation-manager' ); ?></p>
		</div>
	<?php elseif ( 'failed' === $reset_result ) : ?>
		<div class="notice notice-error is-dismissible">
			<p><?php esc_html_e( 'Reset was not performed. Confirm the typed phrase and re-authenticate with your current WordPress password.', 'security-automation-manager' ); ?></p>
		</div>
	<?php endif; ?>

	<h2><?php esc_html_e( 'Plugin and Database', 'security-automation-manager' ); ?></h2>
	<table class="widefat striped wp-sam-readiness-table">
		<thead>
			<tr>
				<th scope="col"><?php esc_html_e( 'Check', 'security-automation-manager' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Value', 'security-automation-manager' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Status', 'security-automation-manager' ); ?></th>
			</tr>
		</thead>
		<tbody>
			<?php foreach ( $readiness['plugin'] as $item ) : ?>
				<tr>
					<th scope="row"><?php echo esc_html( $item['label'] ); ?></th>
					<td><code><?php echo esc_html( (string) $item['value'] ); ?></code></td>
					<td><?php $status_badge( $item['status'] ); ?></td>
				</tr>
			<?php endforeach; ?>
		</tbody>
	</table>

	<h2><?php esc_html_e( 'Schema Health', 'security-automation-manager' ); ?></h2>
	<table class="widefat striped wp-sam-readiness-table">
		<thead>
			<tr>
				<th scope="col"><?php esc_html_e( 'Table', 'security-automation-manager' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Rows', 'security-automation-manager' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Status', 'security-automation-manager' ); ?></th>
			</tr>
		</thead>
		<tbody>
			<?php foreach ( $readiness['schema'] as $item ) : ?>
				<tr>
					<th scope="row"><code><?php echo esc_html( $item['table'] ); ?></code></th>
					<td>
						<?php
						echo null === $item['rows']
							? esc_html__( 'Missing', 'security-automation-manager' )
							: esc_html( (string) $item['rows'] );
						?>
					</td>
					<td><?php $status_badge( $item['status'] ); ?></td>
				</tr>
			<?php endforeach; ?>
		</tbody>
	</table>

	<h2><?php esc_html_e( 'Operational Health', 'security-automation-manager' ); ?></h2>
	<table class="widefat striped wp-sam-readiness-table">
		<thead>
			<tr>
				<th scope="col"><?php esc_html_e( 'Check', 'security-automation-manager' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Value', 'security-automation-manager' ); ?></th>
				<th scope="col"><?php esc_html_e( 'Status', 'security-automation-manager' ); ?></th>
			</tr>
		</thead>
		<tbody>
			<?php foreach ( $readiness['health'] as $item ) : ?>
				<tr>
					<th scope="row"><?php echo esc_html( $item['label'] ); ?></th>
					<td><code><?php echo esc_html( (string) $item['value'] ); ?></code></td>
					<td><?php $status_badge( $item['status'] ); ?></td>
				</tr>
			<?php endforeach; ?>
		</tbody>
	</table>

	<hr>

	<h2 id="wp-sam-reset"><?php esc_html_e( 'Reset Plugin Data', 'security-automation-manager' ); ?></h2>
	<p>
		<?php esc_html_e( 'This clears Security Automation Manager custom-table rows and plugin-owned runtime options, then reseeds the default policy profiles needed for a clean start.', 'security-automation-manager' ); ?>
	</p>
	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="wp-sam-reset-form">
		<?php wp_nonce_field( 'wp_sam_reset_data' ); ?>
		<input type="hidden" name="action" value="wp_sam_reset_data">
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row">
					<label for="wp_sam_current_password"><?php esc_html_e( 'Current password', 'security-automation-manager' ); ?></label>
				</th>
				<td>
					<input type="password" id="wp_sam_current_password" name="wp_sam_current_password" class="regular-text" autocomplete="current-password" required>
					<p class="description"><?php esc_html_e( 'Required to re-authenticate the currently logged-in administrator before destructive reset.', 'security-automation-manager' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row">
					<label for="wp_sam_reset_confirmation"><?php esc_html_e( 'Confirmation', 'security-automation-manager' ); ?></label>
				</th>
				<td>
					<input type="text" id="wp_sam_reset_confirmation" name="wp_sam_reset_confirmation" class="regular-text" pattern="RESET CSP DATA" required>
					<p class="description"><?php esc_html_e( 'Type RESET CSP DATA to start from a blank CSP canvas.', 'security-automation-manager' ); ?></p>
				</td>
			</tr>
		</table>
		<?php submit_button( __( 'Reset CSP Data', 'security-automation-manager' ), 'delete' ); ?>
	</form>
</div>
