<?php
/**
 * Admin view: Information Masking -- per-surface enable toggle for
 * Information_Masking_Builder (X-Powered-By, Server, X-Pingback removal)
 * plus Information_Masking_Diagnostic's live readiness check.
 *
 * Not built on the shared page-pillar-simple.php template (unlike
 * X-Frame-Options/X-Content-Type-Options/Referrer-Policy) because this
 * pillar needs a second section that template has no room for: the
 * diagnostic check, reporting whether each removal is actually taking
 * effect on this specific install (GitHub issue #220's own acceptance
 * criterion -- Server in particular is host-dependent, see Information_
 * Masking_Builder's own docblock).
 *
 * Rendered by Admin_UI::render_information_masking().
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WP_SAM\Security\Information_Masking_Builder;
use WP_SAM\Security\Information_Masking_Diagnostic;

global $wpdb;

$surfaces = array( 'frontend', 'admin', 'login', 'api' );

$profiles_raw = $wpdb->get_results(
	$wpdb->prepare(
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		"SELECT surface, enabled FROM {$wpdb->prefix}sam_pillar_profiles WHERE pillar = %s",
		Information_Masking_Builder::PILLAR_KEY
	),
	ARRAY_A
);

$enabled_by_surface = array();
foreach ( ! empty( $profiles_raw ) ? $profiles_raw : array() as $row ) {
	$enabled_by_surface[ $row['surface'] ] = ! empty( $row['enabled'] );
}

$diagnostic      = new Information_Masking_Diagnostic();
$diag_results    = $diagnostic->results();
$diag_checked_at = $diagnostic->checked_at();
$diag_status     = $diagnostic->last_status();

$item_labels = array(
	'x-powered-by' => __( 'X-Powered-By (PHP version)', 'vcns-security-automation-manager' ),
	'server'       => __( 'Server (web-server signature)', 'vcns-security-automation-manager' ),
	'x-pingback'   => __( 'X-Pingback (this site\'s own hostname)', 'vcns-security-automation-manager' ),
);
?>
<div class="wrap wp-sam-wrap">
	<h1><?php esc_html_e( 'Information Masking', 'vcns-security-automation-manager' ); ?></h1>

	<p>
		<?php esc_html_e( 'Removes headers that disclose the server stack, PHP version, or this site\'s own hostname -- reconnaissance a scanner or attacker would otherwise get for free before ever sending a single probe.', 'vcns-security-automation-manager' ); ?>
	</p>

	<table class="widefat striped wp-sam-readiness-table" style="margin-top: 1em;">
		<thead>
			<tr>
				<th><?php esc_html_e( 'Surface', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Enabled', 'vcns-security-automation-manager' ); ?></th>
			</tr>
		</thead>
		<tbody>
			<?php foreach ( $surfaces as $surface ) : ?>
				<tr>
					<td><?php echo esc_html( ucfirst( $surface ) ); ?></td>
					<td>
						<input
							type="checkbox"
							class="wp-sam-pillar-enabled"
							data-pillar="<?php echo esc_attr( Information_Masking_Builder::PILLAR_KEY ); ?>"
							data-surface="<?php echo esc_attr( $surface ); ?>"
							<?php checked( $enabled_by_surface[ $surface ] ?? false ); ?>
						/>
					</td>
				</tr>
			<?php endforeach; ?>
		</tbody>
	</table>

	<p class="description" style="margin-top: 1em;">
		<?php esc_html_e( 'Changes apply immediately. X-Powered-By and X-Pingback are removed directly from PHP and this always works. Server is best-effort -- see the readiness check below.', 'vcns-security-automation-manager' ); ?>
	</p>

	<h2 style="margin-top:2em"><?php esc_html_e( 'Readiness Check', 'vcns-security-automation-manager' ); ?></h2>
	<p class="description">
		<?php esc_html_e( 'Probes this site\'s own front page over real HTTP and reports whether each header is actually absent from the response. Server is set by the web server itself on most hosts, before PHP ever runs -- a "Present" result for Server is a real limit of this hosting environment, not necessarily a plugin fault; Apache\'s ServerTokens/ServerSignature or Nginx\'s server_tokens off; are the host-level fix in that case.', 'vcns-security-automation-manager' ); ?>
	</p>

	<table class="widefat fixed striped wp-sam-violations-table" style="margin-top:1em;max-width:600px">
		<thead>
			<tr>
				<th><?php esc_html_e( 'Header', 'vcns-security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Result', 'vcns-security-automation-manager' ); ?></th>
			</tr>
		</thead>
		<tbody>
			<?php foreach ( $item_labels as $item_key => $item_label ) : ?>
				<?php $result = $diag_results[ $item_key ] ?? null; ?>
				<tr>
					<td><?php echo esc_html( $item_label ); ?></td>
					<td>
						<?php if ( null === $result ) : ?>
							<?php esc_html_e( 'Not yet checked', 'vcns-security-automation-manager' ); ?>
						<?php elseif ( 'masked' === $result ) : ?>
							<strong style="color:#1a7f37"><?php esc_html_e( 'Masked', 'vcns-security-automation-manager' ); ?></strong>
						<?php else : ?>
							<strong style="color:#cc1818"><?php esc_html_e( 'Present', 'vcns-security-automation-manager' ); ?></strong>
						<?php endif; ?>
					</td>
				</tr>
			<?php endforeach; ?>
		</tbody>
	</table>

	<table class="widefat fixed striped wp-sam-violations-table" style="margin-top:1em;max-width:600px">
		<tbody>
			<tr>
				<th style="width:200px"><?php esc_html_e( 'Last checked', 'vcns-security-automation-manager' ); ?></th>
				<td><?php echo esc_html( $diag_checked_at ?? __( 'Never', 'vcns-security-automation-manager' ) ); ?></td>
			</tr>
			<tr>
				<th><?php esc_html_e( 'Last check status', 'vcns-security-automation-manager' ); ?></th>
				<td><?php echo esc_html( '' !== $diag_status ? ucfirst( $diag_status ) : __( 'Not yet run', 'vcns-security-automation-manager' ) ); ?></td>
			</tr>
		</tbody>
	</table>

	<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:1em">
		<?php wp_nonce_field( 'wp_sam_information_masking_check' ); ?>
		<input type="hidden" name="action" value="wp_sam_information_masking_check" />
		<?php submit_button( __( 'Check Now', 'vcns-security-automation-manager' ), 'secondary', '', false ); ?>
	</form>
</div>
