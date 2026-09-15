<?php
/**
 * Admin view: Reverse Tabnabbing Protection per-surface on/off.
 * Rendered by Admin_UI::render_reverse_tabnabbing().
 *
 * Not a header pillar -- this rewrites rendered HTML (adds rel="noopener"
 * to target="_blank" links), so the shared page-pillar-simple.php template
 * (which describes "the header is either sent or not sent") doesn't apply
 * verbatim. Same enabled-only table shape as X-Content-Type-Options.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WP_SAM\Security\Reverse_Tabnabbing_Builder;

global $wpdb;

$surfaces = array( 'frontend', 'admin', 'login', 'api' );

$profiles_raw = $wpdb->get_results(
	$wpdb->prepare(
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		"SELECT surface, enabled FROM {$wpdb->prefix}sam_pillar_profiles WHERE pillar = %s",
		Reverse_Tabnabbing_Builder::PILLAR_KEY
	),
	ARRAY_A
);

$enabled_by_surface = array();
foreach ( ! empty( $profiles_raw ) ? $profiles_raw : array() as $row ) {
	$enabled_by_surface[ $row['surface'] ] = ! empty( $row['enabled'] );
}
?>
<div class="wrap wp-sam-wrap">
	<h1><?php esc_html_e( 'Reverse Tabnabbing Protection', 'vcns-security-automation-manager' ); ?></h1>

	<p>
		<?php esc_html_e( 'A link with target="_blank" opens in a new tab that, unless prevented, can use window.opener to redirect the original tab to a phishing page -- while the new tab looks completely normal. When enabled for a surface, this plugin scans rendered pages for that surface and adds rel="noopener" to any target="_blank" link missing noopener or noreferrer, leaving every other attribute and any existing rel tokens untouched.', 'vcns-security-automation-manager' ); ?>
	</p>

	<div class="notice notice-warning inline" style="padding:12px 16px;margin:1em 0;">
		<p style="margin:0;">
			<?php esc_html_e( 'Only the Frontend row below has any observable effect. This protection works by rewriting a completed page response rather than by sending a header, and that rewrite step is never reached at all for a request to wp-admin, wp-login.php, the REST API, AJAX, XML-RPC, cron, or CLI -- before this pillar\'s own per-surface setting is even consulted. The Admin, Login, and Api rows exist for the same configuration shape every other surface-based pillar uses, and can be switched on, but doing so changes nothing today. External Scripts (on the Scripts page) shares this same limitation, for the same underlying reason.', 'vcns-security-automation-manager' ); ?>
		</p>
	</div>

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
							data-pillar="<?php echo esc_attr( Reverse_Tabnabbing_Builder::PILLAR_KEY ); ?>"
							data-surface="<?php echo esc_attr( $surface ); ?>"
							<?php checked( $enabled_by_surface[ $surface ] ?? false ); ?>
						/>
					</td>
				</tr>
			<?php endforeach; ?>
		</tbody>
	</table>

	<p class="description" style="margin-top: 1em;">
		<?php esc_html_e( 'Changes apply immediately. This is a content rewrite, not a header -- it never blocks or breaks a link, it only closes an opener-access gap. Only a successful, non-streamed HTML page response on the frontend is ever rewritten (see the notice above for why the other surfaces don\'t apply here).', 'vcns-security-automation-manager' ); ?>
	</p>
</div>
