<?php
/**
 * Admin view: TLS Certificates (ACME).
 * Rendered by Admin_UI::render_certificates().
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WP_SAM\Certificates\Certificate_Store;
use WP_SAM\Certificates\Dns_Provider;

$wp_sam_cert_store  = new Certificate_Store();
$wp_sam_cert_config = $wp_sam_cert_store->get_config();
$wp_sam_cert_latest = $wp_sam_cert_store->latest_certificate();
$wp_sam_cert_run    = $this->plugin->cert_manager->last_run();
$wp_sam_providers   = Dns_Provider::providers();
$wp_sam_action_url  = admin_url( 'admin-post.php' );
?>
<div class="wrap wp-sam-wrap">
	<h1><?php esc_html_e( 'TLS Certificates (ACME / Let\'s Encrypt)', 'security-automation-manager' ); ?></h1>

	<?php if ( isset( $_GET['saved'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only flag. ?>
	<div class="notice notice-success"><p><?php esc_html_e( 'Certificate settings saved.', 'security-automation-manager' ); ?></p></div>
	<?php endif; ?>
	<?php if ( isset( $_GET['queued'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
	<div class="notice notice-info"><p><?php esc_html_e( 'Certificate order queued. It runs in the background via WP-Cron; refresh this page to follow the status below.', 'security-automation-manager' ); ?></p></div>
	<?php endif; ?>

	<p class="description" style="max-width:860px">
		<?php esc_html_e( 'Requests and renews TLS certificates from Let\'s Encrypt using the ACME v2 protocol, directly from this WordPress install. DNS-01 challenges (via your DNS provider\'s API, required for wildcard names) are preferred; HTTP-01 is the automatic fallback when no provider is configured. ACME v1 is not supported anywhere any more -- Let\'s Encrypt retired it in 2021.', 'security-automation-manager' ); ?>
	</p>

	<!-- ── Status ────────────────────────────────────────────────────────── -->
	<h2 class="title"><?php esc_html_e( 'Status', 'security-automation-manager' ); ?></h2>
	<table class="widefat striped" style="max-width:860px">
		<tbody>
			<tr>
				<th scope="row" style="width:220px"><?php esc_html_e( 'Latest certificate', 'security-automation-manager' ); ?></th>
				<td>
					<?php if ( null !== $wp_sam_cert_latest ) : ?>
						<code><?php echo esc_html( implode( ', ', (array) $wp_sam_cert_latest['domains'] ) ); ?></code>
						(<?php echo esc_html( (string) $wp_sam_cert_latest['environment'] ); ?>) —
						<?php
						printf(
							/* translators: %s: expiry date/time (UTC). */
							esc_html__( 'expires %s UTC', 'security-automation-manager' ),
							esc_html( (string) $wp_sam_cert_latest['not_after'] )
						);
						?>
					<?php else : ?>
						<?php esc_html_e( 'None issued yet.', 'security-automation-manager' ); ?>
					<?php endif; ?>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Last run', 'security-automation-manager' ); ?></th>
				<td>
					<strong><?php echo esc_html( $wp_sam_cert_run['status'] ); ?></strong>
					<?php if ( '' !== $wp_sam_cert_run['at'] ) : ?>
						(<?php echo esc_html( $wp_sam_cert_run['at'] ); ?> UTC)
					<?php endif; ?>
					<?php if ( '' !== $wp_sam_cert_run['detail'] ) : ?>
						— <?php echo esc_html( $wp_sam_cert_run['detail'] ); ?>
					<?php endif; ?>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Renewal', 'security-automation-manager' ); ?></th>
				<td><?php esc_html_e( 'Checked daily via WP-Cron; production certificates re-issue automatically inside the 30-day window. WP-Cron only fires when the site receives traffic — for an idle or low-traffic site, point a real system cron at wp-cron.php (see the documentation below).', 'security-automation-manager' ); ?></td>
			</tr>
		</tbody>
	</table>

	<p style="margin-top:12px">
		<form method="post" action="<?php echo esc_url( $wp_sam_action_url ); ?>" style="display:inline">
			<?php wp_nonce_field( 'wp_sam_issue_certificate' ); ?>
			<input type="hidden" name="action" value="wp_sam_issue_certificate" />
			<button type="submit" class="button button-primary"><?php esc_html_e( 'Issue / Renew Now', 'security-automation-manager' ); ?></button>
		</form>
		<?php if ( null !== $wp_sam_cert_latest ) : ?>
			<a class="button" href="<?php echo esc_url( wp_nonce_url( $wp_sam_action_url . '?action=wp_sam_download_certificate&file=fullchain', 'wp_sam_download_certificate' ) ); ?>"><?php esc_html_e( 'Download fullchain.pem', 'security-automation-manager' ); ?></a>
			<a class="button" href="<?php echo esc_url( wp_nonce_url( $wp_sam_action_url . '?action=wp_sam_download_certificate&file=privkey', 'wp_sam_download_certificate' ) ); ?>"><?php esc_html_e( 'Download privkey.pem', 'security-automation-manager' ); ?></a>
		<?php endif; ?>
	</p>

	<!-- ── Settings ──────────────────────────────────────────────────────── -->
	<h2 class="title"><?php esc_html_e( 'Configuration', 'security-automation-manager' ); ?></h2>
	<form method="post" action="<?php echo esc_url( $wp_sam_action_url ); ?>">
		<?php wp_nonce_field( 'wp_sam_save_cert_settings' ); ?>
		<input type="hidden" name="action" value="wp_sam_save_cert_settings" />

		<table class="form-table" style="max-width:860px">
			<tr>
				<th scope="row"><label for="wp_sam_cert_domains"><?php esc_html_e( 'Domains', 'security-automation-manager' ); ?></label></th>
				<td>
					<textarea id="wp_sam_cert_domains" name="wp_sam_cert_domains" class="large-text" rows="3" placeholder="example.com&#10;www.example.com&#10;*.example.com"><?php echo esc_textarea( implode( "\n", (array) $wp_sam_cert_config['domains'] ) ); ?></textarea>
					<p class="description"><?php esc_html_e( 'One per line (or comma-separated). All names go on one certificate; the first becomes the Common Name. Wildcards (*.example.com) require a DNS provider below.', 'security-automation-manager' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="wp_sam_cert_email"><?php esc_html_e( 'Contact email', 'security-automation-manager' ); ?></label></th>
				<td>
					<input type="email" id="wp_sam_cert_email" name="wp_sam_cert_email" class="regular-text" value="<?php echo esc_attr( (string) $wp_sam_cert_config['contact_email'] ); ?>" />
					<p class="description"><?php esc_html_e( 'Registered with the ACME account; the CA sends expiry warnings here.', 'security-automation-manager' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="wp_sam_cert_provider"><?php esc_html_e( 'DNS provider (DNS-01)', 'security-automation-manager' ); ?></label></th>
				<td>
					<select id="wp_sam_cert_provider" name="wp_sam_cert_provider">
						<option value=""><?php esc_html_e( '— None (fall back to HTTP-01, no wildcards) —', 'security-automation-manager' ); ?></option>
						<?php foreach ( $wp_sam_providers as $wp_sam_slug => $wp_sam_class ) : ?>
						<option value="<?php echo esc_attr( $wp_sam_slug ); ?>" <?php selected( $wp_sam_cert_config['provider'], $wp_sam_slug ); ?>><?php echo esc_html( $wp_sam_class::label() ); ?></option>
						<?php endforeach; ?>
					</select>
					<p class="description"><?php esc_html_e( 'Additional providers can be registered by other plugins via the wp_sam_dns_providers filter.', 'security-automation-manager' ); ?></p>
				</td>
			</tr>
			<?php foreach ( $wp_sam_providers as $wp_sam_slug => $wp_sam_class ) : ?>
			<tr class="wp-sam-cert-provider-fields" data-provider="<?php echo esc_attr( $wp_sam_slug ); ?>" style="display:none">
				<th scope="row"><?php echo esc_html( $wp_sam_class::label() ); ?></th>
				<td>
					<?php foreach ( $wp_sam_class::fields() as $wp_sam_field_key => $wp_sam_field ) : ?>
					<p>
						<label for="wp_sam_cert_cred_<?php echo esc_attr( $wp_sam_slug . '_' . $wp_sam_field_key ); ?>"><?php echo esc_html( $wp_sam_field['label'] ); ?></label><br />
						<input type="password" autocomplete="off" class="regular-text"
							id="wp_sam_cert_cred_<?php echo esc_attr( $wp_sam_slug . '_' . $wp_sam_field_key ); ?>"
							<?php echo $wp_sam_slug === $wp_sam_cert_config['provider'] ? 'name="wp_sam_cert_cred_' . esc_attr( $wp_sam_field_key ) . '"' : 'data-cred-name="wp_sam_cert_cred_' . esc_attr( $wp_sam_field_key ) . '"'; ?>
							placeholder="<?php echo esc_attr( isset( $wp_sam_cert_config['dns_credentials'][ $wp_sam_field_key ] ) && '' !== $wp_sam_cert_config['dns_credentials'][ $wp_sam_field_key ] && $wp_sam_slug === $wp_sam_cert_config['provider'] ? __( '•••••• (stored — leave blank to keep)', 'security-automation-manager' ) : ( $wp_sam_field['placeholder'] ?? '' ) ); ?>" />
					</p>
					<?php endforeach; ?>
					<p class="description"><?php esc_html_e( 'Stored encrypted at rest (sodium secretbox). Use the narrowest token scope your provider offers — a DNS API credential is a domain-takeover-grade secret.', 'security-automation-manager' ); ?></p>
				</td>
			</tr>
			<?php endforeach; ?>
			<tr>
				<th scope="row"><?php esc_html_e( 'Key type', 'security-automation-manager' ); ?></th>
				<td>
					<label><input type="radio" name="wp_sam_cert_key_type" value="ec-256" <?php checked( $wp_sam_cert_config['key_type'], 'ec-256' ); ?> /> <?php esc_html_e( 'ECDSA P-256 (recommended)', 'security-automation-manager' ); ?></label><br />
					<label><input type="radio" name="wp_sam_cert_key_type" value="rsa-2048" <?php checked( $wp_sam_cert_config['key_type'], 'rsa-2048' ); ?> /> <?php esc_html_e( 'RSA 2048 (legacy compatibility)', 'security-automation-manager' ); ?></label>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Environment', 'security-automation-manager' ); ?></th>
				<td>
					<label>
						<input type="checkbox" name="wp_sam_cert_staging" value="1" <?php checked( $wp_sam_cert_config['staging'] ); ?> />
						<?php esc_html_e( 'Use the Let\'s Encrypt STAGING directory (untrusted test certificates, generous rate limits)', 'security-automation-manager' ); ?>
					</label>
					<p class="description"><?php esc_html_e( 'Keep this on until a staging order succeeds end-to-end, then switch off. Production rate limits are strict: 5 duplicate certificates per week.', 'security-automation-manager' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="wp_sam_cert_deployment"><?php esc_html_e( 'Deployment', 'security-automation-manager' ); ?></label></th>
				<td>
					<select id="wp_sam_cert_deployment" name="wp_sam_cert_deployment">
						<option value="download" <?php selected( $wp_sam_cert_config['deployment'], 'download' ); ?>><?php esc_html_e( 'Manual download (no automatic installation)', 'security-automation-manager' ); ?></option>
						<option value="export" <?php selected( $wp_sam_cert_config['deployment'], 'export' ); ?>><?php esc_html_e( 'Export PEMs to a directory (host-side script installs)', 'security-automation-manager' ); ?></option>
						<option value="cpanel" <?php selected( $wp_sam_cert_config['deployment'], 'cpanel' ); ?>><?php esc_html_e( 'cPanel UAPI install_ssl (automatic on cPanel hosting)', 'security-automation-manager' ); ?></option>
					</select>
					<p class="description" style="max-width:640px">
						<strong><?php esc_html_e( 'Important:', 'security-automation-manager' ); ?></strong>
						<?php esc_html_e( 'Issuing the certificate happens entirely inside WordPress; INSTALLING it into the web server depends on your hosting platform. Automatic installation relies on your control panel exposing an API such as cPanel\'s install_ssl — implementation steps vary by platform. See the platform notes in the documentation below.', 'security-automation-manager' ); ?>
					</p>
				</td>
			</tr>
			<tr class="wp-sam-cert-deploy-fields" data-deployment="export" style="display:none">
				<th scope="row"><label for="wp_sam_cert_export_path"><?php esc_html_e( 'Export path', 'security-automation-manager' ); ?></label></th>
				<td>
					<input type="text" id="wp_sam_cert_export_path" name="wp_sam_cert_export_path" class="regular-text" value="<?php echo esc_attr( (string) $wp_sam_cert_config['export_path'] ); ?>" placeholder="/home/account/ssl-drop" />
					<p class="description"><?php esc_html_e( 'Must be OUTSIDE the web root; the plugin refuses paths under it. privkey.pem and fullchain.pem are written here on every issue/renewal.', 'security-automation-manager' ); ?></p>
				</td>
			</tr>
			<tr class="wp-sam-cert-deploy-fields" data-deployment="cpanel" style="display:none">
				<th scope="row"><?php esc_html_e( 'cPanel', 'security-automation-manager' ); ?></th>
				<td>
					<p><label><?php esc_html_e( 'Host (hostname:2083)', 'security-automation-manager' ); ?><br /><input type="text" name="wp_sam_cert_cpanel_host" class="regular-text" value="<?php echo esc_attr( (string) $wp_sam_cert_config['cpanel_host'] ); ?>" placeholder="server.example.net:2083" /></label></p>
					<p><label><?php esc_html_e( 'cPanel username', 'security-automation-manager' ); ?><br /><input type="text" name="wp_sam_cert_cpanel_user" class="regular-text" value="<?php echo esc_attr( (string) $wp_sam_cert_config['cpanel_user'] ); ?>" /></label></p>
					<p><label><?php esc_html_e( 'API token', 'security-automation-manager' ); ?><br /><input type="password" autocomplete="off" name="wp_sam_cert_cpanel_token" class="regular-text" placeholder="<?php echo esc_attr( '' !== $wp_sam_cert_config['cpanel_token'] ? __( '•••••• (stored — leave blank to keep)', 'security-automation-manager' ) : 'cPanel > Security > Manage API Tokens' ); ?>" /></label></p>
				</td>
			</tr>
		</table>

		<?php submit_button( __( 'Save Certificate Settings', 'security-automation-manager' ) ); ?>
	</form>

	<!-- ── Platform documentation + consultation ─────────────────────────── -->
	<h2 class="title"><?php esc_html_e( 'Installing the certificate on your platform', 'security-automation-manager' ); ?></h2>
	<p class="description" style="max-width:860px">
		<?php esc_html_e( 'The full platform-by-platform guide (cPanel, Plesk, DirectAdmin, self-managed Apache/nginx/LiteSpeed) ships with the plugin in docs/certificates.md and covers the install_ssl dependency, export-mode root cron examples, and the real-cron renewal recommendation.', 'security-automation-manager' ); ?>
	</p>
	<div class="notice notice-info inline" style="max-width:840px">
		<p>
			<strong><?php esc_html_e( 'Need help getting this right?', 'security-automation-manager' ); ?></strong>
			<?php esc_html_e( 'Certificate automation, security header rollout, and CSP enforcement are exactly what VCNS Tech Ltd does for clients every week. If you would like a security engineer to review your hosting platform, wire up automated certificate deployment end-to-end, or audit your site\'s wider security posture, we offer fixed-scope security consultation engagements.', 'security-automation-manager' ); ?>
			<a href="https://vcns.tech/?utm_source=wp-sam&amp;utm_medium=plugin&amp;utm_campaign=certificates" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Talk to VCNS Tech →', 'security-automation-manager' ); ?></a>
		</p>
	</div>
</div>

<script>
( function () {
	var providerSelect = document.getElementById( 'wp_sam_cert_provider' );
	var deploySelect   = document.getElementById( 'wp_sam_cert_deployment' );

	// Only the visible provider's inputs may carry a name= (so unrelated
	// blank password fields never submit); hidden ones park it in data-cred-name.
	function syncProvider() {
		document.querySelectorAll( '.wp-sam-cert-provider-fields' ).forEach( function ( row ) {
			var active = row.dataset.provider === providerSelect.value;
			row.style.display = active ? '' : 'none';
			row.querySelectorAll( 'input' ).forEach( function ( input ) {
				if ( active && input.dataset.credName ) {
					input.name = input.dataset.credName;
				} else if ( ! active && input.name ) {
					input.dataset.credName = input.name;
					input.removeAttribute( 'name' );
				}
			} );
		} );
	}

	function syncDeploy() {
		document.querySelectorAll( '.wp-sam-cert-deploy-fields' ).forEach( function ( row ) {
			row.style.display = row.dataset.deployment === deploySelect.value ? '' : 'none';
		} );
	}

	providerSelect.addEventListener( 'change', syncProvider );
	deploySelect.addEventListener( 'change', syncDeploy );
	syncProvider();
	syncDeploy();
} )();
</script>
