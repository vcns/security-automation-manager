<?php
/**
 * Admin view: TLS Certificates (ACME).
 * Rendered by Admin_UI::render_certificates().
 *
 * Three tabs: Configuration (what to order and how to validate it),
 * Issue / Renew (status and the manual trigger), Install (how the issued
 * certificate reaches the web server).
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WP_SAM\Certificates\Acme_Crypto;
use WP_SAM\Certificates\Certificate_Store;
use WP_SAM\Certificates\Dns_Provider;

$wp_sam_cert_store  = new Certificate_Store();
$wp_sam_cert_config = $wp_sam_cert_store->get_config();
$wp_sam_cert_latest = $wp_sam_cert_store->latest_certificate();
$wp_sam_cert_run    = $this->plugin->cert_manager->last_run();
$wp_sam_providers   = Dns_Provider::providers();
$wp_sam_action_url  = admin_url( 'admin-post.php' );
$wp_sam_base_url    = admin_url( 'admin.php?page=security-automation-manager-certificates' );

// Current tab.
$wp_sam_cert_tab = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'configuration'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only routing.
if ( ! in_array( $wp_sam_cert_tab, array( 'configuration', 'renew', 'install' ), true ) ) {
	$wp_sam_cert_tab = 'configuration';
}

// Live probe: can THIS server actually generate a certificate key right now?
// extension_loaded('openssl') alone is not reliable -- see
// Acme_Crypto::generation_capability()'s docblock. Only run on the tab that
// needs it; a real key-generation attempt is cheap but not free, and the
// other two tabs never render this section. The "bring your own key" block
// only appears when generation genuinely fails, or a key is already stored
// (so a site that starts working again still has a way to remove it).
if ( 'configuration' === $wp_sam_cert_tab ) {
	$wp_sam_key_capability = Acme_Crypto::generation_capability();
	$wp_sam_show_byo_key   = ! $wp_sam_key_capability['ok'] || '' !== $wp_sam_cert_config['custom_key_pem'];
}

$wp_sam_cert_tabs = array(
	'configuration' => __( 'Configuration', 'vcns-security-automation-manager' ),
	'renew'         => __( 'Issue / Renew', 'vcns-security-automation-manager' ),
	'install'       => __( 'Install', 'vcns-security-automation-manager' ),
);

// Pre-populate the domains box from the site's own address on first visit --
// the overwhelmingly common case is "a certificate for this site".
$wp_sam_cert_domains_value = implode( "\n", (array) $wp_sam_cert_config['domains'] );
if ( '' === trim( $wp_sam_cert_domains_value ) ) {
	$wp_sam_site_host          = strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
	$wp_sam_cert_domains_value = $wp_sam_site_host;
	if ( '' !== $wp_sam_site_host && ! str_starts_with( $wp_sam_site_host, 'www.' ) && substr_count( $wp_sam_site_host, '.' ) === 1 ) {
		// Bare registrable domain: offer the www variant alongside, since most
		// sites serve both. Harmless to delete before ordering.
		$wp_sam_cert_domains_value .= "\nwww." . $wp_sam_site_host;
	}
}
?>
<div class="wrap wp-sam-wrap">
	<h1><?php esc_html_e( 'TLS Certificates (ACME / Let\'s Encrypt)', 'vcns-security-automation-manager' ); ?></h1>

	<?php if ( isset( $_GET['saved'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only flag. ?>
	<div class="notice notice-success"><p><?php esc_html_e( 'Certificate settings saved.', 'vcns-security-automation-manager' ); ?></p></div>
	<?php endif; ?>
	<?php if ( isset( $_GET['queued'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
	<div class="notice notice-info"><p><?php esc_html_e( 'Certificate order queued. It runs in the background via WP-Cron; refresh this page to follow the status.', 'vcns-security-automation-manager' ); ?></p></div>
	<?php endif; ?>
	<?php if ( isset( $_GET['key_error'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
	<div class="notice notice-error"><p><?php esc_html_e( 'The pasted private key could not be loaded and was NOT saved. Paste a complete, unencrypted PEM key (BEGIN PRIVATE KEY / BEGIN EC PRIVATE KEY / BEGIN RSA PRIVATE KEY). Passphrase-protected keys are not supported.', 'vcns-security-automation-manager' ); ?></p></div>
	<?php endif; ?>

	<?php
	$wp_sam_vault_warnings = $wp_sam_cert_store->vault_health_warnings();
	if ( ! empty( $wp_sam_vault_warnings ) ) :
		?>
	<div class="notice notice-warning">
		<p>
			<strong><?php esc_html_e( 'Some stored credentials or keys cannot be decrypted.', 'vcns-security-automation-manager' ); ?></strong>
			<?php esc_html_e( 'This usually means the encryption key changed since these were saved -- most often WP_SAM_CERT_VAULT_KEY being edited or removed in wp-config.php, or WordPress\'s own AUTH_KEY/AUTH_SALT being regenerated. The affected values were NOT erased or replaced; they still exist encrypted in the database and will keep failing to decrypt until either the original key is restored or each one is re-entered below.', 'vcns-security-automation-manager' ); ?>
		</p>
		<ul style="list-style: disc; margin-left: 1.5em;">
			<?php foreach ( $wp_sam_vault_warnings as $wp_sam_vault_field ) : ?>
			<li><?php echo esc_html( $wp_sam_vault_field ); ?></li>
			<?php endforeach; ?>
		</ul>
	</div>
	<?php endif; ?>

	<?php if ( ! extension_loaded( 'openssl' ) || ! function_exists( 'sodium_crypto_secretbox' ) ) : ?>
	<div class="notice notice-error">
		<p>
			<strong><?php esc_html_e( 'Missing PHP requirement.', 'vcns-security-automation-manager' ); ?></strong>
			<?php if ( ! extension_loaded( 'openssl' ) ) : ?>
				<?php esc_html_e( 'The openssl PHP extension is not available on this server. ACME request signing cannot work without it, so certificate automation is disabled - supplying your own private key does not remove this requirement, because every ACME API call must be cryptographically signed. Ask your host to enable ext/openssl (it ships with PHP and is required by WordPress features such as HTTPS API calls).', 'vcns-security-automation-manager' ); ?>
			<?php else : ?>
				<?php esc_html_e( 'The sodium PHP extension is not available on this server; credentials and private keys cannot be encrypted at rest, so certificate automation is disabled. Ask your host to enable ext/sodium (bundled with PHP since 7.2).', 'vcns-security-automation-manager' ); ?>
			<?php endif; ?>
		</p>
	</div>
	<?php endif; ?>

	<nav class="nav-tab-wrapper wp-sam-tab-wrapper" role="tablist" aria-label="<?php esc_attr_e( 'Certificate sections', 'vcns-security-automation-manager' ); ?>">
		<?php foreach ( $wp_sam_cert_tabs as $wp_sam_tab_key => $wp_sam_tab_label ) : ?>
		<a class="nav-tab<?php echo $wp_sam_tab_key === $wp_sam_cert_tab ? ' nav-tab-active' : ''; ?>"
			href="<?php echo esc_url( add_query_arg( 'tab', $wp_sam_tab_key, $wp_sam_base_url ) ); ?>"
			role="tab"
			<?php echo $wp_sam_tab_key === $wp_sam_cert_tab ? 'aria-selected="true" aria-current="page"' : 'aria-selected="false"'; ?>>
			<?php echo esc_html( $wp_sam_tab_label ); ?>
		</a>
		<?php endforeach; ?>
	</nav>

	<div class="tab-content" style="margin-top:1em">

	<?php if ( 'configuration' === $wp_sam_cert_tab ) : ?>
	<!-- ── Configuration tab ─────────────────────────────────────────────── -->
	<p class="description">
		<?php esc_html_e( 'Requests and renews TLS certificates from Let\'s Encrypt using the ACME v2 protocol, directly from this WordPress install. DNS-01 challenges (via your DNS provider\'s API, required for wildcard names) are preferred; HTTP-01 is the automatic fallback when no provider is configured.', 'vcns-security-automation-manager' ); ?>
	</p>

	<form method="post" action="<?php echo esc_url( $wp_sam_action_url ); ?>">
		<?php wp_nonce_field( 'wp_sam_save_cert_settings' ); ?>
		<input type="hidden" name="action" value="wp_sam_save_cert_settings" />
		<input type="hidden" name="wp_sam_cert_section" value="configuration" />

		<table class="form-table">
			<tr>
				<th scope="row"><label for="wp_sam_cert_domains"><?php esc_html_e( 'Domains', 'vcns-security-automation-manager' ); ?></label></th>
				<td>
					<textarea id="wp_sam_cert_domains" name="wp_sam_cert_domains" class="large-text" rows="3" placeholder="example.com&#10;www.example.com&#10;*.example.com"><?php echo esc_textarea( $wp_sam_cert_domains_value ); ?></textarea>
					<p class="description"><?php esc_html_e( 'Pre-filled from this site\'s address; adjust as needed. One per line (or comma-separated). All names go on one certificate; the first becomes the Common Name. Wildcards (*.example.com) require a DNS provider below.', 'vcns-security-automation-manager' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="wp_sam_cert_email"><?php esc_html_e( 'Contact email', 'vcns-security-automation-manager' ); ?></label></th>
				<td>
					<input type="email" id="wp_sam_cert_email" name="wp_sam_cert_email" class="regular-text" value="<?php echo esc_attr( (string) $wp_sam_cert_config['contact_email'] ); ?>" />
					<p class="description"><?php esc_html_e( 'Registered with the ACME account; the CA sends expiry warnings here.', 'vcns-security-automation-manager' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Organisation details (CSR subject)', 'vcns-security-automation-manager' ); ?></th>
				<td>
					<p><label><?php esc_html_e( 'Organisation / company name', 'vcns-security-automation-manager' ); ?><br /><input type="text" name="wp_sam_cert_organization" class="regular-text" value="<?php echo esc_attr( (string) $wp_sam_cert_config['organization'] ); ?>" placeholder="VCNS Tech Ltd" /></label></p>
					<p><label><?php esc_html_e( 'Organisational unit / department', 'vcns-security-automation-manager' ); ?><br /><input type="text" name="wp_sam_cert_org_unit" class="regular-text" value="<?php echo esc_attr( (string) $wp_sam_cert_config['organizational_unit'] ); ?>" placeholder="IT" /></label></p>
					<p><label><?php esc_html_e( 'Country (two-letter code)', 'vcns-security-automation-manager' ); ?><br /><input type="text" name="wp_sam_cert_country" class="small-text" maxlength="2" value="<?php echo esc_attr( (string) $wp_sam_cert_config['country'] ); ?>" placeholder="GB" /></label></p>
					<p><label><?php esc_html_e( 'State / county / region', 'vcns-security-automation-manager' ); ?><br /><input type="text" name="wp_sam_cert_state" class="regular-text" value="<?php echo esc_attr( (string) $wp_sam_cert_config['state'] ); ?>" /></label></p>
					<p><label><?php esc_html_e( 'City / locality', 'vcns-security-automation-manager' ); ?><br /><input type="text" name="wp_sam_cert_locality" class="regular-text" value="<?php echo esc_attr( (string) $wp_sam_cert_config['locality'] ); ?>" /></label></p>
					<p class="description"><?php esc_html_e( 'Optional. These go into the certificate signing request\'s subject alongside the domain. Be aware that domain-validated CAs - Let\'s Encrypt included - validate and issue on the domain names only and omit organisation details from the final certificate; they matter for CAs and internal workflows that consume the CSR itself.', 'vcns-security-automation-manager' ); ?></p>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Validation method', 'vcns-security-automation-manager' ); ?></th>
				<td>
					<label style="margin-right:16px">
						<input type="radio" name="wp_sam_cert_challenge" value="dns-01" <?php checked( $wp_sam_cert_config['challenge'], 'dns-01' ); ?> />
						<?php esc_html_e( 'DNS-01 - prove control via a DNS TXT record through your provider\'s API (required for wildcards)', 'vcns-security-automation-manager' ); ?>
					</label><br />
					<label>
						<input type="radio" name="wp_sam_cert_challenge" value="http-01" <?php checked( $wp_sam_cert_config['challenge'], 'http-01' ); ?> />
						<?php esc_html_e( 'HTTP-01 - prove control via a file this site serves itself (no DNS credentials needed; the CA must reach this site on port 80; no wildcards)', 'vcns-security-automation-manager' ); ?>
					</label>
					<p class="description"><?php esc_html_e( 'HSTS (including hstspreload.org registration) does not conflict with HTTP-01: HSTS is a browser-only policy, and ACME validation servers are not browsers - Let\'s Encrypt starts at http:// and follows your redirect to HTTPS, which is exactly what an HSTS site serves on port 80. Only a firewalled port 80 breaks HTTP-01.', 'vcns-security-automation-manager' ); ?></p>
				</td>
			</tr>
			<tr class="wp-sam-cert-dns-only">
				<th scope="row"><label for="wp_sam_cert_provider"><?php esc_html_e( 'DNS provider (DNS-01)', 'vcns-security-automation-manager' ); ?></label></th>
				<td>
					<select id="wp_sam_cert_provider" name="wp_sam_cert_provider">
						<option value=""><?php esc_html_e( '- None (fall back to HTTP-01, no wildcards) -', 'vcns-security-automation-manager' ); ?></option>
						<?php foreach ( $wp_sam_providers as $wp_sam_slug => $wp_sam_class ) : ?>
						<option value="<?php echo esc_attr( $wp_sam_slug ); ?>" <?php selected( $wp_sam_cert_config['provider'], $wp_sam_slug ); ?>><?php echo esc_html( $wp_sam_class::label() ); ?></option>
						<?php endforeach; ?>
					</select>
					<p class="description"><?php esc_html_e( 'Additional providers can be registered by other plugins via the wp_sam_dns_providers filter.', 'vcns-security-automation-manager' ); ?></p>
				</td>
			</tr>
			<?php foreach ( $wp_sam_providers as $wp_sam_slug => $wp_sam_class ) : ?>
			<tr class="wp-sam-cert-provider-fields wp-sam-cert-dns-only" data-provider="<?php echo esc_attr( $wp_sam_slug ); ?>" style="display:none">
				<th scope="row"><?php echo esc_html( $wp_sam_class::label() ); ?></th>
				<td>
					<?php
					foreach ( $wp_sam_class::fields() as $wp_sam_field_key => $wp_sam_field ) :
						$wp_sam_field_id    = 'wp_sam_cert_cred_' . $wp_sam_slug . '_' . $wp_sam_field_key;
						$wp_sam_is_active   = $wp_sam_slug === $wp_sam_cert_config['provider'];
						$wp_sam_name_attr   = $wp_sam_is_active ? 'name="wp_sam_cert_cred_' . esc_attr( $wp_sam_field_key ) . '"' : 'data-cred-name="wp_sam_cert_cred_' . esc_attr( $wp_sam_field_key ) . '"';
						$wp_sam_has_stored  = $wp_sam_is_active && '' !== ( $wp_sam_cert_config['dns_credentials'][ $wp_sam_field_key ] ?? '' );
						$wp_sam_placeholder = $wp_sam_has_stored ? __( '•••••• (stored - leave blank to keep)', 'vcns-security-automation-manager' ) : (string) ( $wp_sam_field['placeholder'] ?? '' );
						$wp_sam_is_secret   = $wp_sam_field['secret'] ?? true;
						// Non-secret fields (endpoints, usernames, zone names) show their
						// stored value for editing; secret fields never round-trip.
						$wp_sam_text_value = ( ! $wp_sam_is_secret && $wp_sam_is_active ) ? (string) ( $wp_sam_cert_config['dns_credentials'][ $wp_sam_field_key ] ?? '' ) : '';
						?>
					<p>
						<label for="<?php echo esc_attr( $wp_sam_field_id ); ?>"><?php echo esc_html( $wp_sam_field['label'] ); ?></label><br />
						<?php if ( ! empty( $wp_sam_field['textarea'] ) ) : ?>
						<textarea autocomplete="off" class="large-text" rows="6"
							id="<?php echo esc_attr( $wp_sam_field_id ); ?>"
							<?php echo $wp_sam_name_attr; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- attribute pair escaped above. ?>
							placeholder="<?php echo esc_attr( $wp_sam_placeholder ); ?>"></textarea>
						<?php else : ?>
						<input type="<?php echo $wp_sam_is_secret ? 'password' : 'text'; ?>" autocomplete="off" class="regular-text"
							id="<?php echo esc_attr( $wp_sam_field_id ); ?>"
							<?php echo $wp_sam_name_attr; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- attribute pair escaped above. ?>
							value="<?php echo esc_attr( $wp_sam_text_value ); ?>"
							placeholder="<?php echo esc_attr( $wp_sam_placeholder ); ?>" />
						<?php endif; ?>
					</p>
					<?php endforeach; ?>
					<p class="description"><?php esc_html_e( 'Stored encrypted at rest (sodium secretbox). Use the narrowest token scope your provider offers - a DNS API credential is a domain-takeover-grade secret.', 'vcns-security-automation-manager' ); ?></p>
				</td>
			</tr>
			<?php endforeach; ?>
			<tr>
				<th scope="row"><?php esc_html_e( 'Key type', 'vcns-security-automation-manager' ); ?></th>
				<td>
					<label><input type="radio" name="wp_sam_cert_key_type" value="ec-256" <?php checked( $wp_sam_cert_config['key_type'], 'ec-256' ); ?> /> <?php esc_html_e( 'ECDSA P-256 (recommended)', 'vcns-security-automation-manager' ); ?></label><br />
					<label><input type="radio" name="wp_sam_cert_key_type" value="rsa-2048" <?php checked( $wp_sam_cert_config['key_type'], 'rsa-2048' ); ?> /> <?php esc_html_e( 'RSA 2048 (legacy compatibility)', 'vcns-security-automation-manager' ); ?></label>
					<?php if ( $wp_sam_key_capability['ok'] ) : ?>
					<p class="description">✓ <?php esc_html_e( 'This server can generate certificate keys automatically - nothing further needed here.', 'vcns-security-automation-manager' ); ?></p>
					<?php endif; ?>
				</td>
			</tr>
			<?php if ( $wp_sam_show_byo_key ) : ?>
			<tr>
				<th scope="row"><label for="wp_sam_cert_custom_key"><?php esc_html_e( 'Private key', 'vcns-security-automation-manager' ); ?></label></th>
				<td>
					<?php if ( ! $wp_sam_key_capability['ok'] ) : ?>
					<p class="description" style="color:#a00;margin-top:0">
						<strong><?php echo esc_html( (string) $wp_sam_key_capability['error'] ); ?></strong>
					</p>
						<?php if ( ! empty( $wp_sam_key_capability['detail'] ) ) : ?>
						<details class="wp-sam-cert-keygen-detail">
							<summary><?php esc_html_e( "Technical detail (for your host's support team)", 'vcns-security-automation-manager' ); ?></summary>
							<p class="description"><code><?php echo esc_html( (string) $wp_sam_key_capability['detail'] ); ?></code></p>
						</details>
						<?php endif; ?>
					<?php endif; ?>
					<textarea id="wp_sam_cert_custom_key" name="wp_sam_cert_custom_key" class="large-text code" rows="5" autocomplete="off" placeholder="<?php echo esc_attr( '' !== $wp_sam_cert_config['custom_key_pem'] ? __( '•••••• (a key is stored - leave blank to keep it)', 'vcns-security-automation-manager' ) : '-----BEGIN PRIVATE KEY-----' ); ?>"></textarea>
					<?php if ( '' !== $wp_sam_cert_config['custom_key_pem'] && $wp_sam_key_capability['ok'] ) : ?>
					<p><label><input type="checkbox" name="wp_sam_cert_clear_custom_key" value="1" /> <?php esc_html_e( 'Remove the stored key and go back to generating one automatically per order (this server can do so now)', 'vcns-security-automation-manager' ); ?></label></p>
					<?php endif; ?>
					<p class="description">
						<?php
						echo $wp_sam_key_capability['ok']
							? esc_html__( 'A key is already stored from when this server could not generate one, or was set deliberately to control key material. It overrides the key-type choice above and is reused for every order. Paste a replacement below, or use the checkbox to remove it now that automatic generation works.', 'vcns-security-automation-manager' )
							: esc_html__( 'Generate a private key yourself - on your own computer, using the OpenSSL command line - and paste its contents below. It is validated before saving, stored encrypted at rest, and reused for every order.', 'vcns-security-automation-manager' );
						?>
					</p>
					<p class="wp-sam-cert-keygen-cmd" data-keytype="ec-256"><code>openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out privkey.pem</code></p>
					<p class="wp-sam-cert-keygen-cmd" data-keytype="rsa-2048" style="display:none"><code>openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out privkey.pem</code></p>
					<p class="description"><?php esc_html_e( 'Then paste the contents of privkey.pem above - and keep the file somewhere safe; whoever holds the key holds the certificate.', 'vcns-security-automation-manager' ); ?></p>
				</td>
			</tr>
			<?php endif; ?>
			<tr>
				<th scope="row"><?php esc_html_e( 'Environment', 'vcns-security-automation-manager' ); ?></th>
				<td>
					<label>
						<input type="checkbox" name="wp_sam_cert_staging" value="1" <?php checked( $wp_sam_cert_config['staging'] ); ?> />
						<?php esc_html_e( 'Use the Let\'s Encrypt STAGING directory (untrusted test certificates, generous rate limits)', 'vcns-security-automation-manager' ); ?>
					</label>
					<p class="description"><?php esc_html_e( 'Keep this on until a staging order succeeds end-to-end, then switch off. Production rate limits are strict: 5 duplicate certificates per week.', 'vcns-security-automation-manager' ); ?></p>
				</td>
			</tr>
		</table>

		<?php submit_button( __( 'Save Configuration', 'vcns-security-automation-manager' ) ); ?>
	</form>

	<?php elseif ( 'renew' === $wp_sam_cert_tab ) : ?>
	<!-- ── Issue / Renew tab ─────────────────────────────────────────────── -->
	<table class="widefat striped">
		<tbody>
			<tr>
				<th scope="row" style="width:220px"><?php esc_html_e( 'Latest certificate', 'vcns-security-automation-manager' ); ?></th>
				<td>
					<?php if ( null !== $wp_sam_cert_latest ) : ?>
						<code><?php echo esc_html( implode( ', ', (array) $wp_sam_cert_latest['domains'] ) ); ?></code>
						(<?php echo esc_html( (string) $wp_sam_cert_latest['environment'] ); ?>) -
						<?php
						printf(
							/* translators: %s: expiry date/time (UTC). */
							esc_html__( 'expires %s UTC', 'vcns-security-automation-manager' ),
							esc_html( (string) $wp_sam_cert_latest['not_after'] )
						);
						?>
					<?php else : ?>
						<?php esc_html_e( 'None issued yet.', 'vcns-security-automation-manager' ); ?>
					<?php endif; ?>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Last run', 'vcns-security-automation-manager' ); ?></th>
				<td>
					<strong><?php echo esc_html( $wp_sam_cert_run['status'] ); ?></strong>
					<?php if ( '' !== $wp_sam_cert_run['at'] ) : ?>
						(<?php echo esc_html( $wp_sam_cert_run['at'] ); ?> UTC)
					<?php endif; ?>
					<?php if ( '' !== $wp_sam_cert_run['detail'] ) : ?>
						- <?php echo esc_html( $wp_sam_cert_run['detail'] ); ?>
					<?php endif; ?>
				</td>
			</tr>
			<tr>
				<th scope="row"><?php esc_html_e( 'Automatic renewal', 'vcns-security-automation-manager' ); ?></th>
				<td><?php esc_html_e( 'Checked daily via WP-Cron; production certificates re-issue automatically inside the 30-day window before expiry. WP-Cron only fires when the site receives traffic - for an idle or low-traffic site, point a real system cron at wp-cron.php (see the documentation on the Install tab).', 'vcns-security-automation-manager' ); ?></td>
			</tr>
		</tbody>
	</table>

	<p style="margin-top:12px">
		<form method="post" action="<?php echo esc_url( $wp_sam_action_url ); ?>" style="display:inline">
			<?php wp_nonce_field( 'wp_sam_issue_certificate' ); ?>
			<input type="hidden" name="action" value="wp_sam_issue_certificate" />
			<button type="submit" class="button button-primary"><?php esc_html_e( 'Issue / Renew Now', 'vcns-security-automation-manager' ); ?></button>
		</form>
	</p>

	<?php else : ?>
	<!-- ── Install tab ───────────────────────────────────────────────────── -->
	<p class="description">
		<strong><?php esc_html_e( 'Important:', 'vcns-security-automation-manager' ); ?></strong>
		<?php esc_html_e( 'Issuing the certificate happens entirely inside WordPress; INSTALLING it into the web server depends on your hosting platform. Automatic installation relies on your control panel exposing an API such as cPanel\'s install_ssl - implementation steps vary by platform. The full platform-by-platform guide ships with the plugin in docs/certificates.md.', 'vcns-security-automation-manager' ); ?>
	</p>

	<form method="post" action="<?php echo esc_url( $wp_sam_action_url ); ?>">
		<?php wp_nonce_field( 'wp_sam_save_cert_settings' ); ?>
		<input type="hidden" name="action" value="wp_sam_save_cert_settings" />
		<input type="hidden" name="wp_sam_cert_section" value="install" />

		<table class="form-table">
			<tr>
				<th scope="row"><label for="wp_sam_cert_deployment"><?php esc_html_e( 'Deployment', 'vcns-security-automation-manager' ); ?></label></th>
				<td>
					<select id="wp_sam_cert_deployment" name="wp_sam_cert_deployment">
						<option value="download" <?php selected( $wp_sam_cert_config['deployment'], 'download' ); ?>><?php esc_html_e( 'Manual download (no automatic installation)', 'vcns-security-automation-manager' ); ?></option>
						<option value="export" <?php selected( $wp_sam_cert_config['deployment'], 'export' ); ?>><?php esc_html_e( 'Export PEMs to a directory (host-side script installs)', 'vcns-security-automation-manager' ); ?></option>
						<option value="cpanel" <?php selected( $wp_sam_cert_config['deployment'], 'cpanel' ); ?>><?php esc_html_e( 'cPanel UAPI install_ssl (automatic on cPanel hosting)', 'vcns-security-automation-manager' ); ?></option>
					</select>
				</td>
			</tr>
			<tr class="wp-sam-cert-deploy-fields" data-deployment="export" style="display:none">
				<th scope="row"><label for="wp_sam_cert_export_path"><?php esc_html_e( 'Export path', 'vcns-security-automation-manager' ); ?></label></th>
				<td>
					<input type="text" id="wp_sam_cert_export_path" name="wp_sam_cert_export_path" class="regular-text" value="<?php echo esc_attr( (string) $wp_sam_cert_config['export_path'] ); ?>" placeholder="/home/account/ssl-drop" />
					<p class="description">
						<?php
						printf(
							/* translators: %s: example web root path. */
							esc_html__( 'An absolute path that is OUTSIDE the web root (the plugin refuses paths under it, because the private key must never be reachable over HTTP) and writable by the web server\'s PHP user. On most hosts a sibling of the web root works well: if your site lives in %s, use something like /home/youraccount/ssl-drop. privkey.pem and fullchain.pem are written here on every issue and renewal; the plugin creates the directory if it has permission, otherwise create it first via SSH, SFTP, or your control panel\'s file manager one level above the web root.', 'vcns-security-automation-manager' ),
							'<code>' . esc_html( rtrim( str_replace( '\\', '/', ABSPATH ), '/' ) ) . '</code>'
						);
						?>
					</p>
					<p class="description">
						<strong><?php esc_html_e( 'Not sure what path to use, or lacking permissions?', 'vcns-security-automation-manager' ); ?></strong>
						<?php esc_html_e( 'Your hosting provider can plug this gap in minutes - ask them for: (1) a directory outside the document root that PHP can write to, for storing TLS certificate files; and (2) whether they can install the certificate from that directory on renewal, or alternatively enable API access (e.g. a cPanel API token) so the plugin can install it automatically instead. Ultimately all this mode needs is a path and write permission to it.', 'vcns-security-automation-manager' ); ?>
					</p>
				</td>
			</tr>
			<tr class="wp-sam-cert-deploy-fields" data-deployment="cpanel" style="display:none">
				<th scope="row"><?php esc_html_e( 'cPanel', 'vcns-security-automation-manager' ); ?></th>
				<td>
					<p><label><?php esc_html_e( 'Host (hostname:2083)', 'vcns-security-automation-manager' ); ?><br /><input type="text" name="wp_sam_cert_cpanel_host" class="regular-text" value="<?php echo esc_attr( (string) $wp_sam_cert_config['cpanel_host'] ); ?>" placeholder="server.example.net:2083" /></label></p>
					<p><label><?php esc_html_e( 'cPanel username', 'vcns-security-automation-manager' ); ?><br /><input type="text" name="wp_sam_cert_cpanel_user" class="regular-text" value="<?php echo esc_attr( (string) $wp_sam_cert_config['cpanel_user'] ); ?>" /></label></p>
					<p><label><?php esc_html_e( 'API token', 'vcns-security-automation-manager' ); ?><br /><input type="password" autocomplete="off" name="wp_sam_cert_cpanel_token" class="regular-text" placeholder="<?php echo esc_attr( '' !== $wp_sam_cert_config['cpanel_token'] ? __( '•••••• (stored - leave blank to keep)', 'vcns-security-automation-manager' ) : 'cPanel > Security > Manage API Tokens' ); ?>" /></label></p>
				</td>
			</tr>
		</table>

		<?php submit_button( __( 'Save Install Settings', 'vcns-security-automation-manager' ) ); ?>
	</form>

		<?php if ( null !== $wp_sam_cert_latest ) : ?>
	<h2 class="title"><?php esc_html_e( 'Manual download', 'vcns-security-automation-manager' ); ?></h2>
	<p>
		<a class="button" href="<?php echo esc_url( wp_nonce_url( $wp_sam_action_url . '?action=wp_sam_download_certificate&file=fullchain', 'wp_sam_download_certificate' ) ); ?>"><?php esc_html_e( 'Download fullchain.pem', 'vcns-security-automation-manager' ); ?></a>
		<a class="button" href="<?php echo esc_url( wp_nonce_url( $wp_sam_action_url . '?action=wp_sam_download_certificate&file=privkey', 'wp_sam_download_certificate' ) ); ?>"><?php esc_html_e( 'Download privkey.pem', 'vcns-security-automation-manager' ); ?></a>
	</p>
	<?php endif; ?>

	<div class="notice notice-info inline">
		<p>
			<strong><?php esc_html_e( 'Need help getting this right?', 'vcns-security-automation-manager' ); ?></strong>
			<?php esc_html_e( 'Certificate automation, security header rollout, and CSP enforcement are exactly what VCNS Tech Ltd does for clients every week. If you would like a security engineer to review your hosting platform, wire up automated certificate deployment end-to-end, or audit your site\'s wider security posture, we offer fixed-scope security consultation engagements.', 'vcns-security-automation-manager' ); ?>
			<a href="https://vcns.tech/?utm_source=wp-sam&amp;utm_medium=plugin&amp;utm_campaign=certificates" target="_blank" rel="noopener noreferrer"><?php esc_html_e( 'Talk to VCNS Tech →', 'vcns-security-automation-manager' ); ?></a>
		</p>
	</div>
	<?php endif; ?>

	</div>
</div>
<?php // Behaviour lives in assets/js/certificates.js, enqueued by Admin_UI::enqueue_assets() for this page's hook suffix only -- see the "properly enqueued assets" requirement this replaces a literal <script> tag to satisfy. ?>
