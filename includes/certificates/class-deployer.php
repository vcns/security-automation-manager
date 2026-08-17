<?php
/**
 * Certificate deployment adapters.
 *
 * Issuing a certificate is pure PHP; INSTALLING it is where hosting
 * environments diverge, because the web server's TLS configuration is not
 * writable by the PHP user and reloading the server needs privileges PHP
 * does not have. Three adapters cover the spectrum:
 *
 *   - 'cpanel'   : cPanel UAPI SSL::install_ssl over HTTPS with an API token.
 *                  Fully automatic on cPanel/LiteSpeed shared hosting.
 *   - 'export'   : writes key + fullchain PEMs to a directory; a small
 *                  root-side cron or deploy hook copies them into the web
 *                  server config and reloads it. See docs/certificates.md.
 *   - 'download' : no automatic deployment; the admin downloads the PEMs
 *                  from the Certificates page.
 *
 * The platform-specific installation steps are documented (with the
 * install_ssl dependency caveat) in docs/certificates.md.
 */

declare( strict_types=1 );

namespace WP_SAM\Certificates;

use WP_SAM\Modules\Audit_Log;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Deployer {

	private Audit_Log $audit;

	public function __construct( Audit_Log $audit ) {
		$this->audit = $audit;
	}

	/**
	 * Deploys per the configured mode. Throws on failure so the caller can
	 * record the error; 'download' mode is always a silent success.
	 */
	public function deploy( array $config, string $domain, string $key_pem, string $fullchain_pem ): void {
		switch ( (string) $config['deployment'] ) {
			case 'cpanel':
				$this->deploy_cpanel( $config, $domain, $key_pem, $fullchain_pem );
				return;
			case 'export':
				$this->deploy_export( $config, $key_pem, $fullchain_pem );
				return;
			default:
				return;
		}
	}

	// ── cPanel UAPI ───────────────────────────────────────────────────────────

	/**
	 * Installs via cPanel's UAPI SSL::install_ssl. Requires host (usually
	 * hostname:2083), the cPanel account user, and an API token created under
	 * cPanel > Security > Manage API Tokens.
	 */
	private function deploy_cpanel( array $config, string $domain, string $key_pem, string $fullchain_pem ): void {
		$host  = trim( (string) $config['cpanel_host'] );
		$user  = trim( (string) $config['cpanel_user'] );
		$token = (string) $config['cpanel_token'];

		if ( '' === $host || '' === $user || '' === $token ) {
			throw new \RuntimeException( 'cPanel deployment selected but host, user, or API token is missing.' );
		}
		if ( ! str_contains( $host, ':' ) ) {
			$host .= ':2083';
		}

		// The fullchain is leaf-first; UAPI wants the leaf in 'cert' and the
		// remaining chain in 'cabundle'.
		$blocks = array();
		if ( preg_match_all( '/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/s', $fullchain_pem, $matches ) ) {
			$blocks = $matches[0];
		}
		if ( empty( $blocks ) ) {
			throw new \RuntimeException( 'Issued fullchain contains no certificate blocks.' );
		}

		$response = wp_remote_post(
			'https://' . $host . '/execute/SSL/install_ssl',
			array(
				'timeout' => 60,
				'headers' => array( 'Authorization' => 'cpanel ' . $user . ':' . $token ),
				'body'    => array(
					'domain'   => $domain,
					'cert'     => $blocks[0],
					'key'      => $key_pem,
					'cabundle' => implode( "\n", array_slice( $blocks, 1 ) ),
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			throw new \RuntimeException( 'cPanel install_ssl transport error: ' . $response->get_error_message() );
		}

		$body = json_decode( (string) wp_remote_retrieve_body( $response ), true );
		if ( empty( $body['status'] ) ) {
			$errors = isset( $body['errors'] ) ? implode( '; ', (array) $body['errors'] ) : ( 'HTTP ' . wp_remote_retrieve_response_code( $response ) );
			throw new \RuntimeException( 'cPanel install_ssl failed: ' . $errors );
		}

		$this->audit->log( 'certificates', 'cert_deployed', "Certificate for {$domain} installed via cPanel UAPI install_ssl.", 'info' );
	}

	// ── Export directory ──────────────────────────────────────────────────────

	private function deploy_export( array $config, string $key_pem, string $fullchain_pem ): void {
		$dir = rtrim( (string) $config['export_path'], '/\\' );
		if ( '' === $dir ) {
			throw new \RuntimeException( 'Export deployment selected but no export path is configured.' );
		}
		if ( ! is_dir( $dir ) && ! wp_mkdir_p( $dir ) ) {
			throw new \RuntimeException( "Export path {$dir} does not exist and could not be created." );
		}

		// Never export beneath the public webroot: a fullchain leak is
		// harmless, a private-key leak is the certificate. Refuse rather than
		// trusting a deny-rule to hold.
		$webroot = rtrim( str_replace( '\\', '/', ABSPATH ), '/' );
		$target  = rtrim( str_replace( '\\', '/', (string) realpath( $dir ) ), '/' );
		if ( '' !== $target && str_starts_with( $target . '/', $webroot . '/' ) ) {
			throw new \RuntimeException( 'Export path must be OUTSIDE the web root (e.g. a sibling directory of ' . $webroot . ').' );
		}

		// phpcs:disable WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- local key material; WP_Filesystem's indirection adds failure modes without adding safety here.
		if ( false === file_put_contents( $dir . '/privkey.pem', $key_pem ) ) {
			throw new \RuntimeException( "Unable to write privkey.pem to {$dir}." );
		}
		@chmod( $dir . '/privkey.pem', 0600 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged, WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- best-effort tightening; not all hosts allow chmod.
		if ( false === file_put_contents( $dir . '/fullchain.pem', $fullchain_pem ) ) {
			throw new \RuntimeException( "Unable to write fullchain.pem to {$dir}." );
		}
		// phpcs:enable

		$this->audit->log( 'certificates', 'cert_exported', "Certificate written to {$dir} (privkey.pem, fullchain.pem) for the host-side install step.", 'info' );
	}
}
