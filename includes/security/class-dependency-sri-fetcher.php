<?php
/**
 * Fetches one third-party script/stylesheet URL and computes its Subresource
 * Integrity hash -- the single shared implementation behind both the admin
 * "Suggest" helper (Admin_UI::ajax_suggest_dependency_sri()) and the daily
 * pinned-hash drift check (Pinned_Dependency_Checker).
 *
 * The same guard applies to both callers, because both fetch a URL this
 * plugin did not choose itself:
 *   - https:// only;
 *   - the URL's origin must equal the origin of the sam_dependency_inventory
 *     row it is being hashed for -- an origin this plugin already observed
 *     the site loading. Without that restriction this would be a fetch
 *     proxy an administrator (or an imported configuration file's
 *     pinned_url) could point at anything;
 *   - WordPress's own unsafe-URL rejection (reject_unsafe_urls, the
 *     setting wp_safe_remote_get() uses) so neither the URL nor a redirect
 *     it returns can reach a private/loopback address;
 *   - TLS verification on, a 10 second timeout, and a 5 MB cap.
 *
 * A hash computed here is only ever *suggested* or *compared*. Nothing in
 * this class writes to the database, and no caller approves a hash without
 * an administrator's click.
 */

declare( strict_types=1 );

namespace WP_SAM\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Dependency_Sri_Fetcher {

	/** The shape ajax_classify_dependency() already accepts for expected_sri. */
	public const SRI_PATTERN = '/^sha(256|384|512)-[A-Za-z0-9+\/]+=*$/';

	public const ALGORITHMS = array( 'sha256', 'sha384', 'sha512' );

	public const DEFAULT_ALGORITHM = 'sha384';

	/** 5 MB is generously above any legitimate third-party script/stylesheet. */
	public const MAX_BYTES = 5 * MB_IN_BYTES;

	public const TIMEOUT_SECONDS = 10;

	// Error codes returned in ['error'] -- stable, stored in
	// sam_dependency_inventory.integrity_check_error by the drift check.
	public const ERROR_NO_URL          = 'no_url';
	public const ERROR_NOT_HTTPS       = 'not_https';
	public const ERROR_ORIGIN_MISMATCH = 'origin_mismatch';
	public const ERROR_FETCH_FAILED    = 'fetch_failed';
	public const ERROR_HTTP_STATUS     = 'http_status';
	public const ERROR_EMPTY_OR_LARGE  = 'empty_or_too_large';

	/**
	 * The hash algorithm an SRI value was computed with ('sha256', 'sha384'
	 * or 'sha512'), or null when the value isn't a single well-formed SRI
	 * hash.
	 */
	public static function algorithm_of( string $sri ): ?string {
		$sri = trim( $sri );
		if ( 1 !== preg_match( self::SRI_PATTERN, $sri, $matches ) ) {
			return null;
		}
		return 'sha' . $matches[1];
	}

	/** Whether $url is https:// and on exactly $row_origin. */
	public static function is_allowed_url( string $url, string $row_origin ): bool {
		return null === self::url_error( $url, $row_origin );
	}

	/**
	 * Fetches $url and returns its SRI hash under $algorithm.
	 *
	 * @return array{ok:bool, hash?:string, error?:string, status?:int}
	 */
	public static function fetch_and_hash( string $url, string $row_origin, string $algorithm = self::DEFAULT_ALGORITHM ): array {
		$url = trim( $url );

		if ( ! in_array( $algorithm, self::ALGORITHMS, true ) ) {
			$algorithm = self::DEFAULT_ALGORITHM;
		}

		$url_error = self::url_error( $url, $row_origin );
		if ( null !== $url_error ) {
			return array(
				'ok'    => false,
				'error' => $url_error,
			);
		}

		$response = wp_remote_get(
			$url,
			array(
				'timeout'             => self::TIMEOUT_SECONDS,
				'sslverify'           => true,
				'reject_unsafe_urls'  => true,
				// One byte over the cap, so an over-size body is still
				// recognisable as over-size after the transport truncates it.
				'limit_response_size' => self::MAX_BYTES + 1,
			)
		);
		if ( is_wp_error( $response ) ) {
			return array(
				'ok'    => false,
				'error' => self::ERROR_FETCH_FAILED,
			);
		}

		$status = (int) wp_remote_retrieve_response_code( $response );
		if ( 200 !== $status ) {
			return array(
				'ok'     => false,
				'error'  => self::ERROR_HTTP_STATUS,
				'status' => $status,
			);
		}

		$body = wp_remote_retrieve_body( $response );
		if ( '' === $body || strlen( $body ) > self::MAX_BYTES ) {
			return array(
				'ok'    => false,
				'error' => self::ERROR_EMPTY_OR_LARGE,
			);
		}

		return array(
			'ok'   => true,
			'hash' => $algorithm . '-' . base64_encode( hash( $algorithm, $body, true ) ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- SRI values are base64 by definition.
		);
	}

	private static function url_error( string $url, string $row_origin ): ?string {
		$url = trim( $url );
		if ( '' === $url ) {
			return self::ERROR_NO_URL;
		}
		if ( 1 !== preg_match( '#^https://#i', $url ) ) {
			return self::ERROR_NOT_HTTPS;
		}
		$url_origin = Dependency_Governance_Builder::normalize_origin( $url );
		if ( null === $url_origin || '' === $row_origin || $url_origin !== $row_origin ) {
			return self::ERROR_ORIGIN_MISMATCH;
		}
		return null;
	}
}
