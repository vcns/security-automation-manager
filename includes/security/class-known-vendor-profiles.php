<?php
/**
 * Third-party scripts whose content changes routinely at a stable URL, so
 * a Subresource Integrity pin on them breaks whenever the vendor publishes
 * -- they should be allowed by host ("Approved -- mutable provider") rather
 * than pinned by hash ("Approved -- immutable (SRI)").
 *
 * Advisory only. Decide → Dependency Classification shows a "Known vendor"
 * badge and recommends host-based allowance for a matching row; nothing is
 * ever reclassified automatically. If an administrator pins one anyway,
 * Pinned_Dependency_Checker still checks it like any other pinned row, and
 * the drift recommendation points out that host-based allowance is the
 * usual fix for this vendor.
 *
 * Matching is by the row's origin host and, for vendors whose host also
 * serves unrelated content (reCAPTCHA on www.google.com/www.gstatic.com),
 * a path prefix checked against the row's last_seen_url. A host entry
 * starting with "." matches that domain's subdomains (HubSpot serves its
 * loaders from regional hosts such as js-eu1.hs-scripts.com). The list is
 * filterable via 'wp_sam_known_vendor_profiles'.
 */

declare( strict_types=1 );

namespace WP_SAM\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Known_Vendor_Profiles {

	public const FILTER = 'wp_sam_known_vendor_profiles';

	/**
	 * Built-in profiles. Each: key, vendor, hosts (exact host, or ".domain"
	 * for any subdomain of domain), path_prefixes (optional; when set, the
	 * row's last_seen_url path must start with one of them), resource_types
	 * (subset of Dependency_Governance_Builder::RESOURCE_*), reason.
	 *
	 * @return array<int, array{key:string, vendor:string, hosts:array<int,string>, path_prefixes:array<int,string>, resource_types:array<int,string>, reason:string}>
	 */
	public static function defaults(): array {
		return array(
			array(
				'key'            => 'google_tag_manager',
				'vendor'         => 'Google Tag Manager',
				'hosts'          => array( 'www.googletagmanager.com' ),
				'path_prefixes'  => array(),
				'resource_types' => array( Dependency_Governance_Builder::RESOURCE_SCRIPT ),
				'reason'         => __( 'Google serves GTM containers (and gtag.js) with content that changes whenever the container is published; an SRI hash would break on every publish.', 'vcns-security-automation-manager' ),
			),
			array(
				'key'            => 'google_analytics',
				'vendor'         => 'Google Analytics',
				'hosts'          => array( 'www.google-analytics.com', 'ssl.google-analytics.com' ),
				'path_prefixes'  => array(),
				'resource_types' => array( Dependency_Governance_Builder::RESOURCE_SCRIPT ),
				'reason'         => __( 'Google updates analytics.js and ga.js in place at the same URL without notice; an SRI hash would break the next time Google ships a change.', 'vcns-security-automation-manager' ),
			),
			array(
				'key'            => 'hubspot',
				'vendor'         => 'HubSpot',
				'hosts'          => array(
					'.hs-scripts.com',
					'.hs-analytics.net',
					'.hs-banner.com',
					'.hscollectedforms.net',
					'.hsforms.net',
					'.usemessages.com',
					'.hsadspixel.net',
					'.hsleadflows.net',
				),
				'path_prefixes'  => array(),
				'resource_types' => array( Dependency_Governance_Builder::RESOURCE_SCRIPT, Dependency_Governance_Builder::RESOURCE_STYLE ),
				'reason'         => __( 'HubSpot\'s tracking, forms, cookie-banner and chat loaders are regenerated from your portal settings and redirected to regional hosts; their content changes without the URL changing, so an SRI hash would break.', 'vcns-security-automation-manager' ),
			),
			array(
				'key'            => 'cloudflare_turnstile',
				'vendor'         => 'Cloudflare Turnstile',
				'hosts'          => array( 'challenges.cloudflare.com' ),
				'path_prefixes'  => array(),
				'resource_types' => array( Dependency_Governance_Builder::RESOURCE_SCRIPT ),
				'reason'         => __( 'Cloudflare updates the Turnstile api.js in place and does not support serving a copied or cached version of it; an SRI hash would break on its next update.', 'vcns-security-automation-manager' ),
			),
			array(
				'key'            => 'google_recaptcha',
				'vendor'         => 'Google reCAPTCHA',
				'hosts'          => array( 'www.google.com', 'www.gstatic.com', 'www.recaptcha.net' ),
				'path_prefixes'  => array( '/recaptcha/' ),
				'resource_types' => array( Dependency_Governance_Builder::RESOURCE_SCRIPT, Dependency_Governance_Builder::RESOURCE_STYLE ),
				'reason'         => __( 'reCAPTCHA\'s api.js loads a release-specific script whose version Google changes regularly; an SRI hash on api.js would break on each new release. Note that allowing by host allows everything this origin serves, not just reCAPTCHA.', 'vcns-security-automation-manager' ),
			),
		);
	}

	/**
	 * Built-in profiles plus anything added via the filter, with malformed
	 * entries dropped.
	 *
	 * @return array<int, array{key:string, vendor:string, hosts:array<int,string>, path_prefixes:array<int,string>, resource_types:array<int,string>, reason:string}>
	 */
	public static function all(): array {
		$profiles = apply_filters( self::FILTER, self::defaults() );
		if ( ! is_array( $profiles ) ) {
			return self::defaults();
		}

		$valid = array();
		foreach ( $profiles as $profile ) {
			if ( ! is_array( $profile ) || empty( $profile['key'] ) || empty( $profile['vendor'] ) || empty( $profile['hosts'] ) || ! is_array( $profile['hosts'] ) ) {
				continue;
			}
			$valid[] = array(
				'key'            => (string) $profile['key'],
				'vendor'         => (string) $profile['vendor'],
				'hosts'          => array_values( array_map( 'strtolower', array_map( 'strval', $profile['hosts'] ) ) ),
				'path_prefixes'  => is_array( $profile['path_prefixes'] ?? null ) ? array_values( array_map( 'strval', $profile['path_prefixes'] ) ) : array(),
				'resource_types' => is_array( $profile['resource_types'] ?? null ) && ! empty( $profile['resource_types'] )
					? array_values( array_map( 'strval', $profile['resource_types'] ) )
					: array( Dependency_Governance_Builder::RESOURCE_SCRIPT, Dependency_Governance_Builder::RESOURCE_STYLE ),
				'reason'         => (string) ( $profile['reason'] ?? '' ),
			);
		}
		return $valid;
	}

	/**
	 * The profile matching an inventory row, or null.
	 *
	 * @param string      $origin        Row origin, e.g. "https://www.google.com".
	 * @param string|null $url           Row's last_seen_url (needed for profiles with path_prefixes).
	 * @param string      $resource_type 'script' or 'style'.
	 * @return array{key:string, vendor:string, hosts:array<int,string>, path_prefixes:array<int,string>, resource_types:array<int,string>, reason:string}|null
	 */
	public static function match( string $origin, ?string $url, string $resource_type ): ?array {
		$host = strtolower( (string) wp_parse_url( $origin, PHP_URL_HOST ) );
		if ( '' === $host ) {
			return null;
		}

		$path = null;
		if ( null !== $url && '' !== $url ) {
			$url_host = strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) );
			if ( $url_host === $host ) {
				$parsed_path = wp_parse_url( $url, PHP_URL_PATH );
				$path        = is_string( $parsed_path ) ? $parsed_path : '/';
			}
		}

		foreach ( self::all() as $profile ) {
			if ( ! in_array( $resource_type, $profile['resource_types'], true ) ) {
				continue;
			}
			if ( ! self::host_matches( $host, $profile['hosts'] ) ) {
				continue;
			}
			if ( ! empty( $profile['path_prefixes'] ) ) {
				if ( null === $path ) {
					continue;
				}
				$prefix_ok = false;
				foreach ( $profile['path_prefixes'] as $prefix ) {
					if ( '' !== $prefix && str_starts_with( $path, $prefix ) ) {
						$prefix_ok = true;
						break;
					}
				}
				if ( ! $prefix_ok ) {
					continue;
				}
			}
			return $profile;
		}
		return null;
	}

	/** @param array<int,string> $hosts */
	private static function host_matches( string $host, array $hosts ): bool {
		foreach ( $hosts as $candidate ) {
			if ( str_starts_with( $candidate, '.' ) ) {
				if ( str_ends_with( $host, $candidate ) ) {
					return true;
				}
				continue;
			}
			if ( $host === $candidate ) {
				return true;
			}
		}
		return false;
	}
}
