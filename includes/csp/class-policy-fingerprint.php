<?php
/**
 * Compares Content Security Policy header values by what they decide,
 * not by how they happen to be written.
 *
 * Two copies of this site's frontend policy can differ in ways that mean
 * nothing for this comparison. Every response carries its own nonce. The
 * inline-script and inline-style hashes keep growing as Hash_Manager
 * learns new inline blocks while pages render, and a page's own new hash
 * is learned only after that page's header has already been sent.
 * canonicalise() drops both kinds of token and sorts what is left, so
 * what remains is the set of decisions an administrator or the
 * automation engine made: directives, approved hosts, keywords and the
 * report endpoint.
 *
 * Page_Cache_Purger uses this to tell whether a change is worth clearing
 * page caches for, and Delivered_Policy_Check uses it to tell whether the
 * policy visitors receive is the current one.
 */

declare( strict_types=1 );

namespace WP_SAM\CSP;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Policy_Fingerprint {

	/** A 'nonce-…' source, or a 'sha256-…', 'sha384-…' or 'sha512-…' hash source. */
	private const VOLATILE_TOKEN = "/^'(?:nonce-|sha(?:256|384|512)-)/i";

	/**
	 * Parses a policy into directive => sorted source list, without nonce
	 * or hash sources. Directive names are lower-cased. When a directive
	 * appears twice, the first occurrence wins, as it does in browsers.
	 *
	 * @param string $policy A Content-Security-Policy header value.
	 * @return array<string, list<string>>
	 */
	public static function canonicalise( string $policy ): array {
		$directives = array();
		foreach ( explode( ';', $policy ) as $part ) {
			$tokens = preg_split( '/\s+/', trim( $part ), -1, PREG_SPLIT_NO_EMPTY );
			if ( empty( $tokens ) ) {
				continue;
			}

			$name = strtolower( (string) array_shift( $tokens ) );
			if ( isset( $directives[ $name ] ) ) {
				continue;
			}

			$values = array();
			foreach ( $tokens as $token ) {
				if ( 1 !== preg_match( self::VOLATILE_TOKEN, $token ) ) {
					$values[ $token ] = true;
				}
			}
			$values = array_keys( $values );
			sort( $values, SORT_STRING );

			$directives[ $name ] = $values;
		}

		ksort( $directives, SORT_STRING );

		return $directives;
	}

	/**
	 * A short, stable digest of a header's mode, name and canonical
	 * policy. Two policies that differ only in nonces or hashes produce
	 * the same digest.
	 *
	 * @param string $mode   'report-only', 'enforce' or 'disabled'.
	 * @param string $header The header name the policy is sent under.
	 * @param string $policy The policy text.
	 */
	public static function digest( string $mode, string $header, string $policy ): string {
		return hash( 'sha256', (string) wp_json_encode( array( $mode, strtolower( $header ), self::canonicalise( $policy ) ) ) );
	}

	/**
	 * What one canonical policy has that the other lacks, as
	 * "directive source" strings, or just "directive" when the whole
	 * directive is absent.
	 *
	 * @param array<string, list<string>> $expected  The policy that should be in effect.
	 * @param array<string, list<string>> $delivered The policy that was actually received.
	 * @return array{missing: list<string>, unexpected: list<string>}
	 */
	public static function diff( array $expected, array $delivered ): array {
		return array(
			'missing'    => self::one_way_diff( $expected, $delivered ),
			'unexpected' => self::one_way_diff( $delivered, $expected ),
		);
	}

	/**
	 * Entries in $from that $to doesn't have.
	 *
	 * @param array<string, list<string>> $from Canonical policy to read entries from.
	 * @param array<string, list<string>> $to   Canonical policy to look them up in.
	 * @return list<string>
	 */
	private static function one_way_diff( array $from, array $to ): array {
		$entries = array();
		foreach ( $from as $directive => $values ) {
			if ( ! isset( $to[ $directive ] ) ) {
				$entries[] = $directive;
				continue;
			}
			foreach ( array_diff( $values, $to[ $directive ] ) as $value ) {
				$entries[] = $directive . ' ' . $value;
			}
		}

		return $entries;
	}
}
