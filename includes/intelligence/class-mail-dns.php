<?php
/**
 * DNS lookups for this site's own mail domain: its MX records, and the
 * TXT records that MTA-STS (RFC 8461, at _mta-sts.<domain>) and SMTP TLS
 * reporting (RFC 8460, at _smtp._tls.<domain>) are published in.
 *
 * Every lookup asks the wp_sam_pre_dns_lookup filter first, the same
 * short-circuit shape as WordPress core's pre_http_request: a callback
 * that returns an array of dns_get_record()-shaped records, or false for
 * a failed lookup, answers without asking DNS. Tests use it so they never
 * make a real lookup.
 *
 * A failed lookup (null here) is kept apart from "no records" (an empty
 * array): PHP's resolver failing says nothing about what the domain
 * publishes, so nothing here reports a record as missing on its account.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Mail_Dns {

	/** Exactly one record of the kind asked for. */
	public const FOUND = 'found';

	/** No record of that kind. */
	public const MISSING = 'missing';

	/** More than one: RFC 8461 §3.1 has mail servers ignore them all. */
	public const MULTIPLE = 'multiple';

	/** One _mta-sts record, but without a valid id field. */
	public const INVALID = 'invalid';

	/** DNS couldn't be asked from this server. */
	public const UNKNOWN = 'unknown';

	/**
	 * Host names of this domain's mail servers, most preferred first. A
	 * "null MX" (RFC 7505, a target of ".") means the domain accepts no
	 * mail, so it is left out.
	 *
	 * @return array<int, string>|null Null when DNS couldn't be asked.
	 */
	public static function mx_hosts( string $domain ): ?array {
		$records = self::lookup( $domain, DNS_MX );
		if ( null === $records ) {
			return null;
		}

		usort( $records, static fn ( $a, $b ): int => (int) ( $a['pri'] ?? 0 ) <=> (int) ( $b['pri'] ?? 0 ) );

		$hosts = array();
		foreach ( $records as $record ) {
			$target = strtolower( rtrim( (string) ( $record['target'] ?? '' ), '.' ) );
			if ( '' !== $target && ! in_array( $target, $hosts, true ) ) {
				$hosts[] = $target;
			}
		}
		return $hosts;
	}

	/**
	 * The _mta-sts.<domain> record (RFC 8461 §3.1). Records that don't
	 * start with v=STSv1 aren't MTA-STS records and are skipped.
	 *
	 * @return array{status:string, id:?string}
	 */
	public static function sts_record( string $domain ): array {
		$records = self::txt_records( '_mta-sts.' . $domain, '/^v=STSv1[ \t]*;/' );
		if ( null === $records ) {
			return array(
				'status' => self::UNKNOWN,
				'id'     => null,
			);
		}
		if ( 1 !== count( $records ) ) {
			return array(
				'status' => array() === $records ? self::MISSING : self::MULTIPLE,
				'id'     => null,
			);
		}
		if ( 1 !== preg_match( '/;[ \t]*id=([A-Za-z0-9]{1,32})[ \t]*(?:;|$)/', $records[0], $matches ) ) {
			return array(
				'status' => self::INVALID,
				'id'     => null,
			);
		}
		return array(
			'status' => self::FOUND,
			'id'     => $matches[1],
		);
	}

	/**
	 * The _smtp._tls.<domain> record (RFC 8460 §3) that tells mail servers
	 * where to send reports of failed TLS connections.
	 *
	 * @return array{status:string, record:?string}
	 */
	public static function tls_rpt_record( string $domain ): array {
		$records = self::txt_records( '_smtp._tls.' . $domain, '/^v=TLSRPTv1[ \t]*;/' );
		if ( null === $records ) {
			return array(
				'status' => self::UNKNOWN,
				'record' => null,
			);
		}
		if ( 1 !== count( $records ) ) {
			return array(
				'status' => array() === $records ? self::MISSING : self::MULTIPLE,
				'record' => null,
			);
		}
		return array(
			'status' => self::FOUND,
			'record' => $records[0],
		);
	}

	/**
	 * TXT records at $name that match $pattern, each one's strings joined
	 * without spaces (RFC 8461 §3.1, RFC 8460 §3).
	 *
	 * @return array<int, string>|null Null when DNS couldn't be asked.
	 */
	private static function txt_records( string $name, string $pattern ): ?array {
		$records = self::lookup( $name, DNS_TXT );
		if ( null === $records ) {
			return null;
		}

		$matching = array();
		foreach ( $records as $record ) {
			$text = isset( $record['entries'] ) && is_array( $record['entries'] )
				? implode( '', array_map( 'strval', $record['entries'] ) )
				: (string) ( $record['txt'] ?? '' );
			if ( 1 === preg_match( $pattern, $text ) ) {
				$matching[] = $text;
			}
		}
		return $matching;
	}

	/** @return array<int, array<string, mixed>>|null */
	private static function lookup( string $name, int $type ): ?array {
		$pre = apply_filters( 'wp_sam_pre_dns_lookup', null, $name, $type );
		if ( null !== $pre ) {
			return is_array( $pre ) ? $pre : null;
		}
		if ( '' === $name || ! function_exists( 'dns_get_record' ) ) {
			return null;
		}

		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- dns_get_record() emits a warning when the resolver fails; that is an expected outcome here, reported as null. Same rationale as Asn_Lookup_Store.
		$records = @dns_get_record( $name, $type );
		return is_array( $records ) ? $records : null;
	}
}
