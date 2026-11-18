<?php
/**
 * MTA-STS (RFC 8461) for this site's own domain: where its policy lives,
 * what a valid one looks like, which mail servers it covers, and the DNS
 * record that announces it.
 *
 * MTA-STS tells other mail servers that email for a domain must arrive
 * over TLS, to a mail server the policy names, with a valid certificate.
 * Unlike the other well-known files, mail servers never read the policy
 * from the site's own address. They look up a TXT record at
 * _mta-sts.<domain> and, if one exists, fetch
 * https://mta-sts.<domain>/.well-known/mta-sts.txt. So the policy only
 * works once that name reaches this site with a certificate covering it,
 * and the TXT record's id changes whenever the policy does.
 *
 * The domain is this site's own host, less a leading "www.". This class
 * never names any other domain: the mail servers a policy lists are the
 * ones the administrator types, or the ones this domain's own MX records
 * name (Mail_Dns).
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Mta_Sts_Policy {

	public const PATH = '/.well-known/mta-sts.txt';

	/** RFC 8461 §3.2: max_age is at most 31557600 seconds (about a year). */
	public const MAX_AGE_LIMIT = 31557600;

	/** Stand-in mail server in the templates when DNS names none. Saving refuses it. */
	public const PLACEHOLDER_MX = 'mail.example.invalid';

	private const MODES = array( 'testing', 'enforce', 'none' );

	private const FIELDS = array( 'version', 'mode', 'mx', 'max_age' );

	/** RFC 8461 §3.2 field syntax: a name of up to 32 characters, a colon, optional spaces, the value. */
	private const LINE = '/^([A-Za-z0-9][A-Za-z0-9_.-]{0,31}):[ \t]*(.*?)[ \t]*$/';

	/** A host name, or "*." and a host name (the wildcard covers exactly one label). */
	private const MX_PATTERN = '/^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/i';

	private const TESTING_MAX_AGE = 86400;   // One day.
	private const ENFORCE_MAX_AGE = 604800;  // One week.
	private const NONE_MAX_AGE    = 86400;   // One day, as RFC 8461 §8.3 suggests.

	// ── Where ─────────────────────────────────────────────────────────────────

	/**
	 * The mail domain this site publishes a policy for: its own host, less
	 * a leading "www.". Empty when the address isn't a domain name (an IP
	 * address or a single-label host such as localhost).
	 */
	public static function domain(): string {
		$host = strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
		if ( str_starts_with( $host, 'www.' ) ) {
			$host = substr( $host, 4 );
		}
		if ( ! str_contains( $host, '.' ) || false !== filter_var( $host, FILTER_VALIDATE_IP ) ) {
			return '';
		}
		return $host;
	}

	/** The policy host, mta-sts.<domain>, or '' (see domain()). */
	public static function host(): string {
		$domain = self::domain();
		return '' === $domain ? '' : 'mta-sts.' . $domain;
	}

	/** Where mail servers fetch the policy, or '' (see domain()). */
	public static function url(): string {
		$host = self::host();
		return '' === $host ? '' : 'https://' . $host . self::PATH;
	}

	/**
	 * Fetches the policy the way RFC 8461 §3.3 says mail servers do: over
	 * HTTPS with a valid certificate, following no redirect.
	 */
	public static function fetch( string $url ): array|\WP_Error {
		return wp_remote_get(
			$url,
			array(
				'timeout'             => 10,
				'redirection'         => 0,
				'sslverify'           => true,
				'limit_response_size' => Well_Known_File_Catalog::MAX_BYTES,
				'user-agent'          => 'WordPress/' . get_bloginfo( 'version' ) . '; VCNS-Security-Automation-Manager/' . WP_SAM_VERSION . '; ' . get_bloginfo( 'url' ),
			)
		);
	}

	/**
	 * Why a mail server couldn't use this response as a policy, or null
	 * when it could. Never says where a redirect pointed.
	 */
	public static function unusable_reason( array|\WP_Error $response ): ?string {
		if ( is_wp_error( $response ) ) {
			/* translators: %s: error message from the HTTP request */
			return sprintf( __( 'couldn\'t be fetched (%s)', 'vcns-security-automation-manager' ), rtrim( $response->get_error_message(), '.' ) );
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		if ( $code >= 300 && $code < 400 ) {
			return __( 'redirects, and mail servers don\'t follow redirects', 'vcns-security-automation-manager' );
		}
		if ( 200 !== $code ) {
			/* translators: %d: HTTP status code */
			return sprintf( __( 'returned HTTP %d', 'vcns-security-automation-manager' ), $code );
		}
		$type = wp_remote_retrieve_header( $response, 'content-type' );
		$type = strtolower( trim( (string) strtok( (string) ( is_array( $type ) ? reset( $type ) : $type ), ';' ) ) );
		if ( 'text/plain' !== $type ) {
			return __( 'isn\'t sent as text/plain, which mail servers check for', 'vcns-security-automation-manager' );
		}
		return null;
	}

	// ── What ──────────────────────────────────────────────────────────────────

	/**
	 * The policy as a mail server reads it: the first value of each field
	 * (RFC 8461 §3.2 has later ones ignored), every mx line, and unknown
	 * fields dropped.
	 *
	 * @return array{version:?string, mode:?string, max_age:?string, mx:array<int,string>}
	 */
	public static function parse( string $content ): array {
		$fields = array(
			'version' => null,
			'mode'    => null,
			'max_age' => null,
			'mx'      => array(),
		);
		foreach ( explode( "\n", $content ) as $line ) {
			if ( 1 !== preg_match( self::LINE, rtrim( $line, "\r" ), $matches ) ) {
				continue;
			}
			if ( 'mx' === $matches[1] ) {
				$fields['mx'][] = $matches[2];
			} elseif ( array_key_exists( $matches[1], $fields ) && null === $fields[ $matches[1] ] ) {
				$fields[ $matches[1] ] = $matches[2];
			}
		}
		return $fields;
	}

	/**
	 * Why this (already sanitised) policy would be refused or misread, or
	 * an empty array. In enforce mode it is also refused when this
	 * domain's MX records name a mail server no mx line matches: mail
	 * servers that follow the policy would stop delivering to it.
	 *
	 * @param array<int, string>|null $mx_hosts This domain's mail servers (Mail_Dns::mx_hosts()), or null when unknown.
	 * @return array<int, string>
	 */
	public static function problems( string $content, ?array $mx_hosts ): array {
		$problems = array();

		foreach ( explode( "\n", rtrim( $content, "\n" ) ) as $index => $line ) {
			if ( '' === trim( $line ) ) {
				/* translators: %d: line number. */
				$problems[] = sprintf( __( 'Line %d is blank. A policy has one field per line, with no blank lines between them.', 'vcns-security-automation-manager' ), $index + 1 );
				continue;
			}
			if ( 1 !== preg_match( self::LINE, $line, $matches ) ) {
				/* translators: 1: line number, 2: the line's text. */
				$problems[] = sprintf( __( 'Line %1$d isn\'t a "field: value" line: %2$s', 'vcns-security-automation-manager' ), $index + 1, $line );
				continue;
			}
			$lower = strtolower( $matches[1] );
			if ( $lower !== $matches[1] && in_array( $lower, self::FIELDS, true ) ) {
				/* translators: 1: line number, 2: field name, e.g. mode. */
				$problems[] = sprintf( __( 'Line %1$d: field names are lower case. Write "%2$s:".', 'vcns-security-automation-manager' ), $index + 1, $lower );
			}
		}

		$fields = self::parse( $content );
		if ( 'STSv1' !== $fields['version'] ) {
			$problems[] = __( 'The policy needs the line "version: STSv1".', 'vcns-security-automation-manager' );
		}
		if ( ! in_array( $fields['mode'], self::MODES, true ) ) {
			$problems[] = __( 'The policy needs a mode line: "mode: testing", "mode: enforce" or "mode: none".', 'vcns-security-automation-manager' );
		}
		if ( null === $fields['max_age'] || 1 !== preg_match( '/^[0-9]{1,10}$/', $fields['max_age'] ) || (int) $fields['max_age'] > self::MAX_AGE_LIMIT ) {
			/* translators: %d: the largest max_age allowed, in seconds. */
			$problems[] = sprintf( __( 'The policy needs a max_age line: how many seconds mail servers keep it, at most %d (a year). For one week, write "max_age: 604800".', 'vcns-security-automation-manager' ), self::MAX_AGE_LIMIT );
		}
		if ( in_array( $fields['mode'], array( 'testing', 'enforce' ), true ) && array() === $fields['mx'] ) {
			$problems[] = __( 'In testing and enforce mode the policy needs at least one "mx:" line naming a mail server for this domain.', 'vcns-security-automation-manager' );
		}
		foreach ( $fields['mx'] as $pattern ) {
			if ( self::PLACEHOLDER_MX === strtolower( $pattern ) ) {
				/* translators: %s: the placeholder mail server name. */
				$problems[] = sprintf( __( 'Replace %s with the name of a mail server that receives email for this domain.', 'vcns-security-automation-manager' ), self::PLACEHOLDER_MX );
			} elseif ( strlen( $pattern ) > 253 || 1 !== preg_match( self::MX_PATTERN, $pattern ) ) {
				/* translators: %s: the mx line's value. */
				$problems[] = sprintf( __( '"mx: %s" isn\'t a mail server name. Write a name such as mail.example.com, or *.example.com to match any one name in front of it, with no trailing dot.', 'vcns-security-automation-manager' ), $pattern );
			}
		}
		if ( 'enforce' === $fields['mode'] && ! empty( $mx_hosts ) ) {
			foreach ( self::uncovered( $mx_hosts, $fields['mx'] ) as $host ) {
				/* translators: %s: a mail server host name from this domain's MX records. */
				$problems[] = sprintf( __( 'This domain\'s MX records send mail to %s, and no mx line matches it. In enforce mode, mail servers that follow MTA-STS would stop delivering there. Add it, or use testing mode while you check.', 'vcns-security-automation-manager' ), $host );
			}
		}

		return $problems;
	}

	/**
	 * Whether an mx pattern covers a mail server's host name (RFC 8461
	 * §4.1): exactly, or "*." matching one whole left-most label, so
	 * *.example.com covers mail.example.com but not example.com or
	 * a.b.example.com.
	 */
	public static function matches( string $host, string $pattern ): bool {
		$host    = strtolower( rtrim( $host, '.' ) );
		$pattern = strtolower( $pattern );
		if ( ! str_starts_with( $pattern, '*.' ) ) {
			return $host === $pattern;
		}
		$suffix = substr( $pattern, 1 );
		if ( ! str_ends_with( $host, $suffix ) ) {
			return false;
		}
		$label = substr( $host, 0, -strlen( $suffix ) );
		return '' !== $label && ! str_contains( $label, '.' );
	}

	/**
	 * @param array<int, string> $mx_hosts
	 * @param array<int, string> $patterns
	 * @return array<int, string> The mail servers no pattern covers.
	 */
	public static function uncovered( array $mx_hosts, array $patterns ): array {
		return array_values(
			array_filter(
				$mx_hosts,
				static function ( string $host ) use ( $patterns ): bool {
					foreach ( $patterns as $pattern ) {
						if ( self::matches( $host, $pattern ) ) {
							return false;
						}
					}
					return true;
				}
			)
		);
	}

	/**
	 * Starter policies, listing this domain's own mail servers when DNS
	 * names them. Testing first: RFC 8461 §5 and every large mail provider
	 * recommend running in testing mode, with TLS reports, before enforce.
	 *
	 * @param array<int, string>|null $mx_hosts Mail_Dns::mx_hosts() for this domain.
	 * @return array<string, array{label:string, description:string, content:string}>
	 */
	public static function templates( ?array $mx_hosts ): array {
		$found    = ! empty( $mx_hosts );
		$mx_lines = '';
		foreach ( $found ? $mx_hosts : array( self::PLACEHOLDER_MX ) as $host ) {
			$mx_lines .= "mx: {$host}\n";
		}
		$source = $found
			? __( 'It lists the mail servers this domain\'s MX records name.', 'vcns-security-automation-manager' )
			/* translators: %s: the placeholder mail server name. */
			: sprintf( __( 'This plugin found no MX records for the domain, so replace %s with your mail server\'s name.', 'vcns-security-automation-manager' ), self::PLACEHOLDER_MX );

		return array(
			'testing' => array(
				'label'       => __( 'Testing', 'vcns-security-automation-manager' ),
				'description' => __( 'Start here. Mail servers still deliver when a secure connection fails, and those that support TLS reports tell you about it. Kept for one day.', 'vcns-security-automation-manager' ) . ' ' . $source,
				'content'     => "version: STSv1\nmode: testing\n{$mx_lines}max_age: " . self::TESTING_MAX_AGE . "\n",
			),
			'enforce' => array(
				'label'       => __( 'Enforce', 'vcns-security-automation-manager' ),
				'description' => __( 'Once reports show no failures. Mail servers refuse to deliver unless they can connect securely to one of these servers with a valid certificate. Kept for one week.', 'vcns-security-automation-manager' ) . ' ' . $source,
				'content'     => "version: STSv1\nmode: enforce\n{$mx_lines}max_age: " . self::ENFORCE_MAX_AGE . "\n",
			),
			'none'    => array(
				'label'       => __( 'Turn off', 'vcns-security-automation-manager' ),
				'description' => __( 'Tells mail servers this domain no longer uses MTA-STS. Serve it, with a new DNS id, until the policy it replaces has been out for its max_age, then remove the DNS record and stop serving.', 'vcns-security-automation-manager' ),
				'content'     => "version: STSv1\nmode: none\nmax_age: " . self::NONE_MAX_AGE . "\n",
			),
		);
	}

	// ── DNS ───────────────────────────────────────────────────────────────────

	/**
	 * The id for this version of the policy, for the _mta-sts TXT record.
	 * Taken from the content, so it changes exactly when the policy does
	 * and re-saving the same text keeps it.
	 */
	public static function id( string $content ): string {
		return substr( hash( 'sha256', $content ), 0, 20 );
	}

	/** The _mta-sts TXT record value for this version of the policy. */
	public static function dns_record( string $content ): string {
		return 'v=STSv1; id=' . self::id( $content );
	}

	/** A _smtp._tls TXT record value sending TLS reports to the site's admin email. */
	public static function tls_rpt_suggestion(): string {
		$email = (string) get_option( 'admin_email', '' );
		if ( '' === $email ) {
			$email = 'tls-reports@' . self::domain();
		}
		return 'v=TLSRPTv1; rua=mailto:' . $email;
	}
}
