<?php
/**
 * The traffic-advice format: /.well-known/traffic-advice, a JSON file that
 * tells private prefetch proxies whether they may fetch pages from this
 * site, or how much of their traffic to send. Chrome's private prefetch
 * proxy, which loads pages from Google Search results ahead of a click,
 * reads it under the "prefetch-proxy" user agent.
 *
 * Format (Traffic Advice draft, buettner.github.io/private-prefetch-proxy/
 * traffic-advice.html): a JSON array of objects. Each object names a
 * user_agent (a proxy's own name, "prefetch-proxy" for any proxy that
 * only prefetches, or "*" for everyone) and gives "disallow": true, or a
 * "fraction" from 0 to 1 of the traffic it may send. A proxy uses the one
 * entry whose user_agent matches it most specifically; among repeats, the
 * first. Matching is case-sensitive.
 *
 * A proxy ignores the file unless it is served with status 200, without a
 * redirect, as application/trafficadvice+json. It keeps the advice for
 * between 10 minutes and 48 hours, 30 minutes when the response gives no
 * caching lifetime.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Traffic_Advice {

	public const PATH = '/.well-known/traffic-advice';

	public const MEDIA_TYPE = 'application/trafficadvice+json';

	/** The user agent every proxy that only prefetches answers to, Chrome's included. */
	public const PREFETCH_PROXY = 'prefetch-proxy';

	/** Sent as max-age: the 30 minutes the draft suggests as a default, so an edit reaches proxies within half an hour. */
	public const MAX_AGE = 1800;

	private const FIELDS = array( 'user_agent', 'disallow', 'fraction' );

	/**
	 * Starter versions for the editor. The first is the one a missing
	 * file's editor opens with.
	 *
	 * @return array<string, array{label:string, description:string, content:string}>
	 */
	public static function templates(): array {
		return array(
			'disallow' => array(
				'label'       => __( 'Turn off prefetch proxies', 'vcns-security-automation-manager' ),
				'description' => __( 'Asks prefetch proxies, including Chrome\'s, not to fetch pages from this site ahead of a click. Pages still open normally when someone clicks through.', 'vcns-security-automation-manager' ),
				'content'     => self::encode(
					array(
						array(
							'user_agent' => self::PREFETCH_PROXY,
							'disallow'   => true,
						),
					)
				),
			),
			'reduce'   => array(
				'label'       => __( 'Reduce prefetch traffic', 'vcns-security-automation-manager' ),
				'description' => __( 'Asks prefetch proxies to make only half the prefetches they otherwise would. Change 0.5 to any fraction from 0 to 1.', 'vcns-security-automation-manager' ),
				'content'     => self::encode(
					array(
						array(
							'user_agent' => self::PREFETCH_PROXY,
							'fraction'   => 0.5,
						),
					)
				),
			),
		);
	}

	/**
	 * Why this content wouldn't work as traffic advice, or an empty array
	 * when it would. Besides what makes a proxy ignore the file or an
	 * entry, flags what is almost always a typing mistake: a field name a
	 * proxy doesn't know, a user_agent in the wrong case, a repeated
	 * user_agent (proxies use only the first) and an entry that advises
	 * nothing.
	 *
	 * @return array<int, string>
	 */
	public static function problems( string $content ): array {
		$entries = json_decode( $content, true );
		if ( JSON_ERROR_NONE !== json_last_error() ) {
			/* translators: %s: the JSON parser's error message */
			return array( sprintf( __( 'This isn\'t valid JSON: %s.', 'vcns-security-automation-manager' ), json_last_error_msg() ) );
		}
		if ( ! is_array( $entries ) || ! array_is_list( $entries ) ) {
			return array( __( 'Traffic advice must be a JSON list, starting with [ and ending with ], of entries such as {"user_agent": "prefetch-proxy", "disallow": true}.', 'vcns-security-automation-manager' ) );
		}
		if ( array() === $entries ) {
			return array( __( 'The list is empty, so proxies get no advice. Add an entry, or use Stop serving to remove this plugin\'s version.', 'vcns-security-automation-manager' ) );
		}

		$problems = array();
		$seen     = array();
		foreach ( $entries as $index => $entry ) {
			$number = $index + 1;
			if ( ! is_array( $entry ) || ( array() !== $entry && array_is_list( $entry ) ) ) {
				/* translators: %d: entry number, counting from 1 */
				$problems[] = sprintf( __( 'Entry %d isn\'t an object like {"user_agent": "prefetch-proxy", "disallow": true}.', 'vcns-security-automation-manager' ), $number );
				continue;
			}

			foreach ( array_keys( $entry ) as $field ) {
				if ( ! in_array( $field, self::FIELDS, true ) ) {
					/* translators: 1: entry number, 2: the unknown field name */
					$problems[] = sprintf( __( 'Entry %1$d: proxies don\'t know the field "%2$s", so they ignore it. The fields are user_agent, disallow and fraction.', 'vcns-security-automation-manager' ), $number, (string) $field );
				}
			}

			$agent = $entry['user_agent'] ?? null;
			if ( ! is_string( $agent ) || '' === $agent ) {
				/* translators: %d: entry number */
				$problems[] = sprintf( __( 'Entry %d needs a "user_agent" such as "prefetch-proxy", or "*" for every proxy.', 'vcns-security-automation-manager' ), $number );
				continue;
			}
			if ( self::PREFETCH_PROXY !== $agent && 0 === strcasecmp( self::PREFETCH_PROXY, $agent ) ) {
				/* translators: %d: entry number */
				$problems[] = sprintf( __( 'Entry %d: user_agent is case-sensitive. Write "prefetch-proxy" in lower case.', 'vcns-security-automation-manager' ), $number );
			}
			if ( isset( $seen[ $agent ] ) ) {
				/* translators: 1: entry number, 2: the user_agent value, 3: number of the earlier entry */
				$problems[] = sprintf( __( 'Entry %1$d repeats user_agent "%2$s" from entry %3$d. Proxies use only the first, so remove one.', 'vcns-security-automation-manager' ), $number, $agent, $seen[ $agent ] );
			} else {
				$seen[ $agent ] = $number;
			}

			$has_disallow = array_key_exists( 'disallow', $entry );
			$has_fraction = array_key_exists( 'fraction', $entry );
			if ( $has_disallow && ! is_bool( $entry['disallow'] ) ) {
				/* translators: %d: entry number */
				$problems[] = sprintf( __( 'Entry %d: "disallow" must be true or false, without quotes.', 'vcns-security-automation-manager' ), $number );
			}
			if ( $has_fraction && ! self::is_fraction( $entry['fraction'] ) ) {
				/* translators: %d: entry number */
				$problems[] = sprintf( __( 'Entry %d: "fraction" must be a number from 0 to 1, such as 0.5, without quotes.', 'vcns-security-automation-manager' ), $number );
			}
			if ( ! $has_disallow && ! $has_fraction ) {
				/* translators: %d: entry number */
				$problems[] = sprintf( __( 'Entry %d gives no advice. Add "disallow": true, or a "fraction" from 0 to 1.', 'vcns-security-automation-manager' ), $number );
			}
		}

		return $problems;
	}

	/**
	 * What Chrome's prefetch proxy would take from this content: the entry
	 * for "prefetch-proxy", or failing that "*", reduced to disallow and
	 * fraction the way the draft reads them. Null when the content isn't a
	 * list or neither user agent has an entry.
	 *
	 * @return array{user_agent:string, disallow:bool, fraction:float}|null
	 */
	public static function advice_for_prefetch_proxies( string $content ): ?array {
		$entries = json_decode( $content, true );
		if ( ! is_array( $entries ) || ! array_is_list( $entries ) ) {
			return null;
		}

		$best = null;
		foreach ( array( self::PREFETCH_PROXY, '*' ) as $agent ) {
			foreach ( $entries as $entry ) {
				if ( is_array( $entry ) && ( $entry['user_agent'] ?? null ) === $agent ) {
					$best = $entry;
					break 2;
				}
			}
		}
		if ( null === $best ) {
			return null;
		}

		$fraction = $best['fraction'] ?? 1;
		return array(
			'user_agent' => (string) $best['user_agent'],
			'disallow'   => true === ( $best['disallow'] ?? false ),
			'fraction'   => self::is_fraction( $fraction ) ? (float) $fraction : 1.0,
		);
	}

	/** A JSON number from 0 to 1. The draft ignores anything else, which leaves all traffic allowed. */
	private static function is_fraction( mixed $value ): bool {
		return ( is_int( $value ) || is_float( $value ) ) && $value >= 0 && $value <= 1;
	}

	/** Whether a response's Content-Type is the one proxies require. */
	public static function has_media_type( array $response ): bool {
		$type = strtolower( trim( (string) wp_remote_retrieve_header( $response, 'content-type' ) ) );
		return self::MEDIA_TYPE === trim( (string) strtok( $type, ';' ) );
	}

	/** Pretty-printed JSON with a trailing newline, as the editor shows it. */
	private static function encode( array $entries ): string {
		return (string) wp_json_encode( $entries, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) . "\n";
	}
}
