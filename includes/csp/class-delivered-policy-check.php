<?php
/**
 * Checks the Content Security Policy visitors actually receive on this
 * site's home page against the current frontend policy.
 *
 * Everything else SAM shows about delivery (the Violations tab's "Policy
 * is being sent", Verify → CSP Policy Audit) is what PHP sends. A page
 * cache or CDN in front of WordPress can keep serving an older copy of
 * the page, with the header it was stored with, for days after an
 * approval, a rejection or a promotion to enforce. This fetches the home
 * page the way an anonymous visitor would (no cookies, no cache-busting
 * query string) and compares the policy that comes back, ignoring nonces
 * and inline hashes (see Policy_Fingerprint).
 *
 * The request comes from this server. If the server reaches its own
 * address directly rather than through the CDN, a stale CDN copy won't
 * show up here; the cache headers recorded with each result say which
 * layers answered.
 *
 * Uses Same_Host_Fetcher, so a redirect away from this site is reported
 * as such and never followed, and nothing about where it pointed is
 * stored.
 *
 * Runs with the daily scan, two minutes after Page_Cache_Purger deals
 * with a policy change, and from Settings → Security Health's "Check now".
 */

declare( strict_types=1 );

namespace WP_SAM\CSP;

use WP_SAM\Intelligence\Same_Host_Fetcher;
use WP_SAM\Modules\Audit_Log;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Delivered_Policy_Check {

	/** The latest result, as returned by run(). */
	public const OPTION_RESULT = 'wp_sam_delivered_policy_check';

	/** Single cron event scheduled after a policy change. */
	public const CHECK_HOOK = 'wp_sam_delivered_policy_check';

	/** Long enough for a cache that was just cleared to be refilled by a real visit, or by this check. */
	public const DELAY_AFTER_CHANGE = 120;

	/** Visitors get the current policy (or, while the frontend is disabled, none). */
	public const OUTCOME_CURRENT = 'current';

	/** Visitors get a policy, but not the current one. */
	public const OUTCOME_STALE = 'stale';

	/** Visitors get no policy although the frontend is in report-only or enforce mode. */
	public const OUTCOME_MISSING = 'missing';

	/** Visitors get a policy although the frontend is disabled. */
	public const OUTCOME_UNEXPECTED = 'unexpected';

	/** The home page could not be read, so nothing was compared. */
	public const OUTCOME_UNREACHABLE = 'unreachable';

	/** No frontend profile exists yet, so there is nothing to compare with. */
	public const OUTCOME_NOT_CONFIGURED = 'not_configured';

	private const CSP_HEADERS = array( 'content-security-policy', 'content-security-policy-report-only' );

	/** Response headers that say which cache, if any, answered. */
	private const CACHE_HEADERS = array(
		'cf-cache-status',
		'age',
		'x-litespeed-cache',
		'x-lsadc-cache',
		'x-cache',
		'x-cache-status',
		'x-proxy-cache',
		'x-sucuri-cache',
		'x-kinsta-cache',
	);

	/** Most entries kept for each of a stale result's 'missing' and 'unexpected' lists. */
	private const MAX_DIFF_ENTRIES = 20;

	/** @var callable(string):(array|\WP_Error) */
	private $fetch;

	/** @var callable():(array{mode: string, header: string, policy: string}|null) */
	private $read_policy;

	private ?Audit_Log $audit;

	/**
	 * @param callable|null  $fetch       GETs a URL; Same_Host_Fetcher by default, so tests never make a real request.
	 * @param callable|null  $read_policy Returns the current frontend policy; Frontend_Policy_Reader by default.
	 * @param Audit_Log|null $audit       Where a newly found problem is recorded (and so shown as an admin notice).
	 */
	public function __construct( ?callable $fetch = null, ?callable $read_policy = null, ?Audit_Log $audit = null ) {
		$this->fetch       = $fetch ?? static fn ( string $url ): array|\WP_Error => ( new Same_Host_Fetcher() )->get(
			$url,
			array(
				'timeout'             => 15,
				'user-agent'          => 'WP-SAM-Visitor-Check/' . WP_SAM_VERSION,
				'sslverify'           => true,
				'limit_response_size' => 65536,
			)
		);
		$this->read_policy = $read_policy ?? static fn (): ?array => ( new Frontend_Policy_Reader() )->read();
		$this->audit       = $audit;
	}

	/**
	 * Hooks the scheduled check, and schedules one after each policy change.
	 *
	 * @return void
	 */
	public function register(): void {
		add_action( self::CHECK_HOOK, array( $this, 'run' ) );
		add_action( Page_Cache_Purger::CHANGED_ACTION, array( $this, 'schedule_soon' ) );
	}

	/**
	 * Schedules a check DELAY_AFTER_CHANGE seconds from now, unless one is
	 * already due.
	 *
	 * @return void
	 */
	public function schedule_soon(): void {
		if ( false === wp_next_scheduled( self::CHECK_HOOK ) ) {
			wp_schedule_single_event( time() + self::DELAY_AFTER_CHANGE, self::CHECK_HOOK );
		}
	}

	/**
	 * Fetches the home page, compares its policy, stores the result, and
	 * records a newly found problem in the audit log.
	 *
	 * @return array<string, mixed> The result; see evaluate().
	 */
	public function run(): array {
		$previous = $this->result();
		$result   = $this->evaluate( ( $this->read_policy )(), ( $this->fetch )( home_url( '/' ) ) );

		update_option( self::OPTION_RESULT, $result, false );
		$this->maybe_record_problem( $previous, $result );

		return $result;
	}

	/**
	 * The latest stored result, or an empty array before the first check.
	 *
	 * @return array<string, mixed>
	 */
	public function result(): array {
		$stored = get_option( self::OPTION_RESULT, array() );
		return is_array( $stored ) ? $stored : array();
	}

	/**
	 * Compares a fetched home page with the frontend policy.
	 *
	 * @param array|null      $expected Frontend_Policy_Reader::read()'s result.
	 * @param array|\WP_Error $response The home page response.
	 * @return array{checked_at: int, outcome: string, error: string, mode: string, http_code: int, header: string, cache: array<string, string>, missing: list<string>, unexpected: list<string>}
	 */
	public function evaluate( ?array $expected, array|\WP_Error $response ): array {
		$result = array(
			'checked_at' => time(),
			'outcome'    => '',
			'error'      => '',
			'mode'       => (string) ( $expected['mode'] ?? '' ),
			'http_code'  => 0,
			'header'     => '',
			'cache'      => array(),
			'missing'    => array(),
			'unexpected' => array(),
		);

		if ( is_wp_error( $response ) ) {
			$result['outcome'] = self::OUTCOME_UNREACHABLE;
			// Same_Host_Fetcher's off-site redirect message names no destination.
			$result['error'] = $response->get_error_message();
			return $result;
		}

		$code                = (int) wp_remote_retrieve_response_code( $response );
		$result['http_code'] = $code;
		$result['cache']     = $this->cache_headers( $response );

		if ( $code < 200 || $code >= 300 ) {
			$result['outcome'] = self::OUTCOME_UNREACHABLE;
			return $result;
		}

		if ( null === $expected ) {
			$result['outcome'] = self::OUTCOME_NOT_CONFIGURED;
			return $result;
		}

		$found = $this->policy_headers( $response, $expected['header'] );

		if ( 'disabled' === $expected['mode'] ) {
			$result['outcome'] = empty( $found ) ? self::OUTCOME_CURRENT : self::OUTCOME_UNEXPECTED;
			$result['header']  = empty( $found ) ? '' : $found[0]['name'];
			return $result;
		}

		if ( empty( $found ) ) {
			$result['outcome'] = self::OUTCOME_MISSING;
			return $result;
		}

		$want = Policy_Fingerprint::canonicalise( $expected['policy'] );
		$best = null;
		foreach ( $found as $header ) {
			$diff  = Policy_Fingerprint::diff( $want, Policy_Fingerprint::canonicalise( $header['value'] ) );
			$score = count( $diff['missing'] ) + count( $diff['unexpected'] );
			if ( null === $best || $score < $best['score'] ) {
				$best = array(
					'name'  => $header['name'],
					'diff'  => $diff,
					'score' => $score,
				);
			}
		}

		$result['header'] = $best['name'];

		if ( $best['score'] > 0 ) {
			$result['outcome']    = self::OUTCOME_STALE;
			$result['missing']    = array_slice( $best['diff']['missing'], 0, self::MAX_DIFF_ENTRIES );
			$result['unexpected'] = array_slice( $best['diff']['unexpected'], 0, self::MAX_DIFF_ENTRIES );
			return $result;
		}

		// The right policy under the wrong header: a copy cached before a
		// promotion to enforce (or a step back to report-only).
		$result['outcome'] = self::header_matches_mode( $best['name'], $expected ) ? self::OUTCOME_CURRENT : self::OUTCOME_STALE;

		return $result;
	}

	/**
	 * Whether a result's cache headers say a cache, rather than WordPress,
	 * answered.
	 *
	 * @param array<string, string> $cache The result's 'cache' entry.
	 */
	public static function served_from_cache( array $cache ): bool {
		foreach ( $cache as $name => $value ) {
			$value = strtolower( $value );
			if ( 'age' === $name ) {
				if ( (int) $value > 0 ) {
					return true;
				}
				continue;
			}
			if ( 'cf-cache-status' === $name ) {
				if ( in_array( $value, array( 'hit', 'stale', 'updating', 'revalidated' ), true ) ) {
					return true;
				}
				continue;
			}
			if ( str_starts_with( $value, 'hit' ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Plain-language text describing a result, for the audit log and
	 * Settings → Security Health.
	 *
	 * @param array<string, mixed> $result A stored result.
	 */
	public static function describe( array $result ): string {
		$mode       = (string) ( $result['mode'] ?? '' );
		$code       = (int) ( $result['http_code'] ?? 0 );
		$missing    = (array) ( $result['missing'] ?? array() );
		$unexpected = (array) ( $result['unexpected'] ?? array() );

		switch ( (string) ( $result['outcome'] ?? '' ) ) {
			case self::OUTCOME_CURRENT:
				$text = 'disabled' === $mode
					? __( 'The frontend policy is disabled, and visitors receive no Content Security Policy.', 'vcns-security-automation-manager' )
					: __( 'Visitors receive the current Content Security Policy.', 'vcns-security-automation-manager' );
				break;

			case self::OUTCOME_STALE:
				if ( empty( $missing ) && empty( $unexpected ) ) {
					$text = sprintf(
						/* translators: 1: header name, e.g. content-security-policy-report-only, 2: the frontend's mode, e.g. enforce */
						__( 'Visitors receive the current policy, but as %1$s, although the frontend is now in %2$s mode.', 'vcns-security-automation-manager' ),
						(string) ( $result['header'] ?? '' ),
						$mode
					);
					break;
				}
				$text = __( 'Visitors receive an older Content Security Policy than the current one.', 'vcns-security-automation-manager' );
				if ( ! empty( $missing ) ) {
					$text .= ' ' . sprintf(
						/* translators: %s: comma-separated directive and source pairs, e.g. "script-src https://www.example.com" */
						__( 'Missing from what visitors receive: %s.', 'vcns-security-automation-manager' ),
						implode( ', ', $missing )
					);
				}
				if ( ! empty( $unexpected ) ) {
					$text .= ' ' . sprintf(
						/* translators: %s: comma-separated directive and source pairs */
						__( 'No longer in the current policy: %s.', 'vcns-security-automation-manager' ),
						implode( ', ', $unexpected )
					);
				}
				break;

			case self::OUTCOME_MISSING:
				$text = sprintf(
					/* translators: %s: the frontend's mode, e.g. report-only */
					__( 'Visitors receive no Content Security Policy, although the frontend is in %s mode.', 'vcns-security-automation-manager' ),
					$mode
				);
				break;

			case self::OUTCOME_UNEXPECTED:
				$text = __( 'The frontend policy is disabled, but visitors still receive a Content Security Policy. It is either a copy cached before the policy was disabled, or sent by something other than this plugin.', 'vcns-security-automation-manager' );
				break;

			case self::OUTCOME_UNREACHABLE:
				if ( 401 === $code || 403 === $code ) {
					$text = sprintf(
						/* translators: %d: HTTP status code */
						__( "This site's home page refused the request (HTTP %d), usually because of a firewall, bot protection or a login requirement, so its policy could not be read.", 'vcns-security-automation-manager' ),
						$code
					);
				} elseif ( $code > 0 ) {
					$text = sprintf(
						/* translators: %d: HTTP status code */
						__( "This site's home page answered HTTP %d instead of a page, so its policy could not be read.", 'vcns-security-automation-manager' ),
						$code
					);
				} else {
					$text = sprintf(
						/* translators: %s: the error WordPress reported */
						__( "This site's home page could not be fetched: %s", 'vcns-security-automation-manager' ),
						(string) ( $result['error'] ?? '' )
					);
				}
				break;

			case self::OUTCOME_NOT_CONFIGURED:
				$text = __( 'The frontend has no Content Security Policy profile yet, so there is nothing to compare with.', 'vcns-security-automation-manager' );
				break;

			default:
				$text = '';
		}

		$cache = (array) ( $result['cache'] ?? array() );
		if ( ! empty( $cache ) && self::served_from_cache( $cache ) ) {
			$parts = array();
			foreach ( $cache as $name => $value ) {
				$parts[] = $name . ': ' . $value;
			}
			$text .= ' ' . sprintf(
				/* translators: %s: comma-separated cache headers, e.g. "cf-cache-status: HIT, age: 7200" */
				__( 'The page came from a cache (%s).', 'vcns-security-automation-manager' ),
				implode( ', ', $parts )
			);
		}

		return $text;
	}

	/**
	 * Whether a header name is right for the frontend's mode. A custom
	 * header name (Control → Automation Settings → Policy header name) is
	 * copied to the standard header by the proxy, so either is right.
	 *
	 * @param string                                          $name     Header name received, lower-case.
	 * @param array{mode: string, header: string, policy: string} $expected The current frontend policy.
	 */
	private static function header_matches_mode( string $name, array $expected ): bool {
		$standard = 'report-only' === $expected['mode'] ? 'content-security-policy-report-only' : 'content-security-policy';
		return $name === $standard || $name === $expected['header'];
	}

	/**
	 * Every CSP header on the response, plus the custom header name if
	 * one is configured.
	 *
	 * @param array  $response        The home page response.
	 * @param string $expected_header The configured header name, lower-case.
	 * @return list<array{name: string, value: string}>
	 */
	private function policy_headers( array $response, string $expected_header ): array {
		$names = self::CSP_HEADERS;
		if ( '' !== $expected_header && ! in_array( $expected_header, $names, true ) ) {
			$names[] = $expected_header;
		}

		$found = array();
		foreach ( $names as $name ) {
			$values = wp_remote_retrieve_header( $response, $name );
			foreach ( (array) $values as $value ) {
				$value = trim( (string) $value );
				if ( '' !== $value ) {
					$found[] = array(
						'name'  => $name,
						'value' => $value,
					);
				}
			}
		}

		return $found;
	}

	/**
	 * The cache-status headers on the response, reduced to their first
	 * word (HIT, MISS, a number of seconds) so nothing else a proxy puts
	 * there, such as a hostname, is stored.
	 *
	 * @param array $response The home page response.
	 * @return array<string, string>
	 */
	private function cache_headers( array $response ): array {
		$cache = array();
		foreach ( self::CACHE_HEADERS as $name ) {
			$value = wp_remote_retrieve_header( $response, $name );
			if ( is_array( $value ) ) {
				$value = reset( $value );
			}
			if ( 1 === preg_match( '/^\s*([A-Za-z0-9_.-]{1,32})/', (string) $value, $matches ) ) {
				$cache[ $name ] = $matches[1];
			}
		}

		return $cache;
	}

	/**
	 * Records a problem in the audit log (which queues it as an admin
	 * notice) the first time it is found, not on every daily check that
	 * finds it again.
	 *
	 * @param array<string, mixed> $previous The result before this check.
	 * @param array<string, mixed> $result   This check's result.
	 */
	private function maybe_record_problem( array $previous, array $result ): void {
		if ( ! in_array( $result['outcome'], array( self::OUTCOME_STALE, self::OUTCOME_MISSING, self::OUTCOME_UNEXPECTED ), true ) ) {
			return;
		}

		$same = ( $previous['outcome'] ?? '' ) === $result['outcome']
			&& ( $previous['missing'] ?? array() ) === $result['missing']
			&& ( $previous['unexpected'] ?? array() ) === $result['unexpected']
			&& ( $previous['header'] ?? '' ) === $result['header'];
		if ( $same ) {
			return;
		}

		$this->audit?->log( 'delivered_policy', (string) $result['outcome'], self::describe( $result ), 'warning' );
	}
}
