<?php
/**
 * Clears page caches when the frontend Content Security Policy changes.
 *
 * A page cache stores the response headers along with the page. Until the
 * cached copy expires, visitors keep getting the policy it was stored
 * with, whatever has been approved, rejected or promoted since. Some
 * hosts keep cached pages for ten days. SAM's own "Policy is being sent"
 * status only sees what PHP sends, so the delay is invisible from inside
 * WordPress.
 *
 * How a change is noticed: the policy can change from many places
 * (decisions, the automation engine, profile edits, a rollback, an
 * import, a data reset), so this doesn't hook each one. It watches for
 * writes to the two tables the policy is built from, and for the three
 * options that shape the header. When one happens, it compares the
 * policy's digest (Policy_Fingerprint) with the one stored after the last
 * clear, at the end of the request. Requests that don't write to those
 * tables cost one string check per query and nothing else.
 *
 * What doesn't count: per-request nonces, and inline hashes that
 * Hash_Manager learns as pages render. Clearing the cache whenever a new
 * hash was learned would make every cache miss a candidate for another
 * clear, and a page whose inline content varies would keep the cache
 * permanently cold.
 *
 * SAM can clear only caches that run inside WordPress. A CDN in front of
 * the site (Cloudflare, for example) keeps its own copies; the admin
 * notice says so, and Delivered_Policy_Check shows what visitors receive.
 */

declare( strict_types=1 );

namespace WP_SAM\CSP;

use WP_SAM\Modules\Audit_Log;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Page_Cache_Purger {

	/** '1' (the default) or '0'. Saved from Control → Automation Settings. */
	public const OPTION_ENABLED = 'wp_sam_purge_page_cache_on_csp_change';

	/** Policy_Fingerprint::digest() of the frontend policy as of the last clear. */
	public const OPTION_FINGERPRINT = 'wp_sam_frontend_policy_fingerprint';

	/** The last clear that cleared something: array{at: int, caches: list<string>}. */
	public const OPTION_LAST_PURGE = 'wp_sam_page_cache_last_purge';

	/** The same record, waiting to be shown once as an admin notice. */
	public const OPTION_NOTICE = 'wp_sam_page_cache_purge_notice';

	/** Single cron event for a clear that was held back by MIN_INTERVAL. */
	public const CHECK_HOOK = 'wp_sam_page_cache_purge_check';

	/**
	 * Fires once a frontend policy change has been dealt with, whether or
	 * not anything was cleared. Receives the list of caches cleared.
	 */
	public const CHANGED_ACTION = 'wp_sam_frontend_policy_changed';

	/**
	 * Clearing at most once a minute folds a run of approvals, or a burst
	 * of automatic decisions, into one clear and one cache refill.
	 */
	public const MIN_INTERVAL = 60;

	/** Options whose value goes into the frontend header. */
	public const WATCHED_OPTIONS = array(
		'wp_sam_policy_header_name',
		'wp_sam_report_endpoint_url',
		'wp_sam_reporting_transport',
	);

	/** Tables, without prefix, that the frontend policy is built from (approved hashes excepted). */
	private const WATCHED_TABLES = array( 'csp_policy_profiles', 'csp_source_inventory' );

	/** @var callable():(array{mode: string, header: string, policy: string}|null) */
	private $read_policy;

	/** @var list<array{name: string, detect: callable():bool, purge: callable():void}> */
	private array $caches;

	private ?Audit_Log $audit;

	/** @var list<string> */
	private array $watched_tables = array();

	private bool $dirty = false;

	/**
	 * @param callable|null   $read_policy Returns the current frontend policy; Frontend_Policy_Reader by default.
	 * @param array|null      $caches      Caches this class knows how to clear; default_caches() by default.
	 * @param Audit_Log|null  $audit       Where clears and failures are recorded.
	 */
	public function __construct( ?callable $read_policy = null, ?array $caches = null, ?Audit_Log $audit = null ) {
		$this->read_policy = $read_policy ?? static fn (): ?array => ( new Frontend_Policy_Reader() )->read();
		$this->caches      = $caches ?? self::default_caches();
		$this->audit       = $audit;
	}

	/**
	 * Hooks the change watchers, the baseline and the deferred check.
	 *
	 * @return void
	 */
	public function register(): void {
		global $wpdb;
		foreach ( self::WATCHED_TABLES as $table ) {
			$this->watched_tables[] = strtolower( $wpdb->prefix . $table );
		}

		add_filter( 'query', array( $this, 'watch_query' ) );
		foreach ( self::WATCHED_OPTIONS as $option ) {
			add_action( "add_option_{$option}", array( $this, 'mark_dirty' ) );
			add_action( "update_option_{$option}", array( $this, 'mark_dirty' ) );
			add_action( "delete_option_{$option}", array( $this, 'mark_dirty' ) );
		}

		add_action( 'admin_init', array( $this, 'ensure_baseline' ) );
		add_action( self::CHECK_HOOK, array( $this, 'check' ) );
	}

	/**
	 * 'query' filter: notes a write to a watched table. Never changes the
	 * query, and never calls get_option() or anything else that could
	 * query the database from inside this filter.
	 *
	 * @param mixed $query The SQL about to run.
	 * @return mixed The same SQL.
	 */
	public function watch_query( mixed $query ): mixed {
		if ( $this->dirty || ! is_string( $query ) ) {
			return $query;
		}
		if ( 1 !== preg_match( '/^\s*(?:INSERT|UPDATE|DELETE|REPLACE|TRUNCATE)\b/i', $query ) ) {
			return $query;
		}

		$lower = strtolower( $query );
		foreach ( $this->watched_tables as $table ) {
			if ( str_contains( $lower, $table ) ) {
				$this->mark_dirty();
				break;
			}
		}

		return $query;
	}

	/**
	 * Something the frontend policy depends on was written; compare once
	 * this request has finished writing.
	 *
	 * Runs before priority 0 on shutdown so a cache that sends its purge
	 * instruction as a response header (LiteSpeed Cache sends its own
	 * headers on shutdown at priority 0) still gets it onto this response.
	 *
	 * @return void
	 */
	public function mark_dirty(): void {
		if ( $this->dirty ) {
			return;
		}
		$this->dirty = true;
		add_action( 'shutdown', array( $this, 'check' ), -10 );
	}

	/**
	 * Records the current policy's digest if none is stored yet, so the
	 * first real change after this feature arrives has something to be
	 * compared with. Runs on admin_init, before an admin request's own
	 * writes.
	 *
	 * @return void
	 */
	public function ensure_baseline(): void {
		if ( '' !== (string) get_option( self::OPTION_FINGERPRINT, '' ) ) {
			return;
		}

		$fingerprint = $this->fingerprint();
		if ( '' !== $fingerprint ) {
			update_option( self::OPTION_FINGERPRINT, $fingerprint, true );
		}
	}

	/**
	 * Clears page caches if the frontend policy differs from the one they
	 * were last cleared for.
	 *
	 * @return void
	 */
	public function check(): void {
		$current = $this->fingerprint();
		if ( '' === $current ) {
			return;
		}

		$stored = (string) get_option( self::OPTION_FINGERPRINT, '' );
		if ( $current === $stored ) {
			return;
		}
		if ( '' === $stored ) {
			update_option( self::OPTION_FINGERPRINT, $current, true );
			return;
		}

		$purged = array();
		if ( $this->is_enabled() ) {
			$wait = $this->seconds_until_purge_allowed();
			if ( $wait > 0 ) {
				// Leave the stored digest alone so the deferred check still sees the change.
				$this->schedule_check( $wait );
				return;
			}
			$purged = $this->purge();
		}

		update_option( self::OPTION_FINGERPRINT, $current, true );

		/**
		 * Fires once a change to the frontend Content Security Policy has
		 * been dealt with.
		 *
		 * @param list<string> $purged Names of the page caches cleared; empty when none were.
		 */
		do_action( self::CHANGED_ACTION, $purged );
	}

	/**
	 * Clears every page cache this site has that SAM knows how to clear.
	 *
	 * @return list<string> Names of the caches cleared.
	 */
	public function purge(): array {
		$purged = array();
		foreach ( $this->caches as $cache ) {
			try {
				if ( ! ( $cache['detect'] )() ) {
					continue;
				}
				( $cache['purge'] )();
				$purged[] = $cache['name'];
			} catch ( \Throwable $e ) {
				$this->audit?->log(
					'page_cache',
					'purge_failed',
					sprintf( '%1$s could not be cleared after the frontend Content Security Policy changed: %2$s', $cache['name'], $e->getMessage() ),
					'warning'
				);
			}
		}

		/**
		 * Fires when SAM clears page caches after a frontend Content
		 * Security Policy change, so a host or a cache SAM doesn't know
		 * about can clear its own copies too.
		 *
		 * @param list<string> $purged Names of the caches SAM cleared itself.
		 */
		do_action( 'wp_sam_purge_page_caches', $purged );

		if ( ! empty( $purged ) ) {
			$record = array(
				'at'     => time(),
				'caches' => $purged,
			);
			update_option( self::OPTION_LAST_PURGE, $record, false );
			update_option( self::OPTION_NOTICE, $record, false );
			$this->audit?->log(
				'page_cache',
				'purged',
				'The frontend Content Security Policy changed, so these page caches were cleared: ' . implode( ', ', $purged ) . '.',
				'info'
			);
		}

		return $purged;
	}

	/**
	 * Whether clearing is switched on (Control → Automation Settings).
	 */
	public function is_enabled(): bool {
		return '0' !== (string) get_option( self::OPTION_ENABLED, '1' );
	}

	/**
	 * Names of the page caches on this site that SAM knows how to clear.
	 *
	 * @return list<string>
	 */
	public function detected_caches(): array {
		$names = array();
		foreach ( $this->caches as $cache ) {
			try {
				if ( ( $cache['detect'] )() ) {
					$names[] = $cache['name'];
				}
			} catch ( \Throwable $e ) {
				continue;
			}
		}

		return $names;
	}

	/**
	 * Sanitize callback for OPTION_ENABLED. An unticked checkbox is absent
	 * from the form, which the Settings API passes on as null.
	 *
	 * @param mixed $value Submitted value.
	 */
	public static function sanitize_enabled( mixed $value ): string {
		return empty( $value ) ? '0' : '1';
	}

	/**
	 * The page caches SAM recognises, each detected the way that plugin or
	 * host documents for other code to clear its whole cache.
	 *
	 * @return list<array{name: string, detect: callable():bool, purge: callable():void}>
	 */
	public static function default_caches(): array {
		$action   = static fn ( string $name, string $hook ): array => array(
			'name'   => $name,
			'detect' => static fn (): bool => false !== has_action( $hook ),
			'purge'  => static function () use ( $hook ): void {
				do_action( $hook ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.DynamicHooknameFound -- another plugin's documented purge hook.
			},
		);
		$function = static fn ( string $name, string $function_name ): array => array(
			'name'   => $name,
			'detect' => static fn (): bool => function_exists( $function_name ),
			'purge'  => static function () use ( $function_name ): void {
				$function_name();
			},
		);

		return array(
			$action( 'LiteSpeed Cache', 'litespeed_purge_all' ),
			$function( 'WP Rocket', 'rocket_clean_domain' ),
			$function( 'W3 Total Cache', 'w3tc_flush_all' ),
			$function( 'WP Super Cache', 'wp_cache_clear_cache' ),
			$function( 'WP Fastest Cache', 'wpfc_clear_all_cache' ),
			$function( 'SiteGround Speed Optimizer', 'sg_cachepress_purge_cache' ),
			$action( 'Hummingbird', 'wphb_clear_page_cache' ),
			$action( 'Breeze', 'breeze_clear_all_cache' ),
			$action( 'Cache Enabler', 'cache_enabler_clear_complete_cache' ),
			$action( 'Nginx Helper', 'rt_nginx_helper_purge_all' ),
			$function( 'Pantheon edge cache', 'pantheon_wp_clear_edge_all' ),
			array(
				'name'   => 'WP-Optimize',
				'detect' => static fn (): bool => function_exists( 'WP_Optimize' ) && is_object( WP_Optimize() ) && method_exists( WP_Optimize(), 'get_page_cache' ),
				'purge'  => static function (): void {
					$page_cache = WP_Optimize()->get_page_cache();
					if ( is_object( $page_cache ) && method_exists( $page_cache, 'purge' ) ) {
						$page_cache->purge();
					}
				},
			),
			array(
				'name'   => 'WP Engine page cache',
				'detect' => static fn (): bool => is_callable( array( 'WpeCommon', 'purge_varnish_cache' ) ),
				'purge'  => static function (): void {
					call_user_func( array( 'WpeCommon', 'purge_varnish_cache' ) );
				},
			),
		);
	}

	private function fingerprint(): string {
		$policy = ( $this->read_policy )();
		if ( null === $policy ) {
			return '';
		}

		return Policy_Fingerprint::digest( $policy['mode'], $policy['header'], $policy['policy'] );
	}

	private function seconds_until_purge_allowed(): int {
		$last = get_option( self::OPTION_LAST_PURGE, array() );
		$at   = is_array( $last ) ? (int) ( $last['at'] ?? 0 ) : 0;

		return max( 0, $at + self::MIN_INTERVAL - time() );
	}

	private function schedule_check( int $delay ): void {
		if ( false === wp_next_scheduled( self::CHECK_HOOK ) ) {
			wp_schedule_single_event( time() + $delay, self::CHECK_HOOK );
		}
	}
}
