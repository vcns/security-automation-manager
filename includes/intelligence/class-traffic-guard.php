<?php
/**
 * This plugin's first active request-blocking capability (Phase 3E,
 * .roadmap/phase3_early_plan.md §13 Traffic Protection Controls). Every
 * prior pillar only ever adds response headers; this one can reject a
 * request outright.
 *
 * Default-safety (§30) is structural, not a setting an installer can miss:
 *
 * - Every surface seeds in Traffic_Policy_Store's 'observe' mode
 *   (Activator::seed_default_traffic_policies()). decide() always computes
 *   what WOULD happen (`would_block`), but only ever actually blocks
 *   (`action`) when an administrator has explicitly switched that specific
 *   surface to 'enforce'.
 * - A request from an already-authenticated administrator
 *   (is_user_logged_in() && manage_options) is never blocked by automatic
 *   detection -- this plugin must never be the reason a site owner is
 *   locked out of their own site. An explicit admin-entered IP block rule
 *   still applies even to a privileged session; only automatic
 *   rate-limit/brute-force escalation is exempted.
 * - Escalation through Traffic_Block_Store's progressive stages is
 *   automatic only up to 'extended_block'; 'persistent_block' requires an
 *   explicit administrator action (Traffic_Block_Store::set_persistent()).
 *
 * decide() is pure decision logic (DB reads/writes, no request
 * termination) so it's fully unit-testable; enforce() is the actual `init`
 * hook target, which acts on decide()'s verdict. The blocking response
 * itself is behind an injectable callable (like Identity_Resolver's DNS
 * lookups) so tests never need to trigger a real wp_die()/exit().
 *
 * Network_Rule_Store (Phase 4A extension, user-requested: the "traffic
 * control filtering" half of Geo-IP/ASN/Tor awareness Phase 4A itself
 * shipped as evidence-only) is checked the same way Ip_Rule_Store is -- a
 * deliberate admin decision, applies regardless of observe/enforce mode,
 * even to a privileged session. Unlike Ip_Rule_Store, resolving what it
 * needs to check against (ASN, Geo-IP country) is NOT free: Network_
 * Intelligence_Resolver's own docblock notes its cost is only ever paid
 * rarely (cached) once some other detector has already flagged a request.
 * Calling it unconditionally here, on every single request regardless of
 * whether any admin has ever configured a network rule, would silently
 * reintroduce exactly the per-request network-lookup cost that laziness
 * was designed to avoid. So this only resolves network intelligence at all
 * when Network_Rule_Store::has_any() says at least one rule exists --
 * zero added cost on the (default) site with none configured, and the
 * lookup cost becomes an explicit trade-off only once an administrator has
 * actually opted in by adding a rule. Tor exit-node filtering needed none
 * of this: it shipped as its own detector (Tor_Exit_Detector) instead,
 * since Tor_Exit_List_Store's membership check is a local, indexed lookup,
 * not a network call, and is therefore cheap enough to run unconditionally
 * like any other detector.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Traffic_Guard {

	private Traffic_Policy_Store $policies;
	private Ip_Rule_Store $ip_rules;
	private Traffic_Block_Store $blocks;
	private Rate_Limiter $rate_limiter;
	private Network_Rule_Store $network_rules;
	private Network_Intelligence_Resolver $network_intelligence;

	/** @var callable(string):bool Real is_user_logged_in()+manage_options check by default; injectable for tests. */
	private $is_privileged_user;

	/** @var callable(string,?int):void Real 403+wp_die() by default; injectable so tests never actually terminate. */
	private $respond_blocked;

	/** @var callable(int):void Real usleep() by default; injectable so tests never actually sleep. */
	private $throttle_delay;

	public function __construct(
		Traffic_Policy_Store $policies,
		Ip_Rule_Store $ip_rules,
		Traffic_Block_Store $blocks,
		Rate_Limiter $rate_limiter,
		Network_Rule_Store $network_rules,
		Network_Intelligence_Resolver $network_intelligence,
		?callable $is_privileged_user = null,
		?callable $respond_blocked = null,
		?callable $throttle_delay = null
	) {
		$this->policies             = $policies;
		$this->ip_rules             = $ip_rules;
		$this->blocks               = $blocks;
		$this->rate_limiter         = $rate_limiter;
		$this->network_rules        = $network_rules;
		$this->network_intelligence = $network_intelligence;
		$this->is_privileged_user   = $is_privileged_user ?? static function (): bool {
			return is_user_logged_in() && current_user_can( 'manage_options' );
		};
		$this->respond_blocked      = $respond_blocked ?? array( $this, 'real_respond_blocked' );
		$this->throttle_delay       = $throttle_delay ?? static function ( int $microseconds ): void {
			usleep( $microseconds ); // phpcs:ignore WordPress.WP.AlternativeFunctions.usleep_usleep -- deliberate progressive-response throttle, not a busy-wait.
		};
	}

	public function register(): void {
		add_action( 'init', array( $this, 'enforce' ), 1 );
		add_action( 'wp_login_failed', array( $this, 'on_login_failed' ) );
	}

	public function enforce(): void {
		if ( Surface_Classifier::is_conflict_probe_request() ) {
			return;
		}

		$surface    = Surface_Classifier::detect();
		$ip         = Ip_Resolver::resolve();
		$privileged = ( $this->is_privileged_user )();

		$verdict = $this->decide( $ip, $surface, $privileged );

		if ( 'throttle' === $verdict['action'] ) {
			( $this->throttle_delay )( 1500000 ); // 1.5s -- see class docblock; slows automated abuse without fully blocking.
			return;
		}

		if ( 'block' === $verdict['action'] ) {
			( $this->respond_blocked )( $verdict['reason'], $verdict['retry_after_seconds'] );
		}
	}

	/**
	 * wp_login_failed fires after WordPress has already evaluated the
	 * submitted credentials for THIS request -- it can never block the
	 * request that tripped the counter, only ones after it. Uses its own
	 * Rate_Limiter key ('login_failed', distinct from the general 'login'
	 * surface counter) so page-load volume and credential-guessing volume
	 * are never conflated.
	 */
	public function on_login_failed( string $username ): void {
		unset( $username );

		$ip = Ip_Resolver::resolve();
		if ( '' === $ip ) {
			return;
		}

		$policy              = $this->policies->get( 'login' ) ?? array();
		$max_failed_attempts = (int) ( $policy['login_max_failed_attempts'] ?? 10 );
		$lockout_seconds     = (int) ( $policy['login_lockout_seconds'] ?? 900 );

		$count = $this->rate_limiter->hit( $ip, 'login_failed', $lockout_seconds );
		if ( $count > max( 1, $max_failed_attempts ) ) {
			$this->blocks->record_violation( $ip, 'login', 'login_brute_force' );
		}
	}

	/**
	 * @return array{action:string, would_block:bool, reason:string, stage:string, retry_after_seconds:?int}
	 */
	public function decide( string $ip, string $surface, bool $is_privileged_user ): array {
		$allow = array(
			'action'              => 'allow',
			'would_block'         => false,
			'reason'              => '',
			'stage'               => 'observe',
			'retry_after_seconds' => null,
		);

		if ( '' === $ip ) {
			return $allow;
		}

		// An explicit admin-entered allow rule always wins, even for a
		// currently-escalated automatic block -- a deliberate decision
		// overrides automatic detection (§9's "recognition is not
		// authorisation" reasoning, mirrored here).
		$rule = $this->ip_rules->match( $ip, $surface );
		if ( null !== $rule && 'allow' === $rule['list_type'] ) {
			return $allow;
		}
		if ( null !== $rule && 'block' === $rule['list_type'] ) {
			return array(
				'action'              => 'block',
				'would_block'         => true,
				'reason'              => 'ip_rule_block',
				'stage'               => 'persistent_block',
				'retry_after_seconds' => null,
			);
		}

		// A loopback source (Cidr_Matcher::LOOPBACK_CIDRS) is the server
		// calling itself -- wp-cron's own loopback requests, Site Health's
		// "Loopback request" check, or an administrator testing from the
		// same machine -- never a remote attacker (see Identity_Resolver's
		// own docblock for the same recognition applied to identity/
		// classification; both classes share one CIDR definition so they
		// can never disagree on it). Automatic rate-limit escalation must
		// never block it: doing so risks self-inflicted breakage of
		// wp-cron/Site Health, which both depend on a working loopback
		// request, for no security benefit -- there is no remote source to
		// defend against here. Checked after the explicit Ip_Rule_Store
		// lookup above, not before: an administrator can still explicitly
		// deny a loopback source (e.g. a host where a reverse proxy
		// terminates every visitor's connection via loopback, making this
		// recognition wrong for that specific site) and that deliberate
		// decision still wins, exactly as Identity_Resolver's docblock
		// promises elsewhere. This also makes any already-existing
		// automatic block record for a loopback address inert going
		// forward, without needing a data migration.
		//
		// This exemption trusts Ip_Resolver::resolve() the same way every
		// other caller in this method already does -- see that class's own
		// docblock for why it deliberately reads only REMOTE_ADDR. On a
		// topology where the web server itself sees every visitor's
		// connection arrive from a loopback address (e.g. a reverse proxy
		// or load balancer that fronts PHP-FPM over localhost without
		// forwarding the real client address into REMOTE_ADDR), that
		// existing, pre-existing trust decision -- not anything new here --
		// would already make every request look like the server calling
		// itself; this exemption then means such a deployment gets no
		// automatic traffic protection at all. That is a deployment-
		// topology caveat inherent to Ip_Resolver's trust model, not
		// something this exemption introduces or can detect from here.
		if ( Cidr_Matcher::ip_in_any_cidr( $ip, Cidr_Matcher::LOOPBACK_CIDRS ) ) {
			return $allow;
		}

		// Network (ASN/country) rules -- see class docblock for why this
		// only resolves ASN/Geo-IP at all when at least one rule exists.
		if ( $this->network_rules->has_any() ) {
			$network      = $this->network_intelligence->resolve( $ip );
			$network_rule = $this->network_rules->match( $network['asn'] ?? null, $network['country'] ?? null, $surface );
			if ( null !== $network_rule ) {
				return array(
					'action'              => 'block',
					'would_block'         => true,
					'reason'              => 'network_rule_block',
					'stage'               => 'persistent_block',
					'retry_after_seconds' => null,
				);
			}
		}

		$is_enforcing = $this->policies->is_enforcing( $surface );

		// Computed directly from $existing (one query) rather than also
		// calling Traffic_Block_Store::is_blocked() (a second, redundant
		// query for the same fingerprint) -- must stay logically identical
		// to that method's own is-blocked rule.
		$existing          = $this->blocks->get( $ip, $surface );
		$stage             = null !== $existing ? (string) $existing['stage'] : 'observe';
		$currently_blocked = null !== $existing && (
			! empty( $existing['is_persistent'] )
			|| ( ! empty( $existing['blocked_until'] ) && (string) $existing['blocked_until'] > current_time( 'mysql', true ) )
		);

		if ( $currently_blocked ) {
			// A privileged (already-authenticated admin) session is never
			// blocked by automatic escalation -- see class docblock. An
			// explicit IP rule (handled above) still applies regardless.
			if ( $is_privileged_user ) {
				return $allow;
			}

			$retry_after = null;
			if ( ! empty( $existing['blocked_until'] ) ) {
				$retry_after = max( 1, strtotime( (string) $existing['blocked_until'] ) - time() );
			}

			return array(
				'action'              => $is_enforcing ? 'block' : 'allow',
				'would_block'         => true,
				'reason'              => (string) ( $existing['reason'] ?? 'rate_limit' ),
				'stage'               => $stage,
				'retry_after_seconds' => $retry_after,
			);
		}

		$policy = $this->policies->get( $surface );
		if ( null === $policy ) {
			return $allow;
		}

		$exceeded = $this->rate_limiter->exceeded(
			$ip,
			$surface,
			(int) $policy['rate_limit_max_requests'],
			(int) $policy['rate_limit_window_seconds']
		);

		if ( ! $exceeded ) {
			return $allow;
		}

		if ( $is_privileged_user ) {
			return $allow;
		}

		$updated           = $this->blocks->record_violation( $ip, $surface, 'rate_limit' );
		$new_stage         = (string) ( $updated['stage'] ?? 'warn' );
		$is_blocking_stage = in_array( $new_stage, array( 'temporary_block', 'extended_block', 'persistent_block' ), true );
		$is_throttle_stage = 'throttle' === $new_stage;

		$retry_after = null;
		if ( ! empty( $updated['blocked_until'] ) ) {
			$retry_after = max( 1, strtotime( (string) $updated['blocked_until'] ) - time() );
		}

		if ( $is_blocking_stage ) {
			return array(
				'action'              => $is_enforcing ? 'block' : 'allow',
				'would_block'         => true,
				'reason'              => 'rate_limit',
				'stage'               => $new_stage,
				'retry_after_seconds' => $retry_after,
			);
		}

		if ( $is_throttle_stage ) {
			return array(
				'action'              => $is_enforcing ? 'throttle' : 'allow',
				'would_block'         => false,
				'reason'              => 'rate_limit',
				'stage'               => $new_stage,
				'retry_after_seconds' => null,
			);
		}

		// 'warn' stage: logged (record_violation() already wrote the row), never visitor-facing.
		return array(
			'action'              => 'allow',
			'would_block'         => false,
			'reason'              => 'rate_limit',
			'stage'               => $new_stage,
			'retry_after_seconds' => null,
		);
	}

	private function real_respond_blocked( string $reason, ?int $retry_after_seconds ): void {
		unset( $reason );

		if ( ! headers_sent() ) {
			status_header( 403 );
			if ( null !== $retry_after_seconds ) {
				header( 'Retry-After: ' . max( 1, $retry_after_seconds ) );
			}
		}

		wp_die(
			esc_html__( 'This request has been temporarily blocked due to unusual traffic from your network. Please try again later.', 'vcns-security-automation-manager' ),
			esc_html__( 'Request Blocked', 'vcns-security-automation-manager' ),
			array( 'response' => 403 )
		);
	}
}
