<?php
/**
 * Observes every request across all four surfaces (frontend/admin/login/
 * api), runs Detector_Engine against it, and records any Findings via
 * Event_Store.
 *
 * Hooks the same send_headers + login_init + wp_redirect combination
 * Header_Builder already proves covers every surface: send_headers for the
 * normal request lifecycle, login_init because wp-login.php is a standalone
 * entry point that never fires send_headers, and the wp_redirect filter
 * (priority 1) so a request that redirects before send_headers runs is
 * still observed -- a scanner/probe hitting a redirecting URL is exactly
 * the kind of thing worth observing, not something to silently skip.
 *
 * Also hooks `init` (priority 20, after Detector_Registry::register_
 * defaults() -- itself on `init` at the default priority 10, per Plugin::
 * bootstrap()): xmlrpc.php (and wp-cron.php) bootstrap WordPress via
 * wp-load.php directly and never run the wp()/template-loader pipeline that
 * fires send_headers, so without this they'd be structurally invisible to
 * every detector -- discovered live in Docker while verifying Legacy_
 * Endpoint_Detector (Phase 4B): a real request to xmlrpc.php produced no
 * event at all despite matching LEGACY-001 when evaluate() was called
 * directly. `init` is the earliest point common to literally every
 * WordPress entry point (already proven safe to classify a request from
 * this early by Traffic_Guard::enforce(), which runs on `init` priority 1).
 * The existing $observed guard means this never double-records a request
 * that also fires send_headers/login_init/wp_redirect later.
 *
 * Skips Conflict_Detector's own internal probe request, or this class would
 * misclassify the plugin's own diagnostic traffic as an observed event.
 *
 * observe() always runs regardless of what's registered; if a build's
 * Detector_Registry is empty (e.g. no core detector loaded), Detector_Engine
 * ::evaluate() simply returns no Findings and nothing is written to
 * Event_Store.
 *
 * Also resolves the request's claimed identity (Phase 3D, Identity_Resolver)
 * and records it via Scanner_Identity_Store on every hit -- cheap,
 * synchronous, no network I/O (see Identity_Resolver's own docblock).
 * Recognition here is never authorisation: see Scanner_Identity_Store's
 * docblock for why this write path can never set a decision state.
 *
 * Network intelligence (Phase 4A, Network_Intelligence_Resolver -- Tor
 * exit status, ASN, Geo-IP) is resolved only when a detector has actually
 * produced a Finding, not on every request -- unlike identity resolution
 * above, which every request needs for the scanner-recognition feature to
 * work at all, network-fact enrichment is only ever consumed as extra
 * context on evidence that already exists, so skipping it on the
 * overwhelming majority of benign requests is a genuine, safe cost saving,
 * not a feature gap. Since schema v42 (Phase 4A carried-forward item),
 * when this resolution does happen it's also passed to Scanner_Identity_
 * Store::record() so the identity's own asn/geo columns fill in the same
 * lazy, opportunistic way Event_Store's per-event evidence already does --
 * no new resolution, no new cost, just reusing a result already computed.
 *
 * Repeated-errors signal (schema v44, Phase 4C carried-forward item -- the
 * "repeated errors" §10 names, alongside "timing" above): the identity
 * write is deferred from the main observe() flow to a new shutdown hook,
 * because the eventual HTTP response status (needed to know whether this
 * was e.g. a 404) isn't known yet at send_headers time -- WordPress hasn't
 * run query_posts()/handle_404() yet at that point in WP::main(). Deferring
 * only the WRITE, not the READ: identity_resolver->resolve() still runs
 * early (still needed by detectors during evaluate(), unchanged above), but
 * Scanner_Identity_Store::record() itself now runs once, at shutdown, via
 * $pending_identity_write -- carrying forward every value observe() already
 * computed, plus http_response_code() >= 400 read at the one point in the
 * request lifecycle where it's actually settled. The existing $observed
 * guard still prevents redundant identity *resolution*; a second, separate
 * $pending_identity_write !== null check on the new shutdown hook prevents
 * a redundant *write* if shutdown somehow fired more than once.
 *
 * Detector-family-aware control actions (Phase 4B, .roadmap/phase4_plan.md):
 * each Finding already carries its resolved 'control_action' (Detector_
 * Engine, backed by Detector_Policy_Store). When that action is 'enforce',
 * this class calls Traffic_Block_Store::record_violation() -- the exact
 * same call on_login_failed() already makes for login brute force, and the
 * exact same progressive-response ladder (observe -> warn -> throttle ->
 * temporary_block -> extended_block -> admin-only persistent_block)
 * Traffic_Guard already enforces for rate-limit violations. No new
 * enforcement path is introduced: a detector match just becomes another
 * source of violations feeding infrastructure that already exists,
 * including the same per-surface Traffic_Policy_Store observe/enforce gate
 * -- Traffic_Guard::decide() cannot tell a detector-sourced violation from
 * a rate-limit one, by design, and doesn't need to. As with login brute
 * force, this can only ever affect a later request, never the one that
 * tripped it: Traffic_Guard::enforce() runs on `init`, earlier in the
 * request lifecycle than this class's own send_headers/login_init hooks.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Request_Observer {

	private bool $observed = false;

	/** @var array<int, mixed>|null Args for the one deferred Scanner_Identity_Store::record() call this request, or null if none is pending. */
	private ?array $pending_identity_write = null;

	private Detector_Engine $engine;
	private Event_Store $events;
	private Identity_Resolver $identity_resolver;
	private Scanner_Identity_Store $identities;
	private Network_Intelligence_Resolver $network_intelligence;
	private Traffic_Block_Store $blocks;

	public function __construct(
		Detector_Engine $engine,
		Event_Store $events,
		Identity_Resolver $identity_resolver,
		Scanner_Identity_Store $identities,
		Network_Intelligence_Resolver $network_intelligence,
		?Traffic_Block_Store $blocks = null
	) {
		$this->engine               = $engine;
		$this->events               = $events;
		$this->identity_resolver    = $identity_resolver;
		$this->identities           = $identities;
		$this->network_intelligence = $network_intelligence;
		$this->blocks               = $blocks ?? new Traffic_Block_Store();
	}

	public function register(): void {
		add_action( 'send_headers', array( $this, 'observe' ) );
		add_action( 'login_init', array( $this, 'observe' ) );
		add_filter( 'wp_redirect', array( $this, 'observe_before_redirect' ), 1, 2 );
		add_action( 'init', array( $this, 'observe' ), 20 );
		// $accepted_args = 0: do_action( 'shutdown' ) -- called with no extra
		// arguments -- still pushes a filler '' into its internal args array
		// (a long-standing WordPress core quirk), which WP_Hook would
		// otherwise pass through as this method's first argument. Found live
		// in Docker as a real fatal (TypeError: string given for ?int
		// $status), not assumed -- explicitly declaring zero accepted args
		// is what actually keeps $status defaulting to null in production.
		add_action( 'shutdown', array( $this, 'flush_identity_write' ), 10, 0 );
	}

	public function observe_before_redirect( string $location, int $status = 302 ): string {
		unset( $status );
		$this->observe();
		return $location;
	}

	public function observe(): void {
		if ( $this->observed ) {
			return;
		}
		$this->observed = true;

		if ( Surface_Classifier::is_conflict_probe_request() ) {
			return;
		}

		$context = $this->build_context();

		// Resolved before detector evaluation (Phase 4C, Robots_Compliance_
		// Detector) so a detector can read $context['identity_verification_
		// state'] -- a pure, already-computed value, not a new I/O call
		// inside the detector itself. Purely additive: resolve() has no
		// dependency on anything evaluate() computes, and no detector
		// consumed this field before now, so this reorder changes nothing
		// about any existing detector's behaviour.
		$identity = null;
		if ( '' !== $context['ip'] ) {
			$identity                               = $this->identity_resolver->resolve( $context['ip'], $context['user_agent'] );
			$context['identity_verification_state'] = $identity['verification_state'];
		}

		$findings = $this->engine->evaluate( $context );

		// Resolved before identity recording (schema v42) so a repeat
		// offender's identity row can be enriched with the exact same
		// result Event_Store's evidence gets below -- still gated on
		// $findings, so this changes nothing about when the lazy resolve
		// itself happens, only what its result is reused for.
		if ( ! empty( $findings ) && '' !== $context['ip'] ) {
			$context['network'] = $this->network_intelligence->resolve( $context['ip'] );
		}

		if ( null !== $identity && '' !== $context['ip'] ) {
			// Deferred to flush_identity_write() on 'shutdown' -- see class
			// docblock's "Repeated-errors signal" note for why.
			$this->pending_identity_write = array(
				$context['ip'],
				$identity['claimed_identity'],
				$context['user_agent'],
				$identity['vendor_key'],
				$context['surface'],
				$identity['verification_state'],
				$identity['network_match'],
				$context['path'],
				$context['network']['asn'] ?? null,
				$context['network']['asn_org'] ?? null,
				$context['network']['country'] ?? null,
				$context['network']['region'] ?? null,
				$context['network']['city'] ?? null,
			);
		}

		foreach ( $findings as $finding ) {
			$this->events->record(
				(string) ( $finding['detector_id'] ?? '' ),
				(string) ( $finding['detector_family'] ?? '' ),
				(string) ( $finding['surface'] ?? $context['surface'] ),
				(string) ( $finding['severity'] ?? 'unknown' ),
				isset( $finding['confidence'] ) && is_numeric( $finding['confidence'] ) ? (float) $finding['confidence'] : null,
				(string) $context['ip'],
				array_merge(
					array(
						'ip'           => $context['ip'],
						'path'         => $context['path'],
						'query_string' => $context['query_string'],
						'method'       => $context['method'],
						'user_agent'   => $context['user_agent'],
						'is_tor_exit'  => $context['network']['is_tor_exit'] ?? false,
						'asn'          => $context['network']['asn'] ?? null,
						'asn_org'      => $context['network']['asn_org'] ?? null,
						'geo_country'  => $context['network']['country'] ?? null,
						'geo_region'   => $context['network']['region'] ?? null,
						'geo_city'     => $context['network']['city'] ?? null,
					),
					is_array( $finding['detail'] ?? null ) ? $finding['detail'] : array()
				)
			);

			if ( 'enforce' === ( $finding['control_action'] ?? 'observe' ) && '' !== $context['ip'] ) {
				$this->blocks->record_violation(
					$context['ip'],
					(string) ( $finding['surface'] ?? $context['surface'] ),
					'detector:' . (string) ( $finding['detector_family'] ?? $finding['detector_id'] ?? '' )
				);
			}
		}
	}

	/**
	 * Writes this request's deferred identity record, if observe() actually
	 * produced one -- see class docblock's "Repeated-errors signal" note.
	 * http_response_code() is read here (unless $status is passed directly,
	 * the same optional-override convention Content_Rewriter::is_processable_
	 * response() already uses to stay testable without stubbing a PHP global)
	 * rather than during observe() itself, because this is the one point in
	 * the request lifecycle where the eventual status is actually settled
	 * (WordPress's own query resolution and 404 handling, and any REST/admin
	 * error response, have already run by 'shutdown'). A missing or
	 * non-numeric code (e.g. a CLI/WP-CLI context with no real HTTP
	 * response) is treated as "not an error" rather than guessed.
	 */
	public function flush_identity_write( ?int $status = null ): void {
		if ( null === $this->pending_identity_write ) {
			return;
		}
		$args                         = $this->pending_identity_write;
		$this->pending_identity_write = null;

		if ( null === $status ) {
			$code   = http_response_code();
			$status = is_int( $code ) ? $code : 200;
		}

		$args[] = $status >= 400;

		$this->identities->record( ...$args );
	}

	/** @return array<string, mixed> */
	private function build_context(): array {
		return array(
			'surface'                       => Surface_Classifier::detect(),
			'path'                          => Surface_Classifier::request_path(),
			'query_string'                  => Surface_Classifier::query_string(),
			'ip'                            => Ip_Resolver::resolve(),
			'method'                        => isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['REQUEST_METHOD'] ) ) : '',
			'user_agent'                    => isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['HTTP_USER_AGENT'] ) ) : '',
			// §12 HTTP Method Intelligence (Http_Method_Detector): the two
			// headers a genuine browser CORS preflight always carries
			// together -- see that detector's own docblock.
			'origin'                        => isset( $_SERVER['HTTP_ORIGIN'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['HTTP_ORIGIN'] ) ) : '',
			'access_control_request_method' => isset( $_SERVER['HTTP_ACCESS_CONTROL_REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['HTTP_ACCESS_CONTROL_REQUEST_METHOD'] ) ) : '',
			// §10 session/cookie behaviour (Login_Cookie_Consistency_Detector):
			// wordpress_test_cookie is set by WP core itself when it renders
			// the login form -- never introduced by this plugin -- and a real
			// browser resends it on the following POST.
			'has_login_test_cookie'         => isset( $_COOKIE['wordpress_test_cookie'] ),
			// §10 header-consistency (Header_Consistency_Detector): the
			// headers a genuine browser always sends alongside a
			// browser-shaped User-Agent -- see that detector's own docblock.
			'accept'                        => isset( $_SERVER['HTTP_ACCEPT'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['HTTP_ACCEPT'] ) ) : '',
			'accept_language'               => isset( $_SERVER['HTTP_ACCEPT_LANGUAGE'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['HTTP_ACCEPT_LANGUAGE'] ) ) : '',
		);
	}
}
