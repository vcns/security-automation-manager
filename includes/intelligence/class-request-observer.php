<?php
/**
 * Observes every request across all four surfaces (frontend/admin/login/
 * api), runs Detector_Engine against it, and records any Findings via
 * Event_Store.
 *
 * Hooks the exact same send_headers + login_init + wp_redirect combination
 * Header_Builder already proves covers every surface: send_headers for the
 * normal request lifecycle, login_init because wp-login.php is a standalone
 * entry point that never fires send_headers, and the wp_redirect filter
 * (priority 1) so a request that redirects before send_headers runs is
 * still observed -- a scanner/probe hitting a redirecting URL is exactly
 * the kind of thing worth observing, not something to silently skip.
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
 * exit status today, ASN/Geo-IP later) is resolved only when a detector
 * has actually produced a Finding, not on every request -- unlike identity
 * resolution above, which every request needs for the scanner-recognition
 * feature to work at all, network-fact enrichment is only ever consumed
 * as extra context on evidence that already exists, so skipping it on the
 * overwhelming majority of benign requests is a genuine, safe cost saving,
 * not a feature gap.
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

		$context  = $this->build_context();
		$findings = $this->engine->evaluate( $context );

		if ( '' !== $context['ip'] ) {
			$identity = $this->identity_resolver->resolve( $context['ip'], $context['user_agent'] );
			$this->identities->record(
				$context['ip'],
				$identity['claimed_identity'],
				$context['user_agent'],
				$identity['vendor_key'],
				$context['surface'],
				$identity['verification_state'],
				$identity['network_match']
			);
		}

		if ( ! empty( $findings ) && '' !== $context['ip'] ) {
			$context['network'] = $this->network_intelligence->resolve( $context['ip'] );
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

	/** @return array<string, mixed> */
	private function build_context(): array {
		return array(
			'surface'      => Surface_Classifier::detect(),
			'path'         => Surface_Classifier::request_path(),
			'query_string' => Surface_Classifier::query_string(),
			'ip'           => Ip_Resolver::resolve(),
			'method'       => isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['REQUEST_METHOD'] ) ) : '',
			'user_agent'   => isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( (string) $_SERVER['HTTP_USER_AGENT'] ) ) : '',
		);
	}
}
