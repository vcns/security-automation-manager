<?php
/**
 * Central plugin orchestrator.
 * Bootstraps every module, registers REST routes, and wires WordPress hooks.
 *
 * The WordPress.org build runs as a complete local plugin. Commercial service
 * integrations, if any, live outside this submitted package.
 */

declare( strict_types=1 );

namespace WP_SAM;

use WP_SAM\Admin\Admin_UI;
use WP_SAM\CSP\Conflict_Detector;
use WP_SAM\CSP\Hash_Manager;
use WP_SAM\CSP\Learning_Window;
use WP_SAM\CSP\Nonce_Manager;
use WP_SAM\CSP\Policy_Builder;
use WP_SAM\CSP\Scheduler;
use WP_SAM\CSP\Violation_Reporter;
use WP_SAM\Intelligence\Account_Integrity_Recorder;
use WP_SAM\Intelligence\Asn_Lookup_Store;
use WP_SAM\Intelligence\Detector_Engine;
use WP_SAM\Intelligence\Detector_Policy_Store;
use WP_SAM\Intelligence\Detector_Registry;
use WP_SAM\Intelligence\Detectors\Honeypath_Detector;
use WP_SAM\Intelligence\Event_Store;
use WP_SAM\Intelligence\Change_Attribution_Recorder;
use WP_SAM\Intelligence\Change_Log_Store;
use WP_SAM\Intelligence\Geo_Ip_Store;
use WP_SAM\Intelligence\Honeypath_Store;
use WP_SAM\Intelligence\Identity_Resolver;
use WP_SAM\Intelligence\Ip_Rule_Store;
use WP_SAM\Intelligence\Network_Intelligence_Resolver;
use WP_SAM\Intelligence\Rate_Limiter;
use WP_SAM\Intelligence\Request_Observer;
use WP_SAM\Intelligence\Scanner_Identity_Store;
use WP_SAM\Intelligence\Scanner_Vendor_Store;
use WP_SAM\Intelligence\Tor_Exit_List_Store;
use WP_SAM\Intelligence\Traffic_Block_Store;
use WP_SAM\Intelligence\Traffic_Guard;
use WP_SAM\Intelligence\Traffic_Policy_Store;
use WP_SAM\Modules\Audit_Log;
use WP_SAM\Modules\Feature_Gate;
use WP_SAM\Rest\Admin_Controller;
use WP_SAM\Security\Cross_Origin_Embedder_Policy_Builder;
use WP_SAM\Security\Cross_Origin_Opener_Policy_Builder;
use WP_SAM\Security\Cross_Origin_Resource_Policy_Builder;
use WP_SAM\Security\Dependency_Governance_Builder;
use WP_SAM\Security\Dependency_Integrity_Monitor;
use WP_SAM\Security\Internal_Script_Integrity_Builder;
use WP_SAM\Security\Permissions_Policy_Builder;
use WP_SAM\Security\Referrer_Policy_Builder;
use WP_SAM\Security\Reverse_Tabnabbing_Builder;
use WP_SAM\Security\Strict_Transport_Security_Builder;
use WP_SAM\Security\X_Content_Type_Options_Builder;
use WP_SAM\Security\X_Frame_Options_Builder;
use WP_SAM\Security\X_Permitted_Cross_Domain_Policies_Builder;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Plugin {

	private static ?Plugin $instance = null;

	// Shared module instances (read by Admin_UI and other consumers).
	// Nullable compatibility hooks for legacy or future optional integrations.
	public ?object $entitlements = null;
	public ?object $checkout     = null;
	public Feature_Gate $gate;
	public Audit_Log $audit;
	public Nonce_Manager $nonce_manager;
	public Certificates\Challenge_Http $cert_http;
	public Certificates\Certificate_Manager $cert_manager;
	public Certificates\Renewal_Scheduler $cert_schedule;
	public Policy_Builder $policy_builder;
	public X_Frame_Options_Builder $x_frame_options_builder;
	public X_Content_Type_Options_Builder $x_content_type_options_builder;
	public Referrer_Policy_Builder $referrer_policy_builder;
	public Permissions_Policy_Builder $permissions_policy_builder;
	public Strict_Transport_Security_Builder $strict_transport_security_builder;
	public Reverse_Tabnabbing_Builder $reverse_tabnabbing_builder;
	public Dependency_Governance_Builder $dependency_governance_builder;
	public Cross_Origin_Resource_Policy_Builder $cross_origin_resource_policy_builder;
	public X_Permitted_Cross_Domain_Policies_Builder $x_permitted_cross_domain_policies_builder;
	public Cross_Origin_Opener_Policy_Builder $cross_origin_opener_policy_builder;
	public Cross_Origin_Embedder_Policy_Builder $cross_origin_embedder_policy_builder;
	public Internal_Script_Integrity_Builder $internal_script_integrity_builder;
	private Learning_Window $learning_window;

	/**
	 * Hash manager exposed publicly so Scheduler can retrieve captured hashes
	 * after a request-time capture pass.
	 */
	public Hash_Manager $hash_manager;

	private function __construct() {}

	public static function instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	public function init(): void {
		$this->load_textdomain();
		$this->maybe_upgrade_db();
		$this->bootstrap();
	}

	// ── Text domain ───────────────────────────────────────────────────────────

	private function load_textdomain(): void {
		// WordPress core auto-loads translations for WordPress.org-hosted plugins
		// (matched by slug against the wp.org translation API) since 4.6 -- calling
		// this there is discouraged/redundant. The GitHub-channel build isn't
		// installed from wp.org, so that automatic loading never applies to it;
		// it still needs this call to load its own bundled languages/ directory.
		if ( 'github' !== WP_SAM_DISTRIBUTION_CHANNEL ) {
			return;
		}
		load_plugin_textdomain(
			'vcns-security-automation-manager',
			false,
			dirname( plugin_basename( WP_SAM_FILE ) ) . '/languages'
		);
	}

	// ── DB migration gate ─────────────────────────────────────────────────────

	private function maybe_upgrade_db(): void {
		$installed = (int) get_option( 'wp_sam_db_version', 0 );

		// Older plugin code running against a database a newer version
		// already migrated -- Activator::activate() must never run here
		// (see Rollback_Guard's docblock for why). Every other branch below
		// assumes $installed <= WP_SAM_DB_VERSION, so this check comes first
		// and returns before any of them can run.
		if ( 'downgrade_detected' === Rollback_Guard::schema_state() ) {
			Rollback_Guard::record_downgrade_detected( $installed, (int) WP_SAM_DB_VERSION );
			return;
		}
		Rollback_Guard::clear_downgrade_flag_if_resolved();

		$verified = (string) get_option( 'wp_sam_schema_verified_version', '' );
		if (
			$installed < (int) WP_SAM_DB_VERSION
			|| (string) WP_SAM_DB_VERSION !== $verified
			|| ( is_admin() && ! empty( Activator::get_missing_table_names() ) )
		) {
			if ( $installed < (int) WP_SAM_DB_VERSION ) {
				Rollback_Guard::snapshot_before_migration( $installed, (int) WP_SAM_DB_VERSION );
			}
			Activator::activate();
			Activator::mark_schema_verified();
		}
	}

	// ── Module bootstrap ──────────────────────────────────────────────────────

	private function bootstrap(): void {
		// Always-available core services.
		$this->audit = new Audit_Log();

		// Commercial service wiring (entitlements, checkout) is entirely
		// extension-owned -- see includes/extensions/, physically absent
		// from the WordPress.org build. This file has no knowledge of
		// either service's implementing class by name; a listening
		// extension populates $this->entitlements/$this->checkout itself
		// (both remain public, nullable, generic properties for exactly
		// this purpose). Neither is ever populated when no such extension
		// is loaded, so Feature_Gate runs in its free-tier posture exactly
		// as it did before this existed.
		do_action( 'wp_sam_register_commercial_services', $this );

		$this->gate = new Feature_Gate( $this->entitlements );

		// Automation mode registry: the three free modes are registered
		// here; any paid mode is registered only by a loaded extension
		// (see includes/extensions/, physically absent from the
		// WordPress.org build) hooking wp_sam_register_automation_modes --
		// this file has no knowledge of what, if anything, does. See
		// Automation_Mode_Registry's own docblock for why this is the
		// actual compliance boundary, not a channel or entitlement check.
		// Deferred to `init`: bootstrap() itself runs on `plugins_loaded`,
		// which fires before `init`, and register_defaults() translates
		// each mode's label immediately on registration -- calling __()
		// that early trips WordPress's "_load_textdomain_just_in_time
		// called incorrectly" notice on every single request. Every actual
		// consumer of this registry (admin pages, admin-post handlers,
		// AJAX handlers, REST routes) already runs well after `init`, so
		// registering there instead changes no behaviour.
		add_action( 'init', array( $this, 'register_automation_modes' ) );

		// Detector registry: the core detector families (see
		// Detector_Registry::register_defaults()) plus whatever a loaded
		// extension adds via wp_sam_register_detectors. Deferred to `init`
		// for the same reason as register_automation_modes above --
		// register_detectors() itself does no translation, but the deferral
		// keeps both registries on the same, well-understood lifecycle
		// rather than one running earlier than the other for no functional
		// reason.
		add_action( 'init', array( $this, 'register_detectors' ) );

		$this->nonce_manager                             = new Nonce_Manager( $this->gate );
		$this->policy_builder                            = new Policy_Builder( $this->gate, null, null, $this->audit );
		$this->x_frame_options_builder                   = new X_Frame_Options_Builder();
		$this->x_content_type_options_builder            = new X_Content_Type_Options_Builder();
		$this->referrer_policy_builder                   = new Referrer_Policy_Builder();
		$this->permissions_policy_builder                = new Permissions_Policy_Builder();
		$this->strict_transport_security_builder         = new Strict_Transport_Security_Builder();
		$this->reverse_tabnabbing_builder                = new Reverse_Tabnabbing_Builder();
		$this->dependency_governance_builder             = new Dependency_Governance_Builder();
		$this->cross_origin_resource_policy_builder      = new Cross_Origin_Resource_Policy_Builder();
		$this->x_permitted_cross_domain_policies_builder = new X_Permitted_Cross_Domain_Policies_Builder();
		$this->cross_origin_opener_policy_builder        = new Cross_Origin_Opener_Policy_Builder();
		$this->cross_origin_embedder_policy_builder      = new Cross_Origin_Embedder_Policy_Builder();
		$this->internal_script_integrity_builder         = new Internal_Script_Integrity_Builder();
		$this->learning_window                           = new Learning_Window();

		// Hash manager: instantiated here so Scheduler can read captured_hashes
		// after the request-time buffer pass, and so the public property is
		// always available to other modules.
		$this->hash_manager = new Hash_Manager( $this->audit, $this->gate );

		// Register CSP and simple pillar header emission on all request types.
		$this->nonce_manager->register();
		$this->policy_builder->register();
		$this->x_frame_options_builder->register();
		$this->x_content_type_options_builder->register();
		$this->referrer_policy_builder->register();
		$this->permissions_policy_builder->register();
		$this->strict_transport_security_builder->register();
		$this->reverse_tabnabbing_builder->register();
		$this->dependency_governance_builder->register();
		$this->cross_origin_resource_policy_builder->register();
		$this->x_permitted_cross_domain_policies_builder->register();
		$this->cross_origin_opener_policy_builder->register();
		$this->cross_origin_embedder_policy_builder->register();
		$this->internal_script_integrity_builder->register();

		// Request Observation Framework (Layer 3: Continuous Intelligence).
		// Runs on every request, all four surfaces, same as the header
		// pillars above -- see Request_Observer's own docblock for the hook
		// combination. On the empty Detector_Registry every build ships with
		// until an extension (or a future in-core Phase 3C detector family)
		// registers something, this observes every request but records
		// nothing. Identity_Resolver/Scanner_Identity_Store (Phase 3D) run
		// unconditionally alongside it -- see Request_Observer's docblock.
		//
		// Traffic_Block_Store is shared with Traffic_Guard below (Phase 4B):
		// a detector match configured to 'enforce' and a rate-limit
		// violation both write into the same table, so Traffic_Guard's
		// existing progressive-response enforcement is automatically
		// detector-family-aware with no separate blocking path -- see
		// Request_Observer's own docblock.
		$traffic_block_store = new Traffic_Block_Store();

		( new Request_Observer(
			new Detector_Engine( new Detector_Policy_Store() ),
			new Event_Store(),
			new Identity_Resolver( new Scanner_Vendor_Store() ),
			new Scanner_Identity_Store(),
			new Network_Intelligence_Resolver( new Tor_Exit_List_Store(), new Asn_Lookup_Store(), new Geo_Ip_Store() ),
			$traffic_block_store
		) )->register();

		// Traffic Controls (Phase 3E). Every surface seeds in 'observe'
		// mode (Activator::seed_default_traffic_policies()), so this never
		// blocks anything until an administrator explicitly promotes a
		// surface to 'enforce' -- see Traffic_Guard's own docblock for the
		// full default-safety design.
		( new Traffic_Guard(
			new Traffic_Policy_Store(),
			new Ip_Rule_Store(),
			$traffic_block_store,
			new Rate_Limiter()
		) )->register();

		// Change Attribution (Phase 3F). Records real plugin/theme/core
		// change history for Drift_Scanner to correlate drift against --
		// kept entirely separate from Learning_Window's own, narrower
		// hooks so this can never change its CSP-source-learning
		// behaviour. See Change_Attribution_Recorder's own docblock.
		( new Change_Attribution_Recorder( new Change_Log_Store() ) )->register();

		// Integrity Monitoring (Phase 3J, §16): new administrator accounts
		// and role escalations to administrator, written into the same
		// Change_Log_Store as the change-attribution recorder above -- see
		// Account_Integrity_Recorder's own docblock for what §16 signals
		// this covers and which it deliberately doesn't.
		( new Account_Integrity_Recorder( new Change_Log_Store() ) )->register();

		// Register output-buffering hooks to capture inline blocks for hashing.
		// Must be registered after nonce_manager so nonce tags are already
		// stamped before the buffer captures them (and can be skipped).
		$this->hash_manager->register();
		$this->learning_window->register();

		// REST API: violation reporting and privileged admin endpoints.
		add_action( 'rest_api_init', array( $this, 'register_rest_routes' ) );

		// WP Cron: daily policy rescan.
		( new Scheduler( $this->audit ) )->register();

		// ACME certificate automation: http-01 responder runs on every request
		// (the CA's validation fetch is an anonymous front-end GET); the
		// manager, cron hooks, and renewal check ride the same bootstrap.
		$cert_store          = new Certificates\Certificate_Store();
		$this->cert_http     = new Certificates\Challenge_Http();
		$this->cert_manager  = new Certificates\Certificate_Manager(
			$cert_store,
			$this->cert_http,
			new Certificates\Deployer( $this->audit ),
			$this->audit
		);
		$this->cert_schedule = new Certificates\Renewal_Scheduler( $this->cert_manager );
		$this->cert_http->register();
		$this->cert_schedule->register();

		// Conflict detection runs once per admin pageload.
		if ( is_admin() ) {
			( new Conflict_Detector( $this->audit ) )->register();
			( new Dependency_Integrity_Monitor( $this->audit ) )->register();
		}

		// Admin UI.
		if ( is_admin() ) {
			( new Admin_UI( $this ) )->register();
		}
	}

	// ── Automation mode registry ──────────────────────────────────────────────

	/** @see bootstrap()'s call to add_action( 'init', ... ) for why this isn't called directly from bootstrap(). */
	public function register_automation_modes(): void {
		\WP_SAM\CSP\Automation_Mode_Registry::register_defaults();
		do_action( 'wp_sam_register_automation_modes', $this->gate );
	}

	// ── Detector registry ──────────────────────────────────────────────────────

	/**
	 * Registers the core detector families, then fires the extension
	 * point for anything else -- see Detector_Registry's own docblock.
	 *
	 * @see bootstrap()'s call to add_action( 'init', ... ) for why this isn't called directly from bootstrap().
	 */
	public function register_detectors(): void {
		\WP_SAM\Intelligence\Detector_Registry::register_defaults();

		// Deception and Honey Paths (Phase 3J, §15): registered unconditionally,
		// alongside but distinct from the free defaults above -- with zero
		// administrator-configured decoy paths (every fresh install), its
		// rules() is empty and it structurally never matches anything. See
		// Honeypath_Detector's own docblock.
		Detector_Registry::register( new Honeypath_Detector( new Honeypath_Store() ) );

		do_action( 'wp_sam_register_detectors' );
	}

	// ── REST routes ───────────────────────────────────────────────────────────

	public function register_rest_routes(): void {
		// CSP violation report – public, from browsers.
		$violation_reporter = new Violation_Reporter( $this->audit, $this->learning_window );
		$report_route_args  = array(
			'methods'             => \WP_REST_Server::CREATABLE,
			'callback'            => array( $violation_reporter, 'handle' ),
			'permission_callback' => '__return_true',
		);

		register_rest_route( 'sam/v1', '/report', $report_route_args );

		// Legacy alias: browsers holding a CSP header issued before the
		// security-manager/v1 -> sam/v1 rename still POST to the old URL
		// until they receive a fresh policy. Keep this alongside the new
		// route (not a redirect -- redirects on a report-uri are unreliable
		// across browsers) for a couple of releases, then remove it. The
		// even older csp-manager/v1 alias (from the original CSP Manager ->
		// Security Automation Manager plugin rename) has been retired --
		// its own transition window closed long ago.
		register_rest_route( 'security-manager/v1', '/report', $report_route_args );

		( new Admin_Controller( $this->audit ) )->register_routes();

		// A commercial webhook route (e.g. a payment provider's) is
		// entirely extension-owned -- see includes/extensions/, physically
		// absent from the WordPress.org build. This file has no knowledge
		// of its implementing class by name; a listening extension
		// registers its own route here, using
		// $this->entitlements/$this->checkout (already populated by
		// wp_sam_register_commercial_services during bootstrap(), which
		// always runs before rest_api_init).
		do_action( 'wp_sam_register_commercial_routes', $this );
	}
}
