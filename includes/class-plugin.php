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

		// Entitlement modules are only present in a private/commercial build
		// (see offline/modules/ -- gitignored and excluded from every release
		// ZIP this repo's CI produces). The WordPress.org and GitHub-channel
		// builds never find these classes, so $entitlements stays null and
		// Feature_Gate runs in its free-tier posture, exactly as it does today.
		if ( class_exists( \WP_SAM\Modules\Entitlement_Store::class ) ) {
			$this->entitlements = new \WP_SAM\Modules\Entitlement_Store( $this->audit );
		}
		if ( class_exists( \WP_SAM\Modules\Checkout_Service::class ) && null !== $this->entitlements ) {
			$this->checkout = new \WP_SAM\Modules\Checkout_Service( $this->entitlements );
		}
		$this->gate                                      = new Feature_Gate( $this->entitlements );
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

	// ── REST routes ───────────────────────────────────────────────────────────

	public function register_rest_routes(): void {
		// CSP violation report – public, from browsers.
		$violation_reporter = new Violation_Reporter( $this->audit, $this->learning_window, gate: $this->gate );
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

		( new Admin_Controller( $this->audit, gate: $this->gate ) )->register_routes();

		// Stripe webhook -- only registered in a private/commercial build
		// where offline/modules/class-webhook-controller.php is present.
		if ( class_exists( \WP_SAM\Modules\Webhook_Controller::class ) && null !== $this->entitlements && null !== $this->checkout ) {
			( new \WP_SAM\Modules\Webhook_Controller( $this->entitlements, $this->audit, $this->checkout ) )->register_routes();
		}
	}
}
