<?php
/**
 * WordPress Admin UI: menus, settings API, AJAX handlers.
 *
 * Registers a top-level "Security Automation Manager" menu. Submenu items are
 * ordered alphabetically by their left-nav label (not the list order below):
 *   - security-automation-manager                  – Overview: per-pillar status summary, plus
 *      Readiness (plugin-specific schema/runtime checks and reset) and About tabs
 *   - security-automation-manager-dashboard         – CSP: surface profiles, source inventory,
 *      violations, scan history, and settings (promotion gates, learning window, cron schedule,
 *      notify email), all as tabs on one page
 *   - security-automation-manager-xfo               – X-Frame-Options: per-surface DENY/SAMEORIGIN
 *   - security-automation-manager-xcto              – X-Content-Type-Options: per-surface on/off
 *   - security-automation-manager-referrer-policy   – Referrer-Policy: per-surface value picker
 *   - security-automation-manager-permissions-policy – Permissions-Policy: per-surface, per-directive picker
 *   - security-automation-manager-hsts              – Strict-Transport-Security: per-surface max-age/includeSubDomains/preload
 *   - security-automation-manager-reverse-tabnabbing – Reverse Tabnabbing: per-surface on/off, rel=noopener injection
 *   - security-automation-manager-external-scripts  – External Scripts: third-party script/stylesheet inventory, SRI, enforcement
 *   - security-automation-manager-cross-origin      – Cross-Origin Policies: Cross-Origin-Resource-Policy,
 *      X-Permitted-Cross-Domain-Policies, Cross-Origin-Opener-Policy, and Cross-Origin-Embedder-Policy,
 *      each a tab on one page (they previously each had their own separate submenu page)
 *
 * Policy Audit (effective policy, decisions, provenance) is a tab on the CSP
 * page, not a separate top-level page -- it's CSP-specific content.
 *
 * All form submissions are protected by check_admin_referer() and
 * current_user_can('manage_options').
 */

declare( strict_types=1 );

namespace WP_SAM\Admin;

use WP_SAM\Plugin;
use WP_SAM\CSP\Automation_Config;
use WP_SAM\CSP\Policy_Builder;
use WP_SAM\CSP\Policy_Change_Manager;
use WP_SAM\CSP\Policy_Version_Manager;
use WP_SAM\CSP\Scheduler;
use WP_SAM\Security\Cross_Origin_Embedder_Policy_Builder;
use WP_SAM\Security\Cross_Origin_Opener_Policy_Builder;
use WP_SAM\Security\Cross_Origin_Resource_Policy_Builder;
use WP_SAM\Security\Dependency_Governance_Builder;
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

class Admin_UI {

	private Plugin $plugin;

	public function __construct( Plugin $plugin ) {
		$this->plugin = $plugin;
	}

	// ── Bootstrap ─────────────────────────────────────────────────────────────

	public function register(): void {
		add_action( 'admin_menu', array( $this, 'add_menu_pages' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
		add_action( 'admin_notices', array( $this, 'display_admin_notices' ) );
		add_filter( 'plugin_action_links_' . plugin_basename( WP_SAM_FILE ), array( $this, 'add_plugin_action_links' ) );
		add_filter( 'plugin_row_meta', array( $this, 'add_plugin_row_meta' ), 10, 2 );
		add_filter( 'admin_footer_text', array( $this, 'filter_admin_footer_text' ) );

		// AJAX handlers.
		add_action( 'admin_post_wp_sam_reset_data', array( $this, 'handle_reset_data' ) );
		add_action( 'wp_ajax_wp_sam_manual_scan', array( $this, 'ajax_manual_scan' ) );
		add_action( 'wp_ajax_wp_sam_approve_source', array( $this, 'ajax_approve_source' ) );
		add_action( 'wp_ajax_wp_sam_deny_source', array( $this, 'ajax_deny_source' ) );
		add_action( 'wp_ajax_wp_sam_revert_source', array( $this, 'ajax_revert_source' ) );
		add_action( 'wp_ajax_wp_sam_undo_source_decision', array( $this, 'ajax_undo_source_decision' ) );
		add_action( 'wp_ajax_wp_sam_toggle_mode', array( $this, 'ajax_toggle_mode' ) );
		add_action( 'wp_ajax_wp_sam_set_trusted_types', array( $this, 'ajax_set_trusted_types' ) );
		add_action( 'wp_ajax_wp_sam_set_automation_mode', array( $this, 'ajax_set_automation_mode' ) );
		add_action( 'wp_ajax_wp_sam_create_checkout_session', array( $this, 'ajax_create_checkout_session' ) );
		add_action( 'wp_ajax_wp_sam_set_pillar_value', array( $this, 'ajax_set_pillar_value' ) );
		add_action( 'wp_ajax_wp_sam_set_permissions_policy_directive', array( $this, 'ajax_set_permissions_policy_directive' ) );
		add_action( 'wp_ajax_wp_sam_set_hsts', array( $this, 'ajax_set_hsts' ) );
		add_action( 'wp_ajax_wp_sam_set_dependency_mode', array( $this, 'ajax_set_dependency_mode' ) );
		add_action( 'wp_ajax_wp_sam_classify_dependency', array( $this, 'ajax_classify_dependency' ) );
		add_action( 'wp_ajax_wp_sam_suggest_dependency_sri', array( $this, 'ajax_suggest_dependency_sri' ) );
	}

	// ── Menu registration ─────────────────────────────────────────────────────

	public function add_menu_pages(): void {
		add_menu_page(
			__( 'Security Automation Manager', 'security-automation-manager' ),
			__( 'Security Automation Manager', 'security-automation-manager' ),
			'manage_options',
			'security-automation-manager',
			array( $this, 'render_overview' ),
			'dashicons-shield',
			80
		);

		// Submenu order is alphabetical by the label shown in the left nav
		// (not registration/logical order) -- Readiness is a tab on the
		// Overview page (see page-overview.php), not a separate menu entry.
		add_submenu_page(
			'security-automation-manager',
			__( 'Cross-Origin Policies', 'security-automation-manager' ),
			__( 'Cross-Origin Policies', 'security-automation-manager' ),
			'manage_options',
			'security-automation-manager-cross-origin',
			array( $this, 'render_cross_origin' )
		);

		add_submenu_page(
			'security-automation-manager',
			__( 'CSP', 'security-automation-manager' ),
			__( 'CSP', 'security-automation-manager' ),
			'manage_options',
			'security-automation-manager-dashboard',
			array( $this, 'render_dashboard' )
		);

		add_submenu_page(
			'security-automation-manager',
			__( 'External Scripts', 'security-automation-manager' ),
			__( 'External Scripts', 'security-automation-manager' ),
			'manage_options',
			'security-automation-manager-external-scripts',
			array( $this, 'render_external_scripts' )
		);

		add_submenu_page(
			'security-automation-manager',
			__( 'Strict-Transport-Security', 'security-automation-manager' ),
			__( 'HSTS', 'security-automation-manager' ),
			'manage_options',
			'security-automation-manager-hsts',
			array( $this, 'render_hsts' )
		);

		add_submenu_page(
			'security-automation-manager',
			__( 'Overview', 'security-automation-manager' ),
			__( 'Overview', 'security-automation-manager' ),
			'manage_options',
			'security-automation-manager',
			array( $this, 'render_overview' )
		);

		add_submenu_page(
			'security-automation-manager',
			__( 'Permissions-Policy', 'security-automation-manager' ),
			__( 'Permissions-Policy', 'security-automation-manager' ),
			'manage_options',
			'security-automation-manager-permissions-policy',
			array( $this, 'render_permissions_policy' )
		);

		add_submenu_page(
			'security-automation-manager',
			__( 'Referrer-Policy', 'security-automation-manager' ),
			__( 'Referrer-Policy', 'security-automation-manager' ),
			'manage_options',
			'security-automation-manager-referrer-policy',
			array( $this, 'render_referrer_policy' )
		);

		add_submenu_page(
			'security-automation-manager',
			__( 'Reverse Tabnabbing Protection', 'security-automation-manager' ),
			__( 'Reverse Tabnabbing', 'security-automation-manager' ),
			'manage_options',
			'security-automation-manager-reverse-tabnabbing',
			array( $this, 'render_reverse_tabnabbing' )
		);

		add_submenu_page(
			'security-automation-manager',
			__( 'X-Content-Type-Options', 'security-automation-manager' ),
			__( 'X-Content-Type-Options', 'security-automation-manager' ),
			'manage_options',
			'security-automation-manager-xcto',
			array( $this, 'render_x_content_type_options' )
		);

		add_submenu_page(
			'security-automation-manager',
			__( 'X-Frame-Options', 'security-automation-manager' ),
			__( 'X-Frame-Options', 'security-automation-manager' ),
			'manage_options',
			'security-automation-manager-xfo',
			array( $this, 'render_x_frame_options' )
		);
	}

	// ── Settings API ──────────────────────────────────────────────────────────

	public function register_settings(): void {
		$settings = array(
			'wp_sam_cron_hour'                     => 'absint',
			'wp_sam_notify_email'                  => 'sanitize_email',
			'wp_sam_enforce_gate_violation_window' => 'absint',
			'wp_sam_learning_window_hours'         => 'absint',
			'wp_sam_report_endpoint_url'           => array( $this, 'sanitize_report_endpoint_url' ),
			'wp_sam_reporting_transport'           => array( $this, 'sanitize_reporting_transport' ),
			'wp_sam_policy_header_name'            => array( $this, 'sanitize_policy_header_name' ),
			'wp_sam_automation_config'             => array( $this, 'sanitize_automation_config' ),
			// Data retention: days to keep violation reports (0 = keep forever).
			'wp_sam_violation_retention_days'      => 'absint',
			// Stripe configuration for the Fully Automatic checkout flow -- these
			// fields only render when a commercial build's Checkout_Service is
			// present (see the "Stripe Configuration" section further down this
			// tab), but registering the settings unconditionally is harmless and
			// keeps this one list authoritative for every wp_sam_* option.
			'wp_sam_stripe_mode'                   => array( $this, 'sanitize_stripe_mode' ),
			'wp_sam_stripe_secret_key_test'        => 'sanitize_text_field',
			'wp_sam_stripe_secret_key_live'        => 'sanitize_text_field',
			'wp_sam_stripe_price_id_monthly_test'  => 'sanitize_text_field',
			'wp_sam_stripe_price_id_annual_test'   => 'sanitize_text_field',
			'wp_sam_stripe_price_id_monthly_live'  => 'sanitize_text_field',
			'wp_sam_stripe_price_id_annual_live'   => 'sanitize_text_field',
			'wp_sam_webhook_secret'                => 'sanitize_text_field',
		);

		foreach ( $settings as $option => $callback ) {
			register_setting( 'wp_sam_settings_group', $option, array( 'sanitize_callback' => $callback ) );
		}
	}

	public function add_plugin_action_links( array $links ): array {
		$settings_link = sprintf(
			'<a href="%1$s">%2$s</a>',
			esc_url( admin_url( 'admin.php?page=security-automation-manager-dashboard&tab=settings' ) ),
			esc_html__( 'Settings', 'security-automation-manager' )
		);

		$reset_link = sprintf(
			'<a href="%1$s">%2$s</a>',
			esc_url( admin_url( 'admin.php?page=security-automation-manager&tab=readiness#wp-sam-reset' ) ),
			esc_html__( 'Reset', 'security-automation-manager' )
		);

		return array(
			'settings' => $settings_link,
			'reset'    => $reset_link,
		) + $links;
	}

	public function add_plugin_row_meta( array $links, string $file ): array {
		if ( plugin_basename( WP_SAM_FILE ) !== $file ) {
			return $links;
		}

		$update_posture = 'github' === WP_SAM_DISTRIBUTION_CHANNEL
			? __( 'Updates: GitHub Releases channel with checksum verification.', 'security-automation-manager' )
			: __( 'Updates: WordPress.org package; no custom updater runs in this build.', 'security-automation-manager' );

		$links[] = sprintf(
			'<span class="wp-sam-update-posture">%s</span>',
			esc_html( $update_posture )
		);

		return $links;
	}

	/**
	 * Suppresses the default "Thank you for creating with WordPress." footer
	 * text on this plugin's own admin pages only; every other admin screen is
	 * left untouched.
	 *
	 * FIX: accepts mixed, not string. admin_footer_text runs through every
	 * plugin's filter callbacks in sequence, and WordPress does not enforce
	 * that earlier callbacks return a string -- a misbehaving plugin/theme
	 * returning null (or anything else) here previously fataled every wp-admin
	 * page load with a TypeError, since this method's parameter was typed
	 * `string` under this plugin's own strict_types declaration.
	 */
	public function filter_admin_footer_text( mixed $text ): string {
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( $screen && in_array( $screen->id, $this->plugin_page_hooks(), true ) ) {
			return '';
		}

		return is_string( $text ) ? $text : '';
	}

	public function sanitize_report_endpoint_url( mixed $url ): string {
		$url = trim( (string) $url );
		if ( '' === $url ) {
			return '';
		}

		if ( preg_match( '/[\r\n"\\\\]/', $url ) ) {
			return '';
		}

		$url   = esc_url_raw( $url );
		$parts = wp_parse_url( $url );
		if ( ! is_array( $parts ) ) {
			return '';
		}

		$scheme = strtolower( (string) ( $parts['scheme'] ?? '' ) );
		$host   = (string) ( $parts['host'] ?? '' );
		if ( '' === $host || ! in_array( $scheme, array( 'http', 'https' ), true ) ) {
			return '';
		}

		return $url;
	}

	public function sanitize_policy_header_name( mixed $header_name ): string {
		return Policy_Builder::sanitize_custom_policy_header_name( $header_name );
	}

	public function sanitize_stripe_mode( mixed $mode ): string {
		return 'live' === $mode ? 'live' : 'test';
	}

	// ── Asset enqueue ─────────────────────────────────────────────────────────

	public function sanitize_reporting_transport( mixed $transport ): string {
		return Policy_Builder::sanitize_reporting_transport( $transport );
	}

	public function sanitize_automation_config( mixed $config ): array {
		$raw        = is_array( $config ) ? $config : array();
		$normalised = ( new Automation_Config( $this->plugin->gate ) )->normalise_admin_input( $raw );

		foreach ( $normalised as $surface => $surface_config ) {
			$requested_mode = strtolower( trim( (string) ( $raw[ $surface ]['mode'] ?? '' ) ) );
			if ( Automation_Config::MODE_FULLY_AUTOMATIC === $requested_mode && Automation_Config::MODE_FULLY_AUTOMATIC !== $surface_config['mode'] ) {
				add_settings_error(
					'wp_sam_automation_config',
					'wp_sam_fully_automatic_requires_upgrade',
					__( 'Fully Automatic mode requires a paid subscription. The affected surface was kept on "Automatic (with high approvals only)" instead.', 'security-automation-manager' ),
					'warning'
				);
			}
		}

		return $normalised;
	}

	/**
	 * Admin-page hook suffixes this plugin registers, shared by enqueue_assets()
	 * and filter_admin_footer_text() so the list only lives in one place.
	 *
	 * WordPress derives a submenu's hook suffix from sanitize_title() of the
	 * top-level menu's title text, not its slug -- since the top-level menu
	 * title is "Security Automation Manager", every submenu hook is prefixed
	 * "security-automation-manager_page_".
	 */
	private function plugin_page_hooks(): array {
		return array(
			'toplevel_page_security-automation-manager',
			'security-automation-manager_page_security-automation-manager-dashboard',
			'security-automation-manager_page_security-automation-manager-xfo',
			'security-automation-manager_page_security-automation-manager-xcto',
			'security-automation-manager_page_security-automation-manager-referrer-policy',
			'security-automation-manager_page_security-automation-manager-permissions-policy',
			'security-automation-manager_page_security-automation-manager-hsts',
			'security-automation-manager_page_security-automation-manager-reverse-tabnabbing',
			'security-automation-manager_page_security-automation-manager-external-scripts',
			'security-automation-manager_page_security-automation-manager-cross-origin',
		);
	}

	public function enqueue_assets( string $hook_suffix ): void {
		if ( ! in_array( $hook_suffix, $this->plugin_page_hooks(), true ) ) {
			return;
		}

		wp_enqueue_style(
			'wp-sam-admin',
			WP_SAM_URL . 'assets/css/admin.css',
			array(),
			WP_SAM_VERSION
		);

		wp_enqueue_script(
			'wp-sam-admin',
			WP_SAM_URL . 'assets/js/admin.js',
			array( 'jquery' ),
			WP_SAM_VERSION,
			true
		);

		wp_localize_script(
			'wp-sam-admin',
			'wpSamAdmin',
			array(
				'ajaxUrl'   => admin_url( 'admin-ajax.php' ),
				'restUrl'   => esc_url_raw( rest_url( 'security-manager/v1/admin/' ) ),
				'nonce'     => wp_create_nonce( 'wp_sam_admin_nonce' ),
				'restNonce' => wp_create_nonce( 'wp_rest' ),
				'i18n'      => array(
					'scanning'        => __( 'Scanning…', 'security-automation-manager' ),
					'scanDone'        => __( 'Scan complete.', 'security-automation-manager' ),
					'scanError'       => __( 'Scan failed. Check error log.', 'security-automation-manager' ),
					'reasonRequired'  => __( 'A decision reason is required.', 'security-automation-manager' ),
					'upgradeStarting' => __( 'Starting checkout…', 'security-automation-manager' ),
				),
			)
		);
	}

	// ── Page renderers ────────────────────────────────────────────────────────

	public function render_overview(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'security-automation-manager' ) );
		}
		$readiness = ( new Readiness_Checker() )->get_report();
		require WP_SAM_DIR . 'includes/admin/views/page-overview.php';
	}

	public function render_dashboard(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'security-automation-manager' ) );
		}
		require WP_SAM_DIR . 'includes/admin/views/page-csp-dashboard.php';
	}

	public function render_x_frame_options(): void {
		$this->render_pillar_page(
			X_Frame_Options_Builder::PILLAR_KEY,
			__( 'X-Frame-Options', 'security-automation-manager' ),
			'X-Frame-Options',
			'<p>' . esc_html__( 'Controls whether this site may be embedded in a frame or iframe on another site, as a defense against clickjacking. CSP\'s frame-ancestors directive supersedes this header in browsers that support it; X-Frame-Options remains a fallback for older browsers that don\'t.', 'security-automation-manager' ) . '</p>',
			array(
				'DENY'       => __( 'DENY -- never allow framing', 'security-automation-manager' ),
				'SAMEORIGIN' => __( 'SAMEORIGIN -- allow framing only by pages on this same site', 'security-automation-manager' ),
			)
		);
	}

	public function render_x_content_type_options(): void {
		$this->render_pillar_page(
			X_Content_Type_Options_Builder::PILLAR_KEY,
			__( 'X-Content-Type-Options', 'security-automation-manager' ),
			'X-Content-Type-Options',
			'<p>' . esc_html__( 'Stops browsers from guessing ("MIME-sniffing") a response\'s content type away from what the server declared, closing off a class of content-sniffing attacks. nosniff is the only defined value for this header, so each surface is simply on or off.', 'security-automation-manager' ) . '</p>',
			null
		);
	}

	public function render_cross_origin(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'security-automation-manager' ) );
		}
		require WP_SAM_DIR . 'includes/admin/views/page-cross-origin.php';
	}

	public function render_referrer_policy(): void {
		$options = array();
		foreach ( Referrer_Policy_Builder::VALID_VALUES as $value ) {
			$options[ $value ] = Referrer_Policy_Builder::DEFAULT_VALUE === $value
				? sprintf(
					/* translators: %s: policy value token */
					__( '%s (recommended)', 'security-automation-manager' ),
					$value
				)
				: $value;
		}

		$this->render_pillar_page(
			Referrer_Policy_Builder::PILLAR_KEY,
			__( 'Referrer-Policy', 'security-automation-manager' ),
			'Referrer-Policy',
			'<p>' . esc_html__( 'Controls how much of this site\'s URL is sent as the Referer header when a user follows a link away from it. Sent as an HTTP header only -- this plugin does not inject a <meta name="referrer"> tag into page content.', 'security-automation-manager' ) . '</p>',
			$options
		);
	}

	public function render_permissions_policy(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'security-automation-manager' ) );
		}
		require WP_SAM_DIR . 'includes/admin/views/page-permissions-policy.php';
	}

	/**
	 * Shared renderer for the "simple" per-surface pillar pages -- see
	 * includes/admin/views/page-pillar-simple.php for the shared template.
	 *
	 * @param array<string,string>|null $value_options value => label options, or null for no picker (e.g. X-Content-Type-Options).
	 * @param string                    $warning_html  Optional prominent warning notice for a pillar with real breakage risk (e.g. Cross-Origin-Opener-Policy); '' for none.
	 */
	private function render_pillar_page( string $pillar_key, string $page_title, string $header_name, string $intro_html, ?array $value_options, string $warning_html = '' ): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'security-automation-manager' ) );
		}
		require WP_SAM_DIR . 'includes/admin/views/page-pillar-simple.php';
	}

	public function render_hsts(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'security-automation-manager' ) );
		}
		require WP_SAM_DIR . 'includes/admin/views/page-hsts.php';
	}

	public function render_reverse_tabnabbing(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'security-automation-manager' ) );
		}
		require WP_SAM_DIR . 'includes/admin/views/page-reverse-tabnabbing.php';
	}

	public function render_external_scripts(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to view this page.', 'security-automation-manager' ) );
		}
		require WP_SAM_DIR . 'includes/admin/views/page-external-scripts.php';
	}

	public function handle_reset_data(): void {
		check_admin_referer( 'wp_sam_reset_data' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to reset plugin data.', 'security-automation-manager' ) );
		}

		$password     = (string) wp_unslash( $_POST['wp_sam_current_password'] ?? '' );
		$confirmation = sanitize_text_field( wp_unslash( $_POST['wp_sam_reset_confirmation'] ?? '' ) );

		if ( 'RESET CSP DATA' !== $confirmation || ! $this->current_user_password_is_valid( $password ) ) {
			$this->redirect_to_readiness( 'failed' );
		}

		$result = ( new Data_Resetter() )->reset();

		$this->redirect_to_readiness(
			empty( $result['tables_failed'] ) ? 'success' : 'partial'
		);
	}

	private function current_user_password_is_valid( string $password ): bool {
		if ( '' === $password || ! function_exists( 'wp_get_current_user' ) || ! function_exists( 'wp_check_password' ) ) {
			return false;
		}

		$user = wp_get_current_user();
		if ( ! is_object( $user ) || empty( $user->ID ) || empty( $user->user_pass ) ) {
			return false;
		}

		return wp_check_password( $password, (string) $user->user_pass, (int) $user->ID );
	}

	private function redirect_to_readiness( string $result ): void {
		$url = add_query_arg(
			array(
				'tab'          => 'readiness',
				'wp_sam_reset' => $result,
			),
			admin_url( 'admin.php?page=security-automation-manager#wp-sam-reset' )
		);

		wp_safe_redirect( $url );
		exit;
	}

	// ── Admin notices ─────────────────────────────────────────────────────────

	public function display_admin_notices(): void {
		// Platform constraint warning (R9): wp-admin strict CSP is best-effort because
		// WordPress core Trac #59446 is unresolved. Only show when the admin surface
		// profile is in enforce mode, and only once per session per user.
		$this->maybe_show_admin_csp_warning();

		$notices = get_option( 'wp_sam_admin_notices', array() );
		if ( ! is_array( $notices ) || empty( $notices ) ) {
			return;
		}
		foreach ( $notices as $notice ) {
			$type = 'error' === $notice['severity'] ? 'error' : 'warning';
			printf(
				'<div class="notice notice-%1$s is-dismissible"><p><strong>%2$s</strong> [%3$s] %4$s</p></div>',
				esc_attr( $type ),
				esc_html__( 'Security Automation Manager:', 'security-automation-manager' ),
				esc_html( $notice['component'] . '/' . $notice['event'] ),
				esc_html( $notice['detail'] )
			);
		}
		delete_option( 'wp_sam_admin_notices' );
	}

	/**
	 * Shows a one-per-session notice when the admin surface CSP is in enforce mode.
	 * WordPress core Trac #59446 means some admin UI components may break under
	 * strict nonce-based CSP. This warns the admin to monitor violations first.
	 */
	private function maybe_show_admin_csp_warning(): void {
		$user_id  = get_current_user_id();
		$transkey = 'wp_sam_admin59446_warned_' . $user_id;
		if ( get_transient( $transkey ) ) {
			return;
		}

		global $wpdb;
		$table = $wpdb->prefix . 'csp_policy_profiles';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$mode = $wpdb->get_var( $wpdb->prepare( "SELECT mode FROM {$table} WHERE surface = %s LIMIT 1", 'admin' ) );

		if ( 'enforce' !== $mode ) {
			return;
		}

		set_transient( $transkey, 1, DAY_IN_SECONDS );
		printf(
			'<div class="notice notice-info is-dismissible"><p>%s</p></div>',
			wp_kses(
				sprintf(
					/* translators: %s: URL to WordPress core Trac ticket */
					__( '<strong>Security Automation Manager:</strong> The wp-admin CSP surface is in <strong>enforce mode</strong>. WordPress core <a href="%s" target="_blank" rel="noopener">Trac #59446</a> is unresolved - some admin UI components may be blocked. Monitor violation reports before keeping enforce mode active.', 'security-automation-manager' ),
					'https://core.trac.wordpress.org/ticket/59446'
				),
				array(
					'strong' => array(),
					'a'      => array(
						'href'   => array(),
						'target' => array(),
						'rel'    => array(),
					),
				)
			)
		);
	}

	// ── AJAX: manual scan ─────────────────────────────────────────────────────

	public function ajax_manual_scan(): void {
		check_ajax_referer( 'wp_sam_admin_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => __( 'Insufficient permissions.', 'security-automation-manager' ) ), 403 );
		}

		$scheduler = new Scheduler( $this->plugin->audit );
		$results   = $scheduler->run_manual_scan();

		if ( isset( $results['error'] ) ) {
			wp_send_json_error( array( 'message' => $results['error'] ) );
		} else {
			wp_send_json_success( $results );
		}
	}

	// ── AJAX: approve/deny source ─────────────────────────────────────────────

	public function ajax_approve_source(): void {
		check_ajax_referer( 'wp_sam_admin_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( null, 403 );
		}
		$this->decide_source( (int) ( $_POST['source_id'] ?? 0 ), 'approved' );
	}

	public function ajax_deny_source(): void {
		check_ajax_referer( 'wp_sam_admin_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( null, 403 );
		}
		$this->decide_source( (int) ( $_POST['source_id'] ?? 0 ), 'rejected' );
	}

	public function ajax_revert_source(): void {
		check_ajax_referer( 'wp_sam_admin_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( null, 403 );
		}
		$this->decide_source( (int) ( $_POST['source_id'] ?? 0 ), 'reverted' );
	}

	public function ajax_undo_source_decision(): void {
		check_ajax_referer( 'wp_sam_admin_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( null, 403 );
		}
		$this->decide_source( (int) ( $_POST['source_id'] ?? 0 ), 'undone' );
	}

	private function decide_source( int $id, string $action ): void {
		if ( $id <= 0 ) {
			wp_send_json_error( array( 'message' => __( 'Invalid source ID.', 'security-automation-manager' ) ) );
		}

		$reason = sanitize_text_field( wp_unslash( $_POST['reason'] ?? '' ) );
		if ( '' === trim( $reason ) ) {
			wp_send_json_error( array( 'message' => __( 'A decision reason is required.', 'security-automation-manager' ) ) );
		}

		$manager = new Policy_Change_Manager( $this->plugin->audit, null, new Policy_Version_Manager( $this->plugin->policy_builder ), gate: $this->plugin->gate );
		if ( 'approved' === $action ) {
			$ok = $manager->approve_source( $id, $reason );
		} elseif ( 'reverted' === $action ) {
			$ok = $manager->revert_source( $id, $reason );
		} elseif ( 'undone' === $action ) {
			$ok = $manager->undo_source_decision( $id, $reason );
		} else {
			$ok = $manager->reject_source( $id, $reason );
		}

		if ( ! $ok ) {
			wp_send_json_error( array( 'message' => __( 'Could not record policy decision.', 'security-automation-manager' ) ) );
		}
		wp_send_json_success();
	}

	// ── AJAX: toggle surface mode ─────────────────────────────────────────────

	public function ajax_toggle_mode(): void {
		check_ajax_referer( 'wp_sam_admin_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( null, 403 );
		}

		$surface = sanitize_text_field( wp_unslash( $_POST['surface'] ?? '' ) );
		$mode    = sanitize_text_field( wp_unslash( $_POST['mode'] ?? '' ) );

		if ( ! in_array( $surface, array( 'frontend', 'admin', 'login', 'api' ), true ) ) {
			wp_send_json_error( array( 'message' => 'Invalid surface.' ) );
		}
		if ( ! in_array( $mode, array( 'report-only', 'enforce', 'disabled' ), true ) ) {
			wp_send_json_error( array( 'message' => 'Invalid mode.' ) );
		}

		// Full promotion gate: enforce requires passing all configured checks.
		if ( 'enforce' === $mode ) {
			$gate_result = $this->gate_allows_enforce( $surface );
			if ( true !== $gate_result ) {
				wp_send_json_error( array( 'message' => $gate_result ) );
			}
		}

		global $wpdb;
		$wpdb->update(
			$wpdb->prefix . 'csp_policy_profiles',
			array(
				'mode'       => $mode,
				'updated_at' => current_time( 'mysql', true ),
			),
			array( 'surface' => $surface ),
			array( '%s', '%s' ),
			array( '%s' )
		);
		wp_send_json_success();
	}

	public function ajax_set_trusted_types(): void {
		check_ajax_referer( 'wp_sam_admin_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( null, 403 );
		}

		$surface = sanitize_text_field( wp_unslash( $_POST['surface'] ?? '' ) );
		$enabled = ! empty( $_POST['enabled'] );

		if ( ! in_array( $surface, array( 'frontend', 'admin', 'login', 'api' ), true ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid surface.', 'security-automation-manager' ) ) );
		}

		global $wpdb;
		$wpdb->update(
			$wpdb->prefix . 'csp_policy_profiles',
			array(
				'trusted_types' => $enabled ? 1 : 0,
				'updated_at'    => current_time( 'mysql', true ),
			),
			array( 'surface' => $surface ),
			array( '%d', '%s' ),
			array( '%s' )
		);
		wp_send_json_success();
	}

	public function ajax_set_automation_mode(): void {
		check_ajax_referer( 'wp_sam_admin_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( null, 403 );
		}

		$surface = sanitize_text_field( wp_unslash( $_POST['surface'] ?? '' ) );
		$mode    = sanitize_text_field( wp_unslash( $_POST['mode'] ?? '' ) );

		if ( ! in_array( $surface, Automation_Config::SURFACES, true ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid surface.', 'security-automation-manager' ) ) );
		}

		if ( ! in_array( $mode, Automation_Config::MODES, true ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid automation mode.', 'security-automation-manager' ) ) );
		}

		if ( Automation_Config::MODE_FULLY_AUTOMATIC === $mode && ! $this->plugin->gate->is_allowed( 'fully_automatic' ) ) {
			wp_send_json_error(
				array(
					'message'          => __( 'Fully Automatic mode requires a paid subscription.', 'security-automation-manager' ),
					'upgrade_required' => true,
				)
			);
		}

		( new Automation_Config( $this->plugin->gate ) )->update_surface_mode( $surface, $mode );

		wp_send_json_success(
			array(
				'mode'  => $mode,
				'label' => Automation_Config::mode_label( $mode ),
			)
		);
	}

	/**
	 * Creates a Stripe Checkout Session and returns its URL for the browser
	 * to redirect to. Only available when this is a private/commercial build
	 * with the offline Checkout_Service module present -- the WordPress.org
	 * and GitHub-channel builds always return the "not available" error.
	 */
	public function ajax_create_checkout_session(): void {
		check_ajax_referer( 'wp_sam_admin_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( null, 403 );
		}

		if ( null === $this->plugin->checkout ) {
			wp_send_json_error(
				array( 'message' => __( 'Upgrading is not available in this build of the plugin.', 'security-automation-manager' ) )
			);
		}

		$interval = sanitize_text_field( wp_unslash( $_POST['interval'] ?? 'monthly' ) );
		if ( ! in_array( $interval, array( 'monthly', 'annual' ), true ) ) {
			$interval = 'monthly';
		}

		$session = $this->plugin->checkout->create_session(
			'csp-automation-manager',
			admin_url( 'admin.php?page=security-automation-manager-dashboard&wp_sam_checkout=success' ),
			admin_url( 'admin.php?page=security-automation-manager-dashboard&wp_sam_checkout=cancelled' ),
			$interval
		);

		if ( is_wp_error( $session ) ) {
			wp_send_json_error( array( 'message' => $session->get_error_message() ) );
		}

		wp_send_json_success( array( 'url' => $session['url'] ) );
	}

	// ── AJAX: simple pillar profiles ──────────────────────────────────────────

	public function ajax_set_pillar_value(): void {
		check_ajax_referer( 'wp_sam_admin_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( null, 403 );
		}

		$pillar  = sanitize_text_field( wp_unslash( $_POST['pillar'] ?? '' ) );
		$surface = sanitize_text_field( wp_unslash( $_POST['surface'] ?? '' ) );
		$enabled = ! empty( $_POST['enabled'] );
		$value   = sanitize_text_field( wp_unslash( $_POST['value'] ?? '' ) );

		if ( ! in_array( $surface, array( 'frontend', 'admin', 'login', 'api' ), true ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid surface.', 'security-automation-manager' ) ) );
		}

		$sanitized_value = '';
		switch ( $pillar ) {
			case X_Content_Type_Options_Builder::PILLAR_KEY:
				// No configurable value -- nosniff is the only defined value.
				break;

			case Reverse_Tabnabbing_Builder::PILLAR_KEY:
				// No configurable value -- rel=noopener is either injected or it isn't.
				break;

			case X_Frame_Options_Builder::PILLAR_KEY:
				$sanitized_value = X_Frame_Options_Builder::sanitize_value( $value );
				if ( $enabled && '' === $sanitized_value ) {
					wp_send_json_error( array( 'message' => __( 'Invalid X-Frame-Options value.', 'security-automation-manager' ) ) );
				}
				break;

			case Referrer_Policy_Builder::PILLAR_KEY:
				$sanitized_value = Referrer_Policy_Builder::sanitize_value( $value );
				if ( $enabled && '' === $sanitized_value ) {
					wp_send_json_error( array( 'message' => __( 'Invalid Referrer-Policy value.', 'security-automation-manager' ) ) );
				}
				break;

			case Cross_Origin_Resource_Policy_Builder::PILLAR_KEY:
				$sanitized_value = Cross_Origin_Resource_Policy_Builder::sanitize_value( $value );
				if ( $enabled && '' === $sanitized_value ) {
					wp_send_json_error( array( 'message' => __( 'Invalid Cross-Origin-Resource-Policy value.', 'security-automation-manager' ) ) );
				}
				break;

			case X_Permitted_Cross_Domain_Policies_Builder::PILLAR_KEY:
				$sanitized_value = X_Permitted_Cross_Domain_Policies_Builder::sanitize_value( $value );
				if ( $enabled && '' === $sanitized_value ) {
					wp_send_json_error( array( 'message' => __( 'Invalid X-Permitted-Cross-Domain-Policies value.', 'security-automation-manager' ) ) );
				}
				break;

			case Cross_Origin_Opener_Policy_Builder::PILLAR_KEY:
				$sanitized_value = Cross_Origin_Opener_Policy_Builder::sanitize_value( $value );
				if ( $enabled && '' === $sanitized_value ) {
					wp_send_json_error( array( 'message' => __( 'Invalid Cross-Origin-Opener-Policy value.', 'security-automation-manager' ) ) );
				}
				break;

			case Cross_Origin_Embedder_Policy_Builder::PILLAR_KEY:
				$sanitized_value = Cross_Origin_Embedder_Policy_Builder::sanitize_value( $value );
				if ( $enabled && '' === $sanitized_value ) {
					wp_send_json_error( array( 'message' => __( 'Invalid Cross-Origin-Embedder-Policy value.', 'security-automation-manager' ) ) );
				}
				break;

			default:
				wp_send_json_error( array( 'message' => __( 'Invalid pillar.', 'security-automation-manager' ) ) );
		}

		global $wpdb;
		$table   = $wpdb->prefix . 'sam_pillar_profiles';
		$now     = current_time( 'mysql', true );
		$payload = wp_json_encode( array( 'value' => $sanitized_value ) );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.NotPrepared
		$wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"INSERT INTO {$table} (pillar, surface, enabled, payload, created_at, updated_at)
				 VALUES (%s, %s, %d, %s, %s, %s)
				 ON DUPLICATE KEY UPDATE enabled = VALUES(enabled), payload = VALUES(payload), updated_at = VALUES(updated_at)",
				$pillar,
				$surface,
				$enabled ? 1 : 0,
				$payload,
				$now,
				$now
			)
		);

		wp_send_json_success();
	}

	/**
	 * Permissions-Policy has multiple independently-configurable directives
	 * per surface (a directive => allowlist-token map in payload), unlike
	 * the other simple pillars' single scalar value -- so it can't share
	 * ajax_set_pillar_value(), which always overwrites the whole payload.
	 * This does a read-modify-write: load the existing directive map for
	 * the surface, apply at most one directive change (if any was sent),
	 * and persist the current enabled state alongside it.
	 */
	public function ajax_set_permissions_policy_directive(): void {
		check_ajax_referer( 'wp_sam_admin_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( null, 403 );
		}

		$surface   = sanitize_text_field( wp_unslash( $_POST['surface'] ?? '' ) );
		$directive = sanitize_text_field( wp_unslash( $_POST['directive'] ?? '' ) );
		$value     = sanitize_text_field( wp_unslash( $_POST['value'] ?? '' ) );
		$enabled   = ! empty( $_POST['enabled'] );

		if ( ! in_array( $surface, array( 'frontend', 'admin', 'login', 'api' ), true ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid surface.', 'security-automation-manager' ) ) );
		}

		global $wpdb;
		$table = $wpdb->prefix . 'sam_pillar_profiles';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$existing_payload = $wpdb->get_var( $wpdb->prepare( "SELECT payload FROM {$table} WHERE pillar = %s AND surface = %s LIMIT 1", Permissions_Policy_Builder::PILLAR_KEY, $surface ) );
		$directives       = Permissions_Policy_Builder::extract_directives( array( 'payload' => (string) $existing_payload ) );

		if ( '' !== $directive ) {
			if ( ! in_array( $directive, Permissions_Policy_Builder::KNOWN_DIRECTIVES, true ) ) {
				wp_send_json_error( array( 'message' => __( 'Invalid directive.', 'security-automation-manager' ) ) );
			}

			$sanitized_token = Permissions_Policy_Builder::sanitize_token( $value );
			if ( '' === $sanitized_token ) {
				unset( $directives[ $directive ] ); // "(browser default)" -- stop emitting this directive.
			} else {
				$directives[ $directive ] = $sanitized_token;
			}
		}

		$table   = $wpdb->prefix . 'sam_pillar_profiles';
		$now     = current_time( 'mysql', true );
		$payload = wp_json_encode( array( 'directives' => $directives ) );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.NotPrepared
		$wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"INSERT INTO {$table} (pillar, surface, enabled, payload, created_at, updated_at)
				 VALUES (%s, %s, %d, %s, %s, %s)
				 ON DUPLICATE KEY UPDATE enabled = VALUES(enabled), payload = VALUES(payload), updated_at = VALUES(updated_at)",
				Permissions_Policy_Builder::PILLAR_KEY,
				$surface,
				$enabled ? 1 : 0,
				$payload,
				$now,
				$now
			)
		);

		wp_send_json_success();
	}

	/**
	 * HSTS has three independently-configurable fields per surface
	 * (max-age, includeSubDomains, preload), unlike the other simple
	 * pillars' single scalar value -- so it can't share ajax_set_pillar_value().
	 * preload is re-validated server-side against the same eligibility rule
	 * the admin view uses to disable the checkbox client-side, since a
	 * disabled control is only a UI hint, not enforcement.
	 */
	public function ajax_set_hsts(): void {
		check_ajax_referer( 'wp_sam_admin_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( null, 403 );
		}

		$surface            = sanitize_text_field( wp_unslash( $_POST['surface'] ?? '' ) );
		$enabled            = ! empty( $_POST['enabled'] );
		$max_age            = Strict_Transport_Security_Builder::sanitize_max_age( wp_unslash( $_POST['max_age'] ?? Strict_Transport_Security_Builder::DEFAULT_MAX_AGE ) );
		$include_subdomains = ! empty( $_POST['include_subdomains'] );
		$preload            = ! empty( $_POST['preload'] ) && Strict_Transport_Security_Builder::preload_eligible( $max_age, $include_subdomains );

		if ( ! in_array( $surface, array( 'frontend', 'admin', 'login', 'api' ), true ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid surface.', 'security-automation-manager' ) ) );
		}

		global $wpdb;
		$table   = $wpdb->prefix . 'sam_pillar_profiles';
		$now     = current_time( 'mysql', true );
		$payload = wp_json_encode(
			array(
				'max_age'            => $max_age,
				'include_subdomains' => $include_subdomains,
				'preload'            => $preload,
			)
		);

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.NotPrepared
		$wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"INSERT INTO {$table} (pillar, surface, enabled, payload, created_at, updated_at)
				 VALUES (%s, %s, %d, %s, %s, %s)
				 ON DUPLICATE KEY UPDATE enabled = VALUES(enabled), payload = VALUES(payload), updated_at = VALUES(updated_at)",
				Strict_Transport_Security_Builder::PILLAR_KEY,
				$surface,
				$enabled ? 1 : 0,
				$payload,
				$now,
				$now
			)
		);

		wp_send_json_success(
			array(
				'preload_eligible' => Strict_Transport_Security_Builder::preload_eligible( $max_age, $include_subdomains ),
				'preload'          => $preload,
			)
		);
	}

	// ── AJAX: dependency governance ───────────────────────────────────────────

	public function ajax_set_dependency_mode(): void {
		check_ajax_referer( 'wp_sam_admin_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( null, 403 );
		}

		$surface = sanitize_text_field( wp_unslash( $_POST['surface'] ?? '' ) );
		$enabled = ! empty( $_POST['enabled'] );
		$mode    = sanitize_text_field( wp_unslash( $_POST['mode'] ?? 'report' ) );
		$mode    = 'enforce' === $mode ? 'enforce' : 'report';

		if ( ! in_array( $surface, array( 'frontend', 'admin', 'login', 'api' ), true ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid surface.', 'security-automation-manager' ) ) );
		}

		global $wpdb;
		$table   = $wpdb->prefix . 'sam_pillar_profiles';
		$now     = current_time( 'mysql', true );
		$payload = wp_json_encode( array( 'mode' => $mode ) );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.NotPrepared
		$wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"INSERT INTO {$table} (pillar, surface, enabled, payload, created_at, updated_at)
				 VALUES (%s, %s, %d, %s, %s, %s)
				 ON DUPLICATE KEY UPDATE enabled = VALUES(enabled), payload = VALUES(payload), updated_at = VALUES(updated_at)",
				Dependency_Governance_Builder::PILLAR_KEY,
				$surface,
				$enabled ? 1 : 0,
				$payload,
				$now,
				$now
			)
		);

		wp_send_json_success();
	}

	/**
	 * Classifies one discovered origin, and -- only for 'immutable_pinned' --
	 * records the administrator's own expected SRI hash. expected_sri is
	 * never computed by this plugin on its own initiative: it is only ever
	 * what the administrator explicitly typed/pasted in directly, or what
	 * ajax_suggest_dependency_sri() computed for a URL the administrator
	 * themselves supplied and then chose to save here.
	 */
	public function ajax_classify_dependency(): void {
		check_ajax_referer( 'wp_sam_admin_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( null, 403 );
		}

		$id             = (int) ( $_POST['id'] ?? 0 );
		$classification = sanitize_text_field( wp_unslash( $_POST['classification'] ?? '' ) );
		$expected_sri   = sanitize_text_field( wp_unslash( $_POST['expected_sri'] ?? '' ) );

		if ( $id <= 0 ) {
			wp_send_json_error( array( 'message' => __( 'Invalid entry.', 'security-automation-manager' ) ) );
		}

		if ( ! in_array( $classification, Dependency_Governance_Builder::CLASSIFICATIONS, true ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid classification.', 'security-automation-manager' ) ) );
		}

		$sanitized_sri = null;
		if ( 'immutable_pinned' === $classification && '' !== trim( $expected_sri ) ) {
			if ( ! preg_match( '/^sha(256|384|512)-[A-Za-z0-9+\/]+=*$/', trim( $expected_sri ) ) ) {
				wp_send_json_error( array( 'message' => __( 'Expected SRI hash must look like sha256-…, sha384-… or sha512-… (base64).', 'security-automation-manager' ) ) );
			}
			$sanitized_sri = trim( $expected_sri );
		}

		global $wpdb;
		$table = $wpdb->prefix . 'sam_dependency_inventory';
		$wpdb->update(
			$table,
			array(
				'classification' => $classification,
				'expected_sri'   => $sanitized_sri,
				'updated_at'     => current_time( 'mysql', true ),
			),
			array( 'id' => $id ),
			array( '%s', '%s', '%s' ),
			array( '%d' )
		);

		wp_send_json_success();
	}

	/**
	 * Computes a suggested SRI hash for a URL the administrator explicitly
	 * supplies, to save them running an external hash generator by hand.
	 * Never saved automatically -- the computed value is only ever returned
	 * to the browser; the administrator still has to accept it via the
	 * existing "Expected SRI" field (ajax_classify_dependency()) before it's
	 * ever compared against anything.
	 *
	 * Deliberately restricted to a URL whose origin already matches an
	 * origin this plugin has itself observed on a real page load (the
	 * inventory row identified by $id): this endpoint fetches whatever URL
	 * it's given, so without that restriction it would be a same-origin-only
	 * fetch proxy an authenticated admin could point at anything. Requiring
	 * the origin to match a known, passively-discovered one keeps its blast
	 * radius to "third-party assets this site already loads" rather than
	 * arbitrary internal/external URLs.
	 */
	public function ajax_suggest_dependency_sri(): void {
		check_ajax_referer( 'wp_sam_admin_nonce', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( null, 403 );
		}

		$id  = (int) ( $_POST['id'] ?? 0 );
		$url = esc_url_raw( trim( (string) wp_unslash( $_POST['url'] ?? '' ) ) );

		if ( $id <= 0 || '' === $url ) {
			wp_send_json_error( array( 'message' => __( 'A URL is required.', 'security-automation-manager' ) ) );
		}

		if ( ! preg_match( '#^https://#i', $url ) ) {
			wp_send_json_error( array( 'message' => __( 'Only https:// URLs can be hashed.', 'security-automation-manager' ) ) );
		}

		global $wpdb;
		$table = $wpdb->prefix . 'sam_dependency_inventory';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT origin FROM {$table} WHERE id = %d", $id ), ARRAY_A );
		if ( empty( $row ) ) {
			wp_send_json_error( array( 'message' => __( 'Invalid entry.', 'security-automation-manager' ) ) );
		}

		$url_origin = Dependency_Governance_Builder::normalize_origin( $url );
		if ( null === $url_origin || $url_origin !== $row['origin'] ) {
			wp_send_json_error( array( 'message' => __( 'That URL must be on the same origin already shown for this row.', 'security-automation-manager' ) ) );
		}

		$response = wp_remote_get(
			$url,
			array(
				'timeout'   => 10,
				'sslverify' => true,
			)
		);
		if ( is_wp_error( $response ) ) {
			wp_send_json_error( array( 'message' => __( 'Could not fetch that URL.', 'security-automation-manager' ) ) );
		}
		if ( 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			wp_send_json_error( array( 'message' => __( 'That URL did not return a successful response.', 'security-automation-manager' ) ) );
		}

		$body = wp_remote_retrieve_body( $response );
		// 5 MB is generously above any legitimate third-party script/stylesheet;
		// guards against hashing an unexpectedly huge response.
		if ( '' === $body || strlen( $body ) > 5 * MB_IN_BYTES ) {
			wp_send_json_error( array( 'message' => __( 'That URL returned an empty or unexpectedly large response.', 'security-automation-manager' ) ) );
		}

		$hash = 'sha384-' . base64_encode( hash( 'sha384', $body, true ) );

		wp_send_json_success( array( 'hash' => $hash ) );
	}

	// ── Promotion gate ────────────────────────────────────────────────────────

	/**
	 * Checks all configured gates before allowing enforce mode promotion.
	 *
	 * Implements §4.12:
	 *   Gate 1 -- At least one approved source or hash must exist for the surface.
	 *   Gate 2 -- No violations recorded within the configured time window.
	 *   Gate 3 -- No active temporary override that has not yet expired.
	 *
	 * @param  string       $surface  CSP surface identifier.
	 * @return true|string  true if all gates pass; a human-readable failure reason string otherwise.
	 */
	private function gate_allows_enforce( string $surface ): bool|string {
		global $wpdb;

		// ── Gate 1: approved source or hash inventory ─────────────────────────
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$src_count = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->prefix}csp_source_inventory WHERE surface = %s AND approval_state = 'approved'",
				$surface
			)
		);
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$hash_count = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->prefix}csp_hash_inventory WHERE surface = %s AND status = 'active'",
				$surface
			)
		);

		if ( ( $src_count + $hash_count ) === 0 ) {
			return __( 'Cannot promote to enforce: no approved sources or hashes found for this surface. Run a scan and approve at least one source first.', 'security-automation-manager' );
		}

		// ── Gate 2: no violations within the configured time window ───────────
		$window_hours = max( 1, (int) get_option( 'wp_sam_enforce_gate_violation_window', 24 ) );
		$since        = gmdate( 'Y-m-d H:i:s', time() - ( $window_hours * HOUR_IN_SECONDS ) );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$recent_violations = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->prefix}csp_violation_reports
				WHERE profile_surface = %s
				AND reported_at >= %s",
				$surface,
				$since
			)
		);

		if ( $recent_violations > 0 ) {
			return sprintf(
				/* translators: 1: violation count, 2: hours */
				__( 'Cannot promote to enforce: %1$d violation(s) recorded for this surface in the last %2$d hour(s). Resolve violations in report-only mode first, or extend the violation window in Settings.', 'security-automation-manager' ),
				$recent_violations,
				$window_hours
			);
		}

		// ── Gate 3: no active unresolved temporary override ───────────────────
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$profile = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT override_expires_at, override_owner FROM {$wpdb->prefix}csp_policy_profiles WHERE surface = %s LIMIT 1",
				$surface
			),
			ARRAY_A
		);

		if ( $profile ) {
			$expires_at = $profile['override_expires_at'] ?? null;
			$owner      = $profile['override_owner'] ?? null;

			if ( ! empty( $expires_at ) && ! empty( $owner ) ) {
				$expires_ts = strtotime( $expires_at );
				if ( false !== $expires_ts && $expires_ts > time() ) {
					return sprintf(
						/* translators: 1: override owner, 2: expiry datetime */
						__( 'Cannot promote to enforce: a temporary override set by "%1$s" is active until %2$s. Wait for it to expire or remove it before enabling enforce mode.', 'security-automation-manager' ),
						esc_html( $owner ),
						esc_html( $expires_at )
					);
				}
			}
		}

		return true;
	}
}
