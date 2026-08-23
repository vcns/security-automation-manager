<?php
/**
 * Admin view: Scripts -- Start Here, External (third-party <script>/<link
 * rel=stylesheet> origin inventory, admin-supplied SRI, report/enforce), and
 * Internal (first-party SRI, per-surface on/off, read-only hash inventory)
 * tabs. Renamed from the standalone "External Scripts" page so both halves
 * of this plugin's script/stylesheet governance -- what it does for assets
 * you don't control, and what it does for assets you do -- live in one
 * place with a shared orientation tab.
 *
 * Rendered by Admin_UI::render_scripts().
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WP_SAM\Admin\Table_Query;
use WP_SAM\Security\Dependency_Governance_Builder;
use WP_SAM\Security\Internal_Script_Integrity_Builder;

global $wpdb;

$surfaces = array( 'frontend', 'admin', 'login', 'api' );

$tab_help = array(
	'start-here' => array(
		'label'       => __( 'Start Here', 'vcns-security-automation-manager' ),
		'description' => __( 'What this page does for scripts and stylesheets you control, and for the ones you don\'t.', 'vcns-security-automation-manager' ),
	),
	'external'   => array(
		'label'       => __( 'External', 'vcns-security-automation-manager' ),
		'description' => __( 'Third-party script/stylesheet origins: inventory, classification, and admin-supplied Subresource Integrity.', 'vcns-security-automation-manager' ),
	),
	'internal'   => array(
		'label'       => __( 'Internal', 'vcns-security-automation-manager' ),
		'description' => __( 'Automatic Subresource Integrity for your own theme, plugin, and core scripts/stylesheets.', 'vcns-security-automation-manager' ),
	),
);

$tab = isset( $_GET['tab'] ) ? sanitize_text_field( wp_unslash( $_GET['tab'] ) ) : 'start-here';
if ( ! isset( $tab_help[ $tab ] ) ) {
	$tab = 'start-here';
}

$base_url = admin_url( 'admin.php?page=security-automation-manager-scripts' );
?>
<div class="wrap wp-sam-wrap">
	<h1><?php esc_html_e( 'Scripts', 'vcns-security-automation-manager' ); ?></h1>

	<!-- ── Tabs ──────────────────────────────────────────────────────────── -->
	<nav class="nav-tab-wrapper wp-sam-tab-wrapper" role="tablist" aria-label="<?php esc_attr_e( 'Scripts sections', 'vcns-security-automation-manager' ); ?>">
		<?php foreach ( $tab_help as $tab_key => $tab_data ) : ?>
		<a class="nav-tab<?php echo $tab_key === $tab ? ' nav-tab-active' : ''; ?>"
			href="<?php echo esc_url( add_query_arg( 'tab', $tab_key, $base_url ) ); ?>"
			role="tab"
			title="<?php echo esc_attr( $tab_data['description'] ); ?>"
			aria-describedby="wp-sam-tab-help-<?php echo esc_attr( $tab_key ); ?>"
			<?php echo $tab_key === $tab ? 'aria-selected="true" aria-current="page"' : 'aria-selected="false"'; ?>>
			<?php echo esc_html( $tab_data['label'] ); ?>
			<span class="screen-reader-text" id="wp-sam-tab-help-<?php echo esc_attr( $tab_key ); ?>">
				<?php echo esc_html( $tab_data['description'] ); ?>
			</span>
		</a>
		<?php endforeach; ?>
	</nav>
	<div class="wp-sam-tab-help" role="note">
		<strong><?php echo esc_html( $tab_help[ $tab ]['label'] ); ?>:</strong>
		<?php echo esc_html( $tab_help[ $tab ]['description'] ); ?>
	</div>

	<?php if ( 'start-here' === $tab ) : ?>

	<h2><?php esc_html_e( 'External scripts and stylesheets', 'vcns-security-automation-manager' ); ?></h2>
	<p>
		<?php esc_html_e( 'Every third-party <script> and <link rel="stylesheet"> origin this site loads -- analytics, marketing pixels, embedded widgets, CDN-hosted libraries -- is passively inventoried the moment a real visitor\'s page load includes it. Only the origin (scheme and host) is ever recorded, never a path or query string, and never from a dedicated crawl.', 'vcns-security-automation-manager' ); ?>
	</p>
	<p>
		<?php esc_html_e( 'A freshly discovered origin is always Unclassified: neither trusted nor blocked until an administrator decides. You can pin a Subresource Integrity hash for a version-locked script you\'ve reviewed ("Approved -- immutable"), mark a script whose content legitimately changes over time as trusted without SRI ("Approved -- mutable provider"), grant a one-off exception, or block it outright. Report mode (the default) never removes anything; enforce mode removes only what you\'ve explicitly blocked, or an "immutable" origin whose SRI hash no longer matches.', 'vcns-security-automation-manager' ); ?>
	</p>
	<p>
		<?php esc_html_e( 'This plugin never fetches a third-party script in the background or on its own initiative. A pinned SRI hash only ever comes from a URL you yourself provide: paste in a hash you already have (a local copy of the file, the vendor\'s own published value), or use the "Suggest" helper, which fetches the exact URL you type and hashes what it gets back. Suggest saves that hash immediately as the pinned value -- there is no separate confirmation step -- so only fetch a URL you already trust to represent the real, correct file, the same way you\'d only paste in a hash from a source you trust. The fetch itself is restricted to an origin this plugin has already seen this site load, so it can\'t be turned into a general-purpose fetch tool.', 'vcns-security-automation-manager' ); ?>
	</p>

	<h2><?php esc_html_e( 'Internal scripts and stylesheets', 'vcns-security-automation-manager' ); ?></h2>
	<p>
		<?php esc_html_e( 'Your own theme, plugin, and WordPress core scripts and stylesheets are a fundamentally different case: this server already has the exact file it\'s about to send. When enabled for a surface, this plugin reads that file directly, computes its SHA-384 hash, and adds it as the script or stylesheet tag\'s integrity attribute automatically -- no manual review, no pasted hash, no remote fetch of any kind. The hash is recalculated the moment a file\'s size or modified time changes, so a plugin/theme update is reflected on the very next page load that serves it -- nothing to remember to update by hand.', 'vcns-security-automation-manager' ); ?>
	</p>
	<p>
		<?php esc_html_e( 'This is safe in a way a third-party hash never can be: it never trusts a remote party to compute anything, so there is no compromised-CDN scenario to worry about. What it does protect against is the file being altered after this server serves it -- a tampered cache, a compromised CDN sitting in front of this site, or similar -- the same class of threat SRI addresses for third-party assets, just without ever needing a third party in the loop.', 'vcns-security-automation-manager' ); ?>
	</p>
	<p class="description">
		<?php esc_html_e( 'Off by default per surface, like every other pillar in this plugin -- nothing changes until you turn it on for a surface on the Internal tab.', 'vcns-security-automation-manager' ); ?>
	</p>

	<?php elseif ( 'external' === $tab ) : ?>
		<?php require WP_SAM_DIR . 'includes/admin/views/partials/scripts-external.php'; ?>
	<?php elseif ( 'internal' === $tab ) : ?>
		<?php require WP_SAM_DIR . 'includes/admin/views/partials/scripts-internal.php'; ?>
	<?php endif; ?>
</div>
