<?php
/**
 * Admin view: Cross-Origin Policies -- consolidates the four cross-origin/
 * legacy header pillars (Cross-Origin-Resource-Policy,
 * X-Permitted-Cross-Domain-Policies, Cross-Origin-Opener-Policy,
 * Cross-Origin-Embedder-Policy) that previously each had their own separate
 * submenu page, onto one page with a tab per pillar -- same tab pattern as
 * the CSP dashboard. Each tab reuses the same per-surface enable+value
 * table markup page-pillar-simple.php uses for the other simple pillars
 * (X-Frame-Options, X-Content-Type-Options, Referrer-Policy), which stay on
 * their own separate pages since they aren't part of this "cross-origin"
 * grouping.
 *
 * Rendered by Admin_UI::render_cross_origin().
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WP_SAM\Security\Cross_Origin_Resource_Policy_Builder;
use WP_SAM\Security\X_Permitted_Cross_Domain_Policies_Builder;
use WP_SAM\Security\Cross_Origin_Opener_Policy_Builder;
use WP_SAM\Security\Cross_Origin_Embedder_Policy_Builder;

global $wpdb;

$tabs = array(
	'coep'  => array(
		'label'         => __( 'Cross-Origin-Embedder-Policy', 'security-automation-manager' ),
		'pillar_key'    => Cross_Origin_Embedder_Policy_Builder::PILLAR_KEY,
		'header_name'   => 'Cross-Origin-Embedder-Policy',
		'intro_html'    => '<p>' . esc_html__( 'Required for cross-origin isolation (SharedArrayBuffer, high-resolution timers, and similar browser APIs). Most WordPress sites do not need this at all.', 'security-automation-manager' ) . '</p>',
		'value_options' => array(
			'unsafe-none'    => __( 'unsafe-none -- no restriction (browser default)', 'security-automation-manager' ),
			'credentialless' => __( 'credentialless -- cross-origin resources load without credentials instead of being blocked', 'security-automation-manager' ),
			'require-corp'   => __( 'require-corp -- every cross-origin resource must explicitly opt in, or it is blocked', 'security-automation-manager' ),
		),
		'warning_html'  => '<p style="margin-top:0;margin-bottom:0;">' . esc_html__( 'The highest-risk header this plugin manages. "require-corp" blocks every cross-origin subresource (fonts, images, iframes, scripts) that does not explicitly opt in via a matching Cross-Origin-Resource-Policy header or CORS -- most third-party embeds and CDN-hosted fonts, including Google Fonts, do not opt in by default. Enabling this carelessly silently breaks unrelated page content rather than producing an obvious error. Do not enable this unless this site specifically needs cross-origin isolation.', 'security-automation-manager' ) . '</p>',
	),
	'coop'  => array(
		'label'         => __( 'Cross-Origin-Opener-Policy', 'security-automation-manager' ),
		'pillar_key'    => Cross_Origin_Opener_Policy_Builder::PILLAR_KEY,
		'header_name'   => 'Cross-Origin-Opener-Policy',
		'intro_html'    => '<p>' . esc_html__( 'Isolates this site\'s browsing context group from cross-origin windows it opens or is opened by, closing off cross-window/Spectre-style leaks.', 'security-automation-manager' ) . '</p>',
		'value_options' => array(
			'unsafe-none'              => __( 'unsafe-none -- no isolation (browser default)', 'security-automation-manager' ),
			'same-origin-allow-popups' => __( 'same-origin-allow-popups -- isolate, but let popups keep a restricted opener reference', 'security-automation-manager' ),
			'same-origin'              => __( 'same-origin -- full isolation', 'security-automation-manager' ),
		),
		'warning_html'  => '<p style="margin-top:0;margin-bottom:0;">' . esc_html__( '"same-origin" severs window.opener access from any cross-origin popup this site opens or is opened by -- including popup-based OAuth/SSO and payment flows. If this site uses any of those, start with "same-origin-allow-popups" instead, which keeps isolation for this site\'s own top-level navigation while still letting a popup hold a restricted opener reference back.', 'security-automation-manager' ) . '</p>',
	),
	'corp'  => array(
		'label'         => __( 'Cross-Origin-Resource-Policy', 'security-automation-manager' ),
		'pillar_key'    => Cross_Origin_Resource_Policy_Builder::PILLAR_KEY,
		'header_name'   => 'Cross-Origin-Resource-Policy',
		'intro_html'    => '<p>' . esc_html__( 'Controls whether other origins may load this site\'s own resources (scripts, images, fonts) via <img>, <script>, fetch(), and similar. The lowest-risk of the cross-origin headers to enable: a misconfiguration can stop a legitimate third party from loading this site\'s own resource, but it never breaks resources this site itself loads from elsewhere.', 'security-automation-manager' ) . '</p>',
		'value_options' => array(
			'same-site'    => __( 'same-site -- allow same-site origins only', 'security-automation-manager' ),
			'same-origin'  => __( 'same-origin -- allow only this exact origin', 'security-automation-manager' ),
			'cross-origin' => __( 'cross-origin -- allow any origin', 'security-automation-manager' ),
		),
		'warning_html'  => '',
	),
	'xpcdp' => array(
		'label'         => __( 'X-Permitted-Cross-Domain-Policies', 'security-automation-manager' ),
		'pillar_key'    => X_Permitted_Cross_Domain_Policies_Builder::PILLAR_KEY,
		'header_name'   => 'X-Permitted-Cross-Domain-Policies',
		'intro_html'    => '<p>' . esc_html__( 'A legacy header from the Adobe Flash/Acrobat era, controlling whether Flash and PDF plugins may load a cross-domain policy file from this site. Flash is dead, so "none" is almost always the correct value -- this closes a legacy attack surface that would otherwise sit at its permissive browser default.', 'security-automation-manager' ) . '</p>',
		'value_options' => array(
			'none'            => __( 'none -- no policy files allowed (recommended)', 'security-automation-manager' ),
			'master-only'     => __( 'master-only -- only the root crossdomain.xml', 'security-automation-manager' ),
			'by-content-type' => __( 'by-content-type', 'security-automation-manager' ),
			'all'             => __( 'all -- any policy file, anywhere', 'security-automation-manager' ),
		),
		'warning_html'  => '',
	),
);

$tab = isset( $_GET['tab'] ) ? sanitize_text_field( wp_unslash( $_GET['tab'] ) ) : 'coep';
if ( ! isset( $tabs[ $tab ] ) ) {
	$tab = 'coep';
}
$active = $tabs[ $tab ];

$base_url = admin_url( 'admin.php?page=security-automation-manager-cross-origin' );

$surfaces = array( 'frontend', 'admin', 'login', 'api' );

$profiles_raw = $wpdb->get_results(
	$wpdb->prepare(
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		"SELECT surface, enabled, payload FROM {$wpdb->prefix}sam_pillar_profiles WHERE pillar = %s",
		$active['pillar_key']
	),
	ARRAY_A
);

$profiles_by_surface = array();
foreach ( ! empty( $profiles_raw ) ? $profiles_raw : array() as $row ) {
	$payload                                = json_decode( (string) $row['payload'], true );
	$profiles_by_surface[ $row['surface'] ] = array(
		'enabled' => ! empty( $row['enabled'] ),
		'value'   => is_array( $payload ) ? (string) ( $payload['value'] ?? '' ) : '',
	);
}
?>
<div class="wrap wp-sam-wrap">
	<h1><?php esc_html_e( 'Cross-Origin Policies', 'security-automation-manager' ); ?></h1>

	<!-- ── Tabs ──────────────────────────────────────────────────────────── -->
	<nav class="nav-tab-wrapper wp-sam-tab-wrapper" role="tablist" aria-label="<?php esc_attr_e( 'Cross-origin policy pillars', 'security-automation-manager' ); ?>">
		<?php foreach ( $tabs as $tab_key => $tab_data ) : ?>
		<a class="nav-tab<?php echo $tab_key === $tab ? ' nav-tab-active' : ''; ?>"
			href="<?php echo esc_url( add_query_arg( 'tab', $tab_key, $base_url ) ); ?>"
			role="tab"
			<?php echo $tab_key === $tab ? 'aria-selected="true" aria-current="page"' : 'aria-selected="false"'; ?>>
			<?php echo esc_html( $tab_data['label'] ); ?>
		</a>
		<?php endforeach; ?>
	</nav>

	<?php if ( ! empty( $active['warning_html'] ) ) : ?>
	<div class="notice notice-warning inline" style="padding:12px 16px;margin:1em 0;">
		<?php echo wp_kses_post( $active['warning_html'] ); ?>
	</div>
	<?php endif; ?>

	<?php echo wp_kses_post( $active['intro_html'] ); ?>

	<table class="widefat striped wp-sam-readiness-table" style="margin-top: 1em;">
		<thead>
			<tr>
				<th><?php esc_html_e( 'Surface', 'security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Enabled', 'security-automation-manager' ); ?></th>
				<th><?php esc_html_e( 'Value', 'security-automation-manager' ); ?></th>
			</tr>
		</thead>
		<tbody>
			<?php foreach ( $surfaces as $surface ) : ?>
				<?php
				$current = $profiles_by_surface[ $surface ] ?? array(
					'enabled' => false,
					'value'   => '',
				);
				?>
				<tr>
					<td><?php echo esc_html( ucfirst( $surface ) ); ?></td>
					<td>
						<input
							type="checkbox"
							class="wp-sam-pillar-enabled"
							data-pillar="<?php echo esc_attr( $active['pillar_key'] ); ?>"
							data-surface="<?php echo esc_attr( $surface ); ?>"
							<?php checked( $current['enabled'] ); ?>
						/>
					</td>
					<td>
						<select
							class="wp-sam-pillar-value"
							data-pillar="<?php echo esc_attr( $active['pillar_key'] ); ?>"
							data-surface="<?php echo esc_attr( $surface ); ?>"
						>
							<?php foreach ( $active['value_options'] as $value => $label ) : ?>
								<option value="<?php echo esc_attr( $value ); ?>" <?php selected( $current['value'], $value ); ?>>
									<?php echo esc_html( $label ); ?>
								</option>
							<?php endforeach; ?>
						</select>
					</td>
				</tr>
			<?php endforeach; ?>
		</tbody>
	</table>

	<p class="description" style="margin-top: 1em;">
		<?php
		echo wp_kses_post(
			sprintf(
			/* translators: %s: HTTP header name, e.g. "Cross-Origin-Resource-Policy" */
				__( 'Changes apply immediately -- there is no report-only mode, discovery workflow, or automation for this pillar. The %s header is either sent exactly as configured, or not sent at all.', 'security-automation-manager' ),
				'<code>' . esc_html( $active['header_name'] ) . '</code>'
			)
		);
		?>
	</p>
</div>
