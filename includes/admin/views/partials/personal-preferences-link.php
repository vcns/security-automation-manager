<?php
/**
 * Admin partial: "Personal Preferences" link plus the current user's
 * resolved presentation-depth indicator (spec §6, §13.1). Included near the
 * top of each of the five lifecycle pages (Settings/Observe/Decide/Control/
 * Verify), right after the page's own <h1>.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WP_SAM\Admin\Presentation_Preferences;

$wp_sam_header_prefs = Presentation_Preferences::get_for_user();
?>
<p class="wp-sam-personal-preferences">
	<a href="<?php echo esc_url( admin_url( 'admin.php?page=security-automation-manager-welcome' ) ); ?>">
		<?php esc_html_e( 'Personal Preferences', 'vcns-security-automation-manager' ); ?>
	</a>
	<span class="wp-sam-presentation-indicator">
		<?php
		printf(
			/* translators: %s: presentation depth label (Simple, Balanced, or Technical) */
			esc_html__( 'Presentation: %s', 'vcns-security-automation-manager' ),
			esc_html( Presentation_Preferences::depth_label( $wp_sam_header_prefs['presentation_depth'] ) )
		);
		?>
	</span>
</p>
