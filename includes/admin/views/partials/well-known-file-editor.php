<?php
/**
 * Admin partial: the editor for one well-known file, opened from Control
 * → Traffic Controls → Network Intelligence → Well-Known Files (Create or
 * Edit on that file's row).
 *
 * Starter templates fill the text box; nothing reaches visitors until an
 * administrator saves. Before that, the editor warns about anything that
 * would stop the saved version being served or would change what it
 * replaces: a site that isn't at the root of its domain, a real file in
 * the site's folder, or an SEO plugin that also writes robots.txt.
 *
 * Rendered by page-traffic.php.
 *
 * @var string $well_known_key A key of Well_Known_File_Catalog::files().
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use WP_SAM\Admin\Admin_UI;
use WP_SAM\Intelligence\Well_Known_File_Catalog;
use WP_SAM\Intelligence\Well_Known_File_Editor;
use WP_SAM\Intelligence\Well_Known_File_Store;

$wk_file      = Well_Known_File_Catalog::files()[ $well_known_key ];
$wk_url       = Well_Known_File_Catalog::url( $well_known_key );
$wk_templates = Well_Known_File_Catalog::templates( $well_known_key );
$wk_saved     = ( new Well_Known_File_Store() )->get( $well_known_key );
$wk_can_serve = Well_Known_File_Catalog::serves_from_root();
$wk_on_disk   = Well_Known_File_Catalog::files_on_disk( $well_known_key );
$wk_writer    = 'robots' === $well_known_key ? Well_Known_File_Catalog::robots_txt_writer() : null;

$wk_errors = get_transient( 'wp_sam_well_known_errors_' . get_current_user_id() );
$wk_errors = is_array( $wk_errors ) ? $wk_errors : array();
$wk_input  = get_transient( 'wp_sam_well_known_input_' . get_current_user_id() );
delete_transient( 'wp_sam_well_known_errors_' . get_current_user_id() );
delete_transient( 'wp_sam_well_known_input_' . get_current_user_id() );

$wk_template_key = isset( $_GET['template'] ) ? sanitize_key( wp_unslash( $_GET['template'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only choice of starting text.
$wk_saved_check  = isset( $_GET['saved'] ) ? sanitize_key( wp_unslash( $_GET['saved'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display-only flag set by our own redirect.

// What the text box opens with: text that just failed to save, then a
// template the admin picked, then this plugin's saved version, then what
// the site serves now, then the first template.
$wk_note = '';
if ( ! empty( $wk_errors ) && is_string( $wk_input ) ) {
	$wk_content = $wk_input;
} elseif ( isset( $wk_templates[ $wk_template_key ] ) ) {
	$wk_content = $wk_templates[ $wk_template_key ]['content'];
} elseif ( null !== $wk_saved ) {
	$wk_content = $wk_saved['content'];
} else {
	$wk_live = ( new Well_Known_File_Editor() )->live_content( $well_known_key );
	if ( null !== $wk_live ) {
		$wk_content = $wk_live;
		$wk_note    = __( 'Showing what the site serves now.', 'vcns-security-automation-manager' );
	} else {
		$wk_first   = reset( $wk_templates );
		$wk_content = false !== $wk_first ? $wk_first['content'] : '';
		$wk_note    = false !== $wk_first
			/* translators: %s: template name, e.g. "WordPress default". */
			? sprintf( __( 'The site doesn\'t serve this file, or this plugin couldn\'t read it, so this starts from the %s template.', 'vcns-security-automation-manager' ), $wk_first['label'] )
			: '';
	}
}

$wk_check_notices = array(
	Well_Known_File_Store::CHECK_SERVED      => array( 'success', __( 'Saved. Visitors now get this version.', 'vcns-security-automation-manager' ) ),
	Well_Known_File_Store::CHECK_NOT_SERVED  => array( 'warning', __( 'Saved, but the site still returns something else at this address. A real file in the site\'s folder, a page cache or the web server is answering before WordPress. Clear whichever it is, then save again to check.', 'vcns-security-automation-manager' ) ),
	Well_Known_File_Store::CHECK_UNREACHABLE => array( 'warning', __( 'Saved, but this plugin couldn\'t fetch the address to confirm what visitors get.', 'vcns-security-automation-manager' ) ),
);
?>

<p><a href="<?php echo esc_url( admin_url( 'admin.php?page=security-automation-manager-traffic&tab=network-intelligence&subtab=well-known' ) ); ?>">&larr; <?php esc_html_e( 'All well-known files', 'vcns-security-automation-manager' ); ?></a></p>

<h3 class="wp-sam-well-known-editor-title"><?php echo esc_html( $wk_file['label'] ); ?></h3>
<p class="description"><?php echo esc_html( $wk_file['purpose'] ); ?></p>
<p>
	<?php if ( null !== $wk_saved ) : ?>
		<?php esc_html_e( 'This plugin serves the version below at', 'vcns-security-automation-manager' ); ?>
	<?php else : ?>
		<?php esc_html_e( 'This plugin isn\'t serving this file. Saving serves the version below at', 'vcns-security-automation-manager' ); ?>
	<?php endif; ?>
	<code><?php echo esc_html( $wk_url ); ?></code>.
</p>

<?php if ( isset( $wk_check_notices[ $wk_saved_check ] ) ) : ?>
<div class="notice notice-<?php echo esc_attr( $wk_check_notices[ $wk_saved_check ][0] ); ?> inline"><p><?php echo esc_html( $wk_check_notices[ $wk_saved_check ][1] ); ?></p></div>
<?php endif; ?>

<?php if ( ! empty( $wk_errors ) ) : ?>
<div class="notice notice-error inline">
	<p><?php esc_html_e( 'File not saved:', 'vcns-security-automation-manager' ); ?></p>
	<ul>
		<?php foreach ( $wk_errors as $wk_error ) : ?>
		<li><?php echo esc_html( (string) $wk_error ); ?></li>
		<?php endforeach; ?>
	</ul>
</div>
<?php endif; ?>

<?php if ( ! $wk_can_serve ) : ?>
<div class="notice notice-error inline"><p>
	<?php
	/* translators: %s: this site's home address, e.g. https://example.com/blog */
	echo esc_html( sprintf( __( 'This site\'s address (%s) isn\'t the root of its domain. Well-known files are only read at the root, so this plugin can\'t serve them from here.', 'vcns-security-automation-manager' ), home_url() ) );
	?>
</p></div>
<?php endif; ?>

<?php if ( ! empty( $wk_on_disk ) ) : ?>
<div class="notice notice-warning inline"><p>
	<?php
	/* translators: %s: file path(s), e.g. /robots.txt */
	echo esc_html( sprintf( __( 'A real %s file exists in the site\'s folder. The web server sends it without running WordPress, so visitors won\'t get this plugin\'s version until that file is deleted or renamed.', 'vcns-security-automation-manager' ), implode( ', ', $wk_on_disk ) ) );
	?>
</p></div>
<?php endif; ?>

<?php if ( null !== $wk_writer ) : ?>
<div class="notice notice-warning inline"><p>
	<?php
	/* translators: %s: SEO plugin name, e.g. Yoast SEO */
	echo esc_html( sprintf( __( '%s also writes robots.txt. Saving here replaces its version, including lines it adds such as Sitemap. Start from what the site serves now to keep them.', 'vcns-security-automation-manager' ), $wk_writer ) );
	?>
</p></div>
<?php endif; ?>

<h4><?php esc_html_e( 'Start from', 'vcns-security-automation-manager' ); ?></h4>
<ul class="wp-sam-well-known-templates">
	<li>
		<a class="button button-small" href="<?php echo esc_url( Admin_UI::well_known_editor_url( $well_known_key ) ); ?>"><?php echo esc_html( null !== $wk_saved ? __( 'Saved version', 'vcns-security-automation-manager' ) : __( 'Current file', 'vcns-security-automation-manager' ) ); ?></a>
		<?php echo esc_html( null !== $wk_saved ? __( 'The version this plugin serves now.', 'vcns-security-automation-manager' ) : __( 'What the site serves now, if anything.', 'vcns-security-automation-manager' ) ); ?>
	</li>
	<?php foreach ( $wk_templates as $wk_template_id => $wk_template ) : ?>
	<li>
		<a class="button button-small" href="<?php echo esc_url( Admin_UI::well_known_editor_url( $well_known_key, array( 'template' => $wk_template_id ) ) ); ?>"><?php echo esc_html( $wk_template['label'] ); ?></a>
		<?php echo esc_html( $wk_template['description'] ); ?>
	</li>
	<?php endforeach; ?>
</ul>

<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
	<?php wp_nonce_field( 'wp_sam_well_known_save' ); ?>
	<input type="hidden" name="action" value="wp_sam_well_known_save" />
	<input type="hidden" name="file" value="<?php echo esc_attr( $well_known_key ); ?>" />
	<label for="wp-sam-well-known-content">
		<?php
		/* translators: %s: file name, e.g. Robots.txt */
		echo esc_html( sprintf( __( 'Contents of %s', 'vcns-security-automation-manager' ), $wk_file['label'] ) );
		?>
	</label>
	<?php if ( '' !== $wk_note ) : ?>
	<span class="description"><?php echo esc_html( $wk_note ); ?></span>
	<?php endif; ?>
	<textarea id="wp-sam-well-known-content" name="content" class="large-text code" rows="14" spellcheck="false"><?php echo esc_textarea( $wk_content ); ?></textarea>
	<?php if ( $wk_can_serve ) : ?>
		<?php submit_button( null !== $wk_saved ? __( 'Save', 'vcns-security-automation-manager' ) : __( 'Save and serve', 'vcns-security-automation-manager' ), 'primary', 'submit', false ); ?>
	<?php endif; ?>
</form>

<?php if ( null !== $wk_saved ) : ?>
<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="wp-sam-well-known-remove">
	<?php wp_nonce_field( 'wp_sam_well_known_remove' ); ?>
	<input type="hidden" name="action" value="wp_sam_well_known_remove" />
	<input type="hidden" name="file" value="<?php echo esc_attr( $well_known_key ); ?>" />
	<?php submit_button( __( 'Stop serving', 'vcns-security-automation-manager' ), 'delete small', '', false ); ?>
	<span class="description"><?php esc_html_e( 'Visitors then get whatever the site served before this plugin took over.', 'vcns-security-automation-manager' ); ?></span>
</form>
<?php endif; ?>
