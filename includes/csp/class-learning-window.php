<?php
/**
 * Tracks the bounded window where report-endpoint learning may update inventory.
 */

declare( strict_types=1 );

namespace WP_SAM\CSP;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Learning_Window {

	public const OPTION_LAST_CHANGE   = 'wp_sam_last_material_change_at';
	public const OPTION_WINDOW_HOURS  = 'wp_sam_learning_window_hours';
	public const DEFAULT_WINDOW_HOURS = 48;

	/**
	 * Post types that never appear at their own URL but still change what
	 * visitors' pages load: block-theme templates and template parts,
	 * Global Styles (which become an inline stylesheet), navigation menus
	 * and synced patterns. is_post_type_viewable() is false for all of
	 * them, so mark_post_change() names them explicitly.
	 */
	public const SITE_EDITOR_POST_TYPES = array(
		'wp_template',
		'wp_template_part',
		'wp_global_styles',
		'wp_navigation',
		'wp_block',
	);

	/**
	 * Registers the hooks that restart the learning window when the site changes.
	 *
	 * @return void
	 */
	public function register(): void {
		// Every post type, not just posts and pages: a product, event or
		// other custom content type can embed a script or iframe from a
		// host the policy hasn't seen, exactly as a page can.
		// mark_post_change() decides which saves count.
		add_action( 'save_post', array( $this, 'mark_post_change' ), 10, 3 );
		add_action( 'customize_save_after', array( $this, 'mark_material_change' ) );
		add_action( 'activated_plugin', array( $this, 'mark_material_change' ) );
		add_action( 'deactivated_plugin', array( $this, 'mark_material_change' ) );
		add_action( 'upgrader_process_complete', array( $this, 'mark_upgrader_change' ), 10, 2 );
	}

	/**
	 * Marks a save of content visitors can see: a published post of any
	 * public post type (posts, pages, products, events, ...), or any
	 * Site Editor post type (see SITE_EDITOR_POST_TYPES).
	 *
	 * Revisions, autosaves, attachments and anything not yet published
	 * are skipped. A draft, or the auto-draft WordPress creates as soon
	 * as the editor opens, changes nothing visitors load. The save that
	 * publishes it does, and that one counts.
	 */
	public function mark_post_change( int $post_id, object $post, bool $update ): void {
		if ( function_exists( 'wp_is_post_revision' ) && wp_is_post_revision( $post_id ) ) {
			return;
		}
		if ( function_exists( 'wp_is_post_autosave' ) && wp_is_post_autosave( $post_id ) ) {
			return;
		}

		if ( 'publish' !== (string) ( $post->post_status ?? '' ) ) {
			return;
		}

		$post_type = (string) ( $post->post_type ?? '' );
		$counts    = in_array( $post_type, self::SITE_EDITOR_POST_TYPES, true )
			|| ( '' !== $post_type && 'attachment' !== $post_type && is_post_type_viewable( $post_type ) );
		if ( $counts ) {
			$this->mark_material_change();
		}
	}

	/**
	 * Marks plugin, theme, and core installs/updates from the upgrader
	 * workflow. A theme or core update can change the byte content of
	 * inline scripts/styles and the hosts a page depends on just as
	 * surely as a plugin update can -- omitting them here left the window
	 * unopened for exactly the updates most likely to invalidate the
	 * current CSP inventory.
	 */
	public function mark_upgrader_change( object $upgrader, array $hook_extra ): void {
		if ( ! in_array( $hook_extra['type'] ?? '', array( 'plugin', 'theme', 'core' ), true ) ) {
			return;
		}

		$this->mark_material_change();
	}

	/**
	 * Records that a material site change has just happened.
	 *
	 * @return void
	 */
	public function mark_material_change(): void {
		update_option( self::OPTION_LAST_CHANGE, current_time( 'mysql', true ), false );
	}

	/**
	 * Checks whether the learning window is still open.
	 *
	 * @return bool True while the window has not locked.
	 */
	public function is_open(): bool {
		$locks_at = $this->locks_at_timestamp();
		return null === $locks_at || time() < $locks_at;
	}

	/**
	 * Returns the time of the last material change, recording the current time if none exists.
	 *
	 * @return string Time in UTC, as Y-m-d H:i:s.
	 */
	public function last_material_change_at(): string {
		$last_change = get_option( self::OPTION_LAST_CHANGE, '' );
		if ( is_string( $last_change ) && '' !== $last_change ) {
			return $last_change;
		}

		$last_change = current_time( 'mysql', true );
		update_option( self::OPTION_LAST_CHANGE, $last_change, false );

		return $last_change;
	}

	/**
	 * Returns when the learning window locks.
	 *
	 * @return string Time in UTC, as Y-m-d H:i:s, or an empty string when unknown.
	 */
	public function locks_at(): string {
		$locks_at = $this->locks_at_timestamp();
		return null !== $locks_at ? gmdate( 'Y-m-d H:i:s', $locks_at ) : '';
	}

	/**
	 * Returns the configured length of the learning window.
	 *
	 * @return int Hours, at least 1.
	 */
	public function window_hours(): int {
		return max( 1, (int) get_option( self::OPTION_WINDOW_HOURS, self::DEFAULT_WINDOW_HOURS ) );
	}

	/**
	 * Returns when the learning window locks, as a Unix timestamp.
	 *
	 * @return int|null Timestamp, or null when the last change time cannot be read.
	 */
	private function locks_at_timestamp(): ?int {
		$last_change = $this->last_material_change_at();
		$last_ts     = strtotime( $last_change . ' UTC' );

		if ( false === $last_ts ) {
			return null;
		}

		return $last_ts + ( $this->window_hours() * HOUR_IN_SECONDS );
	}
}
