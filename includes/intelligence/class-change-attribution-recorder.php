<?php
/**
 * Records WordPress-environment changes into Change_Log_Store (Phase 3F,
 * .roadmap/phase3_early_plan.md §17 Change Attribution) -- hooks the same
 * upgrader_process_complete/activated_plugin/deactivated_plugin events
 * Learning_Window already listens to, plus switch_theme, but writes real
 * event history (item identity, version) rather than Learning_Window's
 * single re-opens-a-window timestamp. Kept entirely separate from
 * Learning_Window so this can't change its existing CSP-source-learning
 * behaviour.
 *
 * Old plugin/theme versions are best-effort: by the time
 * upgrader_process_complete fires, the update has already happened, so
 * only the new version is reliably available without extra bookkeeping
 * this class doesn't attempt. Drift_Scanner's own baseline-vs-current
 * comparison is what surfaces a precise old-&gt;new transition; this log
 * only needs to answer "did something change around this time".
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Change_Attribution_Recorder {

	private Change_Log_Store $log;

	public function __construct( Change_Log_Store $log ) {
		$this->log = $log;
	}

	public function register(): void {
		add_action( 'upgrader_process_complete', array( $this, 'on_upgrader_process_complete' ), 10, 2 );
		add_action( 'activated_plugin', array( $this, 'on_plugin_activated' ), 10, 1 );
		add_action( 'deactivated_plugin', array( $this, 'on_plugin_deactivated' ), 10, 1 );
		add_action( 'switch_theme', array( $this, 'on_switch_theme' ), 10, 3 );
	}

	public function on_upgrader_process_complete( object $upgrader, array $hook_extra ): void {
		unset( $upgrader );
		$type = (string) ( $hook_extra['type'] ?? '' );

		if ( 'plugin' === $type ) {
			$plugins = $this->extract_items( $hook_extra, 'plugin', 'plugins' );
			foreach ( $plugins as $plugin_file ) {
				$this->log->record( 'plugin_updated', $plugin_file, '', $this->plugin_version( $plugin_file ) );
			}
			return;
		}

		if ( 'theme' === $type ) {
			$themes = $this->extract_items( $hook_extra, 'theme', 'themes' );
			foreach ( $themes as $stylesheet ) {
				$theme = wp_get_theme( $stylesheet );
				$this->log->record( 'theme_updated', $stylesheet, '', (string) $theme->get( 'Version' ) );
			}
			return;
		}

		if ( 'core' === $type ) {
			// Lowercase to match Baseline_State_Builder's core_version item_key
			// exactly -- Drift_Scanner::correlate() matches by string equality.
			$this->log->record( 'core_updated', 'core', '', get_bloginfo( 'version' ) );
		}
	}

	public function on_plugin_activated( string $plugin ): void {
		$this->log->record( 'plugin_activated', $plugin, '', $this->plugin_version( $plugin ) );
	}

	public function on_plugin_deactivated( string $plugin ): void {
		$this->log->record( 'plugin_deactivated', $plugin, $this->plugin_version( $plugin ), '' );
	}

	public function on_switch_theme( string $new_name, \WP_Theme $new_theme, \WP_Theme $old_theme ): void {
		unset( $new_name );
		$this->log->record(
			'theme_switched',
			$new_theme->get_stylesheet(),
			(string) $old_theme->get( 'Version' ),
			(string) $new_theme->get( 'Version' )
		);
	}

	/**
	 * upgrader_process_complete's $hook_extra carries either a single item
	 * under the singular key (one-at-a-time update) or a list under the
	 * plural key (bulk update) -- never both, and WordPress core doesn't
	 * document which a given upgrade path uses, so both are checked.
	 *
	 * @return array<string>
	 */
	private function extract_items( array $hook_extra, string $singular_key, string $plural_key ): array {
		if ( isset( $hook_extra[ $plural_key ] ) && is_array( $hook_extra[ $plural_key ] ) ) {
			return array_map( 'strval', $hook_extra[ $plural_key ] );
		}
		if ( isset( $hook_extra[ $singular_key ] ) && is_string( $hook_extra[ $singular_key ] ) && '' !== $hook_extra[ $singular_key ] ) {
			return array( $hook_extra[ $singular_key ] );
		}
		return array();
	}

	/**
	 * get_plugin_data() reads the file directly and degrades gracefully
	 * (empty values, no fatal) if it can't be opened, so this doesn't
	 * need its own file_exists() guard -- $plugin_file always comes from
	 * a WordPress core hook that only ever fires for a real plugin file.
	 */
	private function plugin_version( string $plugin_file ): string {
		if ( ! function_exists( 'get_plugin_data' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$data = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin_file, false, false );
		return (string) ( $data['Version'] ?? '' );
	}
}
