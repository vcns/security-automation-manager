<?php
/**
 * Proves the commercial-services extension's schema
 * (sam_entitlements/sam_processed_events) is genuinely extension-owned:
 * absent from a base Activator::activate() run -- this suite never loads
 * includes/extensions/ otherwise, so that IS the WordPress.org-channel
 * scenario, not a simulation of it -- and non-destructive to any
 * pre-existing data when the extension is loaded (the GitHub-channel
 * upgrade scenario).
 *
 * Each test that needs the extension's hooks registered calls require()
 * (never require_once) on includes/extensions/commercial-services.php
 * directly, since setUp()'s wp_test_reset_globals() clears
 * $GLOBALS['_wp_actions'] before every test -- require_once would silently
 * no-op on the second and subsequent tests in this file, since PHP tracks
 * "already required" paths for the whole process, not per-test.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Activator;

class CommercialServicesSchemaTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	public function test_clean_activation_does_not_create_commercial_tables(): void {
		Activator::activate();

		$schema = implode( "\n\n", $GLOBALS['_dbdelta_queries'] );

		$this->assertStringNotContainsString( 'sam_entitlements', $schema );
		$this->assertStringNotContainsString( 'sam_processed_events', $schema );
	}

	public function test_all_table_suffixes_excludes_commercial_tables_when_extension_is_not_loaded(): void {
		$suffixes = Activator::get_all_table_suffixes();

		$this->assertNotContains( 'sam_entitlements', $suffixes );
		$this->assertNotContains( 'sam_processed_events', $suffixes );
	}

	public function test_extension_registers_both_commercial_tables_without_dropping_anything(): void {
		require WP_SAM_DIR . 'includes/extensions/commercial-services.php';

		global $wpdb;
		$GLOBALS['_dbdelta_queries'] = array();
		do_action( 'wp_sam_register_schema', $wpdb, $wpdb->get_charset_collate(), $wpdb->prefix );

		$schema = implode( "\n\n", $GLOBALS['_dbdelta_queries'] );

		$this->assertStringContainsString( "CREATE TABLE {$wpdb->prefix}sam_entitlements", $schema );
		$this->assertStringContainsString( "CREATE TABLE {$wpdb->prefix}sam_processed_events", $schema );
		// dbDelta() is additive-only by design -- neither statement issues
		// a DROP, so any pre-existing data in these tables on a real
		// GitHub-channel install upgrading can never be lost by this
		// registration running again.
		$this->assertStringNotContainsStringIgnoringCase( 'DROP TABLE', $schema );
		$this->assertStringNotContainsStringIgnoringCase( 'DROP COLUMN', $schema );
	}

	public function test_extension_adds_its_tables_to_get_all_table_suffixes(): void {
		require WP_SAM_DIR . 'includes/extensions/commercial-services.php';

		$suffixes = Activator::get_all_table_suffixes();

		$this->assertContains( 'sam_entitlements', $suffixes );
		$this->assertContains( 'sam_processed_events', $suffixes );
	}

	/**
	 * A real upgrade re-runs Activator::activate() (and therefore
	 * wp_sam_register_schema) every time the plugin version changes, on a
	 * site that may already have real entitlement rows. This proves that
	 * happening twice in a row produces byte-identical CREATE TABLE SQL --
	 * dbDelta()'s own idempotency guarantee, not something this extension
	 * has to implement itself, and evidence that repeated activation
	 * cannot progressively alter or lose existing data.
	 */
	/**
	 * A real upgrade from a pre-v9 install could still have the old
	 * csp_entitlements/csp_processed_events table names. This proves the
	 * extension issues the same RENAME TABLE (not DROP+CREATE) preservation
	 * Activator::migrate_v9_table_renames() already uses for every other
	 * legacy table -- existing rows move to the new name intact, never
	 * recreated from scratch.
	 */
	public function test_extension_renames_legacy_tables_instead_of_recreating_them(): void {
		require WP_SAM_DIR . 'includes/extensions/commercial-services.php';

		global $wpdb;
		// table_exists() is called once per RENAME candidate as (old, new):
		// old table present, new table absent -- for both tables in turn.
		$GLOBALS['_wpdb_get_var_queue'] = array(
			$wpdb->prefix . 'csp_entitlements', // old exists
			null, // new absent
			$wpdb->prefix . 'csp_processed_events', // old exists
			null, // new absent
		);
		$GLOBALS['_wpdb_queries'] = array();

		do_action( 'wp_sam_register_schema', $wpdb, $wpdb->get_charset_collate(), $wpdb->prefix );

		$rename_queries = array_filter(
			$GLOBALS['_wpdb_queries'],
			static fn( string $sql ): bool => str_starts_with( $sql, 'RENAME TABLE' )
		);

		$this->assertCount( 2, $rename_queries, 'Expected exactly one RENAME TABLE per legacy table.' );
		foreach ( $rename_queries as $sql ) {
			$this->assertStringNotContainsStringIgnoringCase( 'DROP', $sql );
		}
	}

	public function test_extension_schema_registration_is_idempotent_across_repeated_calls(): void {
		require WP_SAM_DIR . 'includes/extensions/commercial-services.php';

		global $wpdb;
		$cc = $wpdb->get_charset_collate();
		$p  = $wpdb->prefix;

		$GLOBALS['_dbdelta_queries'] = array();
		do_action( 'wp_sam_register_schema', $wpdb, $cc, $p );
		$first_run = $GLOBALS['_dbdelta_queries'];

		$GLOBALS['_dbdelta_queries'] = array();
		do_action( 'wp_sam_register_schema', $wpdb, $cc, $p );
		$second_run = $GLOBALS['_dbdelta_queries'];

		$this->assertSame( $first_run, $second_run );
	}
}
