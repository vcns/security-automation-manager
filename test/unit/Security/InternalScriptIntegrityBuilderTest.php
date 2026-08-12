<?php
/**
 * Unit tests for WP_SAM\Security\Internal_Script_Integrity_Builder.
 *
 * Uses real fixture files under a temp directory mapped onto the test
 * bootstrap's content_url()/WP_CONTENT_DIR pairing, since path resolution
 * and hashing both do real filesystem I/O (filemtime/filesize/realpath/
 * file_get_contents) that can't be stubbed the way $wpdb is.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Security\Internal_Script_Integrity_Builder;

class InternalScriptIntegrityBuilderTest extends TestCase {

	private string $fixtureDir;
	private string $fixturePath;
	private string $fixtureUrl;

	protected function setUp(): void {
		wp_test_reset_globals();

		$this->fixtureDir = WP_CONTENT_DIR . '/plugins/wp-sam-test-fixture';
		if ( ! is_dir( $this->fixtureDir ) ) {
			mkdir( $this->fixtureDir, 0777, true );
		}
		$this->fixturePath = $this->fixtureDir . '/script.js';
		file_put_contents( $this->fixturePath, "console.log('v1');" );
		$this->fixtureUrl = 'https://example.com/wp-content/plugins/wp-sam-test-fixture/script.js?ver=1.0';
	}

	protected function tearDown(): void {
		if ( is_file( $this->fixturePath ) ) {
			unlink( $this->fixturePath );
		}
		if ( is_dir( $this->fixtureDir ) ) {
			rmdir( $this->fixtureDir );
		}
	}

	private function builder(): Internal_Script_Integrity_Builder {
		return new Internal_Script_Integrity_Builder();
	}

	// ── resolve_local_path() ─────────────────────────────────────────────────

	public function test_resolve_local_path_maps_content_url_to_wp_content_dir(): void {
		$resolved = Internal_Script_Integrity_Builder::resolve_local_path( $this->fixtureUrl );

		$this->assertNotNull( $resolved );
		$this->assertSame( realpath( $this->fixturePath ), $resolved );
	}

	public function test_resolve_local_path_returns_null_for_third_party_url(): void {
		$this->assertNull( Internal_Script_Integrity_Builder::resolve_local_path( 'https://cdn.example.com/lib.js' ) );
	}

	public function test_resolve_local_path_returns_null_for_nonexistent_file(): void {
		$this->assertNull( Internal_Script_Integrity_Builder::resolve_local_path( 'https://example.com/wp-content/plugins/does-not-exist/x.js' ) );
	}

	public function test_resolve_local_path_returns_null_for_path_traversal_attempt(): void {
		$this->assertNull( Internal_Script_Integrity_Builder::resolve_local_path( 'https://example.com/wp-content/../../../../etc/passwd' ) );
	}

	// ── Tag filtering ─────────────────────────────────────────────────────────

	public function test_script_tag_unchanged_when_pillar_disabled(): void {
		$tag = '<script src="' . $this->fixtureUrl . '"></script>';

		$result = $this->builder()->add_script_integrity( $tag, 'wp-sam-test', $this->fixtureUrl );

		$this->assertSame( $tag, $result );
	}

	public function test_script_tag_gets_integrity_when_pillar_enabled(): void {
		$GLOBALS['_wpdb_get_var'] = 1; // is_active() surface lookup.

		$tag    = '<script src="' . $this->fixtureUrl . '"></script>';
		$result = $this->builder()->add_script_integrity( $tag, 'wp-sam-test', $this->fixtureUrl );

		$expected_hash = 'sha384-' . base64_encode( hash( 'sha384', "console.log('v1');", true ) );
		$this->assertStringContainsString( 'integrity="' . $expected_hash . '"', $result );
		$this->assertStringContainsString( 'crossorigin="anonymous"', $result );
	}

	public function test_style_tag_gets_integrity_when_pillar_enabled(): void {
		$GLOBALS['_wpdb_get_var'] = 1;

		$tag    = '<link rel="stylesheet" href="' . $this->fixtureUrl . '" />';
		$result = $this->builder()->add_style_integrity( $tag, 'wp-sam-test', $this->fixtureUrl, 'all' );

		$this->assertStringContainsString( 'integrity="sha384-', $result );
		$this->assertStringContainsString( 'crossorigin="anonymous"', $result );
	}

	public function test_tag_unchanged_when_integrity_already_present(): void {
		$GLOBALS['_wpdb_get_var'] = 1;

		$tag    = '<script src="' . $this->fixtureUrl . '" integrity="sha384-existing"></script>';
		$result = $this->builder()->add_script_integrity( $tag, 'wp-sam-test', $this->fixtureUrl );

		$this->assertSame( $tag, $result );
	}

	public function test_tag_unchanged_for_third_party_src_even_when_enabled(): void {
		$GLOBALS['_wpdb_get_var'] = 1;

		$tag    = '<script src="https://cdn.example.com/lib.js"></script>';
		$result = $this->builder()->add_script_integrity( $tag, 'external-lib', 'https://cdn.example.com/lib.js' );

		$this->assertSame( $tag, $result );
	}

	// ── Hash caching ──────────────────────────────────────────────────────────

	public function test_reuses_cached_hash_when_file_unchanged(): void {
		$GLOBALS['_wpdb_get_var'] = 1;

		$mtime = filemtime( $this->fixturePath );
		$size  = filesize( $this->fixturePath );
		$cached_hash                       = 'sha384-cached-value-should-be-reused';
		$GLOBALS['_wpdb_get_row_queue'] = array(
			array(
				'id'         => 42,
				'file_mtime' => $mtime,
				'file_size'  => $size,
				'hash'       => $cached_hash,
			),
		);

		$tag    = '<script src="' . $this->fixtureUrl . '"></script>';
		$result = $this->builder()->add_script_integrity( $tag, 'wp-sam-test', $this->fixtureUrl );

		$this->assertStringContainsString( 'integrity="' . $cached_hash . '"', $result );
		// Cache hit -- no fresh insert, only an UPDATE (touching last_seen_at).
		$this->assertSame( 'update', $GLOBALS['_wpdb_last_operation'] );
	}

	public function test_recomputes_hash_when_file_size_differs_from_cache(): void {
		$GLOBALS['_wpdb_get_var'] = 1;

		$GLOBALS['_wpdb_get_row_queue'] = array(
			array(
				'id'         => 42,
				'file_mtime' => filemtime( $this->fixturePath ),
				'file_size'  => 999999, // deliberately stale/wrong -- forces a recompute.
				'hash'       => 'sha384-stale-should-not-be-used',
			),
		);

		$tag    = '<script src="' . $this->fixtureUrl . '"></script>';
		$result = $this->builder()->add_script_integrity( $tag, 'wp-sam-test', $this->fixtureUrl );

		$expected_hash = 'sha384-' . base64_encode( hash( 'sha384', "console.log('v1');", true ) );
		$this->assertStringContainsString( 'integrity="' . $expected_hash . '"', $result );
		$this->assertStringNotContainsString( 'sha384-stale-should-not-be-used', $result );
	}
}
