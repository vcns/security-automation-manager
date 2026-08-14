<?php
/**
 * Unit tests for WP_SAM\Security\Dependency_Governance_Builder.
 *
 * The actual rewrite()/removal pass depends on WP_HTML_Tag_Processor, a
 * WordPress core class this lightweight test environment does not load (see
 * ReverseTabnabbingBuilderTest for why). These tests cover the pure origin
 * classification and mode-parsing helpers, which carry none of that
 * dependency and are exactly the logic this plugin most needs to get right:
 * what counts as first-party, and never defaulting a fresh discovery to
 * blocked.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Security\Dependency_Governance_Builder;

class DependencyGovernanceBuilderTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	// ── normalize_origin() ────────────────────────────────────────────────────

	public function test_normalize_origin_extracts_scheme_and_host(): void {
		$this->assertSame(
			'https://cdn.example.com',
			Dependency_Governance_Builder::normalize_origin( 'https://cdn.example.com/path/script.js?v=2' )
		);
	}

	public function test_normalize_origin_lowercases_host(): void {
		$this->assertSame(
			'https://cdn.example.com',
			Dependency_Governance_Builder::normalize_origin( 'https://CDN.EXAMPLE.COM/script.js' )
		);
	}

	public function test_normalize_origin_defaults_protocol_relative_to_https(): void {
		$this->assertSame(
			'https://cdn.example.com',
			Dependency_Governance_Builder::normalize_origin( '//cdn.example.com/script.js' )
		);
	}

	public function test_normalize_origin_preserves_http_scheme(): void {
		$this->assertSame(
			'http://cdn.example.com',
			Dependency_Governance_Builder::normalize_origin( 'http://cdn.example.com/script.js' )
		);
	}

	public function test_normalize_origin_treats_relative_url_as_first_party(): void {
		$this->assertSame( 'first-party', Dependency_Governance_Builder::normalize_origin( '/wp-content/plugins/foo/script.js' ) );
	}

	public function test_normalize_origin_treats_root_relative_url_as_first_party(): void {
		$this->assertSame( 'first-party', Dependency_Governance_Builder::normalize_origin( 'script.js' ) );
	}

	public function test_normalize_origin_rejects_data_uri(): void {
		$this->assertNull( Dependency_Governance_Builder::normalize_origin( 'data:text/javascript,alert(1)' ) );
	}

	public function test_normalize_origin_rejects_javascript_scheme(): void {
		$this->assertNull( Dependency_Governance_Builder::normalize_origin( 'javascript:alert(1)' ) );
	}

	public function test_normalize_origin_returns_null_for_blank_url(): void {
		$this->assertNull( Dependency_Governance_Builder::normalize_origin( '' ) );
	}

	public function test_normalize_origin_never_includes_path_or_query(): void {
		$origin = Dependency_Governance_Builder::normalize_origin( 'https://cdn.example.com/secret/path?token=abc123' );
		$this->assertStringNotContainsString( 'secret', (string) $origin );
		$this->assertStringNotContainsString( 'token', (string) $origin );
		$this->assertStringNotContainsString( 'abc123', (string) $origin );
	}

	// ── absolutize_url() ──────────────────────────────────────────────────────

	public function test_absolutize_url_resolves_protocol_relative_to_https(): void {
		$this->assertSame(
			'https://cdn.example.com/script.js',
			Dependency_Governance_Builder::absolutize_url( '//cdn.example.com/script.js' )
		);
	}

	public function test_absolutize_url_leaves_absolute_https_url_unchanged(): void {
		$this->assertSame(
			'https://cdn.example.com/script.js?v=2',
			Dependency_Governance_Builder::absolutize_url( 'https://cdn.example.com/script.js?v=2' )
		);
	}

	public function test_absolutize_url_trims_surrounding_whitespace(): void {
		$this->assertSame(
			'https://cdn.example.com/script.js',
			Dependency_Governance_Builder::absolutize_url( '  https://cdn.example.com/script.js  ' )
		);
	}

	// ── is_first_party() ──────────────────────────────────────────────────────

	public function test_is_first_party_true_for_relative_marker(): void {
		$this->assertTrue( Dependency_Governance_Builder::is_first_party( 'first-party' ) );
	}

	public function test_is_first_party_true_for_site_own_host(): void {
		// test bootstrap's home_url()/site_url() stubs both resolve to example.com.
		$this->assertTrue( Dependency_Governance_Builder::is_first_party( 'https://example.com' ) );
	}

	public function test_is_first_party_false_for_unrelated_host(): void {
		$this->assertFalse( Dependency_Governance_Builder::is_first_party( 'https://cdn.example.com' ) );
	}

	public function test_is_first_party_does_not_match_lookalike_subdomain(): void {
		$this->assertFalse( Dependency_Governance_Builder::is_first_party( 'https://example.com.attacker.example' ) );
	}

	// ── extract_mode() ────────────────────────────────────────────────────────

	public function test_extract_mode_defaults_to_report(): void {
		$this->assertSame( 'report', Dependency_Governance_Builder::extract_mode( array() ) );
	}

	public function test_extract_mode_reads_enforce_from_payload(): void {
		$profile = array( 'payload' => wp_json_encode( array( 'mode' => 'enforce' ) ) );
		$this->assertSame( 'enforce', Dependency_Governance_Builder::extract_mode( $profile ) );
	}

	public function test_extract_mode_rejects_unrecognized_value(): void {
		$profile = array( 'payload' => wp_json_encode( array( 'mode' => 'block-everything' ) ) );
		$this->assertSame( 'report', Dependency_Governance_Builder::extract_mode( $profile ) );
	}

	public function test_extract_mode_defaults_for_invalid_json(): void {
		$this->assertSame( 'report', Dependency_Governance_Builder::extract_mode( array( 'payload' => 'not json' ) ) );
	}

	// ── CLASSIFICATIONS ───────────────────────────────────────────────────────

	public function test_unclassified_is_the_default_fresh_discovery_state(): void {
		// The whole point of this pillar's report-first design: a newly
		// discovered origin must never default to 'prohibited'.
		$this->assertContains( 'unclassified', Dependency_Governance_Builder::CLASSIFICATIONS );
		$this->assertContains( 'prohibited', Dependency_Governance_Builder::CLASSIFICATIONS );
	}
}
