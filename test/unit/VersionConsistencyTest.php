<?php
/**
 * Release metadata consistency tests.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;

class VersionConsistencyTest extends TestCase {

	public function test_release_version_metadata_is_consistent(): void {
		$root = dirname( __DIR__, 2 );

		$plugin_version   = $this->extract_plugin_header_version( $root . '/security-automation-manager.php' );
		$constant_version = $this->extract_plugin_constant_version( $root . '/security-automation-manager.php' );
		$stable_tag       = $this->extract_readme_stable_tag( $root . '/readme.txt' );
		$changelog        = $this->extract_latest_changelog_release( $root . '/CHANGELOG.md' );

		$this->assertMatchesRegularExpression( '/^\d+\.\d+\.\d+$/', $plugin_version, 'Plugin version must be a valid semver string.' );
		$this->assertSame( $plugin_version, $constant_version );
		$this->assertSame( $plugin_version, $stable_tag );
		$this->assertSame( $plugin_version, $changelog );
	}

	/**
	 * SPECIFICATION.md sat five schema generations stale (declared "aligned
	 * to DB schema v4" while WP_SAM_DB_VERSION had reached 22) with nothing
	 * catching it -- see docs/consolidation-ledger.md. This asserts the
	 * document's declared schema alignment tracks the live constant so a
	 * future schema bump without a spec update fails CI instead of shipping.
	 */
	public function test_specification_schema_alignment_matches_code(): void {
		$root = dirname( __DIR__, 2 );

		$db_version   = $this->extract_db_schema_version( $root . '/security-automation-manager.php' );
		$spec_version = $this->extract_specification_schema_alignment( $root . '/SPECIFICATION.md' );

		$this->assertSame(
			$db_version,
			$spec_version,
			'SPECIFICATION.md\'s "DB schema alignment" line has drifted from WP_SAM_DB_VERSION -- update SPECIFICATION.md (and audit it for anything else the schema change affects) alongside the schema bump.'
		);
	}

	/**
	 * Regression coverage for specific documentation drift found and
	 * corrected in the consolidation review (docs/consolidation-ledger.md):
	 * the pre-2.8.0 two-asset GitHub package name, and the "automation
	 * defaults to Manual" claim that contradicted the plugin's own schema
	 * v18 migration note. Neither should reappear in the public-facing docs.
	 */
	public function test_public_docs_do_not_contain_known_stale_claims(): void {
		$root = dirname( __DIR__, 2 );

		$readme_md  = $this->read_file( $root . '/README.md' );
		$readme_txt = $this->read_file( $root . '/readme.txt' );

		$this->assertStringNotContainsString(
			'security-automation-manager-github-v',
			$readme_md,
			'README.md references the retired pre-2.8.0 two-asset GitHub package name.'
		);
		$this->assertStringNotContainsString(
			'security-automation-manager-github-v',
			$readme_txt,
			'readme.txt references the retired pre-2.8.0 two-asset GitHub package name.'
		);
		$this->assertStringNotContainsString(
			'Automation defaults to `Manual` for every surface',
			$readme_md,
			'README.md claims automation defaults to Manual, contradicting the schema v18 migration note.'
		);
	}

	public function test_release_workflow_builds_separate_update_channels(): void {
		$workflow = $this->read_file( dirname( __DIR__, 2 ) . '/.github/workflows/release-package.yml' );

		$this->assertStringContainsString( 'security-automation-manager-${TAG}.zip', $workflow );
		$this->assertStringContainsString( 'security-automation-manager-github-${TAG}.zip', $workflow );
		$this->assertStringContainsString( 'vcns-security-automation-manager-${TAG}.zip', $workflow );
		$this->assertStringContainsString( 'rm -f dist/wporg/vcns-security-automation-manager/includes/modules/class-github-update-checker.php', $workflow );
		$this->assertStringContainsString( 'WP_SAM_DISTRIBUTION_CHANNEL\', \'github', $workflow );
		// The GitHub repo path and the update-feed publish path must match the
		// live repository name and Github_Update_Checker::SLUG.
		$this->assertStringContainsString( 'Update URI:        https://github.com/vcns/security-automation-manager', $workflow );
		$this->assertStringContainsString( 'https://vcns.github.io/wp-updates/security-automation-manager/', $workflow );
		$this->assertStringContainsString( 'WP_UPDATES_TOKEN', $workflow );
		$this->assertStringContainsString( 'sha256sum', $workflow );
	}

	private function extract_plugin_header_version( string $file ): string {
		$contents = $this->read_file( $file );

		$this->assertMatchesRegularExpression( '/^\s*\*\s+Version:\s*([^\r\n]+)/mi', $contents );
		preg_match( '/^\s*\*\s+Version:\s*([^\r\n]+)/mi', $contents, $matches );

		return trim( $matches[1] );
	}

	private function extract_plugin_constant_version( string $file ): string {
		$contents = $this->read_file( $file );

		$this->assertMatchesRegularExpression( "/define\(\s*'WP_SAM_VERSION'\s*,\s*'([^']+)'\s*\)/", $contents );
		preg_match( "/define\(\s*'WP_SAM_VERSION'\s*,\s*'([^']+)'\s*\)/", $contents, $matches );

		return trim( $matches[1] );
	}

	private function extract_readme_stable_tag( string $file ): string {
		$contents = $this->read_file( $file );

		$this->assertMatchesRegularExpression( '/^Stable tag:\s*([^\r\n]+)/mi', $contents );
		preg_match( '/^Stable tag:\s*([^\r\n]+)/mi', $contents, $matches );

		return trim( $matches[1] );
	}

	private function extract_latest_changelog_release( string $file ): string {
		$contents = $this->read_file( $file );

		$this->assertMatchesRegularExpression( '/^## \[([0-9]+\.[0-9]+\.[0-9]+)\]/m', $contents );
		preg_match( '/^## \[([0-9]+\.[0-9]+\.[0-9]+)\]/m', $contents, $matches );

		return trim( $matches[1] );
	}

	private function extract_db_schema_version( string $file ): string {
		$contents = $this->read_file( $file );

		$this->assertMatchesRegularExpression( "/define\(\s*'WP_SAM_DB_VERSION'\s*,\s*'([^']+)'\s*\)/", $contents );
		preg_match( "/define\(\s*'WP_SAM_DB_VERSION'\s*,\s*'([^']+)'\s*\)/", $contents, $matches );

		return trim( $matches[1] );
	}

	private function extract_specification_schema_alignment( string $file ): string {
		$contents = $this->read_file( $file );

		$this->assertMatchesRegularExpression( '/^\*\*DB schema alignment:\*\*\s*v(\d+)/mi', $contents, 'SPECIFICATION.md is missing a "DB schema alignment" front-matter line.' );
		preg_match( '/^\*\*DB schema alignment:\*\*\s*v(\d+)/mi', $contents, $matches );

		return trim( $matches[1] );
	}

	private function read_file( string $file ): string {
		$contents = file_get_contents( $file );

		$this->assertIsString( $contents, "Expected {$file} to be readable." );

		return $contents;
	}
}
