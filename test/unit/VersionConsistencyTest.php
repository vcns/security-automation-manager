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

	public function test_release_workflow_builds_separate_update_channels(): void {
		$workflow = $this->read_file( dirname( __DIR__, 2 ) . '/.github/workflows/release-package.yml' );

		$this->assertStringContainsString( 'security-automation-manager-${TAG}.zip', $workflow );
		$this->assertStringContainsString( 'security-automation-manager-github-${TAG}.zip', $workflow );
		$this->assertStringContainsString( 'rm -f dist/wporg/security-automation-manager/includes/modules/class-github-update-checker.php', $workflow );
		$this->assertStringContainsString( 'WP_SAM_DISTRIBUTION_CHANNEL\', \'github', $workflow );
		// NOTE: the GitHub repo path and the update-feed publish path intentionally
		// still use the pre-rename slug -- the actual GitHub repository has not
		// been renamed (a separate, deliberately deferred decision), and the feed
		// path must match Github_Update_Checker::SLUG in already-installed copies.
		$this->assertStringContainsString( 'Update URI:        https://github.com/vcns/csp-automation-manager', $workflow );
		$this->assertStringContainsString( 'https://vcns.github.io/wp-updates/csp-automation-manager/', $workflow );
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

	private function read_file( string $file ): string {
		$contents = file_get_contents( $file );

		$this->assertIsString( $contents, "Expected {$file} to be readable." );

		return $contents;
	}
}
