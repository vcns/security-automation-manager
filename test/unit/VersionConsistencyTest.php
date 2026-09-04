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

	/**
	 * docs/database-schema.md's version table sat frozen at v12 (two of its
	 * last rows even describing what are now v20's and v22's changes) while
	 * WP_SAM_DB_VERSION advanced to v36 -- 24 schema bumps, spanning more than
	 * a dozen new tables, went completely undocumented (see GitHub issue
	 * #163's 2026-09-02 comment, which found this gap). This asserts the
	 * table's highest documented version always matches the live constant, so
	 * a future schema bump without a corresponding table row fails CI instead
	 * of quietly falling further behind.
	 */
	public function test_database_schema_doc_version_table_matches_code(): void {
		$root = dirname( __DIR__, 2 );

		$db_version = $this->extract_db_schema_version( $root . '/security-automation-manager.php' );
		$doc_latest = $this->extract_database_schema_doc_latest_version( $root . '/docs/database-schema.md' );

		$this->assertSame(
			$db_version,
			$doc_latest,
			'docs/database-schema.md\'s version table\'s highest row has drifted from WP_SAM_DB_VERSION -- add a row documenting the new schema version.'
		);
	}

	/**
	 * The WordPress/PHP minimums are declared once in the plugin header and
	 * repeated in prose across docs/architecture.md's "Operational
	 * dependencies", docs/user-guide.html's "Requirements" card, and
	 * docs/faq.html's "minimum requirements" answer. Nothing previously
	 * caught these three drifting from the header or from each other.
	 */
	public function test_operational_requirements_match_across_public_docs(): void {
		$root = dirname( __DIR__, 2 );

		$requires_wp  = $this->extract_plugin_header_field( $root . '/security-automation-manager.php', 'Requires at least' );
		$requires_php = $this->extract_plugin_header_field( $root . '/security-automation-manager.php', 'Requires PHP' );

		$architecture = $this->read_file( $root . '/docs/architecture.md' );
		$user_guide   = $this->read_file( $root . '/docs/user-guide.html' );
		$faq          = $this->read_file( $root . '/docs/faq.html' );

		$this->assertStringContainsString( "WordPress {$requires_wp}+", $architecture, 'docs/architecture.md\'s Operational dependencies WordPress minimum has drifted from the plugin header\'s "Requires at least".' );
		$this->assertStringContainsString( "PHP {$requires_php}+", $architecture, 'docs/architecture.md\'s Operational dependencies PHP minimum has drifted from the plugin header\'s "Requires PHP".' );

		$this->assertStringContainsString( "WordPress {$requires_wp} or later", $user_guide, 'docs/user-guide.html\'s Requirements card WordPress minimum has drifted from the plugin header.' );
		$this->assertStringContainsString( "PHP {$requires_php} or later", $user_guide, 'docs/user-guide.html\'s Requirements card PHP minimum has drifted from the plugin header.' );

		$this->assertStringContainsString( "WordPress {$requires_wp} or later and PHP {$requires_php} or later", $faq, 'docs/faq.html\'s minimum-requirements answer has drifted from the plugin header.' );
	}

	/**
	 * The Fully Automatic CSP subscription price is quoted in SPECIFICATION.md
	 * and repeated verbatim in docs/user-guide.html's "Automation tiers"
	 * section and docs/faq.html's "WordPress.org build & pricing" section.
	 * Nothing previously caught a price change in one place going unreflected
	 * in the others.
	 */
	public function test_subscription_price_is_consistent_across_public_docs(): void {
		$root = dirname( __DIR__, 2 );

		$price = $this->extract_subscription_price( $root . '/SPECIFICATION.md' );

		$user_guide = $this->read_file( $root . '/docs/user-guide.html' );
		$faq        = $this->read_file( $root . '/docs/faq.html' );

		$this->assertStringContainsString( $price, $user_guide, 'docs/user-guide.html\'s quoted Fully Automatic subscription price has drifted from SPECIFICATION.md.' );
		$this->assertStringContainsString( $price, $faq, 'docs/faq.html\'s quoted Fully Automatic subscription price has drifted from SPECIFICATION.md.' );
	}

	/**
	 * The GitHub-channel update manifest URL is a hardcoded security boundary
	 * (Github_Update_Checker only ever fetches from this exact host/path) as
	 * well as a documented fact in docs/release-and-publishing.md. Asserts
	 * the doc quotes the same URL the updater actually fetches, so a future
	 * manifest relocation in code can't leave the docs pointing at a dead URL.
	 */
	public function test_update_manifest_url_matches_docs(): void {
		$root = dirname( __DIR__, 2 );

		$checker_source = $this->read_file( $root . '/includes/modules/class-github-update-checker.php' );

		$this->assertMatchesRegularExpression( "/UPDATE_URL\s*=\s*'([^']+)'/", $checker_source, 'Github_Update_Checker::UPDATE_URL not found.' );
		preg_match( "/UPDATE_URL\s*=\s*'([^']+)'/", $checker_source, $matches );
		$manifest_url = $matches[1];

		$release_docs = $this->read_file( $root . '/docs/release-and-publishing.md' );

		$this->assertStringContainsString( $manifest_url, $release_docs, 'docs/release-and-publishing.md\'s update manifest URL has drifted from Github_Update_Checker::UPDATE_URL.' );
	}

	/**
	 * The short "tagline" description (readme.txt's own line just above
	 * "== Description ==", and the plugin header's Description: field) is
	 * what WordPress.org actually shows in plugin-directory search results
	 * and the "Add Plugins" install screen -- user-flagged 2026-09-04 after
	 * it still read "Ten security headers..." with no mention of
	 * Continuous Intelligence, traffic filtering, or Baseline & Drift, all
	 * shipped features by then. The two copies must stay byte-identical,
	 * and (WordPress.org truncates a directory tagline past this length)
	 * must stay within the conventional 150-character budget.
	 */
	public function test_short_description_is_consistent_and_within_the_wporg_length_budget(): void {
		$root = dirname( __DIR__, 2 );

		$plugin_header_description = $this->extract_plugin_header_field( $root . '/security-automation-manager.php', 'Description' );
		$readme_short_description  = $this->extract_readme_short_description( $root . '/readme.txt' );

		$this->assertSame(
			$plugin_header_description,
			$readme_short_description,
			'security-automation-manager.php\'s Description: header and readme.txt\'s short/tagline description have drifted apart.'
		);
		$this->assertLessThanOrEqual(
			150,
			strlen( $readme_short_description ),
			'readme.txt\'s short description exceeds WordPress.org\'s conventional 150-character directory-tagline budget -- it will be truncated.'
		);
	}

	/**
	 * COMMERCIAL_TERMS.md still opened as "CSP Automation Manager" -- the
	 * product's name from before the plugin was renamed to Security
	 * Automation Manager (see CHANGELOG.md's [2.0.0] entry) to cover more
	 * than just CSP. TRADEMARK_POLICY.md carries the same stale name but is
	 * outside this test's scope (issue #163 names only the 9 files this suite
	 * covers). Regression coverage for the fix: the current legal name must
	 * appear, and the retired one must not.
	 */
	public function test_commercial_terms_uses_current_product_name(): void {
		$root = dirname( __DIR__, 2 );

		$commercial_terms = $this->read_file( $root . '/COMMERCIAL_TERMS.md' );

		$this->assertStringContainsString( 'VCNS Security Automation Manager', $commercial_terms, 'COMMERCIAL_TERMS.md should refer to the plugin by its current name.' );
		$this->assertStringNotContainsString( 'CSP Automation Manager', $commercial_terms, 'COMMERCIAL_TERMS.md references the retired "CSP Automation Manager" product name.' );
	}

	/**
	 * Schema v9 renamed every wp_csp_-prefixed option to wp_sam_ and renamed
	 * seven shared/generic tables from a csp_ to a sam_ prefix (see
	 * Activator::migrate_v9_option_renames() and docs/database-schema.md's
	 * own v9 row) -- but docs/testing-and-quality.md and docs/architecture.md
	 * still referenced the pre-rename identifiers throughout (wp_csp_db_version,
	 * csp_audit_log, csp_policy_change_decisions, etc.), which would send
	 * anyone following those docs literally to grep or query table/option
	 * names that have not existed since v9. Guards against that regressing.
	 * (csp_policy_profiles, csp_source_inventory, csp_hash_inventory, and
	 * csp_violation_reports are CSP-owned and correctly keep their csp_
	 * prefix -- v9 did not rename those four. docs/database-schema.md itself
	 * is deliberately excluded: its v4/v5 rows correctly name the pre-rename
	 * table names as history, e.g. "named `csp_audit_log` until v9".)
	 */
	public function test_public_docs_do_not_contain_pre_v9_rename_identifiers(): void {
		$root = dirname( __DIR__, 2 );

		$stale_identifiers = array(
			'wp_csp_',
			'csp_scan_logs',
			'csp_entitlements',
			'csp_processed_events',
			'csp_audit_log',
			'csp_policy_change_decisions',
			'csp_policy_versions',
			'csp_decision_rule_evaluations',
		);

		$docs_to_check = array(
			'docs/testing-and-quality.md',
			'docs/architecture.md',
			'docs/threat-model.md',
		);

		foreach ( $docs_to_check as $doc_path ) {
			$contents = $this->read_file( $root . '/' . $doc_path );
			foreach ( $stale_identifiers as $identifier ) {
				$this->assertStringNotContainsString(
					$identifier,
					$contents,
					"{$doc_path} references the pre-schema-v9 identifier \"{$identifier}\", renamed away in schema v9."
				);
			}
		}
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

	/**
	 * Returns the highest "| vNN |" row found in docs/database-schema.md's
	 * version table, as a string matching WP_SAM_DB_VERSION's own string type.
	 */
	private function extract_database_schema_doc_latest_version( string $file ): string {
		$contents = $this->read_file( $file );

		$this->assertMatchesRegularExpression( '/^\|\s*v(\d+)\s*\|/m', $contents, 'docs/database-schema.md is missing its "| vNN | Change |" version table.' );
		preg_match_all( '/^\|\s*v(\d+)\s*\|/m', $contents, $matches );

		$versions = array_map( 'intval', $matches[1] );

		return (string) max( $versions );
	}

	/**
	 * Extracts a "* {$field}: value" line from the plugin header docblock,
	 * e.g. extract_plugin_header_field($file, 'Requires at least') -> '6.4'.
	 */
	private function extract_plugin_header_field( string $file, string $field ): string {
		$contents = $this->read_file( $file );
		$pattern  = '/^\s*\*\s+' . preg_quote( $field, '/' ) . ':\s*([^\r\n]+)/mi';

		$this->assertMatchesRegularExpression( $pattern, $contents, "Plugin header is missing a \"{$field}\" line." );
		preg_match( $pattern, $contents, $matches );

		return trim( $matches[1] );
	}

	/**
	 * Extracts readme.txt's short/tagline description -- the single line of
	 * body text between the header metadata block and "== Description ==".
	 */
	private function extract_readme_short_description( string $file ): string {
		$contents = $this->read_file( $file );
		$pattern  = '/\n\n([^\n]+)\n\n== Description ==/';

		$this->assertMatchesRegularExpression( $pattern, $contents, 'readme.txt is missing its short/tagline description line before "== Description ==".' );
		preg_match( $pattern, $contents, $matches );

		return trim( $matches[1] );
	}

	/**
	 * Extracts the "£X.XX/month or £Y.YY/year" Fully Automatic subscription
	 * price quoted in SPECIFICATION.md's product description.
	 */
	private function extract_subscription_price( string $file ): string {
		$contents = $this->read_file( $file );
		$pattern  = '/£\d+\.\d{2}\/month or £\d+\.\d{2}\/year/';

		$this->assertMatchesRegularExpression( $pattern, $contents, 'SPECIFICATION.md is missing the "£X.XX/month or £Y.YY/year" subscription price.' );
		preg_match( $pattern, $contents, $matches );

		return $matches[0];
	}

	private function read_file( string $file ): string {
		$contents = file_get_contents( $file );

		$this->assertIsString( $contents, "Expected {$file} to be readable." );

		return $contents;
	}
}
