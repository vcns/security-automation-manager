<?php
/**
 * Documentation-alignment regression coverage for the Customer-Centred
 * Administration Experience (2.10.0).
 *
 * This does not (and cannot) verify the docs are well-written -- only that
 * the public help site, FAQ, and readme.txt actually mention the interface
 * a user lands on today, and that a specific previously-published false
 * claim ("the front door after activation" attached to a screenshot that
 * predates the Home page's scorecard) doesn't silently reappear. A future
 * change that guts this documentation without updating these fixtures
 * fails here instead of shipping unnoticed.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;

class DocumentationCoverageTest extends TestCase {

	private function read_file( string $file ): string {
		$contents = file_get_contents( $file );
		$this->assertIsString( $contents, "Expected {$file} to be readable." );
		return $contents;
	}

	public function test_user_guide_documents_the_welcome_and_home_experience(): void {
		$root       = dirname( __DIR__, 2 );
		$user_guide = $this->read_file( $root . '/docs/user-guide.html' );

		foreach (
			array(
				'Welcome',
				'Personal Preferences',
				'Simple',
				'Balanced',
				'Technical',
				'Security Scorecard',
				'Protection Status',
				'Not in use',
				'Unavailable',
				'Action Centre',
				'Detections',
				'Recommendations',
			) as $term
		) {
			$this->assertStringContainsString(
				$term,
				$user_guide,
				"docs/user-guide.html no longer mentions \"{$term}\" -- the Welcome/Home-page documentation may have been removed or rewritten without updating this coverage."
			);
		}
	}

	public function test_user_guide_no_longer_claims_the_stale_front_door(): void {
		$root       = dirname( __DIR__, 2 );
		$user_guide = $this->read_file( $root . '/docs/user-guide.html' );

		$this->assertStringNotContainsString(
			'the front door after activation',
			$user_guide,
			'docs/user-guide.html still describes the per-pillar Overview tab as "the front door after activation" -- since 2.10.0, the Welcome page and Home page scorecard are what a user sees first.'
		);
	}

	public function test_user_guide_flags_the_stale_overview_screenshot(): void {
		$root       = dirname( __DIR__, 2 );
		$user_guide = $this->read_file( $root . '/docs/user-guide.html' );

		$this->assertStringContainsString(
			'sam-overview.png',
			$user_guide,
			'Expected the Overview-tab screenshot to still be present (correctly captioned), not removed outright.'
		);
		$this->assertStringContainsString(
			'pending a refresh',
			$user_guide,
			'The sam-overview.png screenshot no longer flags itself as stale/pending a refresh for the 2.10.0 Home experience -- if it has actually been recaptured, update this assertion (and docs/images/README.md) to match.'
		);
	}

	public function test_faq_documents_personal_preferences_and_protection_status(): void {
		$root = dirname( __DIR__, 2 );
		$faq  = $this->read_file( $root . '/docs/faq.html' );

		foreach (
			array(
				'Welcome page',
				'Simple, Balanced, and Technical',
				'Security Scorecard',
				'Protection Status',
				'Detections',
				'Action Centre',
				'Personal Preferences',
			) as $term
		) {
			$this->assertStringContainsString(
				$term,
				$faq,
				"docs/faq.html no longer mentions \"{$term}\"."
			);
		}
	}

	public function test_help_site_landing_page_documents_the_home_experience(): void {
		$root  = dirname( __DIR__, 2 );
		$index = $this->read_file( $root . '/docs/index.html' );

		foreach ( array( 'Welcome', 'scorecard', 'Protection Status', 'Action Centre' ) as $term ) {
			$this->assertStringContainsString(
				$term,
				$index,
				"docs/index.html no longer mentions \"{$term}\"."
			);
		}
	}

	public function test_help_site_landing_page_flags_the_stale_navigation_screenshot(): void {
		$root  = dirname( __DIR__, 2 );
		$index = $this->read_file( $root . '/docs/index.html' );

		$this->assertStringContainsString(
			'This screenshot is stale and pending a refresh',
			$index,
			'docs/index.html no longer flags sam-navigation.png as stale -- if it has actually been recaptured against the current five-item menu, update this assertion (and docs/images/README.md) to match.'
		);
	}

	public function test_readme_description_documents_the_welcome_experience(): void {
		$root   = dirname( __DIR__, 2 );
		$readme = $this->read_file( $root . '/readme.txt' );

		$description_section = substr(
			$readme,
			(int) strpos( $readme, '== Description ==' ),
			(int) strpos( $readme, '== External services ==' ) - (int) strpos( $readme, '== Description ==' )
		);

		foreach ( array( 'Welcome page', 'Technical presentation', 'per WordPress user' ) as $term ) {
			$this->assertStringContainsString(
				$term,
				$description_section,
				"readme.txt's == Description == section no longer mentions \"{$term}\" -- this is user-facing onboarding copy, not just the changelog."
			);
		}
	}
}
