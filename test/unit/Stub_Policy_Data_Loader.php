<?php
/**
 * Shared test double for WP_SAM\CSP\Policy_Data_Loader (GitHub issue
 * #170) -- replaces the previous pattern of tests subclassing Policy_
 * Builder itself to override its protected DB-loading methods, which
 * turned a security-sensitive header-emitting class into a de facto
 * subclass extension point. Used by PolicyBuilderTest, BaselineState
 * BuilderTest, and DriftScannerTest.
 *
 * Required explicitly by test/bootstrap.php, matching NonceBridge.php's
 * own precedent: PHPUnit's directory-based test discovery does not
 * guarantee this file loads before every test file that needs it.
 *
 * load_profile() defaults to null: nothing that uses this double with
 * its default constructor actually goes through Policy_Builder's own
 * load_profile() (it's `final protected`, unreachable from outside the
 * class) -- every caller either passes its profile directly to
 * build_policy_string() or fetches its own profile independently (see
 * Baseline_State_Builder's own docblock for why). Pass $profile
 * explicitly for a test that specifically exercises load_profile()'s
 * own delegation via reflection.
 */

declare( strict_types=1 );

use WP_SAM\CSP\Policy_Data_Loader;

if ( ! class_exists( 'Stub_Policy_Data_Loader', false ) ) {
	final class Stub_Policy_Data_Loader implements Policy_Data_Loader {

		/**
		 * @param array<int,array<string,string>> $hashes
		 * @param array<int,array<string,string>> $sources
		 * @param array<string,mixed>|null        $profile
		 */
		public function __construct( private array $hashes = array(), private array $sources = array(), private ?array $profile = null ) {}

		public function load_profile( string $surface ): ?array {
			return $this->profile;
		}

		public function load_approved_hashes( string $surface ): array {
			return $this->hashes;
		}

		public function load_approved_sources( string $surface ): array {
			return $this->sources;
		}
	}
}
