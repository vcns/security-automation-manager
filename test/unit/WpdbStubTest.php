<?php
/**
 * Unit tests for the wpdb_stub::prepare() test stub itself
 * (test/bootstrap.php) -- GitHub issue #169. Confirms it mirrors real
 * WordPress wpdb::prepare() behaviour closely enough for this codebase's
 * own placeholder usage: %s/%d/%f/%i, %% as a literal percent, multiple
 * placeholders, LIKE expressions, and an argument-count mismatch
 * returning null.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;

class WpdbStubTest extends TestCase {

	private wpdb_stub $wpdb;

	protected function setUp(): void {
		wp_test_reset_globals();
		$this->wpdb = $GLOBALS['wpdb'];
	}

	public function test_percent_s_is_quoted_and_escaped(): void {
		// addslashes()-style backslash escaping, matching wpdb's own
		// _real_escape() fallback (this stub never has a real mysqli
		// connection to escape through) -- not SQL-standard doubled quotes.
		$this->assertSame( 'SELECT * FROM t WHERE a = \'it\\\'s\'', $this->wpdb->prepare( 'SELECT * FROM t WHERE a = %s', "it's" ) );
	}

	public function test_percent_d_is_cast_to_int_and_not_quoted(): void {
		$this->assertSame( 'SELECT * FROM t WHERE id = 42', $this->wpdb->prepare( 'SELECT * FROM t WHERE id = %d', '42abc' ) );
	}

	public function test_percent_f_is_cast_to_float_and_not_quoted(): void {
		$this->assertSame( 'SELECT * FROM t WHERE score = 3.140000', $this->wpdb->prepare( 'SELECT * FROM t WHERE score = %f', 3.14 ) );
	}

	public function test_percent_i_wraps_the_identifier_in_backticks(): void {
		$this->assertSame( 'SELECT * FROM `wp_sam_events`', $this->wpdb->prepare( 'SELECT * FROM %i', 'wp_sam_events' ) );
	}

	public function test_percent_i_doubles_an_embedded_backtick(): void {
		$this->assertSame( 'SELECT * FROM `weird``table`', $this->wpdb->prepare( 'SELECT * FROM %i', 'weird`table' ) );
	}

	public function test_double_percent_is_a_literal_percent_with_no_argument_consumed(): void {
		$this->assertSame( "SELECT * FROM t WHERE a LIKE '100%' AND b = 5", $this->wpdb->prepare( "SELECT * FROM t WHERE a LIKE '100%%' AND b = %d", 5 ) );
	}

	public function test_multiple_placeholders_consume_arguments_in_order(): void {
		$this->assertSame(
			"SELECT * FROM t WHERE surface = 'admin' AND id = 7",
			$this->wpdb->prepare( 'SELECT * FROM t WHERE surface = %s AND id = %d', 'admin', 7 )
		);
	}

	/**
	 * A LIKE wildcard search value is itself an argument passed through
	 * %s (built via esc_like() + concatenation), never a placeholder in
	 * the query template -- the literal '%' characters inside the escaped
	 * search term must survive untouched.
	 */
	public function test_like_expression_wildcard_percent_signs_in_the_argument_survive(): void {
		$term = '%' . $this->wpdb->esc_like( 'sam_scan' ) . '%';

		// esc_like() backslash-escapes the underscore first (sam\_scan);
		// addslashes() then doubles that same backslash on top when %s
		// escapes the whole argument -- two real backslash characters in
		// the final query, hence four in this double-quoted PHP source.
		$this->assertSame(
			"SELECT * FROM t WHERE path LIKE '%sam\\\\_scan%'",
			$this->wpdb->prepare( 'SELECT * FROM t WHERE path LIKE %s', $term )
		);
	}

	public function test_too_few_arguments_returns_null(): void {
		$this->assertNull( $this->wpdb->prepare( 'SELECT * FROM t WHERE a = %s AND b = %d', 'only-one' ) );
	}

	public function test_too_many_arguments_returns_null(): void {
		$this->assertNull( $this->wpdb->prepare( 'SELECT * FROM t WHERE a = %s', 'one', 'two' ) );
	}

	public function test_a_query_with_no_placeholders_and_no_arguments_is_returned_unchanged(): void {
		$this->assertSame( 'SELECT * FROM t', $this->wpdb->prepare( 'SELECT * FROM t' ) );
	}

	public function test_null_argument_for_percent_s_becomes_an_empty_quoted_string(): void {
		$this->assertSame( "SELECT * FROM t WHERE a = ''", $this->wpdb->prepare( 'SELECT * FROM t WHERE a = %s', null ) );
	}

	public function test_null_argument_for_percent_d_becomes_zero(): void {
		$this->assertSame( 'SELECT * FROM t WHERE id = 0', $this->wpdb->prepare( 'SELECT * FROM t WHERE id = %d', null ) );
	}

	/**
	 * Real wpdb::prepare() also accepts a single array argument as an
	 * alternative to the variadic calling convention -- this codebase
	 * never actually calls prepare() that way, but the stub should not
	 * misbehave if something did.
	 */
	public function test_a_single_array_argument_is_unpacked_the_same_as_variadic_arguments(): void {
		$this->assertSame(
			$this->wpdb->prepare( 'SELECT * FROM t WHERE a = %s AND b = %d', 'x', 5 ),
			$this->wpdb->prepare( 'SELECT * FROM t WHERE a = %s AND b = %d', array( 'x', 5 ) )
		);
	}
}
