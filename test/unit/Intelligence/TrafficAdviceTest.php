<?php
/**
 * Unit tests for WP_SAM\Intelligence\Traffic_Advice and
 * Traffic_Advice_Store: the /.well-known/traffic-advice format, its
 * checks, and the daily reading of what the site serves there.
 */

declare( strict_types=1 );

use PHPUnit\Framework\TestCase;
use WP_SAM\Intelligence\Traffic_Advice;
use WP_SAM\Intelligence\Traffic_Advice_Store;
use WP_SAM\Intelligence\Well_Known_File_Catalog;

class TrafficAdviceTest extends TestCase {

	protected function setUp(): void {
		wp_test_reset_globals();
	}

	private function response( string $body, int $code = 200, string $type = Traffic_Advice::MEDIA_TYPE ): array {
		return array(
			'response' => array( 'code' => $code ),
			'headers'  => array( 'content-type' => $type ),
			'body'     => $body,
		);
	}

	// ── Catalog entry and templates ──────────────────────────────────────────────

	public function test_the_catalog_serves_it_from_the_well_known_path(): void {
		$this->assertSame( 'traffic-advice', Well_Known_File_Catalog::key_for_path( '/.well-known/traffic-advice' ) );
		$this->assertSame( 'https://example.com/.well-known/traffic-advice', Well_Known_File_Catalog::url( 'traffic-advice' ) );
	}

	public function test_the_templates_are_the_two_ways_to_shed_prefetch_traffic(): void {
		$templates = Traffic_Advice::templates();

		$this->assertSame( array( 'disallow', 'reduce' ), array_keys( $templates ) );
		$this->assertSame(
			array( array( 'user_agent' => 'prefetch-proxy', 'disallow' => true ) ),
			json_decode( $templates['disallow']['content'], true )
		);
		$this->assertSame(
			array( array( 'user_agent' => 'prefetch-proxy', 'fraction' => 0.5 ) ),
			json_decode( $templates['reduce']['content'], true )
		);
	}

	// ── problems() ───────────────────────────────────────────────────────────────

	public function test_valid_advice_has_no_problems(): void {
		$this->assertSame( array(), Traffic_Advice::problems( '[{"user_agent": "prefetch-proxy", "disallow": true}, {"user_agent": "*", "fraction": 0.25}]' ) );
		$this->assertSame( array(), Traffic_Advice::problems( '[{"user_agent": "*", "fraction": 1}]' ) );
	}

	public function test_text_that_isnt_json_is_refused(): void {
		$problems = Traffic_Advice::problems( "User-agent: prefetch-proxy\nDisallow: /\n" );

		$this->assertCount( 1, $problems );
		$this->assertStringStartsWith( 'This isn\'t valid JSON', $problems[0] );
	}

	public function test_the_top_level_must_be_a_non_empty_list(): void {
		$this->assertStringContainsString( 'must be a JSON list', Traffic_Advice::problems( '{"user_agent": "prefetch-proxy", "disallow": true}' )[0] );
		$this->assertStringContainsString( 'The list is empty', Traffic_Advice::problems( '[]' )[0] );
	}

	public function test_each_entry_needs_an_object_with_a_user_agent(): void {
		$problems = Traffic_Advice::problems( '["prefetch-proxy", {"disallow": true}]' );

		$this->assertStringContainsString( 'Entry 1 isn\'t an object', $problems[0] );
		$this->assertStringContainsString( 'Entry 2 needs a "user_agent"', $problems[1] );
	}

	public function test_values_proxies_would_ignore_are_refused(): void {
		$problems = implode(
			"\n",
			Traffic_Advice::problems( '[{"user_agent": "a", "disallow": "true"}, {"user_agent": "b", "fraction": "0.5"}, {"user_agent": "c", "fraction": 1.5}]' )
		);

		$this->assertStringContainsString( 'Entry 1: "disallow" must be true or false', $problems );
		$this->assertStringContainsString( 'Entry 2: "fraction" must be a number from 0 to 1', $problems );
		$this->assertStringContainsString( 'Entry 3: "fraction" must be a number from 0 to 1', $problems );
	}

	public function test_typing_mistakes_are_caught(): void {
		$problems = implode(
			"\n",
			Traffic_Advice::problems( '[{"user_agent": "Prefetch-Proxy", "dissallow": true}, {"user_agent": "*", "fraction": 0.5}, {"user_agent": "*", "disallow": true}]' )
		);

		$this->assertStringContainsString( 'proxies don\'t know the field "dissallow"', $problems );
		$this->assertStringContainsString( 'Entry 1: user_agent is case-sensitive', $problems );
		$this->assertStringContainsString( 'Entry 1 gives no advice', $problems );
		$this->assertStringContainsString( 'Entry 3 repeats user_agent "*" from entry 2', $problems );
	}

	public function test_the_catalog_runs_these_checks_on_save(): void {
		$this->assertStringContainsString( 'valid JSON', Well_Known_File_Catalog::problems( 'traffic-advice', "not json\n" )[0] );
	}

	// ── advice_for_prefetch_proxies() ────────────────────────────────────────────

	public function test_prefetch_proxies_take_their_own_entry_before_the_wildcard(): void {
		$advice = Traffic_Advice::advice_for_prefetch_proxies( '[{"user_agent": "*", "disallow": true}, {"user_agent": "prefetch-proxy", "fraction": 0.2}]' );

		$this->assertSame( array( 'user_agent' => 'prefetch-proxy', 'disallow' => false, 'fraction' => 0.2 ), $advice );
	}

	public function test_prefetch_proxies_fall_back_to_the_wildcard_and_ignore_a_bad_fraction(): void {
		$advice = Traffic_Advice::advice_for_prefetch_proxies( '[{"user_agent": "PollyPrefetchProxy", "disallow": true}, {"user_agent": "*", "fraction": "half"}]' );

		$this->assertSame( array( 'user_agent' => '*', 'disallow' => false, 'fraction' => 1.0 ), $advice );
	}

	public function test_no_advice_when_nothing_matches_or_it_isnt_a_list(): void {
		$this->assertNull( Traffic_Advice::advice_for_prefetch_proxies( '[{"user_agent": "PollyPrefetchProxy", "disallow": true}]' ) );
		$this->assertNull( Traffic_Advice::advice_for_prefetch_proxies( '{"user_agent": "*"}' ) );
	}

	public function test_has_media_type_ignores_case_and_parameters(): void {
		$this->assertTrue( Traffic_Advice::has_media_type( $this->response( '[]', 200, 'Application/TrafficAdvice+JSON; charset=utf-8' ) ) );
		$this->assertFalse( Traffic_Advice::has_media_type( $this->response( '[]', 200, 'application/json' ) ) );
	}

	// ── Traffic_Advice_Store ─────────────────────────────────────────────────────

	public function test_store_records_the_advice_and_its_media_type(): void {
		$fetched = array();
		$store   = new Traffic_Advice_Store(
			function ( string $url ) use ( &$fetched ) {
				$fetched[] = $url;
				return $this->response( '[{"user_agent": "prefetch-proxy", "disallow": true}]' );
			}
		);

		$result = $store->refresh();

		$this->assertSame( 'refreshed', $result['status'] );
		$this->assertSame( array( 'https://example.com/.well-known/traffic-advice' ), $fetched );
		$this->assertTrue( $store->is_present() );
		$this->assertTrue( $store->has_media_type() );
		$this->assertTrue( $store->advice()['disallow'] );
	}

	public function test_store_notes_a_file_sent_with_the_wrong_media_type(): void {
		$store = new Traffic_Advice_Store( fn () => $this->response( '[{"user_agent": "*", "disallow": true}]', 200, 'application/octet-stream' ) );

		$store->refresh();

		$this->assertTrue( $store->is_present() );
		$this->assertFalse( $store->has_media_type() );
	}

	public function test_store_treats_404_as_no_file_and_keeps_its_reading_on_failure(): void {
		( new Traffic_Advice_Store( fn () => $this->response( '[{"user_agent": "*", "disallow": true}]' ) ) )->refresh();

		$failed = ( new Traffic_Advice_Store( fn () => $this->response( 'oops', 500 ) ) )->refresh();
		$this->assertSame( 'failed', $failed['status'] );
		$this->assertSame( '[{"user_agent": "*", "disallow": true}]', ( new Traffic_Advice_Store() )->content() );

		$absent = ( new Traffic_Advice_Store( fn () => $this->response( '', 404, 'text/html' ) ) )->refresh();
		$this->assertSame( 'absent', $absent['status'] );
		$this->assertFalse( ( new Traffic_Advice_Store() )->is_present() );
		$this->assertSame( '', ( new Traffic_Advice_Store() )->content() );
	}
}
