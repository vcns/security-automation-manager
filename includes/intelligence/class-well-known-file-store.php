<?php
/**
 * The versions of the well-known files an administrator saved on Control
 * → Traffic Controls → Network Intelligence → Well-Known Files, which
 * Well_Known_File_Server then serves.
 *
 * One option holds all six, not autoloaded: the server only reads it once
 * a request's path has already matched one of the files, so ordinary page
 * loads never load it.
 *
 * Separate from the six *_Store classes beside it, which record what the
 * site actually serves (whoever serves it), fetched over HTTP. After a
 * save, Well_Known_File_Editor compares the two and records the outcome
 * here as 'check'.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Well_Known_File_Store {

	public const OPTION = 'wp_sam_well_known_files';

	/** Visitors get the saved version. */
	public const CHECK_SERVED = 'served';

	/** The site answered with something else: a real file, a cache, or the web server. */
	public const CHECK_NOT_SERVED = 'not_served';

	/** The site couldn't be fetched, so what visitors get is unknown. */
	public const CHECK_UNREACHABLE = 'unreachable';

	/** @return array{content:string, saved_at:string, saved_by:int, check:string}|null */
	public function get( string $key ): ?array {
		$entry = $this->all()[ $key ] ?? null;
		if ( ! is_array( $entry ) || ! is_string( $entry['content'] ?? null ) || '' === $entry['content'] ) {
			return null;
		}

		return array(
			'content'  => $entry['content'],
			'saved_at' => (string) ( $entry['saved_at'] ?? '' ),
			'saved_by' => (int) ( $entry['saved_by'] ?? 0 ),
			'check'    => (string) ( $entry['check'] ?? '' ),
		);
	}

	/** The saved version, or null when this plugin isn't serving the file. */
	public function content( string $key ): ?string {
		return $this->get( $key )['content'] ?? null;
	}

	public function save( string $key, string $content, int $user_id ): void {
		$all         = $this->all();
		$all[ $key ] = array(
			'content'  => $content,
			'saved_at' => current_time( 'mysql', true ),
			'saved_by' => $user_id,
			'check'    => '',
		);
		update_option( self::OPTION, $all, false );
	}

	public function record_check( string $key, string $check ): void {
		$all = $this->all();
		if ( ! isset( $all[ $key ] ) || ! is_array( $all[ $key ] ) ) {
			return;
		}
		$all[ $key ]['check'] = $check;
		update_option( self::OPTION, $all, false );
	}

	public function remove( string $key ): void {
		$all = $this->all();
		unset( $all[ $key ] );
		if ( empty( $all ) ) {
			delete_option( self::OPTION );
			return;
		}
		update_option( self::OPTION, $all, false );
	}

	/** @return array<string, mixed> */
	private function all(): array {
		$stored = get_option( self::OPTION, array() );
		return is_array( $stored ) ? $stored : array();
	}
}
