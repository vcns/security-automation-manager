<?php
/**
 * Saving and removing this plugin's version of a well-known file, for
 * Admin_UI's handlers on Control → Traffic Controls → Network Intelligence
 * → Well-Known Files.
 *
 * After a save it fetches the file from the site the way a visitor would
 * and records whether the saved version is what comes back: a real file
 * in the site's folder, a page cache, or a web server that never passes
 * the path to WordPress can each answer first. Both a save and a removal
 * then refresh that file's *_Store, so the Well-Known Files table shows
 * the new contents straight away rather than after the next daily fetch.
 *
 * MTA-STS.txt is fetched from its policy address on mta-sts.<domain>,
 * the way mail servers fetch it (Mta_Sts_Policy::fetch()): following a
 * redirect there would report a policy as served that no mail server
 * would ever accept.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Well_Known_File_Editor {

	private Well_Known_File_Store $store;

	/** @var callable(string):(array|\WP_Error) */
	private $http_get;

	/** @var callable(string):(array|\WP_Error) Fetches the MTA-STS policy address. */
	private $policy_get;

	/** @var callable(string):void Refreshes the named file's *_Store reading. */
	private $refresh;

	/**
	 * @param callable(string):(array|\WP_Error)|null $http_get   Same_Host_Fetcher by default; injectable so tests make no HTTP call.
	 * @param callable(string):void|null              $refresh    Each file's own *_Store::refresh() by default.
	 * @param callable(string):(array|\WP_Error)|null $policy_get Mta_Sts_Policy::fetch() by default, or $http_get when only that is injected.
	 */
	public function __construct( ?Well_Known_File_Store $store = null, ?callable $http_get = null, ?callable $refresh = null, ?callable $policy_get = null ) {
		$this->store      = $store ?? new Well_Known_File_Store();
		$this->http_get   = $http_get ?? static fn ( string $url ) => ( new Same_Host_Fetcher() )->get(
			$url,
			array(
				'timeout'    => 10,
				'sslverify'  => true,
				'user-agent' => 'WordPress/' . get_bloginfo( 'version' ) . '; VCNS-Security-Automation-Manager/' . WP_SAM_VERSION . '; ' . get_bloginfo( 'url' ),
			)
		);
		$this->refresh    = $refresh ?? array( self::class, 'refresh_store' );
		$this->policy_get = $policy_get ?? ( null !== $http_get ? $http_get : array( Mta_Sts_Policy::class, 'fetch' ) );
	}

	/**
	 * @return array{saved:bool, problems:array<int,string>, content:string, check:string}
	 *         content is the sanitised text, also when it wasn't saved.
	 */
	public function save( string $key, string $raw, int $user_id ): array {
		$content  = Well_Known_File_Catalog::sanitize( $raw );
		$problems = Well_Known_File_Catalog::problems( $key, $content );
		if ( ! empty( $problems ) ) {
			return array(
				'saved'    => false,
				'problems' => $problems,
				'content'  => $content,
				'check'    => '',
			);
		}

		$this->store->save( $key, $content, $user_id );
		$check = $this->check( $key, $content );
		$this->store->record_check( $key, $check );
		( $this->refresh )( $key );

		return array(
			'saved'    => true,
			'problems' => array(),
			'content'  => $content,
			'check'    => $check,
		);
	}

	public function remove( string $key ): void {
		$this->store->remove( $key );
		( $this->refresh )( $key );
	}

	/**
	 * What the site serves at this file's address right now, or null when
	 * it serves nothing (or couldn't be fetched). Used to open the editor
	 * on a file this plugin isn't serving yet.
	 */
	public function live_content( string $key ): ?string {
		$response = $this->fetch( $key );
		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return null;
		}
		$content = Well_Known_File_Catalog::sanitize( (string) wp_remote_retrieve_body( $response ) );
		return '' === $content ? null : $content;
	}

	/** One of Well_Known_File_Store's CHECK_* values. */
	private function check( string $key, string $content ): string {
		$response = $this->fetch( $key );
		if ( is_wp_error( $response ) ) {
			return Well_Known_File_Store::CHECK_UNREACHABLE;
		}
		if ( 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return Well_Known_File_Store::CHECK_NOT_SERVED;
		}
		if ( 'mta-sts' === $key && null !== Mta_Sts_Policy::unusable_reason( $response ) ) {
			return Well_Known_File_Store::CHECK_NOT_SERVED;
		}

		return Well_Known_File_Catalog::sanitize( (string) wp_remote_retrieve_body( $response ) ) === $content
			? Well_Known_File_Store::CHECK_SERVED
			: Well_Known_File_Store::CHECK_NOT_SERVED;
	}

	private function fetch( string $key ): array|\WP_Error {
		$get = 'mta-sts' === $key ? $this->policy_get : $this->http_get;
		return $get( Well_Known_File_Catalog::url( $key ) );
	}

	public static function refresh_store( string $key ): void {
		switch ( $key ) {
			case 'robots':
				( new Robots_Rules_Store() )->refresh();
				break;
			case 'agents':
				( new Agents_Rules_Store() )->refresh();
				break;
			case 'security':
				( new Security_Txt_Store() )->refresh();
				break;
			case 'humans':
				( new Humans_Txt_Store() )->refresh();
				break;
			case 'ads':
				( new Ads_Txt_Store() )->refresh();
				break;
			case 'app-ads':
				( new App_Ads_Txt_Store() )->refresh();
				break;
			case 'mta-sts':
				( new Mta_Sts_Txt_Store() )->refresh();
				break;
		}
	}
}
