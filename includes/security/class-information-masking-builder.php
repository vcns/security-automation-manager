<?php
/**
 * Removes headers that disclose the server stack, PHP version, or this
 * site's own hostname -- GitHub issue #220. No configurable value -- each
 * surface is simply on (all three removals applied) or off, same shape as
 * X_Content_Type_Options_Builder.
 *
 * X-Powered-By (PHP version) and X-Pingback (this site's own xmlrpc.php
 * URL, i.e. its hostname) are set by PHP/WordPress itself, well within
 * header_remove()'s reach -- removal is reliable.
 *
 * Server is a different story: on most hosting configurations it is set
 * by the web server (Apache/Nginx/LiteSpeed) *before* PHP ever runs, at a
 * layer this call cannot reach or override. header_remove('Server') is
 * still attempted -- it costs nothing and does work on some hosts/SAPIs
 * -- but whether it actually took effect on a given install is never
 * assumed here; that's what Information_Masking_Diagnostic's live
 * self-probe is for. A host where it doesn't work needs host-level
 * config instead (Apache ServerTokens/ServerSignature, Nginx
 * server_tokens off;), documented on the admin page rather than promised
 * by this toggle.
 *
 * X-Generator (WordPress core's own version tag) is deliberately out of
 * scope: confirmed live that WordPress emits it as a <generator> element
 * in RSS/Atom feed body content via the the_generator filter, never as an
 * actual HTTP header -- masking body content is a different mechanism
 * entirely and doesn't fit this plugin's header-only architecture (see
 * Referrer_Policy_Builder's own docblock for the same "headers only,
 * never body content" principle applied elsewhere).
 */

declare( strict_types=1 );

namespace WP_SAM\Security;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Information_Masking_Builder extends Pillar_Header_Builder {

	public const PILLAR_KEY = 'information-masking';

	protected function emit_profile_header( array $profile, string $surface ): bool {
		unset( $profile, $surface );
		header_remove( 'X-Powered-By' );
		header_remove( 'Server' );
		header_remove( 'X-Pingback' );
		return true;
	}
}
