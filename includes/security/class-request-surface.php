<?php
/**
 * Shared request-classification helpers for anything that behaves
 * differently per site surface (frontend/admin/login/api) or needs to
 * recognise Conflict_Detector's internal probe request.
 *
 * Split out of Header_Builder so Content_Rewriter (body-rewriting
 * components like reverse-tabnabbing and dependency governance) can reuse
 * the exact same surface detection without extending a header-emission
 * class it has nothing to do with.
 */

declare( strict_types=1 );

namespace WP_SAM\Security;

use WP_SAM\Intelligence\Surface_Classifier;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

abstract class Request_Surface {

	/**
	 * HTTP header name Conflict_Detector's internal probe sends, and this
	 * class checks the corresponding $_SERVER key for, to recognise and
	 * suppress the plugin's own CSP output during that one request. Defined
	 * once and referenced by both sides so they can never silently drift
	 * apart again -- they already did once (the outgoing probe header was
	 * never updated during the WP_CSP -> WP_SAM rename while this check
	 * was), which meant the suppression never actually triggered and every
	 * probe misreported this plugin's own live CSP header as a "competing"
	 * header from another plugin or the web server.
	 */
	public const CONFLICT_PROBE_HEADER = 'X-WP-SAM-Probe';

	/**
	 * Conflict_Detector issues an internal request carrying CONFLICT_PROBE_HEADER
	 * to see what security headers other plugins/web-server config are already
	 * sending, without this plugin's own header masking the result.
	 */
	protected function is_conflict_probe_request(): bool {
		return Surface_Classifier::is_conflict_probe_request();
	}

	// ── Surface detection ─────────────────────────────────────────────────────

	protected function detect_surface(): string {
		return Surface_Classifier::detect();
	}

	protected function get_request_path(): string {
		return Surface_Classifier::request_path();
	}
}
