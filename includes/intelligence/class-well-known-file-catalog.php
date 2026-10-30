<?php
/**
 * The six well-known files listed on Control → Traffic Controls → Network
 * Intelligence → Well-Known Files: where each is served, what it is for,
 * the starter templates its editor offers, and the checks a version must
 * pass before this plugin will serve it.
 *
 * A template only fills the editor's text box. Nothing reaches visitors
 * until an administrator saves (Well_Known_File_Editor), and then only
 * through WordPress itself (Well_Known_File_Server) -- this plugin never
 * writes a file into the site's folder.
 */

declare( strict_types=1 );

namespace WP_SAM\Intelligence;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

final class Well_Known_File_Catalog {

	/** Far larger than any of these files needs; keeps a pasted mistake out of the options table. */
	public const MAX_BYTES = 65536;

	/** Stand-in publisher ID in the Google ads.txt/app-ads.txt templates. Saving refuses it. */
	public const PLACEHOLDER_PUBLISHER_ID = 'pub-0000000000000000';

	/**
	 * Robots.txt tokens of crawlers that collect content to train AI
	 * models, each documented by its operator. Search crawlers (Googlebot,
	 * Bingbot, OAI-SearchBot, PerplexityBot) are left out on purpose:
	 * blocking them takes the site out of search results.
	 */
	private const AI_TRAINING_CRAWLERS = array( 'GPTBot', 'ClaudeBot', 'CCBot', 'Google-Extended', 'Applebot-Extended', 'meta-externalagent' );

	/**
	 * SEO plugins that add to or replace robots.txt themselves, keyed by
	 * the version constant each defines. A version saved here replaces
	 * theirs, so the editor names the plugin before anyone saves.
	 */
	private const ROBOTS_TXT_WRITERS = array(
		'WPSEO_VERSION'             => 'Yoast SEO',
		'RANK_MATH_VERSION'         => 'Rank Math',
		'AIOSEO_VERSION'            => 'All in One SEO',
		'SEOPRESS_VERSION'          => 'SEOPress',
		'THE_SEO_FRAMEWORK_VERSION' => 'The SEO Framework',
	);

	/** Problems listed per save; the rest would only bury the first ones. */
	private const MAX_PROBLEMS = 5;

	/** @return array<string, array{label:string, paths:array<int,string>, purpose:string}> */
	public static function files(): array {
		return array(
			'robots'   => array(
				'label'   => __( 'Robots.txt', 'vcns-security-automation-manager' ),
				'paths'   => array( '/robots.txt' ),
				'purpose' => __( 'Tells search engines and other crawlers which parts of the site to stay out of. Well-behaved crawlers follow it; it does not stop anyone else.', 'vcns-security-automation-manager' ),
			),
			'agents'   => array(
				'label'   => __( 'Agents.txt', 'vcns-security-automation-manager' ),
				'paths'   => array( '/agents.txt' ),
				'purpose' => __( 'An emerging convention for telling AI agents what they may access, written the same way as robots.txt. Only some agents read it so far.', 'vcns-security-automation-manager' ),
			),
			'security' => array(
				'label'   => __( 'Security.txt', 'vcns-security-automation-manager' ),
				'paths'   => array( '/.well-known/security.txt', '/security.txt' ),
				'purpose' => __( 'Tells security researchers how to report a vulnerability they find on this site (RFC 9116). Everything in it is public.', 'vcns-security-automation-manager' ),
			),
			'humans'   => array(
				'label'   => __( 'Humans.txt', 'vcns-security-automation-manager' ),
				'paths'   => array( '/humans.txt' ),
				'purpose' => __( 'An informal credits page in plain text: who made the site and what it runs on. Entirely optional.', 'vcns-security-automation-manager' ),
			),
			'ads'      => array(
				'label'   => __( 'Ads.txt', 'vcns-security-automation-manager' ),
				'paths'   => array( '/ads.txt' ),
				'purpose' => __( 'Lists the companies allowed to sell ad space on this site, so advertisers can refuse anyone else (IAB ads.txt). Only needed if the site shows ads.', 'vcns-security-automation-manager' ),
			),
			'app-ads'  => array(
				'label'   => __( 'App-Ads.txt', 'vcns-security-automation-manager' ),
				'paths'   => array( '/app-ads.txt' ),
				'purpose' => __( 'The ads.txt list for mobile apps whose app store listing names this site as the developer website. Only needed if you publish apps with ads.', 'vcns-security-automation-manager' ),
			),
		);
	}

	public static function has( string $key ): bool {
		return isset( self::files()[ $key ] );
	}

	/** The address visitors use for this file -- its first path, on this site. */
	public static function url( string $key ): string {
		return home_url( self::files()[ $key ]['paths'][0] ?? '/' );
	}

	/** Which file a request path asks for, or null when it isn't one of them. */
	public static function key_for_path( string $path ): ?string {
		foreach ( self::files() as $key => $file ) {
			if ( in_array( $path, $file['paths'], true ) ) {
				return $key;
			}
		}
		return null;
	}

	/**
	 * Well-known files belong at the root of a domain. A site whose
	 * address has a path (example.com/blog) doesn't own that root, so
	 * nothing it serves would be read.
	 */
	public static function serves_from_root(): bool {
		$path = (string) wp_parse_url( home_url(), PHP_URL_PATH );
		return '' === trim( $path, '/' );
	}

	/** Name of an active SEO plugin that also writes robots.txt, or null. */
	public static function robots_txt_writer(): ?string {
		$writer = null;
		foreach ( self::ROBOTS_TXT_WRITERS as $constant => $name ) {
			if ( defined( $constant ) ) {
				$writer = $name;
				break;
			}
		}
		$writer = apply_filters( 'wp_sam_robots_txt_writer', $writer );
		return is_string( $writer ) && '' !== $writer ? $writer : null;
	}

	/**
	 * Paths of this file that exist as real files in the site's folder.
	 * The web server sends those before WordPress runs, so a version saved
	 * here never reaches visitors while one exists.
	 *
	 * @return array<int, string>
	 */
	public static function files_on_disk( string $key ): array {
		$root  = function_exists( 'get_home_path' ) ? get_home_path() : ABSPATH;
		$found = array();
		foreach ( self::files()[ $key ]['paths'] ?? array() as $path ) {
			if ( is_file( rtrim( $root, '/\\' ) . $path ) ) {
				$found[] = $path;
			}
		}
		return $found;
	}

	/**
	 * Starter versions for the editor, built from this site's own details.
	 * The first is the one a missing file's editor opens with.
	 *
	 * @return array<string, array{label:string, description:string, content:string}>
	 */
	public static function templates( string $key ): array {
		switch ( $key ) {
			case 'robots':
				return self::robots_templates();
			case 'agents':
				return self::agents_templates();
			case 'security':
				return self::security_templates();
			case 'humans':
				return self::humans_templates();
			case 'ads':
				return self::ads_templates( __( 'Google AdSense', 'vcns-security-automation-manager' ), __( 'The line Google asks AdSense publishers to add. Replace the publisher ID with yours (AdSense → Account → Account information) before saving.', 'vcns-security-automation-manager' ) );
			case 'app-ads':
				return self::ads_templates( __( 'Google AdMob', 'vcns-security-automation-manager' ), __( 'The line Google asks AdMob publishers to add. Replace the publisher ID with yours (AdMob → Settings → Account information) before saving.', 'vcns-security-automation-manager' ) );
		}
		return array();
	}

	/**
	 * Normalises submitted text the way it is stored and served: Unix line
	 * endings, no byte-order mark or control characters, no leading blank
	 * lines, exactly one trailing newline. Returns '' for blank input.
	 */
	public static function sanitize( string $raw ): string {
		$text = str_replace( array( "\r\n", "\r" ), "\n", $raw );
		if ( str_starts_with( $text, "\xEF\xBB\xBF" ) ) {
			$text = substr( $text, 3 );
		}
		$text = (string) preg_replace( '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $text );
		$text = rtrim( ltrim( $text, "\n" ) );
		return '' === $text ? '' : $text . "\n";
	}

	/**
	 * Why this (already sanitised) version can't be served, or an empty
	 * array when it can. Covers what would make the file wrong for every
	 * reader, not style: a robots.txt line that isn't a rule, a
	 * security.txt without the two fields RFC 9116 requires, an ads.txt
	 * line that isn't a seller record.
	 *
	 * @return array<int, string>
	 */
	public static function problems( string $key, string $content ): array {
		if ( '' === $content ) {
			return array( __( 'The file is empty. Enter its contents, or use Stop serving to remove this plugin\'s version.', 'vcns-security-automation-manager' ) );
		}
		if ( strlen( $content ) > self::MAX_BYTES ) {
			return array( __( 'The file is larger than 64 KB.', 'vcns-security-automation-manager' ) );
		}
		if ( 1 !== preg_match( '//u', $content ) ) {
			return array( __( 'The file contains characters that aren\'t valid UTF-8 text.', 'vcns-security-automation-manager' ) );
		}

		switch ( $key ) {
			case 'robots':
			case 'agents':
				$problems = self::robots_problems( $content );
				break;
			case 'security':
				$problems = self::security_problems( $content );
				break;
			case 'ads':
			case 'app-ads':
				$problems = self::ads_problems( $content );
				break;
			default:
				$problems = array();
		}

		return array_slice( $problems, 0, self::MAX_PROBLEMS );
	}

	// ── Templates ─────────────────────────────────────────────────────────────

	/** @return array<string, array{label:string, description:string, content:string}> */
	private static function robots_templates(): array {
		$default = self::wordpress_default_robots_rules();
		$sitemap = self::core_sitemap_url();
		$sitemap = '' !== $sitemap ? "\nSitemap: {$sitemap}\n" : '';

		$ai_block = "\n# Crawlers that collect content to train AI models. Search engines are not affected.\n";
		foreach ( self::AI_TRAINING_CRAWLERS as $token ) {
			$ai_block .= "User-agent: {$token}\n";
		}
		$ai_block .= "Disallow: /\n";

		return array(
			'wordpress-default' => array(
				'label'       => __( 'WordPress default', 'vcns-security-automation-manager' ),
				'description' => __( 'What WordPress serves out of the box: everything open to crawlers except the admin area.', 'vcns-security-automation-manager' ),
				'content'     => $default . $sitemap,
			),
			'block-ai-training' => array(
				'label'       => __( 'Block AI training crawlers', 'vcns-security-automation-manager' ),
				'description' => sprintf(
					/* translators: %s: comma-separated crawler names, e.g. "GPTBot, ClaudeBot". */
					__( 'The WordPress default, plus a rule asking %s to stay out. Search engines can still index the site.', 'vcns-security-automation-manager' ),
					implode( ', ', self::AI_TRAINING_CRAWLERS )
				),
				'content'     => $default . $ai_block . $sitemap,
			),
		);
	}

	/** @return array<string, array{label:string, description:string, content:string}> */
	private static function agents_templates(): array {
		$admin_path = (string) wp_parse_url( admin_url(), PHP_URL_PATH );
		$login_path = (string) wp_parse_url( wp_login_url(), PHP_URL_PATH );

		return array(
			'keep-out-of-admin' => array(
				'label'       => __( 'Keep agents out of the admin area', 'vcns-security-automation-manager' ),
				'description' => __( 'AI agents may read the site but are asked not to open the admin area or the login page.', 'vcns-security-automation-manager' ),
				'content'     => "User-agent: *\nDisallow: {$admin_path}\nDisallow: {$login_path}\n",
			),
			'block-all'         => array(
				'label'       => __( 'Block all AI agents', 'vcns-security-automation-manager' ),
				'description' => __( 'Asks every AI agent that reads agents.txt to stay off the whole site.', 'vcns-security-automation-manager' ),
				'content'     => "User-agent: *\nDisallow: /\n",
			),
		);
	}

	/** @return array<string, array{label:string, description:string, content:string}> */
	private static function security_templates(): array {
		$email = (string) get_option( 'admin_email', '' );
		if ( '' === $email ) {
			$email = 'security@' . (string) wp_parse_url( home_url(), PHP_URL_HOST );
		}
		$locale   = function_exists( 'get_locale' ) ? (string) get_locale() : 'en_US';
		$language = strtolower( (string) strtok( $locale, '_' ) );
		$expires  = gmdate( 'Y-m-d\TH:i:s\Z', time() + 364 * DAY_IN_SECONDS );

		return array(
			'rfc9116' => array(
				'label'       => __( 'Standard (RFC 9116)', 'vcns-security-automation-manager' ),
				'description' => __( 'The site\'s admin email as the contact, expiring in just under a year (the RFC recommends less than a year). Change the contact if that inbox shouldn\'t be public.', 'vcns-security-automation-manager' ),
				'content'     => "Contact: mailto:{$email}\nExpires: {$expires}\nPreferred-Languages: {$language}\nCanonical: " . home_url( '/.well-known/security.txt' ) . "\n",
			),
		);
	}

	/** @return array<string, array{label:string, description:string, content:string}> */
	private static function humans_templates(): array {
		$name = (string) get_bloginfo( 'name' );
		if ( '' === $name ) {
			$name = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		}

		return array(
			'credits' => array(
				'label'       => __( 'Credits', 'vcns-security-automation-manager' ),
				'description' => __( 'The site\'s name and address, with room to add the people who built it.', 'vcns-security-automation-manager' ),
				'content'     => "/* TEAM */\nSite: {$name}\nContact: " . home_url( '/' ) . "\n\n/* SITE */\nLast update: " . gmdate( 'Y/m/d' ) . "\nSoftware: WordPress\n",
			),
		);
	}

	/** @return array<string, array{label:string, description:string, content:string}> */
	private static function ads_templates( string $google_label, string $google_description ): array {
		return array(
			'google' => array(
				'label'       => $google_label,
				'description' => $google_description,
				'content'     => '# Replace ' . self::PLACEHOLDER_PUBLISHER_ID . " with your own publisher ID.\ngoogle.com, " . self::PLACEHOLDER_PUBLISHER_ID . ", DIRECT, f08c47fec0942fa0\n",
			),
			// IAB ads.txt 1.1 §3.2.1: a file that authorises no sellers.
			'no-ads' => array(
				'label'       => __( 'No ads sold here', 'vcns-security-automation-manager' ),
				'description' => __( 'States that nobody is authorised to sell ad space here, so ad networks reject anyone who claims to.', 'vcns-security-automation-manager' ),
				'content'     => "# Nobody is authorised to sell ad space on this site.\nplaceholder.example.com, placeholder, DIRECT, placeholder\n",
			),
		);
	}

	/** The rules WordPress core's do_robots() writes, built the same way. */
	private static function wordpress_default_robots_rules(): string {
		return "User-agent: *\nDisallow: " . wp_parse_url( admin_url(), PHP_URL_PATH ) . "\nAllow: " . wp_parse_url( admin_url( 'admin-ajax.php' ), PHP_URL_PATH ) . "\n";
	}

	/** WordPress core's sitemap index, or '' when core sitemaps are off (an SEO plugin often turns them off). */
	private static function core_sitemap_url(): string {
		if ( ! function_exists( 'wp_sitemaps_get_server' ) || ! function_exists( 'get_sitemap_url' ) ) {
			return '';
		}
		if ( ! wp_sitemaps_get_server()->sitemaps_enabled() ) {
			return '';
		}
		$url = get_sitemap_url( 'index' );
		return is_string( $url ) ? $url : '';
	}

	// ── Checks ────────────────────────────────────────────────────────────────

	/**
	 * Robots.txt syntax (RFC 9309), which agents.txt shares: every line is
	 * "Field: value", and Allow/Disallow belong to a User-agent group.
	 *
	 * @return array<int, string>
	 */
	private static function robots_problems( string $content ): array {
		$problems   = array();
		$in_group   = false;
		$line_count = 0;

		foreach ( explode( "\n", $content ) as $line ) {
			++$line_count;
			$line = trim( (string) preg_replace( '/#.*$/', '', $line ) );
			if ( '' === $line ) {
				continue;
			}
			if ( 1 !== preg_match( '/^([A-Za-z-]+)\s*:/', $line, $matches ) ) {
				/* translators: 1: line number, 2: the line's text. */
				$problems[] = sprintf( __( 'Line %1$d isn\'t a "Field: value" rule: %2$s', 'vcns-security-automation-manager' ), $line_count, $line );
				continue;
			}
			$field = strtolower( $matches[1] );
			if ( 'user-agent' === $field ) {
				$in_group = true;
			} elseif ( in_array( $field, array( 'allow', 'disallow' ), true ) && ! $in_group ) {
				/* translators: %d: line number. */
				$problems[] = sprintf( __( 'Line %d: Allow and Disallow rules must come after a User-agent line.', 'vcns-security-automation-manager' ), $line_count );
			}
		}

		return $problems;
	}

	/**
	 * RFC 9116's two required fields: at least one Contact (a mailto:,
	 * https:// or tel: URI) and exactly one Expires, still in the future.
	 *
	 * @return array<int, string>
	 */
	private static function security_problems( string $content ): array {
		$problems = array();
		$contacts = 0;
		$expires  = array();

		foreach ( explode( "\n", $content ) as $index => $line ) {
			$line = trim( $line );
			if ( 1 !== preg_match( '/^([A-Za-z-]+):\s*(.+)$/', $line, $matches ) ) {
				continue;
			}
			$field = strtolower( $matches[1] );
			$value = trim( $matches[2] );
			if ( 'contact' === $field ) {
				++$contacts;
				if ( 1 !== preg_match( '#^(mailto:|https://|tel:)#i', $value ) ) {
					/* translators: %d: line number. */
					$problems[] = sprintf( __( 'Line %d: Contact must start with mailto:, https:// or tel:.', 'vcns-security-automation-manager' ), $index + 1 );
				}
			} elseif ( 'expires' === $field ) {
				$expires[] = $value;
			}
		}

		if ( 0 === $contacts ) {
			$problems[] = __( 'security.txt needs at least one Contact line, such as Contact: mailto:security@example.com.', 'vcns-security-automation-manager' );
		}
		if ( 1 !== count( $expires ) ) {
			$problems[] = __( 'security.txt needs exactly one Expires line, such as Expires: 2027-01-01T00:00:00Z.', 'vcns-security-automation-manager' );
		} else {
			$timestamp = strtotime( $expires[0] );
			if ( false === $timestamp ) {
				$problems[] = __( 'Expires isn\'t a date and time like 2027-01-01T00:00:00Z.', 'vcns-security-automation-manager' );
			} elseif ( $timestamp <= time() ) {
				$problems[] = __( 'Expires is in the past. Set a date less than a year ahead.', 'vcns-security-automation-manager' );
			}
		}

		return $problems;
	}

	/**
	 * IAB ads.txt 1.1 records (domain, account ID, DIRECT or RESELLER,
	 * optional certification ID) and variables (CONTACT=, OWNERDOMAIN=, ...).
	 *
	 * @return array<int, string>
	 */
	private static function ads_problems( string $content ): array {
		$problems = array();

		foreach ( explode( "\n", $content ) as $index => $line ) {
			$line = trim( (string) preg_replace( '/#.*$/', '', $line ) );
			if ( '' === $line ) {
				continue;
			}
			if ( str_contains( $line, self::PLACEHOLDER_PUBLISHER_ID ) ) {
				/* translators: 1: line number, 2: the placeholder publisher ID. */
				$problems[] = sprintf( __( 'Line %1$d: replace %2$s with your own publisher ID.', 'vcns-security-automation-manager' ), $index + 1, self::PLACEHOLDER_PUBLISHER_ID );
				continue;
			}
			if ( ! str_contains( $line, ',' ) && 1 === preg_match( '/^[A-Za-z]+\s*=/', $line ) ) {
				continue; // A variable such as CONTACT= or OWNERDOMAIN=.
			}
			$fields = array_map( 'trim', explode( ',', $line ) );
			if ( count( $fields ) < 3 || '' === $fields[0] || '' === $fields[1] || ! in_array( strtoupper( $fields[2] ), array( 'DIRECT', 'RESELLER' ), true ) ) {
				/* translators: 1: line number, 2: the line's text. */
				$problems[] = sprintf( __( 'Line %1$d isn\'t a seller record (domain, account ID, DIRECT or RESELLER): %2$s', 'vcns-security-automation-manager' ), $index + 1, $line );
			}
		}

		return $problems;
	}
}
