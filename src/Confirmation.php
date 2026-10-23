<?php
/**
 * One click to confirm, from this site's own page.
 *
 * @package SugarCommerce\WebSecurity
 */

declare( strict_types=1 );

namespace SugarCommerce\WebSecurity;

/**
 * Class Confirmation
 *
 * A link that does something — signs in, unsubscribes, accepts an invite —
 * is fetched by mail scanners and link previewers before anybody clicks it.
 * So the link opens a page with one button, and only the POST that button
 * makes does the thing. That POST has to be proved to come from the page
 * this site served, not from a form somebody else built pointing here.
 *
 * The page carries a random nonce in the form, and the same nonce goes in a
 * SameSite=Strict, HttpOnly cookie that lasts ten minutes. A browser sends a
 * Strict cookie only on a request from this site's own pages, and no other
 * page can read it to copy into a form — so a POST where the two match came
 * from the page served here, in this browser.
 *
 * ```php
 * // GET: the page the link opens
 * [ 'nonce' => $nonce, 'cookie' => $set_cookie ] = $confirm->start( $secure );
 * // render a form with <input type="hidden" name="nonce" value="$nonce">, send $set_cookie
 *
 * // POST: the button
 * if ( ! $confirm->confirmed( $request->cookies, $request->input( 'nonce' ) ) ) {
 *     // "Open the link again"
 * }
 * ```
 *
 * Pair it with MagicLink::spend_once() on the POST so the link works once.
 *
 * @since 1.7.0
 */
final readonly class Confirmation {

	use ShortCookie;

	/**
	 * @since 1.7.0
	 *
	 * @param string $cookie   Cookie name.
	 * @param string $path     Path it is set at — the narrowest covering the
	 *                         page and its POST.
	 * @param int    $lifetime Seconds the page stays confirmable.
	 *
	 * @throws \InvalidArgumentException When the cookie name is not a token,
	 *                                   the path is not one, or the lifetime
	 *                                   is under a second.
	 */
	public function __construct(
		private string $cookie = 'confirm',
		private string $path = '/',
		private int $lifetime = 600,
	) {
		self::check_cookie( $cookie, $path );

		if ( $lifetime < 1 ) {
			throw new \InvalidArgumentException( 'A confirmation has to last at least a second.' );
		}
	}

	/**
	 * A fresh nonce for the page's form, and the Set-Cookie value carrying it.
	 *
	 * @since 1.7.0
	 *
	 * @param bool $secure Whether the request arrived over TLS.
	 *
	 * @return array{nonce: string, cookie: string}
	 */
	public function start( bool $secure ): array {
		$nonce = bin2hex( random_bytes( 16 ) );

		return array(
			'nonce'  => $nonce,
			'cookie' => $this->line( $nonce, time() + $this->lifetime, $secure, 'Strict' ),
		);
	}

	/**
	 * Whether the posted nonce is the one this browser's cookie holds.
	 *
	 * Constant-time. Both have to be there: a missing cookie (expired, or a
	 * POST from another site, which a Strict cookie does not travel with) or
	 * a missing field is refused.
	 *
	 * @since 1.7.0
	 *
	 * @param array<array-key, mixed> $cookies The request's cookies.
	 * @param string                  $posted  The form's nonce field.
	 *
	 * @return bool
	 */
	#[\NoDiscard( 'False means the confirmation did not come from this page.' )]
	public function confirmed( array $cookies, string $posted ): bool {
		$held = $cookies[ $this->cookie ] ?? '';

		return is_string( $held ) && 1 === preg_match( '/^[0-9a-f]{32}$/D', $held ) && hash_equals( $held, $posted );
	}

	/**
	 * The Set-Cookie value that clears it, once the confirmation is used.
	 *
	 * @since 1.7.0
	 *
	 * @param bool $secure Whether the request arrived over TLS.
	 *
	 * @return string
	 */
	public function clear_header( bool $secure = false ): string {
		return $this->line( '', 1, $secure, 'Strict' );
	}
}
