<?php
/**
 * A secret shown once on the page after a redirect.
 *
 * @package SugarCommerce\WebSecurity
 */

declare( strict_types=1 );

namespace SugarCommerce\WebSecurity;

/**
 * Class Reveal
 *
 * "Here is your new API key — copy it now, it will not be shown again."
 * The handler that mints it redirects, and the page it redirects to has to
 * show it once. Putting it in the redirect URL — `?key=…` — writes a live
 * credential into browser history, server and proxy access logs, and the
 * Referer of anything the page loads. {@see Flash} keeps it out of the URL
 * but is signed, not encrypted, and holds one short line.
 *
 * So it travels as an encrypted cookie ({@see Sealer}, under its own
 * context): HttpOnly, SameSite=Lax, a minute by default, read once and
 * cleared whenever it is sent, good or bad. The expiry is inside what is
 * sealed, so a captured cookie stops opening when it would have expired.
 *
 * ```php
 * $reveal->set( array( 'url' => $link, 'customer' => $id ), $secure );
 * return Response::redirect( "/customers/{$id}" );
 *
 * // on that page
 * $shown = $reveal->take( secure: $secure );
 * if ( null !== $shown && $id === $shown['customer'] ) { … }
 * ```
 *
 * Check that what comes back belongs to the page showing it, as above: the
 * cookie is not tied to a URL, only to a path.
 *
 * @since 1.6.0
 */
final readonly class Reveal {

	use ShortCookie;

	/**
	 * Most bytes of JSON one reveal carries. Browsers drop cookies past about
	 * 4 KB with no error; sealing adds a third.
	 */
	public const int MAX_BYTES = 2048;

	/**
	 * Encrypts and opens the cookie, or null when there is no secret.
	 */
	private ?Sealer $sealer;

	/**
	 * @since 1.6.0
	 *
	 * @param string $secret   The application's token secret, at least 32
	 *                         bytes; a key is derived from it. '' means nothing
	 *                         is ever set or accepted.
	 * @param string $cookie   Cookie name.
	 * @param string $path     Path the cookie is set at — the narrowest that
	 *                         covers the page that shows it.
	 * @param int    $lifetime Seconds it lasts. Long enough to follow a
	 *                         redirect, and no longer.
	 *
	 * @throws \InvalidArgumentException When the secret is shorter than 32
	 *                                   bytes, the cookie name is not a
	 *                                   token, the path is not one, or the
	 *                                   lifetime is under a second.
	 */
	public function __construct(
		#[\SensitiveParameter]
		string $secret,
		private string $cookie = 'reveal',
		private string $path = '/',
		private int $lifetime = 60,
	) {
		self::check_cookie( $cookie, $path );

		if ( $lifetime < 1 ) {
			throw new \InvalidArgumentException( 'A reveal has to last at least a second.' );
		}

		$this->sealer = '' === $secret ? null : new Sealer( $secret, 'reveal' );
	}

	/**
	 * Keep the key out of `var_dump()` and `print_r()`.
	 *
	 * @since 1.6.0
	 *
	 * @return array{cookie: string, path: string, lifetime: int}
	 */
	public function __debugInfo(): array {
		return array(
			'cookie'   => $this->cookie,
			'path'     => $this->path,
			'lifetime' => $this->lifetime,
		);
	}

	/**
	 * Leave the values for the next page. Nothing is sent when there is no
	 * secret.
	 *
	 * @since 1.6.0
	 *
	 * @param array<string, mixed> $values What to show: strings, numbers,
	 *                                     booleans, null.
	 * @param bool                 $secure Whether the request arrived over
	 *                                     TLS.
	 *
	 * @return void
	 *
	 * @throws \InvalidArgumentException As cookie_header().
	 */
	public function set( array $values, bool $secure ): void {
		$header = $this->cookie_header( $values, $secure );

		if ( '' !== $header ) {
			header( 'Set-Cookie: ' . $header, false );
		}
	}

	/**
	 * The Set-Cookie value set() sends, without sending it.
	 *
	 * @since 1.6.0
	 *
	 * @param array<string, mixed> $values As set(); anything but a scalar or
	 *                                     null is refused.
	 * @param bool                 $secure As set().
	 *
	 * @return string '' when there is no secret.
	 *
	 * @throws \InvalidArgumentException When a value is not a scalar or
	 *                                   null, or the lot is over MAX_BYTES.
	 */
	public function cookie_header( array $values, bool $secure ): string {
		foreach ( $values as $value ) {
			if ( null !== $value && ! is_scalar( $value ) ) {
				throw new \InvalidArgumentException( 'A reveal holds strings, numbers, booleans and null only.' );
			}
		}

		$expires = time() + $this->lifetime;
		$json    = (string) json_encode( array( $values, $expires ), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE );

		if ( strlen( $json ) > self::MAX_BYTES ) {
			throw new \InvalidArgumentException( 'A reveal is limited to ' . self::MAX_BYTES . ' bytes of JSON.' );
		}

		return null === $this->sealer ? '' : $this->line( $this->sealer->seal( $json ), $expires, $secure );
	}

	/**
	 * The values the previous page left, once.
	 *
	 * @since 1.6.0
	 *
	 * @param array<array-key, mixed>|null $cookies Cookie jar. Defaults to
	 *                                              $_COOKIE.
	 * @param bool                         $secure  As set(), for the line that
	 *                                              clears it.
	 *
	 * @return array<string, scalar|null>|null Null when there was none, or it
	 *                                         was forged, tampered with,
	 *                                         sealed under another secret,
	 *                                         expired or malformed.
	 */
	public function take( ?array $cookies = null, bool $secure = false ): ?array {
		$sealed = $this->take_value( $cookies, $secure );
		$json   = null === $sealed || null === $this->sealer ? null : $this->sealer->open( $sealed );
		$data   = null === $json ? null : json_decode( $json, true );

		if ( ! is_array( $data ) || ! array_is_list( $data ) || 2 !== count( $data ) ) {
			return null;
		}

		[ $values, $expires ] = $data;

		if ( ! is_array( $values ) || ! is_int( $expires ) || $expires < time() ) {
			return null;
		}

		$shown = array();

		foreach ( $values as $key => $value ) {
			if ( ! is_string( $key ) || ( null !== $value && ! is_scalar( $value ) ) ) {
				return null;
			}

			$shown[ $key ] = $value;
		}

		return $shown;
	}

	/**
	 * The Set-Cookie value that clears it, without sending it.
	 *
	 * @since 1.6.0
	 *
	 * @param bool $secure As set().
	 *
	 * @return string
	 */
	public function clear_header( bool $secure = false ): string {
		return $this->line( '', 1, $secure );
	}
}
