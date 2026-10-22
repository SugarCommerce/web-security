<?php
/**
 * A one-shot message that survives a redirect.
 *
 * @package SugarCommerce\WebSecurity
 */

declare( strict_types=1 );

namespace SugarCommerce\WebSecurity;

/**
 * Class Flash
 *
 * Post, redirect, get: the form handler does its work and redirects, and the
 * page it redirects to says how it went. The message has to cross the
 * redirect somehow, and a `?saved=1` in the URL is one anybody can type, link
 * to and bookmark — "Payment refunded" on a page that refunded nothing.
 *
 * So it travels as a cookie, signed. The signature is an HMAC under a key
 * derived from the secret with its own HKDF context, never the secret itself,
 * for the reason Csrf gives: an application hands the same secret to
 * everything, and a construction keyed with the bare secret over a value
 * somebody else can influence is an oracle for every other one. The expiry is
 * inside what is signed, so a captured cookie stops working when it would
 * have expired, whatever the browser holding it was told.
 *
 * take() clears the cookie whenever one was sent — good, forged or broken —
 * so a message shows once, and a bad cookie does not sit there being
 * rejected on every page.
 *
 * Nothing here depends on a request or response object. The cookie is sent
 * with header(), and cookie_header() and clear_header() give the same lines
 * unsent, for tests and for a Response that carries its own headers.
 *
 * @since 1.5.0
 */
final readonly class Flash {

	/**
	 * HKDF context the signing key is derived under.
	 */
	private const string KDF_CONTEXT = 'web-security/flash/v1';

	/**
	 * Longest message kept, in characters.
	 */
	public const int MAX_LENGTH = 200;

	/**
	 * What a cookie name may be: an RFC 9110 token.
	 */
	private const string TOKEN = '/^[A-Za-z0-9!#$%&\'*+\-.^_`|~]+$/D';

	/**
	 * The key messages are signed with, or '' when there is no secret.
	 */
	private string $key;

	/**
	 * The kinds a message may be, the first being the fallback.
	 *
	 * @var non-empty-list<non-empty-string>
	 */
	private array $kinds;

	/**
	 * @since 1.5.0
	 *
	 * @param string        $secret   Signing secret. The application's general
	 *                                token secret is right; it is never used
	 *                                as the key directly. '' means no message
	 *                                is ever set or accepted.
	 * @param string        $cookie   Cookie name.
	 * @param string        $path     Path the cookie is set at. Must start
	 *                                with `/`.
	 * @param int           $lifetime Seconds a message lasts. Long enough to
	 *                                follow a redirect, and no longer.
	 * @param array<string> $kinds    The kinds a message may be — `ok` and
	 *                                `err`, by default. The first is what an
	 *                                unknown kind becomes.
	 *
	 * @throws \InvalidArgumentException When the cookie name is not a token,
	 *                                   the path is not one, the lifetime is
	 *                                   under a second, or there are no kinds.
	 */
	public function __construct(
		#[\SensitiveParameter]
		string $secret,
		private string $cookie = 'flash',
		private string $path = '/',
		private int $lifetime = 30,
		array $kinds = array( 'ok', 'err' ),
	) {
		if ( 1 !== preg_match( self::TOKEN, $cookie ) ) {
			throw new \InvalidArgumentException( 'Invalid cookie name: ' . json_encode( $cookie ) );
		}

		// A separator or a control character in the path would add
		// attributes, or a header, of its own.
		if ( ! str_starts_with( $path, '/' ) || 1 === preg_match( '/[\x00-\x20\x7F;,]/', $path ) ) {
			throw new \InvalidArgumentException( 'Invalid cookie path: ' . json_encode( $path ) );
		}

		if ( $lifetime < 1 ) {
			throw new \InvalidArgumentException( 'A flash message has to last at least a second.' );
		}

		$kinds = array_values( array_unique( array_filter( $kinds, static fn( string $kind ): bool => '' !== $kind ) ) );

		if ( array() === $kinds ) {
			throw new \InvalidArgumentException( 'A flash message needs at least one kind.' );
		}

		$this->kinds = $kinds;
		$this->key   = '' === $secret ? '' : hash_hkdf( 'sha256', $secret, 32, self::KDF_CONTEXT );
	}

	/**
	 * Keep the key out of `var_dump()` and `print_r()`.
	 *
	 * @since 1.5.0
	 *
	 * @return array{key: string, cookie: string, path: string, lifetime: int, kinds: list<string>}
	 */
	public function __debugInfo(): array {
		return array(
			'key'      => '[redacted]',
			'cookie'   => $this->cookie,
			'path'     => $this->path,
			'lifetime' => $this->lifetime,
			'kinds'    => $this->kinds,
		);
	}

	/**
	 * Leave a message for the next page.
	 *
	 * ```php
	 * $flash->set( 'ok', 'Refund sent.', $request->is_https( $proxies ) );
	 *
	 * return Response::redirect( '/orders/7', 303 );
	 * ```
	 *
	 * Nothing is sent when there is no secret.
	 *
	 * @since 1.5.0
	 *
	 * @param string $kind    One of the kinds; anything else becomes the
	 *                        first.
	 * @param string $message Plain text. Line breaks become spaces, control
	 *                        characters are removed, and it is cut to
	 *                        MAX_LENGTH characters. Escape it when printing:
	 *                        it is signed, not safe.
	 * @param bool   $secure  Whether the request arrived over TLS. A Secure
	 *                        cookie on a plain-HTTP development host is
	 *                        dropped without a word.
	 *
	 * @return void
	 */
	public function set( string $kind, string $message, bool $secure ): void {
		$header = $this->cookie_header( $kind, $message, $secure );

		if ( '' !== $header ) {
			header( 'Set-Cookie: ' . $header, false );
		}
	}

	/**
	 * The Set-Cookie value set() sends, without sending it.
	 *
	 * @since 1.5.0
	 *
	 * @param string $kind    As set().
	 * @param string $message As set().
	 * @param bool   $secure  As set().
	 *
	 * @return string '' when there is no secret to sign with.
	 */
	public function cookie_header( string $kind, string $message, bool $secure ): string {
		if ( '' === $this->key ) {
			return '';
		}

		$expires = time() + $this->lifetime;
		$payload = self::base64url( (string) json_encode(
			array( in_array( $kind, $this->kinds, true ) ? $kind : $this->kinds[0], self::clean( $message ), $expires ),
			JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE
		) );

		return $this->line( $payload . '.' . $this->sign( $payload ), $expires, $secure );
	}

	/**
	 * The message the previous page left, once.
	 *
	 * Whenever the cookie was sent at all, it is cleared — whether or not it
	 * was any good — and, when it came from $_COOKIE, removed from there too,
	 * so a second take() in the same request finds nothing either.
	 *
	 * ```php
	 * $flash = $messages->take( secure: $request->is_https( $proxies ) );
	 *
	 * if ( null !== $flash ) {
	 *     printf( '<p class="%s">%s</p>', $flash['kind'], htmlspecialchars( $flash['message'] ) );
	 * }
	 * ```
	 *
	 * @since 1.5.0
	 *
	 * @param array<array-key, mixed>|null $cookies Cookie jar. Defaults to
	 *                                              $_COOKIE; passed
	 *                                              explicitly by tests.
	 * @param bool                         $secure  As set(), for the line that
	 *                                              clears it.
	 *
	 * @return array{kind: string, message: string}|null Null when there was
	 *                                                   none, or it was
	 *                                                   forged, tampered
	 *                                                   with, expired or
	 *                                                   malformed.
	 */
	public function take( ?array $cookies = null, bool $secure = false ): ?array {
		$jar = $cookies ?? $_COOKIE;

		if ( ! array_key_exists( $this->cookie, $jar ) ) {
			return null;
		}

		header( 'Set-Cookie: ' . $this->clear_header( $secure ), false );

		if ( null === $cookies ) {
			unset( $_COOKIE[ $this->cookie ] );
		}

		$value = $jar[ $this->cookie ];

		return is_string( $value ) ? $this->open( $value ) : null;
	}

	/**
	 * The Set-Cookie value that clears the message, without sending it.
	 *
	 * @since 1.5.0
	 *
	 * @param bool $secure As set().
	 *
	 * @return string
	 */
	public function clear_header( bool $secure = false ): string {
		return $this->line( '', 1, $secure );
	}

	/**
	 * A cookie value's message, if this key signed it and it has not
	 * expired.
	 *
	 * @since 1.5.0
	 *
	 * @param string $value The cookie as sent.
	 *
	 * @return array{kind: string, message: string}|null
	 */
	private function open( string $value ): ?array {
		$dot = strrpos( $value, '.' );

		if ( '' === $this->key || false === $dot ) {
			return null;
		}

		$payload = substr( $value, 0, $dot );

		// Constant-time, and before anything in the payload is read: a
		// forged cookie is rejected as forged, not as malformed.
		if ( ! hash_equals( $this->sign( $payload ), substr( $value, $dot + 1 ) ) ) {
			return null;
		}

		$json = base64_decode( strtr( $payload, '-_', '+/' ), true );
		$data = false === $json ? null : json_decode( $json, true );

		if ( ! is_array( $data ) || ! array_is_list( $data ) || 3 !== count( $data ) ) {
			return null;
		}

		[ $kind, $message, $expires ] = $data;

		if ( ! is_string( $kind ) || ! in_array( $kind, $this->kinds, true ) || ! is_string( $message ) || ! is_int( $expires ) || $expires < time() ) {
			return null;
		}

		return array(
			'kind'    => $kind,
			'message' => $message,
		);
	}

	/**
	 * A Set-Cookie value for this cookie.
	 *
	 * @since 1.5.0
	 *
	 * @param string $value   Cookie value. Base64url and a hex signature,
	 *                        so nothing in it needs encoding.
	 * @param int    $expires Unix time it expires.
	 * @param bool   $secure  Whether to mark it Secure.
	 *
	 * @return string
	 */
	private function line( string $value, int $expires, bool $secure ): string {
		return $this->cookie . '=' . $value
			. '; Expires=' . gmdate( 'D, d M Y H:i:s \G\M\T', $expires )
			. '; Max-Age=' . max( 0, $expires - time() )
			. '; Path=' . $this->path
			. ( $secure ? '; Secure' : '' )
			. '; HttpOnly; SameSite=Lax';
	}

	/**
	 * The signature of a payload.
	 *
	 * @since 1.5.0
	 *
	 * @param string $payload Encoded payload.
	 *
	 * @return string Hex HMAC-SHA256.
	 */
	private function sign( string $payload ): string {
		return hash_hmac( 'sha256', $payload, $this->key );
	}

	/**
	 * A message fit to keep: one line, no control characters, MAX_LENGTH
	 * characters at most.
	 *
	 * Counted in characters rather than bytes, so a cut never lands inside
	 * one. Bytes that are not UTF-8 become U+FFFD first; the patterns that
	 * follow need valid UTF-8, and would otherwise fail and lose the lot.
	 *
	 * @since 1.5.0
	 *
	 * @param string $message As given.
	 *
	 * @return string
	 */
	private static function clean( string $message ): string {
		$message = htmlspecialchars_decode( htmlspecialchars( $message, ENT_NOQUOTES | ENT_SUBSTITUTE, 'UTF-8' ), ENT_NOQUOTES );
		$message = (string) preg_replace( '/[\r\n\t]+/', ' ', $message );
		$message = trim( (string) preg_replace( '/\p{Cc}/u', '', $message ) );

		return 1 === preg_match( '/^.{0,' . self::MAX_LENGTH . '}/us', $message, $match ) ? $match[0] : '';
	}

	/**
	 * URL-safe base64 without padding: cookie-safe as it stands.
	 *
	 * @since 1.5.0
	 *
	 * @param string $bytes Raw bytes.
	 *
	 * @return string
	 */
	private static function base64url( string $bytes ): string {
		return rtrim( strtr( base64_encode( $bytes ), '+/', '-_' ), '=' );
	}
}
