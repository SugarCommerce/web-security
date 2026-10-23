<?php
/**
 * The cookie both one-shot handoffs travel in.
 *
 * @package SugarCommerce\WebSecurity
 */

declare( strict_types=1 );

namespace SugarCommerce\WebSecurity;

/**
 * Trait ShortCookie
 *
 * A short-lived, HttpOnly, SameSite cookie that crosses one redirect:
 * the name and path checks, the Set-Cookie line, and the take-and-clear
 * read. {@see Flash}, {@see Reveal} and {@see Confirmation} differ only in
 * what the value holds,
 * so the parts that decide how it is sent live here once.
 *
 * @internal
 *
 * @since 1.6.0
 */
trait ShortCookie {

	/**
	 * Refuse a cookie name or path that would add attributes, or a header,
	 * of its own.
	 *
	 * @since 1.6.0
	 *
	 * @param string $cookie Cookie name: an RFC 9110 token.
	 * @param string $path   Cookie path: starts with `/`, no separators.
	 *
	 * @return void
	 *
	 * @throws \InvalidArgumentException When either is not.
	 */
	private static function check_cookie( string $cookie, string $path ): void {
		if ( 1 !== preg_match( '/^[A-Za-z0-9!#$%&\'*+\-.^_`|~]+$/D', $cookie ) ) {
			throw new \InvalidArgumentException( 'Invalid cookie name: ' . json_encode( $cookie ) );
		}

		// A separator or a control character in the path would add
		// attributes, or a header, of its own.
		if ( ! str_starts_with( $path, '/' ) || 1 === preg_match( '/[\x00-\x20\x7F;,]/', $path ) ) {
			throw new \InvalidArgumentException( 'Invalid cookie path: ' . json_encode( $path ) );
		}
	}

	/**
	 * The cookie's value, once: whenever it was sent at all it is cleared —
	 * good, forged or broken — and, when it came from $_COOKIE, removed from
	 * there too, so a second read in the same request finds nothing.
	 *
	 * @since 1.6.0
	 *
	 * @param array<array-key, mixed>|null $cookies Cookie jar, or null for
	 *                                              $_COOKIE.
	 * @param bool                         $secure  Whether to mark the
	 *                                              clearing line Secure.
	 *
	 * @return string|null Null when it was not sent, or was not a string.
	 */
	private function take_value( ?array $cookies, bool $secure ): ?string {
		$jar = $cookies ?? $_COOKIE;

		if ( ! array_key_exists( $this->cookie, $jar ) ) {
			return null;
		}

		header( 'Set-Cookie: ' . $this->line( '', 1, $secure ), false );

		if ( null === $cookies ) {
			unset( $_COOKIE[ $this->cookie ] );
		}

		$value = $jar[ $this->cookie ];

		return is_string( $value ) ? $value : null;
	}

	/**
	 * A Set-Cookie value for this cookie.
	 *
	 * @since 1.5.0
	 *
	 * @param string $value   Cookie value. Base64url and separators that need
	 *                        no encoding.
	 * @param int    $expires  Unix time it expires.
	 * @param bool   $secure   Whether to mark it Secure.
	 * @param string $samesite Lax, or Strict for a cookie only this site's
	 *                         own pages may send back. Since 1.7.0.
	 *
	 * @return string
	 */
	private function line( string $value, int $expires, bool $secure, string $samesite = 'Lax' ): string {
		return $this->cookie . '=' . $value
			. '; Expires=' . gmdate( 'D, d M Y H:i:s \G\M\T', $expires )
			. '; Max-Age=' . max( 0, $expires - time() )
			. '; Path=' . $this->path
			. ( $secure ? '; Secure' : '' )
			. '; HttpOnly; SameSite=' . ( 'Strict' === $samesite ? 'Strict' : 'Lax' );
	}
}
