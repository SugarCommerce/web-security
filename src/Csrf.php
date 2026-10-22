<?php
/**
 * Cross-site request forgery protection.
 *
 * @package SugarCommerce\WebSecurity
 */

declare( strict_types=1 );

namespace SugarCommerce\WebSecurity;

/**
 * Class Csrf
 *
 * The token is an HMAC of the session cookie under a server secret, so there
 * is nothing to store and nothing to expire separately: it rotates whenever
 * the session does, and a restarted server does not sign everyone out of their
 * half-filled forms.
 *
 * Why this works. The cookie is HttpOnly, so a malicious cross-origin page
 * cannot read it, which means it cannot derive the token. `SameSite=Lax` alone
 * is not enough — it still permits top-level cross-origin POSTs in some
 * browsers, which is exactly the shape of a form-submit attack.
 *
 * Not built on the signed-tokens library, deliberately. There is no payload
 * here and nothing to expire; a token that carried its own expiry would need
 * refreshing in every open tab, which is the failure mode people recognise as
 * "the form said my session expired but I was right here". One HMAC of one
 * value is the whole of it.
 *
 * The HMAC is keyed with a key derived from the secret, never with the
 * secret itself. token() answers for whatever cookie a request sends, signed
 * in or not, so it hashes a value the caller chooses — and an application
 * usually hands the same secret to Hash, to Session, to its own key
 * derivations. Keyed with the bare secret, as it was before 1.4, a request
 * with its cookie set to some other construction's input got that
 * construction's output printed into the form.
 *
 * Login is deliberately exempt. There is no session yet, and forging a login
 * request only forces the victim to submit a password the attacker does not
 * have.
 *
 * @since 1.0.0
 */
final readonly class Csrf {

	/**
	 * Form field carrying the token.
	 */
	public const string FIELD = '_csrf';

	/**
	 * Header carrying the token, lower-cased.
	 */
	public const string HEADER = 'x-csrf-token';

	/**
	 * HKDF context the token key is derived under.
	 */
	private const string KDF_CONTEXT = 'web-security/csrf/v1';

	/**
	 * The key tokens are signed with, or '' when there is no secret.
	 */
	private string $key;

	/**
	 * @since 1.0.0
	 * @since 1.4.0 Signs with a key derived from the secret.
	 *
	 * @param string $secret      Signing key. Use the application's general
	 *                            token secret, not the password behind the
	 *                            session — rotating one should not silently
	 *                            invalidate the other. '' means there is no
	 *                            token, so every check fails.
	 * @param string $cookie_name Session cookie the token is derived from.
	 */
	public function __construct(
		#[\SensitiveParameter]
		string $secret,
		private string $cookie_name = Session::COOKIE,
	) {
		$this->key = '' === $secret ? '' : hash_hkdf( 'sha256', $secret, 32, self::KDF_CONTEXT );
	}

	/**
	 * Keep the key out of `var_dump()` and `print_r()`.
	 *
	 * @since 1.4.0
	 *
	 * @return array{key: string, cookie_name: string}
	 */
	public function __debugInfo(): array {
		return array(
			'key'         => '[redacted]',
			'cookie_name' => $this->cookie_name,
		);
	}

	/**
	 * The token for the current session, or '' when there is no session.
	 *
	 * Callers must treat '' as "always fail verification" rather than as "no
	 * check needed". verify() already does; anything reading token() directly
	 * has to make the same choice.
	 *
	 * A cookie that is not a string — `name[]=x` arrives as an array — is no
	 * session. Cast, it would be the string "Array" for everybody, and so
	 * one token anybody could read off their own page.
	 *
	 * @since 1.0.0
	 *
	 * @param array<string, mixed>|null $cookies Cookie jar. Defaults to
	 *                                           $_COOKIE; passed explicitly
	 *                                           by tests.
	 *
	 * @return string
	 */
	public function token( ?array $cookies = null ): string {
		$cookie = ( $cookies ?? $_COOKIE )[ $this->cookie_name ] ?? '';

		if ( ! is_string( $cookie ) || '' === $cookie || '' === $this->key ) {
			return '';
		}

		return hash_hmac( 'sha256', $cookie, $this->key );
	}

	/**
	 * A hidden input carrying the token, for embedding in a form.
	 *
	 * @since 1.0.0
	 *
	 * @param array<string, mixed>|null $cookies Cookie jar. Defaults to $_COOKIE.
	 *
	 * @return string HTML.
	 */
	public function field( ?array $cookies = null ): string {
		return sprintf(
			'<input type="hidden" name="%s" value="%s">',
			self::FIELD,
			htmlspecialchars( $this->token( $cookies ), ENT_QUOTES, 'UTF-8' )
		);
	}

	/**
	 * Does this request carry a valid token?
	 *
	 * @since 1.0.0
	 *
	 * @param string                    $submitted The value from the form
	 *                                             field or the header.
	 * @param array<string, mixed>|null $cookies   Cookie jar. Defaults to $_COOKIE.
	 *
	 * @return bool
	 */
	#[\NoDiscard( 'False means the request did not come from this site.' )]
	public function verify( string $submitted, ?array $cookies = null ): bool {
		$expected = $this->token( $cookies );

		if ( '' === $expected || '' === $submitted ) {
			return false;
		}

		// Constant-time: a plain === short-circuits on the first differing
		// byte, leaking how much of a guess was correct.
		return hash_equals( $expected, $submitted );
	}

	/**
	 * The token a request submitted, wherever it put it.
	 *
	 * A form posts it as a hidden field, a script's JSON body may carry it,
	 * and a fetch() sends it as a header. Never from the query string: a
	 * token in a URL ends up in access logs, browser history and the
	 * Referer of the next page, and a leaked token is a forged request.
	 *
	 * @since 1.3.0
	 *
	 * @param array<string, mixed>      $form   The parsed form body.
	 * @param string                    $header The X-CSRF-Token header's value.
	 * @param array<string, mixed>|null $json   A parsed JSON body, if any.
	 *
	 * @return string The first one present, or ''.
	 */
	public static function submitted( array $form, string $header = '', ?array $json = null ): string {
		foreach ( array( $form[ self::FIELD ] ?? null, $json[ self::FIELD ] ?? null, $header ) as $candidate ) {
			if ( is_string( $candidate ) && '' !== $candidate ) {
				return $candidate;
			}
		}

		return '';
	}

	/**
	 * Whether the browser's own account of where a request came from allows
	 * it: false only when it named somewhere else.
	 *
	 * Browsers send Origin on a cross-site POST, and Referer usually; a page
	 * cannot forge either. So when one is present and names another host,
	 * the request is forged, whatever else it carries. When neither is
	 * present — privacy settings and some proxies strip them — that is not
	 * evidence either way, which is why this is a first check to pair with
	 * verify(), never a replacement for it.
	 *
	 * Origin wins over Referer when both are sent. Hosts are compared
	 * exactly, port included: a suffix match lets `notexample.com` through.
	 * "null", what a sandboxed frame or a privacy redirect sends, names no
	 * host and so counts as elsewhere.
	 *
	 * @since 1.3.0
	 *
	 * @param string $origin  The Origin header, or ''.
	 * @param string $referer The Referer header, or ''.
	 * @param string $host    The host the request arrived on, with any port.
	 *
	 * @return bool
	 */
	#[\NoDiscard( 'False means another site sent this request.' )]
	public static function same_origin( string $origin, string $referer, string $host ): bool {
		$claimed = '' !== $origin ? $origin : $referer;

		return '' === $claimed || self::names_host( $claimed, $host );
	}

	/**
	 * Whether a URL names exactly this host.
	 *
	 * @since 1.3.0
	 *
	 * @param string $url  An Origin or Referer.
	 * @param string $host Host, with any port.
	 *
	 * @return bool
	 */
	public static function names_host( string $url, string $host ): bool {
		$parts = parse_url( $url );

		if ( ! is_array( $parts ) || ! isset( $parts['host'] ) || '' === $host ) {
			return false;
		}

		$claimed = strtolower( $parts['host'] ) . ( isset( $parts['port'] ) ? ':' . $parts['port'] : '' );

		return $claimed === strtolower( $host );
	}
}
