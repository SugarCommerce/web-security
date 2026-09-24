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
 * Login is deliberately exempt. There is no session yet, and forging a login
 * request only forces the victim to submit a password the attacker does not
 * have.
 *
 * @since 1.0.0
 */
final readonly class Csrf {

	/**
	 * Form field and header name carrying the token.
	 */
	public const string FIELD = '_csrf';
	public const string HEADER = 'x-csrf-token';

	/**
	 * @param string $secret      Signing key. Use the application's general
	 *                            token secret, not the password behind the
	 *                            session — rotating one should not silently
	 *                            invalidate the other.
	 * @param string $cookie_name Session cookie the token is derived from.
	 */
	public function __construct(
		#[\SensitiveParameter]
		private string $secret,
		private string $cookie_name = Session::COOKIE,
	) {}

	/**
	 * The token for the current session, or '' when there is no session.
	 *
	 * Callers must treat '' as "always fail verification" rather than as "no
	 * check needed". verify() already does; anything reading token() directly
	 * has to make the same choice.
	 *
	 * @since 1.0.0
	 *
	 * @param array<string, string>|null $cookies Cookie jar. Defaults to
	 *                                            $_COOKIE; passed explicitly
	 *                                            by tests.
	 *
	 * @return string
	 */
	public function token( ?array $cookies = null ): string {
		$cookie = (string) ( ( $cookies ?? $_COOKIE )[ $this->cookie_name ] ?? '' );

		return '' === $cookie ? '' : hash_hmac( 'sha256', $cookie, $this->secret );
	}

	/**
	 * A hidden input carrying the token, for embedding in a form.
	 *
	 * @since 1.0.0
	 *
	 * @param array<string, string>|null $cookies Cookie jar. Defaults to $_COOKIE.
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
	 * @param string                     $submitted The value from the form
	 *                                              field or the header.
	 * @param array<string, string>|null $cookies   Cookie jar. Defaults to $_COOKIE.
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
}
