<?php
/**
 * Signed-cookie sessions for a single shared password.
 *
 * @package SugarCommerce\WebSecurity
 */

declare( strict_types=1 );

namespace SugarCommerce\WebSecurity;

use SugarCommerce\SignedTokens\{Reason, Token, TokenSigner};

/**
 * Class Session
 *
 * For the operator panel, the staging gate, the internal tool — anywhere there
 * is one password rather than user accounts, and adding a users table to get a
 * login would be the wrong shape entirely.
 *
 * A signed cookie rather than a PHP session: there is nothing on disk to clean
 * up, nothing shared between workers, and no session store to make sticky
 * behind a load balancer. Rotating the password invalidates every existing
 * session for free, because the password is what the signing key is derived
 * from — an old cookie stops verifying the moment it changes.
 *
 * Signing everyone out should not need a new password, so the key is derived
 * from a generation as well: a number the application keeps — a row in its
 * settings table is enough — and passes in on every request. Incrementing it
 * ends every session issued under the old one, exactly as rotating the
 * password would, and the password stays the same. The generation is never
 * written into the cookie, so there is nothing in it to edit: a cookie from
 * an older generation fails as a bad signature, before anything in it is
 * read. The increment has to be durable before the response that announces
 * it goes out, or a crash in between leaves every session it was meant to
 * end still valid. Generation 0 derives the same key as before there were
 * generations, so cookies issued without one keep verifying.
 *
 * The signing itself is TokenSigner rather than a hand-rolled HMAC. That
 * matters for more than tidiness: it checks the signature before the expiry,
 * so a forged cookie can never come back as "expired" and tell its forger the
 * structure was right, and it namespaces what it signs, so a token minted for
 * anything else in the same application can never be presented as a session.
 *
 * @since 1.0.0
 */
final readonly class Session {

	/**
	 * Default cookie name. Override it per application when two of them
	 * might share a hostname.
	 */
	public const string COOKIE = 'session';

	/**
	 * Namespace the cookie is signed under.
	 */
	private const string NAMESPACE = 'web-security.session';

	/**
	 * Separates the password from the signing key derived from it.
	 *
	 * The password itself is never the key. TokenSigner requires at least
	 * 32 bytes and a chosen password is usually shorter, but the real reason
	 * is that a key and a credential should not be the same bytes: anything
	 * that leaks one would otherwise hand over the other.
	 */
	private const string KDF_CONTEXT = 'web-security/session/v1';

	/**
	 * How long a session lasts, in seconds. Long enough to work through a
	 * moderation queue, short enough that a forgotten laptop is not
	 * indefinite access.
	 */
	public const LIFETIME = 43200; // 12 hours.

	/**
	 * The signer, or null when no password is configured.
	 */
	private ?TokenSigner $signer;

	/**
	 * @since 1.0.0
	 * @since 1.4.0 Takes a generation.
	 *
	 * @param string   $password   The shared password. '' means "no password
	 *                             set", which makes every check fail rather
	 *                             than every check pass — see configured().
	 * @param string   $subject    What the session says it is. Recorded in the
	 *                             payload and checked on the way back, so two
	 *                             roles signed with the same key stay distinct.
	 * @param int      $lifetime   Seconds a session lasts.
	 * @param int|null $timestamp  Fixed clock, for tests.
	 * @param int      $generation Which generation of sessions is current.
	 *                             Stored by the application and incremented to
	 *                             sign everyone out; a cookie issued under any
	 *                             other generation does not verify. 0, the
	 *                             default, is what every session was before
	 *                             there were generations.
	 *
	 * @throws \InvalidArgumentException When the generation is negative.
	 */
	public function __construct(
		#[\SensitiveParameter]
		private string $password,
		private string $subject = 'operator',
		private int $lifetime = self::LIFETIME,
		?int $timestamp = null,
		int $generation = 0,
	) {
		if ( $generation < 0 ) {
			throw new \InvalidArgumentException( 'A session generation cannot be negative.' );
		}

		$this->signer = '' === $password
			? null
			: new TokenSigner( self::derive( $password, $generation ), timestamp: $timestamp );
	}

	/**
	 * Is a password configured at all?
	 *
	 * With none set every check fails closed. An application may then choose
	 * to fall back to something else — localhost-only access during
	 * development is the usual one — but that is its decision to make
	 * explicitly, not something this class does quietly on its behalf.
	 *
	 * @since 1.0.0
	 *
	 * @return bool
	 */
	public function configured(): bool {
		return null !== $this->signer;
	}

	/**
	 * Mint a session value, for setting as a cookie.
	 *
	 * Claims are for what the session needs to remember about who it belongs
	 * to — a buyer's address, an account id — and are signed with the rest of
	 * it, so the browser holding the cookie cannot edit them. They are not
	 * secret: anybody with the cookie can read them, so a claim is an
	 * identifier, never a credential.
	 *
	 * `sub` is reserved. It carries the subject this session was issued for
	 * and is checked on the way back.
	 *
	 * @since 1.0.0
	 * @since 1.1.0 Takes claims.
	 *
	 * @param array<string, scalar> $claims Extra values to sign into it.
	 *
	 * @return string The cookie value.
	 *
	 * @throws \LogicException When no password is configured.
	 */
	public function issue( array $claims = array() ): string {
		if ( null === $this->signer ) {
			throw new \LogicException( 'Cannot issue a session with no password configured.' );
		}

		return $this->signer->sign(
			self::NAMESPACE,
			// Subject first: `+` keeps the left side's keys, so a caller
			// passing their own `sub` cannot mint a session for another role.
			array( 'sub' => $this->subject ) + $claims,
			$this->lifetime
		);
	}

	/**
	 * Is this cookie value a valid, unexpired session?
	 *
	 * @since 1.0.0
	 *
	 * @param string $cookie The submitted cookie value.
	 *
	 * @return bool
	 */
	#[\NoDiscard( 'False means the caller is not signed in.' )]
	public function valid( string $cookie ): bool {
		return $this->read( $cookie ) instanceof Token;
	}

	/**
	 * Verify a cookie, reporting why it failed.
	 *
	 * Worth the extra call where the difference is visible to the person:
	 * "your session has expired, sign in again" is a different message from
	 * "that is not a session", and showing the second for the first is how a
	 * tool earns a reputation for logging people out at random.
	 *
	 * @since 1.0.0
	 *
	 * @param string $cookie The submitted cookie value.
	 *
	 * @return Token|Reason The session, or why it was refused.
	 */
	#[\NoDiscard( 'A Reason means the session is not valid.' )]
	public function read( string $cookie ): Token|Reason {
		if ( null === $this->signer ) {
			return Reason::Malformed;
		}

		if ( '' === $cookie ) {
			return Reason::Malformed;
		}

		$result = $this->signer->inspect( self::NAMESPACE, $cookie );

		if ( ! $result instanceof Token ) {
			return $result;
		}

		// A valid signature for the wrong subject is somebody presenting one
		// role's cookie to another role's gate.
		return $this->subject === $result->get( 'sub' ) ? $result : Reason::Malformed;
	}

	/**
	 * Check a submitted password.
	 *
	 * Constant time, and deliberately slow to fail, so the endpoint is not a
	 * usable oracle for guessing. The delay is on failure only: making the
	 * success path slow too would punish the one person who is allowed in.
	 *
	 * @since 1.0.0
	 *
	 * @param string $submitted What was typed.
	 *
	 * @return bool
	 */
	#[\NoDiscard( 'False means the password was wrong.' )]
	public function authenticate( #[\SensitiveParameter] string $submitted ): bool {
		if ( ! $this->configured() || '' === $submitted ) {
			return false;
		}

		if ( hash_equals( $this->password, $submitted ) ) {
			return true;
		}

		usleep( 400_000 );

		return false;
	}

	/**
	 * Attributes for the session cookie.
	 *
	 * HttpOnly, so a CSRF token derived from it cannot be read by script.
	 * Strict rather than Lax, because nothing should ever navigate into an
	 * admin panel from another site.
	 *
	 * Scope it by path rather than leaving it at '/'. Where several surfaces
	 * share one hostname — which is the simple deployment — a cookie at the
	 * root is sent on every public request too. That is needless exposure at
	 * best, and at worst it is what an XSS on a public page would reach for.
	 *
	 * @since 1.0.0
	 *
	 * @param bool   $is_https Whether the request arrived over TLS. Setting
	 *                         `secure` on a plain-HTTP local host means the
	 *                         browser silently drops the cookie and the login
	 *                         form appears to do nothing.
	 * @param string $path     Path the cookie is confined to.
	 *
	 * @return array<string, mixed> For setcookie()'s options argument.
	 */
	public function cookie_options( bool $is_https, string $path = '/' ): array {
		return array(
			'expires'  => time() + $this->lifetime,
			'path'     => $path,
			'secure'   => $is_https,
			'httponly' => true,
			'samesite' => 'Strict',
		);
	}

	/**
	 * Attributes that clear the cookie.
	 *
	 * The path has to match the one it was set at, or the browser keeps the
	 * original and the person stays signed in after clicking sign out.
	 *
	 * @since 1.0.0
	 *
	 * @param string $path The path it was set at.
	 *
	 * @return array<string, mixed> For setcookie()'s options argument.
	 */
	public static function clear_options( string $path = '/' ): array {
		return array( 'expires' => 1, 'path' => $path );
	}

	/**
	 * Derive a signing key from a password and a generation.
	 *
	 * Generation 0 is the bare context, byte for byte the key from before
	 * there were generations, so cookies already out there keep verifying.
	 * Every other generation is its own context, and so its own key.
	 *
	 * @since 1.0.0
	 * @since 1.4.0 Takes a generation.
	 *
	 * @param string $password   The shared password.
	 * @param int    $generation Which generation of sessions is current.
	 *
	 * @return string 64 hex characters.
	 */
	private static function derive( #[\SensitiveParameter] string $password, int $generation ): string {
		$context = 0 === $generation
			? self::KDF_CONTEXT
			: self::KDF_CONTEXT . '/generation/' . $generation;

		return hash_hmac( 'sha256', $context, $password );
	}
}
