<?php
/**
 * Passwordless sign-in: a short-lived link that starts a session.
 *
 * @package   SugarCommerce\WebSecurity
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.3.0
 */

declare( strict_types=1 );

namespace SugarCommerce\WebSecurity;

use SugarCommerce\SignedTokens\{Reason, Token, TokenSigner};

/**
 * Class MagicLink
 *
 * Two signed values with different jobs. The link in the email is short-
 * lived and is the only thing that can start a session; the session cookie
 * it is exchanged for is what saves sending another one next week.
 *
 * The mistake this exists to prevent is the two being interchangeable. If
 * the cookie were signed like the link, a month-long cookie pasted into the
 * sign-in URL would be a month-long sign-in link; if the link were signed
 * like the cookie, a forwarded email would be a session. So the link is
 * signed under its own namespace and the session under Session's, with its
 * subject — neither verifies as the other.
 *
 * Deliberately not single-use. Mail scanners and link previewers fetch every
 * URL in a message before the person sees it, and a link that burns on the
 * first fetch has been spent before anybody clicks it. Its short life is
 * what limits it.
 *
 * Claims are identifiers — an address, an account id — signed so they
 * cannot be edited, but readable by whoever holds the link or cookie. Never
 * put a credential in one.
 *
 * @since 1.3.0
 */
final readonly class MagicLink {

	/**
	 * How long a link lasts by default: an hour, enough to walk to a laptop
	 * and not much more.
	 */
	public const int TTL = 3600;

	/**
	 * @since 1.3.0
	 *
	 * @param TokenSigner|null $signer    Signs the link. Null disables links,
	 *                                    which is what an install with no
	 *                                    secret should do rather than mint
	 *                                    forgeable ones.
	 * @param Session          $session   The session a link is exchanged for.
	 * @param string           $namespace What links are signed under. Any
	 *                                    name except Session's own.
	 * @param int              $ttl       Seconds a link lasts.
	 *
	 * @throws \InvalidArgumentException When the namespace is Session's.
	 */
	public function __construct(
		private ?TokenSigner $signer,
		private Session $session,
		private string $namespace = 'web-security.magic-link',
		private int $ttl = self::TTL,
	) {
		if ( 'web-security.session' === strtolower( $namespace ) ) {
			throw new \InvalidArgumentException( 'A link signed like a session could be presented as one.' );
		}
	}

	/**
	 * Can this install sign anybody in?
	 *
	 * @since 1.3.0
	 *
	 * @return bool
	 */
	public function configured(): bool {
		return null !== $this->signer && $this->session->configured();
	}

	/**
	 * The token for an emailed sign-in link.
	 *
	 * @since 1.3.0
	 *
	 * @param array<string, scalar> $claims Who it signs in, e.g. `['e' => $email]`.
	 *
	 * @return string The token, or '' when this install cannot sign one.
	 */
	public function link( array $claims ): string {
		return null === $this->signer ? '' : $this->signer->sign( $this->namespace, $claims, max( 1, $this->ttl ) );
	}

	/**
	 * What a sign-in link says, or why it was refused.
	 *
	 * @since 1.3.0
	 *
	 * @param string $token Token from the URL.
	 *
	 * @return Token|Reason
	 */
	#[\NoDiscard( 'A Reason means the link must not sign anybody in.' )]
	public function redeem( string $token ): Token|Reason {
		if ( null === $this->signer || '' === $token ) {
			return Reason::Malformed;
		}

		return $this->signer->inspect( $this->namespace, $token );
	}

	/**
	 * A session cookie value, for after a link was redeemed.
	 *
	 * @since 1.3.0
	 *
	 * @param array<string, scalar> $claims Who is signed in. `sub` is
	 *                                      reserved by Session.
	 *
	 * @return string
	 *
	 * @throws \LogicException When the session has no secret.
	 */
	public function issue( array $claims ): string {
		return $this->session->issue( $claims );
	}

	/**
	 * Who a session cookie signs in, or why not.
	 *
	 * @since 1.3.0
	 *
	 * @param string $cookie The cookie's value.
	 *
	 * @return Token|Reason
	 */
	#[\NoDiscard( 'A Reason means nobody is signed in.' )]
	public function read( string $cookie ): Token|Reason {
		return $this->session->read( $cookie );
	}

	/**
	 * Attributes for the session cookie. See Session::cookie_options().
	 *
	 * @since 1.3.0
	 *
	 * @param bool   $is_https Whether the request arrived over TLS.
	 * @param string $path     Path the cookie is confined to.
	 *
	 * @return array<string, mixed>
	 */
	public function cookie_options( bool $is_https, string $path = '/' ): array {
		return $this->session->cookie_options( $is_https, $path );
	}
}
