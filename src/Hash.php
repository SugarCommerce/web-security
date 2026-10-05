<?php
/**
 * Keyed hashing for values that must be comparable but not recoverable.
 *
 * @package SugarCommerce\WebSecurity
 */

declare( strict_types=1 );

namespace SugarCommerce\WebSecurity;

/**
 * Class Hash
 *
 * For the values an application has to store in order to count, compare or
 * rate-limit, but has no business being able to read back: addresses, user
 * agents, an email used only as a key.
 *
 * Deliberately keyed, and that is the whole point of the class. IPv4 is only
 * four billion values, so an unkeyed SHA-256 of an address can be reversed by
 * brute force in seconds — the digest is still personal data, and storing it
 * satisfies nobody's data protection officer. Keyed, a digest only ever
 * compares equal to itself, which is all that counting distinct visitors
 * needs, and it is worthless to anyone who takes the table without the secret.
 *
 * Not for API keys or passwords. An API key is looked up by its digest, so it
 * cannot be keyed with a secret the finder might not have — use
 * `SugarCommerce\Generate\Token::digest()`. A password needs a slow hash —
 * use `password_hash()`.
 *
 * @since 1.0.0
 */
final readonly class Hash {

	/**
	 * @param string $secret Signing key. Losing it does not lose data, but it
	 *                       does break comparison against everything already
	 *                       stored, so rotating it is a migration and not a
	 *                       configuration change.
	 */
	public function __construct(
		#[\SensitiveParameter]
		private string $secret,
	) {}

	/**
	 * A hasher keyed for one purpose, from a secret shared by several.
	 *
	 * An application usually has one configured secret. Keying every index
	 * with it directly means two indexes compare equal across purposes —
	 * an email's lookup hash would match its rate-limit key — and that
	 * rotating one rotates all of them without anybody deciding to. HKDF
	 * gives each purpose its own key, and none of them reveals the secret
	 * or each other.
	 *
	 * Stable: the same secret and context always give the same key, so
	 * digests stored yesterday still match today.
	 *
	 * @since 1.3.0
	 *
	 * @param string $secret  The shared secret.
	 * @param string $context What the digests are for, e.g. `app/email-index`.
	 *                        Different contexts never produce equal digests.
	 *
	 * @return self
	 */
	public static function derived( #[\SensitiveParameter] string $secret, string $context ): self {
		return new self( hash_hkdf( 'sha256', $secret, 32, $context ) );
	}

	/**
	 * Pseudonymise an IP address.
	 *
	 * @since 1.0.0
	 *
	 * @param string $ip The address. '' passes through unchanged, so a
	 *                   caller with no address stores no digest rather than
	 *                   a digest of nothing that compares equal across every
	 *                   such row.
	 *
	 * @return string
	 */
	public function ip( string $ip ): string {
		return '' === $ip ? '' : hash_hmac( 'sha256', $ip, $this->secret );
	}

	/**
	 * Pseudonymise any short string, under the same reasoning.
	 *
	 * @since 1.0.0
	 *
	 * @param string $value A user agent, an email used as a rate-limit key.
	 *
	 * @return string
	 */
	public function opaque( string $value ): string {
		return '' === $value ? '' : hash_hmac( 'sha256', $value, $this->secret );
	}

	/**
	 * Whether a value matches a stored digest.
	 *
	 * Constant-time. Comparing with `===` short-circuits on the first
	 * differing byte, which over enough requests says how much of a guess was
	 * right.
	 *
	 * @since 1.0.0
	 *
	 * @param string $value  The plain value.
	 * @param string $digest A digest from ip() or opaque().
	 *
	 * @return bool
	 */
	#[\NoDiscard( 'An unchecked comparison checks nothing.' )]
	public function matches( string $value, string $digest ): bool {
		return '' !== $digest && hash_equals( $digest, $this->opaque( $value ) );
	}
}
