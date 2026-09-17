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
	public function matches( string $value, string $digest ): bool {
		return '' !== $digest && hash_equals( $digest, $this->opaque( $value ) );
	}
}
