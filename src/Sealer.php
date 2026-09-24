<?php
/**
 * Encryption for values kept at rest.
 *
 * @package   SugarCommerce\WebSecurity
 * @copyright Copyright (c) 2026, ArrayPress Limited
 * @license   GPL-2.0-or-later
 * @since     1.2.0
 */

declare( strict_types=1 );

namespace SugarCommerce\WebSecurity;

/**
 * Class Sealer
 *
 * For the personal data an application has to keep but should never be able
 * to leak by losing a database file or a backup: an email address, a payload
 * that carries one. Sealed with libsodium's secretbox — XSalsa20-Poly1305,
 * authenticated, so a tampered value fails to open rather than opening as
 * something else.
 *
 * The key lives with the application's configuration and nowhere near the
 * data. A stolen database, or a backup copied out of a bucket, is then
 * ciphertext; which is also what lets a breach of it not be one that has to
 * be reported to every person in it.
 *
 * Sealed values carry a short prefix (`s1.`) so code can tell them from
 * plain ones. That is what makes turning this on for an existing table a
 * migration that can run in the background: reads open what is sealed and
 * pass through what is not yet.
 *
 * Pair with Hash::opaque() for anything that has to be looked up by value —
 * each seal uses a fresh nonce, so two seals of one address never compare
 * equal, and must not.
 *
 * @since 1.2.0
 */
final readonly class Sealer {

	/**
	 * Marks a sealed value, and which format it is in.
	 */
	public const PREFIX = 's1.';

	/**
	 * The derived key.
	 */
	private string $key;

	/**
	 * @since 1.2.0
	 *
	 * @param string $secret Any high-entropy secret, at least 32 bytes. The
	 *                       key is derived from it, so an application can
	 *                       hand over one configured secret for several
	 *                       purposes without them sharing a key.
	 * @param string $context What this sealer is for. Different contexts
	 *                        cannot open each other's values.
	 *
	 * @throws \InvalidArgumentException When the secret is too short.
	 */
	public function __construct( #[\SensitiveParameter] string $secret, string $context = 'sealer' ) {
		if ( strlen( $secret ) < 32 ) {
			throw new \InvalidArgumentException( 'A sealing secret must be at least 32 bytes.' );
		}

		$this->key = hash_hkdf( 'sha256', $secret, SODIUM_CRYPTO_SECRETBOX_KEYBYTES, 'web-security/sealer/v1/' . $context );
	}

	/**
	 * Seal a value.
	 *
	 * '' stays '' — sealing nothing would store a ciphertext that looks like
	 * something.
	 *
	 * @since 1.2.0
	 *
	 * @param string $plain Value.
	 *
	 * @return string `s1.` followed by URL-safe base64.
	 */
	public function seal( #[\SensitiveParameter] string $plain ): string {
		if ( '' === $plain ) {
			return '';
		}

		$nonce = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );

		return self::PREFIX . sodium_bin2base64( $nonce . sodium_crypto_secretbox( $plain, $nonce, $this->key ), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING );
	}

	/**
	 * Open a sealed value.
	 *
	 * @since 1.2.0
	 *
	 * @param string $sealed From seal().
	 *
	 * @return string|null The value, or null when it is not one this key
	 *                     sealed — tampered, truncated, or another key's.
	 */
	public function open( string $sealed ): ?string {
		if ( ! self::sealed( $sealed ) ) {
			return null;
		}

		try {
			$raw = sodium_base642bin( substr( $sealed, strlen( self::PREFIX ) ), SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING );
		} catch ( \SodiumException ) {
			return null;
		}

		if ( strlen( $raw ) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ) {
			return null;
		}

		$plain = sodium_crypto_secretbox_open(
			substr( $raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ),
			substr( $raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ),
			$this->key
		);

		return false === $plain ? null : $plain;
	}

	/**
	 * Open a value if it is sealed, and hand back anything else as it is.
	 *
	 * For reading a column that is part-way through being sealed. A sealed
	 * value that will not open comes back as '' rather than as ciphertext:
	 * showing somebody `s1.Qk9…` as their email address helps nobody.
	 *
	 * @since 1.2.0
	 *
	 * @param mixed $value Stored value.
	 *
	 * @return mixed
	 */
	public function reveal( mixed $value ): mixed {
		return is_string( $value ) && self::sealed( $value ) ? ( $this->open( $value ) ?? '' ) : $value;
	}

	/**
	 * Whether a value is in sealed form.
	 *
	 * @since 1.2.0
	 *
	 * @param string $value Stored value.
	 *
	 * @return bool
	 */
	public static function sealed( string $value ): bool {
		return str_starts_with( $value, self::PREFIX );
	}
}
