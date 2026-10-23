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
	public const string PREFIX = 's1.';

	/**
	 * What follows the prefix in a sealed value: URL-safe base64 of a nonce,
	 * a MAC and at least one byte, which is 55 characters or more.
	 */
	private const string SHAPE = '/^s1\.[A-Za-z0-9_-]{55,}\z/';

	/**
	 * The derived key.
	 */
	private string $key;

	/**
	 * The key files are sealed with: derived apart from $key, so the two
	 * constructions never share one.
	 */
	private string $stream_key;

	/**
	 * What a sealed file starts with, and which format it is in.
	 */
	private const string FILE_MAGIC = "SCSEAL\x00\x01";

	/**
	 * Bytes of plain text per sealed chunk.
	 */
	private const int CHUNK = 65536;

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

		$this->key        = hash_hkdf( 'sha256', $secret, SODIUM_CRYPTO_SECRETBOX_KEYBYTES, 'web-security/sealer/v1/' . $context );
		$this->stream_key = hash_hkdf( 'sha256', $secret, SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES, 'web-security/sealer/file/v1/' . $context );
	}

	/**
	 * Keep the key out of `var_dump()` and `print_r()`.
	 *
	 * @since 1.4.0
	 *
	 * @return array{key: string}
	 */
	public function __debugInfo(): array {
		return array( 'key' => '[redacted]' );
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
	 * Seal a value unless it already is.
	 *
	 * For write paths that are handed a value from either side of a
	 * migration — a row read and written back, a payload passed through. A
	 * sealed value sealed again is ciphertext of ciphertext: it opens to
	 * `s1.…` rather than to the value, and every reader shows that instead.
	 *
	 * Already sealed means sealed by anybody: this does not open it to check
	 * whose key it is under. To move a value to this key, use reseal().
	 *
	 * @since 1.3.0
	 *
	 * @param string $value Plain or sealed.
	 *
	 * @return string Sealed, or '' for ''.
	 */
	public function seal_once( #[\SensitiveParameter] string $value ): string {
		return self::sealed( $value ) ? $value : $this->seal( $value );
	}

	/**
	 * Bring a stored value under this key.
	 *
	 * The step a key rotation repeats for every sealed column: open the value
	 * with whichever key sealed it — an old one, or this one when a rotation
	 * that died part-way already moved it — and seal it again here. A plain
	 * value, from before the column was sealed at all, is sealed too, so
	 * after a rotation every value is under the new key.
	 *
	 * Safe to run twice: a value this key sealed opens with it and is sealed
	 * again, with a fresh nonce, to the same plain value.
	 *
	 * @since 1.3.0
	 *
	 * @param string $value   Stored value.
	 * @param Sealer ...$from The keys it may be sealed under now. Each is
	 *                        tried in turn, then this one.
	 *
	 * @return string|null The value sealed under this key ('' stays ''), or
	 *                     null when it is sealed and opens under none of
	 *                     them. Stop there rather than write: the value is
	 *                     under a key nobody has, and overwriting it loses it.
	 */
	#[\NoDiscard( 'Null means the value opens under none of the keys, and must not be overwritten.' )]
	public function reseal( string $value, Sealer ...$from ): ?string {
		if ( ! self::sealed( $value ) ) {
			return $this->seal( $value );
		}

		foreach ( array( ...$from, $this ) as $sealer ) {
			$plain = $sealer->open( $value );

			if ( null !== $plain ) {
				return $this->seal( $plain );
			}
		}

		return null;
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
	#[\NoDiscard( 'Null means the value was not sealed with this key.' )]
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
	 * The prefix and a body that could be a sealed one, not the prefix
	 * alone: a plain value that happens to start `s1.` — anything a person
	 * typed can — is not ciphertext, and seal_once() must not store it
	 * unsealed on that account.
	 *
	 * @since 1.2.0
	 * @since 1.4.0 Checks the shape of what follows the prefix.
	 *
	 * @param string $value Stored value.
	 *
	 * @return bool
	 */
	public static function sealed( string $value ): bool {
		return str_starts_with( $value, self::PREFIX ) && 1 === preg_match( self::SHAPE, $value );
	}

	/**
	 * Seal a file into another, a chunk at a time.
	 *
	 * seal() needs the whole value in memory, and so would a backup sealed
	 * that way — a database that grows past memory_limit stops being backed
	 * up at all. This reads and writes 64 KB at a time (libsodium's
	 * secretstream, XChaCha20-Poly1305), so memory stays flat whatever the
	 * size. Each chunk is authenticated and the last one marked, so a sealed
	 * file that was cut short, reordered or edited does not open.
	 *
	 * @since 1.7.0
	 *
	 * @param string $from File to seal.
	 * @param string $to   Where the sealed copy goes; replaced if present.
	 *
	 * @return void
	 *
	 * @throws \RuntimeException When either file cannot be opened or written.
	 */
	public function seal_file( string $from, string $to ): void {
		$in  = self::handle( $from, 'rb' );
		$out = self::handle( $to, 'wb' );

		try {
			[ $state, $header ] = sodium_crypto_secretstream_xchacha20poly1305_init_push( $this->stream_key );

			if ( ! is_string( $state ) || ! is_string( $header ) ) {
				throw new \RuntimeException( 'libsodium could not start a sealed stream.' );
			}

			self::write_all( $out, self::FILE_MAGIC . $header );

			$chunk = self::read_up_to( $in, self::CHUNK );

			do {
				$next = self::read_up_to( $in, self::CHUNK );
				$last = '' === $next;
				self::write_all( $out, sodium_crypto_secretstream_xchacha20poly1305_push( $state, $chunk, '', $last ? SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL : SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE ) );
				$chunk = $next;
			} while ( ! $last );
		} finally {
			fclose( $in );
			fclose( $out );
		}
	}

	/**
	 * Open a file seal_file() sealed, into another.
	 *
	 * False — and nothing left at $to — when it was sealed with another key
	 * or context, is not a sealed file, or was cut short, reordered or
	 * edited: the plain copy is only kept once every chunk has verified and
	 * the last one says it is the last.
	 *
	 * @since 1.7.0
	 *
	 * @param string $from Sealed file.
	 * @param string $to   Where the plain copy goes; replaced if present.
	 *
	 * @return bool
	 *
	 * @throws \RuntimeException When either file cannot be opened or written.
	 */
	#[\NoDiscard( 'False means the file did not open, and nothing was written.' )]
	public function open_file( string $from, string $to ): bool {
		$in  = self::handle( $from, 'rb' );
		$out = self::handle( $to, 'wb' );
		$ok  = false;

		try {
			$head = self::read_up_to( $in, strlen( self::FILE_MAGIC ) + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES );

			if ( ! str_starts_with( $head, self::FILE_MAGIC ) || strlen( $head ) !== strlen( self::FILE_MAGIC ) + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES ) {
				return false;
			}

			$state = sodium_crypto_secretstream_xchacha20poly1305_init_pull( substr( $head, strlen( self::FILE_MAGIC ) ), $this->stream_key );

			while ( true ) {
				$sealed = self::read_up_to( $in, self::CHUNK + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES );

				if ( '' === $sealed ) {
					return false; // Ended without the final chunk: cut short.
				}

				$opened = sodium_crypto_secretstream_xchacha20poly1305_pull( $state, $sealed );

				if ( ! is_array( $opened ) || ! is_string( $opened[0] ?? null ) ) {
					return false;
				}

				self::write_all( $out, $opened[0] );

				if ( SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL === $opened[1] ) {
					// Anything after the final chunk was added later.
					return $ok = '' === self::read_up_to( $in, 1 );
				}
			}
		} finally {
			fclose( $in );
			fclose( $out );

			if ( ! $ok ) {
				@unlink( $to );
			}
		}
	}

	/**
	 * A file handle, or a RuntimeException naming the file.
	 *
	 * @since 1.7.0
	 *
	 * @param string $path File.
	 * @param string $mode fopen() mode.
	 *
	 * @return resource
	 *
	 * @throws \RuntimeException When it cannot be opened.
	 */
	private static function handle( string $path, string $mode ) {
		$handle = '' === $path ? false : @fopen( $path, $mode );

		if ( false === $handle ) {
			throw new \RuntimeException( 'Could not open ' . json_encode( $path ) . '.' );
		}

		return $handle;
	}

	/**
	 * Up to $length bytes, fewer only at the end of the file.
	 *
	 * @since 1.7.0
	 *
	 * @param resource $handle Open file.
	 * @param int      $length Bytes wanted.
	 *
	 * @return string
	 */
	private static function read_up_to( $handle, int $length ): string {
		$data = '';

		while ( strlen( $data ) < $length && ! feof( $handle ) ) {
			$part = fread( $handle, max( 1, $length - strlen( $data ) ) );

			if ( false === $part ) {
				throw new \RuntimeException( 'Could not read a file being sealed or opened.' );
			}

			$data .= $part;
		}

		return $data;
	}

	/**
	 * Write all of it, or a RuntimeException.
	 *
	 * @since 1.7.0
	 *
	 * @param resource $handle Open file.
	 * @param string   $data   Bytes.
	 *
	 * @return void
	 */
	private static function write_all( $handle, string $data ): void {
		if ( '' !== $data && strlen( $data ) !== fwrite( $handle, $data ) ) {
			throw new \RuntimeException( 'Could not write a file being sealed or opened (disk full?).' );
		}
	}
}
