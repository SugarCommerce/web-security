<?php
/**
 * Input cleaning and validation.
 *
 * @package SugarCommerce\WebSecurity
 */

declare( strict_types=1 );

namespace SugarCommerce\WebSecurity;

/**
 * Class Input
 *
 * Every method takes an untrusted string and returns something safe to store,
 * or an empty string the caller must handle. Nothing here escapes for output —
 * that is the view's job, and a class that does both produces double-escaped
 * text the first time somebody uses them together.
 *
 * The empty string rather than null or an exception, consistently. A validator
 * that sometimes throws and sometimes returns null makes every call site a
 * decision; one that always answers the same way makes them all the same
 * shape: `if ( '' === $email )`.
 *
 * @since 1.0.0
 */
final class Input {

	/**
	 * Strip control characters and collapse whitespace.
	 *
	 * Removes the C0 and C1 ranges except tab, newline and carriage return,
	 * plus the Unicode characters used for display spoofing: zero-width
	 * joiners, bidirectional overrides and the byte-order mark. A filename
	 * containing U+202E renders right-to-left and can make `exe.txt` look
	 * like `txt.exe`, which is a real upload attack and not a theoretical one.
	 *
	 * @since 1.0.0
	 *
	 * @param string $value      Untrusted text.
	 * @param int    $max_length Truncation point. 0 for no limit.
	 *
	 * @return string
	 */
	public static function clean_text( string $value, int $max_length = 0 ): string {
		$value = preg_replace( '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $value ) ?? '';
		$value = preg_replace( '/[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2060}-\x{2064}\x{FEFF}]/u', '', $value ) ?? '';
		$value = trim( preg_replace( '/\s+/u', ' ', $value ) ?? '' );

		if ( $max_length > 0 && mb_strlen( $value ) > $max_length ) {
			$value = mb_substr( $value, 0, $max_length );
		}

		return $value;
	}

	/**
	 * A valid, normalised email address, or ''.
	 *
	 * The local part keeps its case because RFC 5321 says it is significant;
	 * the domain is lower-cased because it is not. Normalising the whole
	 * thing to lower case is the common shortcut and it is wrong — there are
	 * mail servers that treat the local part as case-sensitive, and the
	 * bounce is nobody's fault but yours.
	 *
	 * @since 1.0.0
	 *
	 * @param string $value Untrusted address.
	 *
	 * @return string The address, or '' when it is not one.
	 */
	public static function email( string $value ): string {
		$value = self::clean_text( $value, 254 );

		if ( ! str_contains( $value, '@' ) ) {
			return '';
		}

		[ $local, $domain ] = explode( '@', $value, 2 );
		$value              = $local . '@' . mb_strtolower( $domain );

		return false === filter_var( $value, FILTER_VALIDATE_EMAIL ) ? '' : $value;
	}

	/**
	 * An email with its local part masked, for display in logs and lists.
	 *
	 * `jordan@example.com` becomes `jo****@example.com`. Enough to recognise
	 * an address you already know, not enough to harvest one you do not.
	 *
	 * @since 1.0.0
	 *
	 * @param string $value An address.
	 *
	 * @return string The masked form, or '' when the input was not an address.
	 */
	public static function mask_email( string $value ): string {
		if ( ! str_contains( $value, '@' ) ) {
			return '';
		}

		[ $local, $domain ] = explode( '@', $value, 2 );
		$keep               = mb_substr( $local, 0, min( 2, mb_strlen( $local ) ) );

		return $keep . str_repeat( '*', max( 1, mb_strlen( $local ) - mb_strlen( $keep ) ) ) . '@' . $domain;
	}

	/**
	 * An http(s) URL, or ''.
	 *
	 * Other schemes are rejected outright. `javascript:` and `data:` are the
	 * ones that matter — both become script execution the moment the value
	 * reaches an href, and `filter_var` alone accepts them happily.
	 *
	 * @since 1.0.0
	 *
	 * @param string $value Untrusted URL.
	 *
	 * @return string The URL, or '' when it is not a usable one.
	 */
	public static function url( string $value ): string {
		$value  = self::clean_text( $value, 2048 );
		$scheme = strtolower( (string) parse_url( $value, PHP_URL_SCHEME ) );

		if ( ! in_array( $scheme, array( 'http', 'https' ), true ) ) {
			return '';
		}

		return false === filter_var( $value, FILTER_VALIDATE_URL ) ? '' : $value;
	}

	/**
	 * An identifier of the form `prefix_alphanumeric`, or ''.
	 *
	 * The shape most object-store APIs use — Stripe's `acct_`, `price_`,
	 * `cs_`; Slack's, Shopify's, plenty of others. Checking the prefix as
	 * well as the alphabet is what stops a caller passing a customer id where
	 * an account id was meant and having it silently look up nothing.
	 *
	 * @since 1.0.0
	 *
	 * @param string $value  Untrusted identifier.
	 * @param string $prefix Expected prefix, without the underscore.
	 *
	 * @return string The id, or '' when it does not match.
	 */
	public static function prefixed_id( string $value, string $prefix ): string {
		$value = trim( $value );

		return preg_match( '/^' . preg_quote( $prefix, '/' ) . '_[A-Za-z0-9_]+$/', $value ) ? $value : '';
	}

	/**
	 * A hex string of an exact length, or ''. For tokens and digests.
	 *
	 * Lower-cased on the way out, so a value that round-trips through a
	 * database comparison matches whichever case it arrived in.
	 *
	 * @since 1.0.0
	 *
	 * @param string $value  Untrusted hex.
	 * @param int    $length Exact number of characters required.
	 *
	 * @return string The lower-cased hex, or ''.
	 */
	public static function hex( string $value, int $length ): string {
		$value = trim( $value );

		return preg_match( '/^[a-f0-9]{' . $length . '}$/i', $value ) ? strtolower( $value ) : '';
	}

	/**
	 * An integer clamped to a range.
	 *
	 * Clamped rather than rejected: a page number of 10,000,000 is somebody
	 * fuzzing, and answering with the last page is a better response than an
	 * error page that tells them the query ran.
	 *
	 * @since 1.0.0
	 *
	 * @param mixed $value   Untrusted value.
	 * @param int   $min     Lower bound.
	 * @param int   $max     Upper bound.
	 * @param int   $default Returned when the value is not numeric at all.
	 *
	 * @return int
	 */
	public static function int( mixed $value, int $min, int $max, int $default = 0 ): int {
		if ( ! is_numeric( $value ) ) {
			return $default;
		}

		return max( $min, min( $max, (int) $value ) );
	}

	/**
	 * One of a fixed set, or a default.
	 *
	 * The allow-list form of validation, which is the only one that works for
	 * values that reach SQL as identifiers — a sort column, a table alias.
	 * See the paginate library for what that looks like in practice.
	 *
	 * @since 1.0.0
	 *
	 * @param string             $value   Untrusted value.
	 * @param array<int, string> $allowed Permitted values.
	 * @param string|null        $default Returned when it is not one. Falls
	 *                                    back to the first permitted value.
	 *
	 * @return string
	 */
	public static function one_of( string $value, array $allowed, ?string $default = null ): string {
		return in_array( $value, $allowed, true ) ? $value : ( $default ?? $allowed[0] );
	}
}
