# web-security

Signed-cookie sessions for a single shared password, CSRF tokens with nothing
to store, and keyed hashing for the values an application has to compare but
should never be able to read back.

Three classes. No framework, no container, no middleware stack.

For cleaning and validating the input itself, see
[sanitize](https://github.com/sugarcommerce/sanitize), which this deliberately
does not depend on.

```bash
composer require sugarcommerce/web-security
```

## Hash

For values you have to store in order to count, compare or rate-limit, but have
no business being able to read back.

```php
use SugarCommerce\WebSecurity\Hash;

$hash = new Hash( $secret );

$hash->ip( $request_ip );         // store this, not the address
$hash->opaque( $user_agent );
$hash->matches( $ip, $stored );   // constant time
```

Keyed, and that is the entire point. IPv4 is four billion values, so an unkeyed
SHA-256 of an address is reversed by brute force in seconds — the digest is
still personal data, and storing it satisfies no data protection officer.
Keyed, it only ever compares equal to itself, which is all that counting
distinct visitors needs, and it is worthless to whoever takes the table without
the secret.

An empty value hashes to `''`, not to a digest of the empty string, which would
otherwise compare equal across every row that had no address.

Not for API keys — those are looked up *by* their digest, so the digest cannot
depend on a secret the finder might not have; use
`SugarCommerce\Generate\Token::digest()`. Not for passwords either; those want
a slow hash.

## Session

One password, no users table.

```php
use SugarCommerce\WebSecurity\Session;

$session = new Session( $password, subject: 'operator' );

if ( $session->authenticate( $submitted ) ) {
    setcookie( Session::COOKIE, $session->issue(), $session->cookie_options( $is_https, '/admin' ) );
}

$session->valid( $_COOKIE[ Session::COOKIE ] ?? '' );
```

A session can carry claims — who it belongs to, rather than only which role it
is:

```php
$cookie = $session->issue( array( 'e' => 'jordan@example.com' ) );
$token  = $session->read( $cookie );

$token instanceof Token ? $token->get( 'e' ) : null;
```

They are signed with the rest of it, so the browser holding the cookie cannot
edit them — but they are not secret, and anybody with the cookie can read them.
A claim is an identifier, never a credential. `sub` is reserved and always wins,
so a caller cannot pass one to mint another role's session.

A signed cookie rather than a PHP session: nothing on disk to clean up, nothing
shared between workers, nothing to make sticky behind a load balancer. Rotating
the password ends every existing session for free, because the signing key is
derived from it.

The signing is [signed-tokens](https://github.com/sugarcommerce/signed-tokens)
rather than a hand-rolled HMAC, which buys two things beyond tidiness. The
signature is checked before the expiry, so a forged cookie can never come back
as "expired" and tell its forger the structure was right. And what is signed is
namespaced, so a token minted elsewhere in the same application can never be
presented as a session.

Where the difference is visible to the person, read the reason:

```php
use SugarCommerce\SignedTokens\Reason;

match ( true ) {
    $session->read( $cookie ) instanceof Token => $panel,
    Reason::Expired === $session->read( $cookie ) => 'Your session expired. Sign in again.',
    default => 'Sign in.',
};
```

Scope the cookie by path rather than leaving it at `/`. Where several surfaces
share one hostname, a root cookie is sent on every public request too — needless
exposure at best, and at worst it is what an XSS on a public page reaches for.

With no password set, `configured()` is false and every check fails closed. An
application may then fall back to something else — localhost-only access during
development is the usual one — but that is its decision to make explicitly.

## Csrf

```php
use SugarCommerce\WebSecurity\Csrf;

$csrf = new Csrf( $token_secret, Session::COOKIE );

echo $csrf->field();                       // hidden input, escaped

if ( ! $csrf->verify( $request->input( Csrf::FIELD ) ) ) {
    http_response_code( 403 );
}
```

The token is an HMAC of the session cookie under a server secret, so there is
nothing to store and nothing to expire separately: it rotates when the session
does, and a restarted server does not sign everyone out of their half-filled
forms.

That works because the cookie is HttpOnly — a malicious cross-origin page
cannot read it, so it cannot derive the token. `SameSite=Lax` alone is not
enough; it still permits top-level cross-origin POSTs in some browsers, which
is exactly the shape of a form-submit attack.

Key it on a general token secret rather than the password behind the session,
so rotating one does not silently invalidate the other.

Exempt the login form. There is no session yet, and forging a login only forces
the victim to submit a password the attacker does not have.

An empty token means *always fail*, never *no check needed*. `verify()` already
reads it that way; anything calling `token()` directly has to make the same
choice.

## Sealing values at rest

```php
use SugarCommerce\WebSecurity\{Hash, Sealer};

$sealer = new Sealer( $data_key, 'emails' );
$index  = new Hash( $data_key );

$row = array(
    'email'      => $sealer->seal( $email ),          // s1.… — useless without the key
    'email_hash' => $index->opaque( strtolower( $email ) ), // what lookups compare
);

$email = $sealer->reveal( $row['email'] );             // opens sealed, passes plain through
```

libsodium secretbox (authenticated), a fresh nonce per seal, a key derived per context. Keep the key in configuration, never beside the data: a stolen database or backup is then ciphertext. `reveal()` lets a column be sealed gradually — sealed values open, plain ones pass through, and a value that will not open reads as `''` rather than as ciphertext.

## Testing

```bash
composer test
```

## License

GPL-2.0-or-later
