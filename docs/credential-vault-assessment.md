# Credential Vault: Key Derivation Assessment

## Purpose

`WP_SAM\Certificates\Credential_Vault` (`includes/certificates/class-credential-vault.php`)
encrypts DNS-provider/cPanel credentials and certificate private keys at
rest, using libsodium's XSalsa20-Poly1305 secretbox with a key derived by
`hash('sha256', 'wp-sam-cert-vault|' . $source, true)`.
`docs/consolidation-ledger.md` flagged this derivation as "a bare SHA-256
hash rather than a proper KDF (Argon2/HKDF)" and worth a deliberate
decision rather than an inherited one. This document is that decision.

**Conclusion up front: the current derivation is not changed by this
review, and should not be changed without the migration and recovery
process described at the end of this document.** SHA-256 is not the wrong
primitive here — see "Why Argon2 doesn't apply" below — but the operational
gaps around rotation and recovery are real and are recorded as follow-up
work, not fixed in this pass (Phase 3 of the consolidation effort is scoped
to a small hardening PR, not a vault redesign).

## The six factors

### 1. Entropy of `WP_SAM_CERT_VAULT_KEY`

Administrator-supplied, via a `wp-config.php` constant. No minimum length
or format is enforced by `Credential_Vault::key()` — it accepts whatever
string is defined, the same trust model WordPress itself uses for
`AUTH_KEY`/`AUTH_SALT`. When set to a properly random value (the documented
recommendation, e.g. output from WordPress.org's own secret-key API or
`wp_generate_password( 64, true, true )`), entropy is effectively as high as
the input length allows — a 64-character value drawn from a large charset
comfortably exceeds the 256 bits `sodium_crypto_secretbox` needs. When set
to something an administrator typed by hand, entropy could be arbitrarily
low. This is an administrator-configuration risk, not a defect in the
derivation itself, and matches the trust model of every other WordPress
secret constant.

### 2. Entropy of `wp_salt('auth')`

Falls back to WordPress's own `AUTH_KEY`/`AUTH_SALT` constants when defined
(the WordPress.org norm — the installer and most host provisioning flows
populate these from WordPress.org's secret-key API, which generates
cryptographically-random 64-character values), or to a value WordPress
itself generates and stores in `wp_options` when they're absent. In a
normally-provisioned site this is high-entropy. It is not a value this
plugin controls or can verify the quality of; it inherits WordPress core's
own security posture for this value, the same as every other WordPress
subsystem that derives keys from the auth salts (nonces, auth cookies).

### 3. Domain separation

Present, via the literal prefix `'wp-sam-cert-vault|'` concatenated before
hashing. This ensures the derived key differs from any other value derived
from the same underlying secret by WordPress core or another plugin using
the same naive prefix-then-hash pattern, as long as no other consumer
happens to use the identical prefix string — vanishingly unlikely for a
plugin-specific, namespaced string. `wp_salt('auth')` is a single
high-entropy secret already reused by WordPress core for an unrelated
purpose (auth cookie hashing); domain-separating a *new* derived use from
that existing use is exactly what this prefix does, and is the load-bearing
property here — not the specific hash function.

### 4. Existing ciphertext compatibility

Every currently-sealed value carries a `sam-v1:` prefix and was encrypted
under the key this exact derivation produces. **Any change to `key()`'s
inputs, prefix string, or hash function invalidates every previously-sealed
DNS-provider credential, cPanel token, ACME account key, and certificate
private key already stored** — `sodium_crypto_secretbox_open` fails
authentication under a different key, `open()` returns `null`, and current
call sites coerce that to an empty string. A site with certificates already
issued and DNS credentials already configured would silently lose access to
all of them on upgrade if the derivation changed without a migration. This
is the primary reason this document does not recommend a change without one.

### 5. Rotation requirements

None exist today, by design or otherwise. There is no dual-key transition
period, no re-encryption utility, and no way to rotate `WP_SAM_CERT_VAULT_KEY`
(or have `wp_salt('auth')` rotate, which can happen as a side effect of a
site migration or a security-conscious admin manually regenerating
`AUTH_KEY`/`AUTH_SALT`) without losing every secret sealed under the
previous key. The class docblock already anticipates rotation as an admin
action ("a full-files+database leak of a *backup* taken before the constant
was rotated") without actually supporting it in code.

### 6. Recovery behaviour

`open()` fails closed: a wrong key or tampered ciphertext returns `null`,
never a partial or garbage plaintext, and never a crash. Current call sites
(`Certificate_Store`, DNS-provider config) coerce a `null` decrypt to an
empty string. This is the secure choice, but it has an operational cost:
**a field that fails to decrypt because the vault key changed is
indistinguishable in the admin UI from a field that was simply never
configured.** An administrator who rotates `AUTH_KEY`/`AUTH_SALT` for
unrelated reasons (a reasonable, commonly-recommended security practice)
gets no warning that their DNS credentials and certificate private keys are
now gone — only silently blank fields, discovered whenever the next
renewal attempt fails.

## Why Argon2 doesn't apply

Argon2 (and other password-hashing KDFs — bcrypt, scrypt, PBKDF2) exist to
slow down brute-force guessing of a *low-entropy secret*, typically a
human-chosen password. Both inputs here — `WP_SAM_CERT_VAULT_KEY` when set
as recommended, and `wp_salt('auth')` — are meant to already be
high-entropy random values, not guessable passwords. Applying a
deliberately-slow KDF to an already-random 256+ bit secret adds
computational cost (Argon2's whole design point) without adding security:
there is nothing to make brute-forcing harder when the input space is
already 2^256, and every certificate/credential decrypt during a renewal
run would pay that cost for no benefit. Argon2 would matter here only if
the derivation's actual entropy floor were the *administrator-chosen*
`WP_SAM_CERT_VAULT_KEY`, and only if that value were expected to sometimes
be low-entropy — which points at input validation (rejecting an
obviously-weak constant), not a slower hash function, as the fix for that
specific risk.

## Would HKDF be better than the current prefix-then-hash?

Marginally, and only on rigor grounds, not on any concrete attack this
review identified. HKDF (RFC 5869) is the purpose-built primitive for
"derive one or more keys from an existing high-entropy secret with domain
separation," and its `info` parameter formalizes exactly what the
`'wp-sam-cert-vault|'` prefix is doing informally. A `hash('sha256', info .
secret, true)` construction is not a known-broken pattern for this use case
(it is, in effect, a single-block HMAC-like construction over a
high-entropy key) but it is not the primitive a cryptography review would
sign off on as best-practice for anything more sensitive than this. If this
derivation is revisited, HKDF-SHA256 is the recommended replacement — but
only bundled with the migration in the next section, since it is a
ciphertext-breaking change identical in effect to any other derivation
change.

## If this is ever changed: required migration and recovery design

Per the decision that scoped this review: **do not change the derivation
format without this.** Any future change must include, before it ships:

1. A version marker on sealed values (the existing `sam-v1:` prefix can
   become `sam-v2:` for the new derivation) so old and new records can
   coexist during a transition.
2. An upgrade-time migration that reads every sealed value with the *old*
   derivation while the old key material is still available, and re-seals
   it under the *new* derivation — run once, logged to the audit log
   (success/failure per record), not left to happen lazily on next use
   (lazy re-seal would leave old-format records permanently stuck if they're
   never subsequently read/written).
3. Explicit handling for the case where the old key material is *already*
   gone at migration time (constant removed, salts already rotated before
   the plugin upgraded) — the migration must detect decrypt failure per
   record and report it, not silently drop the secret.
4. A tested recovery path: what an administrator does when the migration
   reports undecryptable records — at minimum, clear documentation that
   those specific credentials/keys must be re-entered, and which UI fields
   are affected.
5. Regression tests covering: migration with valid old-format data, migration
   after key material has already been lost (must fail loudly per record,
   not silently), and idempotency (running the migration twice must not
   double-encrypt or corrupt already-migrated records).

## Recommended follow-up (not implemented in this review)

Independent of any derivation change, the recovery-behaviour gap in item 6
is worth its own fix: distinguish "never configured" from "stored but
undecryptable" in the admin UI (Certificates > Configuration, and the
DNS-provider credential fields), so a vault-key rotation produces a visible
warning instead of silently blank fields. This does not require changing
the derivation or ciphertext format — it only requires `Credential_Vault`
or its callers to expose *why* a value came back empty, and is a smaller,
independently-shippable follow-up.
