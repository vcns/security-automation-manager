# TLS Certificates (ACME / Let's Encrypt)

Security Automation Manager can request, validate, and renew TLS certificates
from Let's Encrypt (or any RFC 8555 ACME v2 directory) entirely from inside
WordPress - no shell access, no daemons, no certbot. This document explains
how the pieces fit, and - critically - what the plugin **can and cannot do on
your hosting platform**.

> **ACME v1 note:** there is no ACME v1 support and there never will be.
> Let's Encrypt switched its v1 endpoints off in June 2021. What is often
> called "the HTTP fallback" is the **http-01 challenge type inside ACME v2**,
> which this plugin fully supports.

## How it works

1. **Account** - an ACME account key (EC P-256) is generated on first use and
   registered with the CA. Staging and production use separate accounts.
2. **Order** - one order covers every domain you list; the first name becomes
   the certificate's Common Name, all of them appear as Subject Alternative
   Names.
3. **Challenges** - for each name the CA demands proof of control:
   - **dns-01** (preferred; required for wildcards): the plugin creates a
     `_acme-challenge` TXT record through your DNS provider's API, waits for
     propagation, then removes it afterwards. **41 built-in providers**:

     AWS Route 53, Azure DNS, Google Cloud DNS, Cloudflare, Akamai Edge DNS,
     Alibaba Cloud DNS, Bunny.net, ClouDNS, deSEC, DigitalOcean, DNSimple,
     DNS Made Easy, DNSPod, Domeneshop, DreamHost, Dynu, easyDNS, Gandi
     (LiveDNS), GleSYS, GoDaddy, Hetzner DNS, INWX, IONOS, Joker.com,
     Linode/Akamai, Mythic Beasts, Namecheap, Name.com, NameSilo, netcup,
     Netlify, Njalla, NS1, OVH, Porkbun, PowerDNS (self-hosted), Scaleway,
     Vercel, Vultr - plus two universal mechanisms:

     - **acme-dns** (CNAME delegation): point a single
       `_acme-challenge` CNAME at an acme-dns instance once, and every
       challenge is fulfilled there - **works with any DNS provider on the
       planet**, including ones with no API at all.
     - **RFC 2136 dynamic updates** (TSIG-signed): any self-hosted or
       enterprise authoritative server - BIND, Knot, PowerDNS, Windows
       Server DNS - no vendor API needed.

     Anything still not covered can be added by any plugin through the
     `wp_sam_dns_providers` filter (one small class: label, credential
     fields, create/delete TXT).
   - **http-01** (automatic fallback when no DNS provider is configured): the
     plugin answers `/.well-known/acme-challenge/<token>` itself, before
     WordPress routing, so it works with or without pretty permalinks. The CA
     must be able to reach the site on port 80. Wildcard names cannot be
     validated this way.
4. **Issuance** - a CSR is generated (ECDSA P-256 by default, RSA-2048
   selectable), finalized, and the full chain downloaded.
5. **Storage** - the private key is encrypted at rest (sodium secretbox)
   before it touches the database. Define `WP_SAM_CERT_VAULT_KEY` in
   `wp-config.php` to keep the vault key out of the database entirely
   (recommended; any long random string).
6. **Renewal** - a daily WP-Cron task re-issues production certificates
   inside the 30-day window before expiry.

## ⚠ Installing the certificate: platform-dependent

**Issuing** a certificate is pure PHP and works everywhere. **Installing** it
into the web server is where platforms diverge, because the server's TLS
configuration is not writable by the PHP user and reloading the server
requires privileges PHP does not have - this is a privilege boundary, not an
Apache limitation.

Automatic installation therefore depends entirely on which hosting platform
you use, and specifically on whether it exposes an installation API such as
**cPanel's UAPI `SSL::install_ssl`**. The plugin ships three deployment
modes; pick the one that matches your platform, and treat the steps below as
the *basic* shape - control panels vary between versions and hosts.

### cPanel (including most LiteSpeed shared hosting) - automatic

1. In cPanel: **Security → Manage API Tokens → Create**. The token only needs
   SSL feature access.
2. In the plugin's Certificates page choose **Deployment: cPanel UAPI
   install_ssl** and enter the host (`server.example.net:2083`), your cPanel
   username, and the token.
3. Every issue/renewal calls `SSL::install_ssl` for the first listed domain.
   Nothing else to do.

Caveat: some resellers disable API tokens or the SSL UAPI module; if the
deploy step fails with an authorization error, that is a host policy issue,
not a plugin one. Note also that hosts running **AutoSSL** may already renew
certificates for you - check before doubling up.

### Plesk - semi-automatic

Plesk has its own REST API (`/api/v2/domains/{id}/certificates`), which this
plugin does not call yet. Use **Export** mode and either:

- upload the PEMs under **Websites & Domains → SSL/TLS Certificates**, or
- script the Plesk CLI on the host: `plesk bin certificate --update` pointing
  at the exported `privkey.pem`/`fullchain.pem`.

### DirectAdmin - semi-automatic

Use **Export** mode and paste the PEMs under **SSL Certificates**, or script
`/CMD_API_SSL` with a login key if your host allows API access.

### Self-managed Apache / nginx / LiteSpeed (root access) - export + hook

1. Choose **Deployment: Export** and set a directory **outside the web root**
   (the plugin refuses paths under it), e.g. `/home/account/ssl-drop`.

   Requirements for the path - ultimately all this mode needs is a path and
   write permission to it:
   - **Outside the document root.** The private key must never be reachable
     over HTTP; the plugin enforces this rather than trusting a deny rule.
     A sibling directory of the web root is the usual choice (web root
     `/home/account/public_html` → export `/home/account/ssl-drop`).
   - **Writable by the PHP user** the site runs as. The plugin creates the
     directory itself when it can; otherwise create it once via SSH, SFTP,
     or the control panel file manager one level above the web root.
     `privkey.pem` is written `0600` (best effort - some hosts ignore chmod).
   - **Don't know the paths, or can't write outside the web root?** Ask
     your hosting provider - this is a routine request. Word it as:
     *"Please give me a directory outside the document root that PHP can
     write to, for storing TLS certificate files"* - and while you have
     them, ask **(a)** whether they can install the certificate from that
     directory on renewal (the cron hook below, run by them), or **(b)**
     whether they can issue an API credential (e.g. a cPanel API token)
     instead, which upgrades you to the fully automatic deployment mode.
2. Install a small root-side cron that watches the drop directory and
   installs on change - the plugin does 95% of the work, root does the last
   copy + reload:

   ```bash
   #!/bin/sh
   # /etc/cron.daily/install-wp-sam-cert
   DROP=/home/account/ssl-drop
   LIVE=/etc/ssl/site
   if [ "$DROP/fullchain.pem" -nt "$LIVE/fullchain.pem" ]; then
     install -m 600 "$DROP/privkey.pem"   "$LIVE/privkey.pem"
     install -m 644 "$DROP/fullchain.pem" "$LIVE/fullchain.pem"
     apachectl graceful   # or: nginx -s reload / systemctl reload lsws
   fi
   ```

3. Point your vhost at `$LIVE/fullchain.pem` / `$LIVE/privkey.pem` once.

### Anything else - manual download

**Download** mode issues and stores the certificate; fetch `fullchain.pem`
and `privkey.pem` from the Certificates page and install them wherever your
platform expects. Renewal still happens automatically - only the final
install step is yours.

## Scheduling and WP-Cron reality

Renewal checks ride WP-Cron, which only fires when the site receives
traffic. A quiet staging site can sleep straight through a renewal window.
Point a real cron at WP-Cron and the problem disappears:

```
*/15 * * * * curl -s https://example.com/wp-cron.php?doing_wp_cron > /dev/null
```

(and optionally `define( 'DISABLE_WP_CRON', true );` in `wp-config.php` so
page loads stop double-firing it).

## FAQ

### Does HTTP-01 work with HSTS / hstspreload.org?

Yes - this looks contradictory but isn't. HSTS (and browser preload lists)
is a **browser** policy: it makes *browsers* refuse plain-HTTP connections.
ACME validation servers are not browsers and do not honour HSTS. Let's
Encrypt's HTTP-01 validator deliberately makes its first request over
`http://` on port 80 and **follows redirects, including to HTTPS** - which
is exactly what an HSTS-enabled site serves on port 80 (the 301 to HTTPS is
how browsers get the HSTS header in the first place). This plugin's token
responder answers on either scheme, so the redirect chain resolves cleanly.

The only configuration that genuinely breaks HTTP-01 is a **firewalled or
closed port 80**. If you cannot keep port 80 open (even just to redirect),
use DNS-01.

### Can I supply my own private key?

Yes - Configuration → "Bring your own private key". Paste an unencrypted
PEM key; it is validated before saving, stored encrypted at rest, and
reused for every order (overriding the key-type choice). Generate one with:

```bash
# ECDSA P-256 (recommended)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out privkey.pem
# or RSA 2048
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out privkey.pem
```

Note the boundary: supplying a key removes the *key generation* dependency,
but the **openssl PHP extension is still required** - every ACME API call
must be cryptographically signed, and that signing happens in PHP. If
ext/openssl is missing entirely (the Certificates page will tell you),
certificate automation cannot run; ask your host to enable it.

## Testing safely

Keep the **staging** toggle on until an order succeeds end-to-end. Let's
Encrypt production rate limits are strict (5 duplicate certificates per
week; failed validations are limited too); the staging directory is for
exactly this. Staging certificates are not trusted by browsers - that is
expected.

## Security notes

- DNS API credentials are **domain-takeover-grade secrets**. Use the
  narrowest scope your provider offers (e.g. a Cloudflare token restricted
  to Zone → DNS → Edit on one zone), and rotate them if you ever remove the
  plugin without uninstalling cleanly.
- All secrets (DNS credentials, cPanel token, private keys, account keys)
  are sealed with sodium `crypto_secretbox` before storage. Define
  `WP_SAM_CERT_VAULT_KEY` in `wp-config.php` so a database dump alone can
  never yield key material. Rotating this constant, or WordPress's own
  `AUTH_KEY`/`AUTH_SALT`, invalidates every already-sealed secret with no
  automatic recovery -- see `docs/credential-vault-assessment.md` before
  changing either.
- The private-key download link is audit-logged at warning severity.

## Need a second pair of eyes?

Certificate automation touches DNS control, privileged host configuration,
and the trust anchor of your entire site - it is worth getting right the
first time. **VCNS Tech Ltd** (the team behind this plugin) offers
fixed-scope security consultation engagements covering:

- end-to-end certificate automation wired up for your specific hosting
  platform (cPanel, Plesk, self-managed, or behind Cloudflare),
- security header rollout and CSP enforcement using this plugin's full
  workflow, and
- broader WordPress hardening and hosting-platform security reviews.

If you would rather have a security engineer own this than burn an
afternoon on it: **[vcns.tech](https://vcns.tech/?utm_source=wp-sam&utm_medium=docs&utm_campaign=certificates)**.
