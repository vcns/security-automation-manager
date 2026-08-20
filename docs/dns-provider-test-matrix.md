# DNS Provider Test Evidence Matrix

Tracks, per registered DNS-01 provider driver, exactly what has and has not
been verified. Two columns are kept strictly separate and must never be
conflated:

- **Mocked-contract coverage** — request-level PHPUnit tests against
  `test/bootstrap.php`'s WordPress stubs. No real network call is possible
  from this suite (see `test/bootstrap.php` — WordPress core is never
  loaded, and the only real network activity anywhere in the suite is one
  disclosed loopback-only TCP attempt to `127.0.0.1:1`, described under
  RFC 2136 below). Passing here proves the driver builds the request it
  claims to build and reacts correctly to the responses it's given. It
  does **not** prove the real provider API still behaves the way the
  fixture assumes.
- **Live verification** — a real issuance/deletion cycle run against the
  real provider API with real credentials and a real DNS zone. As of this
  writing **no provider has live verification**; it was explicitly
  deferred pending suitable test zones, credentials, and authorisation
  (Cloudflare, Route53, DigitalOcean, Google Cloud DNS, and Azure DNS are
  the five providers slated for manual staging verification once that is
  authorised).

A provider with mocked-contract coverage and no live verification should
be reported as exactly that — "request-level behaviour verified against
stubs; not yet verified against the live API" — never as "verified" or
"tested" without the qualifier.

## Status

| Provider | Registry/metadata | Mocked-contract (request-level) | Live verification | Batch |
|---|---|---|---|---|
| cloudflare | ✅ | ✅ (Phase 6B, `ProviderContractCloudflareTest`) | ❌ | — |
| route53 | ✅ | ✅ (Phase 6B, `ProviderContractRoute53Test`) | ❌ | — |
| google-cloud | ✅ | ✅ (Phase 6B, `ProviderContractGoogleCloudTest`) | ❌ | — |
| desec | ✅ | ✅ (Phase 6C Batch 1, `ProviderContractDesecTest`) | ❌ | 1 |
| gandi | ✅ | ✅ (Phase 6C Batch 1, `ProviderContractGandiTest`) | ❌ | 1 |
| godaddy | ✅ | ✅ (Phase 6C Batch 1, `ProviderContractGodaddyTest`) | ❌ | 1 |
| ns1 | ✅ | ✅ (Phase 6C Batch 1, `ProviderContractNs1Test`) | ❌ | 1 |
| scaleway | ✅ | ✅ (Phase 6C Batch 1, `ProviderContractScalewayTest`) | ❌ | 1 |
| digitalocean | ✅ | ⏳ not yet | ❌ | 2 |
| vultr | ✅ | ⏳ not yet | ❌ | 2 |
| namecom | ✅ | ⏳ not yet | ❌ | 2 |
| easydns | ✅ | ⏳ not yet | ❌ | 2 |
| hetzner | ✅ | ⏳ not yet | ❌ | 2 |
| bunny | ✅ | ⏳ not yet | ❌ | 2 |
| domeneshop | ✅ | ⏳ not yet | ❌ | 2 |
| vercel | ✅ | ⏳ not yet | ❌ | 2 |
| ionos | ✅ | ⏳ not yet | ❌ | 3 |
| linode | ✅ | ⏳ not yet | ❌ | 3 |
| netlify | ✅ | ⏳ not yet | ❌ | 3 |
| powerdns | ✅ | ⏳ not yet | ❌ | 3 |
| dynu | ✅ | ⏳ not yet | ❌ | 3 |
| dnsimple | ✅ | ⏳ not yet | ❌ | 4 |
| dnsmadeeasy | ✅ | ⏳ not yet | ❌ | 4 |
| porkbun | ✅ | ⏳ not yet | ❌ | 4 |
| acmedns | ✅ | ⏳ not yet | ❌ | 5 |
| dreamhost | ✅ | ⏳ not yet | ❌ | 5 |
| joker | ✅ | ⏳ not yet | ❌ | 5 |
| cloudns | ✅ | ⏳ not yet | ❌ | 5 |
| namesilo | ✅ | ⏳ not yet (see note) | ❌ | 5 |
| dnspod | ✅ | ⏳ not yet | ❌ | 5 |
| glesys | ✅ | ⏳ not yet | ❌ | 6 |
| njalla | ✅ | ⏳ not yet | ❌ | 6 |
| netcup | ✅ | ⏳ not yet | ❌ | 6 |
| alidns | ✅ | ⏳ not yet | ❌ | 6 |
| akamai | ✅ | ⏳ not yet | ❌ | 7 |
| ovh | ✅ | ⏳ not yet | ❌ | 7 |
| namecheap | ✅ | ⏳ not yet | ❌ | 7 |
| azure | ✅ | ⏳ not yet | ❌ | 7 |
| mythicbeasts | ✅ | ⏳ not yet | ❌ | 7 |
| inwx | ✅ | ⏳ not yet | ❌ | 7 |
| rfc2136 | ✅ | ⚠️ partial — see note | ❌ | separate |

**41/41** have registry/metadata coverage. **8/41** have mocked-contract
(request-level) coverage. **0/41** have live verification.

### Notes

- **namesilo**: the Phase 6C classification pass flagged a possible
  create/delete asymmetry at `includes/certificates/providers/class-provider-namesilo.php:56`
  (`delete_txt_record()` appears to match `<host>` against the full FQDN
  while `create_txt_record()` submits a zone-relative name). Not yet
  confirmed as a live bug. Batch 5 will include a targeted regression test
  to confirm or rule this out before any production fix is made, per the
  standing rule that production defects are corrected only through an
  explicit regression test plus a clearly disclosed change — never silently.
- **rfc2136**: out of scope for the HTTP-transport contract framework —
  it speaks raw DNS over `stream_socket_client()`, never any `wp_remote_*`
  function, so `Dns_Provider_Contract_TestCase` does not apply. One real
  (disclosed, loopback-only) connection-failure test already exists
  (`CertificateManagerTest::test_dns_provider_transport_failure_is_recorded_as_a_failed_run`,
  Phase 6A, attempts a real TCP connect to `127.0.0.1:1` which is
  immediately refused). A dedicated controlled local socket-level test
  harness — covering successful TXT add/delete, TSIG authentication,
  and failure paths — is a separate, not-yet-built deliverable required
  before Phase 6C can be marked complete.

This matrix is updated with every Phase 6C batch PR.
