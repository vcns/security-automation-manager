# DNS Provider Test Evidence Matrix

Tracks, per registered DNS-01 provider driver, exactly what has and has not
been verified. Two columns are kept strictly separate and must never be
conflated:

- **Mocked-contract coverage** — request-level PHPUnit tests against
  `test/bootstrap.php`'s WordPress stubs. WordPress HTTP API calls are
  intercepted by the test stubs, so these provider-contract tests cannot
  contact external HTTP services. The separately disclosed RFC 2136 test
  still performs a refused loopback TCP connection to `127.0.0.1:1`
  (described under RFC 2136 below). Passing here proves the driver builds
  the request it claims to build and reacts correctly to the responses
  it's given. It does **not** prove the real provider API still behaves
  the way the fixture assumes.
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
| digitalocean | ✅ | ✅ (Phase 6C Batch 2, `ProviderContractDigitaloceanTest`) | ❌ | 2 |
| vultr | ✅ | ✅ (Phase 6C Batch 2, `ProviderContractVultrTest`) | ❌ | 2 |
| namecom | ✅ | ✅ (Phase 6C Batch 2, `ProviderContractNamecomTest`) | ❌ | 2 |
| easydns | ✅ | ✅ (Phase 6C Batch 2, `ProviderContractEasydnsTest`) | ❌ | 2 |
| hetzner | ✅ | ✅ (Phase 6C Batch 2, `ProviderContractHetznerTest`) | ❌ | 2 |
| bunny | ✅ | ✅ (Phase 6C Batch 2, `ProviderContractBunnyTest`) | ❌ | 2 |
| domeneshop | ✅ | ✅ (Phase 6C Batch 2, `ProviderContractDomeneshopTest`) | ❌ | 2 |
| vercel | ✅ | ✅ (Phase 6C Batch 2, `ProviderContractVercelTest`) | ❌ | 2 |
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

**41/41** have registry/metadata coverage. **16/41** have mocked-contract
(request-level) coverage. **0/41** have live verification.

### Notes

- **desec, gandi, godaddy, ns1, digitalocean, vultr, namecom, easydns,
  vercel** (confirmed production defect, not fixed in the test-only Batch
  1/Batch 2 PRs): each driver's `zone()` wraps every per-candidate lookup
  in a try/catch that treats *any* response status >= 400 as "not this
  candidate, try the next one." An authentication failure (401/403) during
  zone discovery is therefore indistinguishable from a genuine 404 and,
  once every candidate is exhausted, surfaces as the same generic
  "no domain/zone found for {fqdn}" diagnostic a real zone-not-found would
  produce — discarding the actual cause. An operator with a revoked or
  mis-scoped token sees a message suggesting a DNS/zone configuration
  problem, not an authentication problem. Proven precisely by
  `test_authentication_failure_during_zone_discovery_is_misreported_as_zone_not_found()`
  in each of the nine fixtures (asserts both the misleading message text
  and that no write request is attempted). Batch 2 confirms this is a
  recurring pattern across the try/catch-shaped zone-discovery family, not
  an isolated Batch 1 issue — the same fix, if authorised, would need to
  land across all nine drivers together. Per the standing rule, production
  defects are corrected only through an explicit regression test plus a
  clearly disclosed, separate change — not silently, and not mixed into
  batch coverage work.
- **hetzner, bunny, domeneshop** (contrast finding, not a defect): these
  three drivers discover their zone via a client-side filter over a 200
  response's body (matching Cloudflare's/Scaleway's shape) with *no*
  try/catch around the lookup at all. A 401/403 on the very first
  zone-discovery candidate therefore propagates immediately and directly
  as the shared `request()` helper's own distinct "API error (HTTP 401)"
  message — it is never retried against further candidates, and never
  collapsed into a "zone not found" diagnostic. Proven by
  `test_authentication_failure_during_zone_discovery_surfaces_distinctly_not_as_zone_not_found()`
  in each of the three fixtures, deliberately included to confirm the test
  framework distinguishes real defects from correct behaviour rather than
  flagging every provider uniformly.
- **Batch 2 pagination findings, verified per provider against each
  API's current authoritative documentation** (2026-08-20) rather than
  treated as one uniform limitation. `delete_txt_record()`'s record-listing
  call was checked against each provider's own docs for a real,
  documented pagination mechanism (page/cursor/limit parameters and a
  way to fetch subsequent pages); a record absent from whatever this
  driver actually fetches is, in every case, silently left undeleted with
  no error surfaced. Whether that is an actionable defect depends
  entirely on whether the endpoint truly paginates:

  - **Confirmed pagination defect — digitalocean**: the List All Domain
    Records endpoint documents `per_page` (1–200, default 20), `page`,
    and a `name` filter for narrowing results to a single record name
    ([DigitalOcean API documentation](https://docs.digitalocean.com/products/networking/dns/reference/api/domain-records/)).
    The driver sends `per_page=200` (the documented maximum) but never
    follows a further page, and never uses the documented `name` filter
    that would make the whole risk moot. A matching record beyond the
    first 200 remains undeleted.
  - **Confirmed pagination defect — vultr**: Vultr's v2 API documents
    cursor-based pagination (`per_page` plus a `meta.links.next`/`prev`
    cursor) as a platform-wide convention for all v2 list endpoints,
    including the domain-records list; the driver sends `per_page=500`
    but never follows `meta.links.next`. Verified via Vultr's own
    published API documentation (`vultr.com/api`, `docs.vultr.com`);
    direct automated retrieval of the specific endpoint page was blocked
    (403/404), so this rests on the platform-wide pagination convention
    Vultr documents for this endpoint's own API family rather than a
    single directly-quoted endpoint page.
  - **Confirmed pagination defect — vercel**: the List existing DNS
    records endpoint documents `limit` (default 20), and `since`/`until`
    timestamp cursors, returning a `pagination.next`/`prev` object when
    more records exist than fit in one page
    ([Vercel API documentation](https://vercel.com/docs/rest-api/reference/endpoints/dns/list-existing-dns-records)).
    The driver sends `?limit=100` but never uses `since`/`until` to fetch
    a further page.
  - **No pagination mechanism applicable — domeneshop**: the official API
    docs ([api.domeneshop.no/docs](https://api.domeneshop.no/docs/))
    document only `host` and `type` filter parameters for the DNS records
    list endpoint — no page, cursor, or limit parameter exists at all.
    The fixture's test proves absent-record handling for a
    server-filtered query, not an ignored pagination cursor, and is named
    accordingly.
  - **No pagination mechanism applicable — bunny**: confirmed directly
    against Bunny's published OpenAPI reference — `GET /dnszone/{id}` is a
    single-resource fetch (a zone detail object) whose embedded `Records`
    array carries no pagination parameters, and no separate paginated
    records-listing endpoint exists. The fixture's test proves
    absent-record handling within that one response, not an ignored
    pagination cursor, and is named accordingly.
  - **[Unverified] — namecom**: name.com's docs confirm `perPage`/`page`
    pagination as a general convention for "List functions" platform-wide,
    but no source located (including two direct fetches of name.com's own
    primary documentation) explicitly confirms whether the
    `/v4/domains/{domainName}/records` endpoint specifically is paginated
    or returns every record in one response.
  - **[Unverified] — easydns**: easyDNS's REST API documentation is not
    publicly accessible (`docs.rest.easydns.net` did not resolve; search
    results indicate API documentation access requires a request/account),
    so no authoritative statement about pagination on
    `/zones/records/all/{domain}` could be established.
  - **[Unverified] — hetzner**: Hetzner's public API documentation URL
    (`dns.hetzner.com/api-docs`) now redirects to a login-required
    console page rather than a publicly accessible reference. Third-party,
    non-authoritative sources (community client libraries, a generated
    doc derived from an older copy of the OpenAPI spec) describe a
    `page`/`per_page`/`next_page` pagination structure with a default
    `per_page` of 25 for Hetzner's list endpoints generally, which would
    make this a real risk for the `/records` list endpoint if accurate —
    but this could not be confirmed against Hetzner's current, official
    documentation.

  Test method names reflect this: `test_pagination_only_fetches_a_single_page_of_records()`
  is used only for digitalocean/vultr/vercel, where a real, documented
  pagination mechanism is confirmed ignored. The namecom/easydns/hetzner
  fixtures use the same assertion but under a neutral name (renamed away
  from "pagination" pending the [Unverified] classification above), and
  bunny/domeneshop's tests were already named around absent-record
  handling rather than pagination. None of this is fixed here — per the
  standing rule, production defects are corrected only through an
  explicit regression test plus a clearly disclosed, separate change.
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
