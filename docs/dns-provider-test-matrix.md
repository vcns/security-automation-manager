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
| ionos | ✅ | ✅ (Phase 6C Batch 3, `ProviderContractIonosTest`) | ❌ | 3 |
| linode | ✅ | ✅ (Phase 6C Batch 3, `ProviderContractLinodeTest`) | ❌ | 3 |
| netlify | ✅ | ✅ (Phase 6C Batch 3, `ProviderContractNetlifyTest`) | ❌ | 3 |
| powerdns | ✅ | ✅ (Phase 6C Batch 3, `ProviderContractPowerdnsTest`) | ❌ | 3 |
| dynu | ✅ | ✅ (Phase 6C Batch 3, `ProviderContractDynuTest`) | ❌ | 3 |
| dnsimple | ✅ | ✅ (Phase 6C Batch 4, `ProviderContractDnsimpleTest`) | ❌ | 4 |
| dnsmadeeasy | ✅ | ✅ (Phase 6C Batch 4, `ProviderContractDnsmadeeasyTest`) | ❌ | 4 |
| porkbun | ✅ | ✅ (Phase 6C Batch 4, `ProviderContractPorkbunTest`) | ❌ | 4 |
| acmedns | ✅ | ✅ (Phase 6C Batch 5, `AcmednsProviderTest` -- bespoke, see note) | ❌ | 5 |
| dreamhost | ✅ | ✅ (Phase 6C Batch 5, `ProviderContractDreamhostTest`) | ❌ | 5 |
| joker | ✅ | ✅ (Phase 6C Batch 5, `ProviderContractJokerTest`) | ❌ | 5 |
| cloudns | ✅ | ✅ (Phase 6C Batch 5, `ProviderContractCloudnsTest`) | ❌ | 5 |
| namesilo | ✅ | ✅ (Phase 6C Batch 5, `ProviderContractNamesiloTest` -- see note, asymmetry confirmed NOT a defect) | ❌ | 5 |
| dnspod | ✅ | ✅ (Phase 6C Batch 5, `ProviderContractDnspodTest`) | ❌ | 5 |
| glesys | ✅ | ✅ (Phase 6C Batch 6, `ProviderContractGlesysTest`) | ❌ | 6 |
| njalla | ✅ | ✅ (Phase 6C Batch 6, `ProviderContractNjallaTest`) | ❌ | 6 |
| netcup | ✅ | ✅ (Phase 6C Batch 6, `ProviderContractNetcupTest`) | ❌ | 6 |
| alidns | ✅ | ✅ (Phase 6C Batch 6, `ProviderContractAlidnsTest` -- see note, unvalidated write responses) | ❌ | 6 |
| akamai | ✅ | ✅ (Phase 6C Batch 7, `ProviderContractAkamaiTest`) | ❌ | 7 |
| ovh | ✅ | ✅ (Phase 6C Batch 7, `ProviderContractOvhTest`) | ❌ | 7 |
| namecheap | ✅ | ✅ (Phase 6C Batch 7, `ProviderContractNamecheapTest`) | ❌ | 7 |
| azure | ✅ | ✅ (Phase 6C Batch 7, `ProviderContractAzureTest` -- see note, destructive delete) | ❌ | 7 |
| mythicbeasts | ✅ | ✅ (Phase 6C Batch 7, `ProviderContractMythicbeastsTest`) | ❌ | 7 |
| inwx | ✅ | ✅ (Phase 6C Batch 7, `ProviderContractInwxTest` -- see note, cookieless-login gap) | ❌ | 7 |
| rfc2136 | ✅ | ⚠️ partial — see note | ❌ | separate |

**41/41** have registry/metadata coverage. **40/41** have mocked-contract
(request-level) coverage — every provider except rfc2136 (partial, see
note). **0/41** have live verification.

### Notes

- **Auth-during-discovery misdiagnosis defect — complete, recalculated
  classification across all 40 mocked-contract providers** (last
  recalculated 2026-08-21, after Batch 7; see the correction note below
  the Batch 5 entry for the last classification-changing review). Every
  provider falls into exactly one of three groups:

  - **Confirmed defect — 19 providers**: desec, gandi, godaddy, ns1
    (Batch 1); digitalocean, vultr, namecom, easydns, vercel (Batch 2);
    dnsimple, dnsmadeeasy, porkbun (Batch 4); cloudns, namesilo, dnspod
    (Batch 5); glesys, netcup (Batch 6); akamai, namecheap (Batch 7). Three
    distinct code shapes produce the identical outcome:
    - deSEC-style (desec/gandi/godaddy/ns1/digitalocean/vultr/namecom/
      easydns/vercel/dnsimple/dnsmadeeasy/porkbun/glesys/netcup/akamai):
      `zone()` wraps every per-candidate lookup in a try/catch that treats
      *any* response status >= 400 (or, for netcup, any thrown `call()`
      failure — see below) as "not this candidate, try the next one." A
      genuine authentication failure (401/403) is caught identically to a
      404. glesys's own official Go client (`glesys-go`) confirms its API
      signals failure via real HTTP status codes, so this is the standard
      try/catch shape, not the in-band-body variant. netcup's `call()`
      explicitly validates a `status` field in the body for every
      operation (robust design), but a login failure inside its memoised
      session pre-step — structurally identical to dnsimple's `whoami()`
      (Batch 4) — is itself thrown from inside the same try/catch and
      retried once per candidate exactly like dnsimple's, since the
      session is only cached after a *non-throwing* login response.
      akamai's EdgeGrid-signed `GET /config-dns/v2/zones/{candidate}`
      check is the same shape, and additionally never reads any response
      body anywhere in the driver (zone/create/delete all discard their
      return value, deciding success purely from whether `signed()`
      threw) — proven by `test_write_operations_never_read_the_response_body()`.
    - ClouDNS-style (cloudns/namesilo/dnspod): `zone()` has *no*
      try/catch at all, but determines "found" via a plain body-content
      check (a substring search or a decoded status field) rather than
      relying on an HTTP-level exception. These three providers'
      real-world APIs represent an authentication failure as an HTTP 200
      response with the failure encoded in the body (ClouDNS:
      `{"status":"Failed",...}`; NameSilo: a non-`300` `<code>`; DNSPod:
      `status.code` other than `1`, with `-1` specifically documented as
      "Login fails") — exactly the shape each zone() check treats as "not
      this candidate," so the failure falls through silently (no
      exception at all) rather than being caught. The end result is
      identical: once every candidate is exhausted, both shapes collapse
      into the same generic "no domain/zone found for {fqdn}" diagnostic
      a real zone-not-found would produce, discarding the actual cause.
      An operator with a revoked or mis-scoped credential sees a message
      suggesting a DNS/zone configuration problem, not an authentication
      problem.
    - Namecheap-style (namecheap only, Batch 7) — a third, distinct
      mechanism: `zone()` has no try/catch either, and needs none, because
      Namecheap's XML API always returns HTTP 200 regardless of the
      logical outcome — `request_raw()` itself never throws for an
      in-band API-level failure. Every failure, including an invalid API
      key or a non-whitelisted client IP, is represented identically to
      "this candidate isn't a domain in this account": a body containing
      `Status="ERROR"`. zone()'s only check,
      `str_contains($body, 'Status="OK"')`, cannot distinguish the two.
      Unlike the ClouDNS-style shape, this isn't a try/catch-adjacent
      body-content check standing in for an HTTP exception — it's the
      *only* mechanism this API exposes for reporting failure at all.
      Distinctly, a genuine HTTP-level failure (5xx, or a transport
      WP_Error) is NOT subject to this — `zone()` has nothing to catch it
      with, so it propagates immediately and distinctly, proven by
      `test_a_genuine_http_failure_during_discovery_propagates_directly_unlike_an_in_band_auth_error()`.

    Proven precisely by
    `test_authentication_failure_during_zone_discovery_is_misreported_as_zone_not_found()`
    in each deSEC-style and ClouDNS-style fixture (including akamai's own
    copy of that same test), and by
    `test_authentication_failure_during_zone_discovery_is_misreported_as_no_manageable_domain_found()`
    for namecheap specifically (asserts both the misleading message
    text and that no write request is attempted), using each provider's
    own authentic failure representation (a real HTTP 401/403 for the
    deSEC-style group; the provider's own documented in-band 200-status
    failure shape for the ClouDNS-style and Namecheap-style groups). The
    same fix, if authorised, would need to land across all nineteen
    drivers together, with different code changes depending on shape. Per
    the standing rule, production defects are corrected only through an
    explicit regression test plus a clearly disclosed, separate change —
    not silently, and not mixed into batch coverage work.
  - **Contrast finding, not a defect — 18 providers**: cloudflare,
    route53, google-cloud (Phase 6B); scaleway (Batch 1); hetzner, bunny,
    domeneshop (Batch 2); ionos, linode, netlify, powerdns, dynu (Batch
    3); njalla, alidns (Batch 6); ovh, azure, mythicbeasts, inwx (Batch
    7). Most of these discover their zone via a client-side filter over a
    200 response's body, or a single upfront enumeration, with *no*
    try/catch around the lookup at all — confirmed directly against each
    provider's source. njalla is additionally well-designed against the
    ClouDNS-style risk specifically: its single `list-domains` call has no
    try/catch, AND `call()` itself explicitly checks for a JSON-RPC
    `"error"` key in the decoded body and throws a distinct exception if
    present — converting any in-band failure into a genuine, uncaught
    exception regardless of shape. alidns is immune for this specific
    dimension based on Alibaba Cloud's general documented convention that
    authentication/signature failures use real HTTP status codes
    (403/400) — see alidns's own separate, more significant confirmed
    defect below, which is unrelated to this dimension. ovh's immunity
    rests on multiple independent reports of OVH's real API returning
    genuine HTTP 401/403/400 for signature/consumer-key failures (e.g.
    `ovh/php-ovh` GitHub issues showing `"httpCode":"403 Forbidden"` for
    `INVALID_CREDENTIAL`); azure's rests on Azure Resource Manager's
    well-documented standard error-response convention (real HTTP 401/403
    for authentication/authorization failures); mythicbeasts's and inwx's
    each rest on standard OAuth2 Bearer-token semantics (RFC 6750) for
    rejecting an invalid/expired token via genuine HTTP 401. inwx has no
    try/catch anywhere in `zone()` either, but for a different reason than
    ovh/azure/mythicbeasts: a genuine login failure throws from inside
    `login()`, called as a side effect of the very first `rpc()`, before
    `zone()`'s per-candidate loop (which doesn't exist as a try/catch to
    begin with) ever runs — see inwx's own separate, distinct
    cookieless-login defect below, which shares the same *outcome*
    (misdiagnosis) via a different mechanism than either family above. A
    genuinely throwing HTTP-level error (401/403, or any status >= 400) on
    the very first zone-discovery candidate therefore propagates
    immediately and directly as the shared `request()`/`request_raw()`
    helper's own distinct "API error (HTTP …)" message — it is never
    retried against further candidates, and never collapsed into a "zone
    not found" diagnostic. Proven by
    `test_a_genuine_http_level_error_during_zone_discovery_surfaces_distinctly()`
    (cloudns/namesilo/dnspod's fixtures; renamed from the prior,
    overclaiming name after the correction below),
    `test_authentication_failure_during_zone_discovery_surfaces_distinctly_not_as_zone_not_found()`
    (most of the remaining fixtures in this group, including ovh, azure,
    and mythicbeasts), and
    `test_an_in_band_json_rpc_error_during_zone_discovery_is_not_misreported()`
    (njalla specifically, proving immunity to the in-band-failure risk
    too), deliberately included to confirm the test framework
    distinguishes real defects from correct behaviour rather than
    flagging every provider uniformly. Note this immunity is narrower
    than blanket safety for cloudns/namesilo/dnspod specifically — see
    the correction below; it only holds when the failure is a genuine
    HTTP-level status, which is not how those three providers' real APIs
    represent an authentication failure.
  - **No applicable mechanism — 3 providers**: acmedns, dreamhost, joker
    (Batch 5) — none has a zone-discovery request resembling either shape
    above (see the dedicated note below for each).

  19 + 18 + 3 = 40, all mocked-contract providers accounted for.

- **Correction, 2026-08-21**: cloudns, namesilo, and dnspod were
  originally classified as contrast-group (immune), based on the true but
  incomplete observation that each has no try/catch in `zone()`. Review
  established that immunity from a *caught* exception does not imply
  immunity from the defect overall: these three providers' real APIs
  represent authentication failures as HTTP 200 responses with the
  failure encoded in the body, which is exactly the shape each zone()
  check already treats as "not this candidate" — the same misdiagnosis
  results, just via silent fall-through rather than a caught exception.
  Reclassified as confirmed-defect (see above); the original 401-based
  tests were kept (renamed, not deleted) since they still correctly prove
  a narrower, genuinely-distinct fact — that a real HTTP-level error is
  not misdiagnosed — and new tests were added using each provider's
  actual documented in-band failure shape to prove the real defect. This
  also surfaced that cloudflare, route53, google-cloud, and scaleway had
  never been explicitly named in this matrix's contrast-group list, even
  though they share that exact shape (verified directly against their
  source in this same review) — they are now listed above.
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
- **ionos, linode, netlify, powerdns, dynu** (contrast finding, extends
  hetzner/bunny/domeneshop's, not a defect): all five Batch 3 providers
  discover their zone with exactly ONE request — either by enumerating the
  whole zone/domain list once and filtering client-side across every
  zone_candidates() entry (ionos, linode, netlify, powerdns), or by
  delegating zone-and-label resolution entirely to a specialised
  server-side endpoint that replaces the candidate walk altogether (dynu's
  `getroot`). None of the five has a try/catch around that one request, so
  a 401/403 propagates immediately and distinctly as the shared
  `request()` helper's own "API error (HTTP …)" message — never retried,
  never collapsed into a "zone/domain not found" diagnostic. Proven by
  `test_authentication_failure_during_zone_discovery_surfaces_distinctly_not_as_zone_not_found()`
  in each of the five fixtures. (Historical note: this bullet's original
  "12 of 21 immune / 9 of 21 share it" running total is superseded by the
  complete, recalculated classification and totals in the dedicated
  auth-misdiagnosis note near the top of this section — that total is
  authoritative, not this one.)
- **Confirmed production defect — powerdns, destructive, not merely an
  architectural consequence** (not fixed here; unrelated to, and must not
  be conflated with, powerdns's separate "no applicable mechanism" finding
  below): verified directly against
  [doc.powerdns.com's Zone API reference](https://doc.powerdns.com/authoritative/http-api/zone.html).
  Quoting the documentation precisely: "With DELETE, all existing RRs
  matching name and type will be deleted... With REPLACE, when records is
  present, all existing RRs matching name and type will be deleted, and
  then new records given in records will be created." `create_txt_record()`
  always sends `changetype=REPLACE` and `delete_txt_record()` always sends
  `changetype=DELETE`, with no read-before-write step — both
  unconditionally act on the *entire* RRSet at that name and type, not on
  a specific value.
  - **Affected behaviour, precisely**: `create_txt_record()` can silently
    overwrite an unrelated TXT value another concurrent operation placed
    at the same `_acme-challenge` name; `delete_txt_record()` can silently
    delete an unrelated TXT value regardless of the `$value` passed in
    (it never inspects the RRSet's contents before removing it). This is
    unsafe wherever multiple TXT values can legitimately coexist in one
    `_acme-challenge` RRSet — e.g. concurrent challenge validations, or
    RFC 8555's own allowance for multiple TXT values at one challenge
    name.
  - **PowerDNS version boundary**: the documented narrower alternative —
    changetype `EXTEND` (adds one record without replacing the RRSet) and
    `PRUNE` (removes one specific record) — is only available **from
    PowerDNS 4.9.12 and 5.0.2 onward**. Self-hosted servers on older
    versions do not have `EXTEND`/`PRUNE` at all, so any fix must decide
    how to behave against those versions (e.g. version detection with a
    REPLACE/DELETE fallback, or a documented minimum-version requirement)
    — a genuine compatibility design decision that belongs in its own
    regression-tested production PR, not this test-only one.
  - Proven precisely by `test_delete_uses_changetype_delete_and_ignores_the_provided_value()`
    (confirms DELETE removes the whole RRSet regardless of `$value`) and
    `test_create_uses_replace_without_reading_the_existing_rrset_first()`
    (confirms REPLACE sends only the new record, with no prior read of
    the RRSet to preserve anything already present).
- **Batch 3 pagination/record-listing findings, verified per provider
  against each API's current authoritative documentation** (2026-08-20):

  - **Confirmed pagination defect — ionos**, more severe than any Batch 2
    finding: `GET /zones` (the single call zone discovery depends on
    entirely) paginates via `offset`/`limit`, default `limit=100`, per
    IONOS's own published Go SDK reference derived from their OpenAPI spec
    ([sdk-go-dns ZonesApi.md](https://github.com/ionos-cloud/sdk-go-dns/blob/master/docs/api/ZonesApi.md)).
    zone() sends neither parameter. An account with more than 100 DNS
    zones can have its correct zone fall outside that default page,
    causing `create_txt_record()` to throw "no zone found" even though
    the zone genuinely exists — this can break issuance entirely, not just
    leave a cleanup record behind.
  - **Confirmed pagination defect — linode**, on *both* endpoints zone()
    and delete_txt_record() depend on: Linode's v4 API documents
    `page`/`page_size` pagination (default page_size 100, maximum 500)
    with `page`/`pages`/`results` response fields, verified directly
    against Linode's (Akamai TechDocs) published reference
    ([get-domain-records](https://techdocs.akamai.com/linode-api/reference/get-domain-records)).
    The driver sends `page_size=500` (the documented maximum) on both the
    domains list and the records list, but never checks `pages` or
    requests a further page on either. An account with more than 500
    domains breaks zone discovery entirely; a zone with more than 500
    records leaves a matching cleanup record undeleted.
  - **No applicable mechanism — powerdns** (record identifiers *and*
    pagination, confirmed directly against
    [doc.powerdns.com's Zone API reference](https://doc.powerdns.com/authoritative/http-api/zone.html)):
    this driver's create/delete both PATCH an entire RRset (changetype
    REPLACE/DELETE) rather than listing records and deleting by
    server-assigned ID — there is no records-list endpoint to paginate or
    extract an identifier from at all. Confirmed directly: `GET /zones`
    documents no pagination parameters, and `GET /zones/{id}` returns
    complete RRsets in one response with no separate records endpoint.
    This finding is unrelated to, and must not be conflated with, the
    separate confirmed destructive defect below — the absence of a
    pagination/record-ID mechanism is not itself a problem; how the driver
    writes to the RRSet without one is.
  - **[Unverified] — netlify**: the operation-specific OpenAPI spec for
    `GET /dns_zones/{zone_id}/dns_records`
    ([open-api.netlify.com, getGetDnsRecords](https://open-api.netlify.com/#tag/dnsZone/operation/getDnsRecords))
    documents no pagination parameters at all, while Netlify's general
    platform documentation separately states pagination is "applied to
    all API requests that return over 100 items" — a genuine
    inconsistency between the endpoint's own specification and the
    general platform documentation that could not be resolved with
    confidence either way.
  - **[Unverified] — dynu**: no authoritative v2 API documentation for
    `GET /dns/{id}/record`'s pagination behaviour could be located; the
    only reachable Dynu documentation page described a different (v1)
    endpoint path, giving no confidence it was even the correct reference
    for the v2 endpoint this driver calls.

  Test naming follows the same convention established in Batch 2:
  ionos/linode use pagination-specific test names describing the
  confirmed defect; netlify/dynu use
  `test_a_record_absent_from_the_fetched_list_is_not_deleted_and_does_not_throw()`
  (no pagination claim); powerdns has no equivalent test at all, since no
  list-of-records response exists to be incomplete. None of this is fixed
  here — per the standing rule, production defects are corrected only
  through an explicit regression test plus a clearly disclosed, separate
  change, and are kept out of batch coverage PRs entirely.
- **dnsimple, dnsmadeeasy, porkbun** (Batch 4, extends the established
  Batch 1/2/3 auth-during-discovery family, each with direct code
  evidence — not inferred from similarity alone): all three drivers wrap
  their per-candidate zone lookup in a try/catch identical in shape to
  deSEC's, so a genuine authentication failure (a request that actually
  throws, e.g. 401) during zone discovery is misreported as "no zone/
  managed domain found" once every candidate is exhausted. This brings
  the family to **12 of 24** mocked-contract providers. Proven per
  provider by
  `test_authentication_failure_during_zone_discovery_is_misreported_as_zone_not_found()`.
  dnsimple's version of this runs through an added memoised
  account-resolution pre-step (`account()`, calling `GET /whoami`) that
  is evaluated *inside* the same try block — a throwing whoami() (e.g.
  401) is swallowed identically, and since `account_id` is only cached
  after a *non-throwing* whoami response, a persistent auth failure
  causes whoami() to be retried once per zone candidate (proven by
  `test_whoami_is_called_once_and_cached_across_create_and_delete()`
  showing the *success* case caches after one call, by contrast).
  Distinctly, dnsimple's own malformed-response behaviour is **not** the
  same code path: a malformed-but-2xx whoami response throws exactly once
  (candidate 1 only) because `account_id` is assigned *before* its own
  empty-value check runs, then permanently caches an empty ID and stops
  retrying whoami() at all — from candidate 2 onward the zone check
  behaves like Batch 1's status-only providers (a non-throwing response,
  regardless of body content, is treated as "zone found").
  `response_body_is_validated_on_success()` is false for both dnsimple
  and porkbun (their zone-check success path never reads a body); dns
  made easy's is true, since its zone() explicitly checks
  `!empty($response['body']['id'])` on top of the try/catch — proven by
  `test_a_2xx_response_with_no_matching_domain_id_is_treated_as_not_found_without_throwing()`,
  which confirms this second, non-exception failure path also falls
  through correctly without ever throwing mid-loop.
- **Confirmed pagination defect — dnsimple** (Batch 4, verified against
  current authoritative documentation): the records-list endpoint
  documents `page`/`per_page` pagination (default `per_page=30`) per
  [developer.dnsimple.com](https://developer.dnsimple.com/v2/zones/records/)
  and DNSimple's general pagination guide; the driver sends neither
  parameter. The list call is already server-filtered by record name and
  type, making an overflow less likely in practice than an unfiltered
  list, but the pagination mechanism is confirmed to exist and go unused —
  proven by
  `test_records_list_pagination_can_leave_a_matching_record_undeleted()`.
- **[Unverified] — dnsmadeeasy**: `api-docs.dnsmadeeasy.com` did not
  render its content for automated retrieval, so no accessible official
  primary source could confirm this endpoint's pagination behaviour. A
  third-party Go client library
  (`github.com/john-k/dnsmadeeasy`) defines a `RecordsResp` struct with
  `totalRecords`/`totalPages`/`page` fields, evidence a mechanism likely
  exists, but a third-party client's struct definitions reflect that
  library's own interpretation of observed responses, not a confirmed
  current provider contract — the same evidence standard applied to
  Name.com/easyDNS/Hetzner in Batches 2–3. Not counted in the confirmed
  pagination defect total. Test renamed to
  `test_a_record_absent_from_the_fetched_list_is_not_deleted_and_does_not_throw()`
  to avoid asserting a mechanism that isn't authoritatively confirmed; the
  `totalRecords`/`totalPages`/`page` fields are retained in that test's
  queued response purely as provisional contract evidence should an
  accessible primary source surface later.
- **No pagination mechanism applicable — porkbun** (confirmed directly
  against Porkbun's own published API documentation): neither
  `POST /dns/retrieve/{domain}` nor
  `POST /dns/retrieveByNameType/{domain}/{type}/{subdomain}` documents
  any offset/limit/pagination parameter, and both return complete result
  sets. This finding is unrelated to, and must not be conflated with, the
  separate confirmed destructive defect below.
- **Confirmed production defect — porkbun, destructive and avoidable**
  (not fixed here; a genuinely new finding, independently verified — NOT
  an extension of the PowerDNS destructive-write family from Batch 3,
  which has a different root cause): verified directly against Porkbun's
  own published API documentation
  (porkbun.com/api/json/v3/documentation and llms-full.txt).
  `delete_txt_record()` calls
  `POST /dns/deleteByNameType/{zone}/TXT/{relative}`, which removes every
  TXT record at that name regardless of content — the driver never
  inspects `$value` when deleting at all, and never lists or retrieves
  records first. Unlike PowerDNS (whose API has no by-value deletion
  mechanism at all below a version threshold), Porkbun's own API
  documents both `POST /dns/delete/{domain}/{id}` ("Delete DNS record by
  ID") and `POST /dns/retrieveByNameType/{domain}/{type}/{subdomain}`
  ("Retrieve DNS records by name and type", returning each record's ID)
  — the exact safe list-then-delete-by-ID pattern nearly every other
  provider in this registry already uses is directly available in
  Porkbun's API and simply isn't used here, making this an *avoidable*
  defect rather than an architectural limitation. Proven by
  `test_delete_uses_delete_by_name_type_and_ignores_the_provided_value()`
  and `test_delete_never_lists_or_retrieves_records_first()`.
- **namesilo — investigated and RESOLVED, not a defect** (Batch 5): the
  earlier classification pass flagged a possible create/delete asymmetry
  at `class-provider-namesilo.php:56` (`delete_txt_record()` matches
  `<host>` against the full fqdn while `create_txt_record()` submits a
  zone-relative name via `rrhost`). Investigated directly against two
  independent pieces of primary-source evidence from NameSilo's own
  official API documentation: `dnsAddRecord`'s `rrhost` parameter is
  documented as relative-only ("there is no need to include the
  '.DOMAIN'", namesilo.com/api-reference, dns/dns-add-record), while
  `dnsListRecords`' own official example response shows the returned
  `<host>` field as fully qualified — `<host>test.namesilo.com</host>`
  for a record under namesilo.com
  (namesilo.com/api-reference/pages?uid=dns/dns-list-records). NameSilo's
  own API is asymmetric by design (relative on write, fully-qualified on
  read-back), and the driver correctly mirrors that asymmetry — it is not
  a bug. Proven by
  `test_delete_matches_a_resource_record_whose_host_is_the_fully_qualified_name()`
  and a contrasting negative case,
  `test_delete_does_not_match_a_resource_record_whose_host_is_only_the_relative_name()`,
  which confirms the full-fqdn match is deliberate and exact (a scenario
  NameSilo's real API does not actually produce). No production defect is
  logged for this finding.
- **Confirmed pagination defects — cloudns, dnspod** (Batch 5, verified
  against current authoritative documentation): cloudns's "List records"
  endpoint documents `rows-per-page` (10/20/30/50/100) and `page`
  parameters ([cloudns.net/wiki/article/57](https://www.cloudns.net/wiki/article/57/));
  dnspod's Record.List documents `offset`/`length`, returning at most 500
  records by default
  ([docs.dnspod.com/api-legacy/records.html](https://docs.dnspod.com/api-legacy/records.html):
  "If there are more than 500 records, only the first 500 will be
  responded"). Both drivers' list calls are already filtered by
  domain/type/host or sub_domain, narrowing results, but neither sends
  any pagination parameter, so the mechanism is confirmed to exist and go
  unused in both cases.
- **No pagination mechanism applicable — namesilo** (confirmed directly):
  `dnsListRecords`' entire documented parameter list is exactly one
  entry, "domain" — no page, limit, or offset parameter exists
  (namesilo.com/api-reference/pages?uid=dns/dns-list-records).
- **No applicable mechanism — acmedns, dreamhost, joker** (zone
  discovery, record identifiers, and pagination all): none of these three
  drivers perform any zone lookup, records-list call, or record-ID
  extraction at all, so none of these dimensions apply.
  - **acmedns** has no zone concept whatsoever ($fqdn is accepted but
    never read in either method — the real target is the "subdomain"
    credential captured once at registration), and `delete_txt_record()`
    is an intentional, total no-op: acme-dns keeps a rolling window of
    the last two TXT values server-side and has no delete endpoint at
    all. This provider is architecturally incompatible with the shared
    ten-item contract, not merely a variant of it, so it is covered by a
    **bespoke, non-`Dns_Provider_Contract_TestCase` test file**
    (`AcmednsProviderTest`) that tests its actual behaviour directly
    (request construction, malformed/failed-response handling,
    transport/HTTP failures, and the delete-no-op explicitly) rather than
    forcing it through hooks that don't reflect real behaviour — the same
    precedent RFC 2136 already established for this framework.
  - **dreamhost** takes the full record name directly in its
    `dns-add_record`/`dns-remove_record` calls — no zone resolution
    happens at all. It does extend the shared contract (every base test
    still passes meaningfully, since "zone discovery" only requires "at
    least one request happened"), but `queue_zone_not_found()` and the
    write-stage auth-failure hook both simulate a generic body-encoded
    API failure rather than a distinct discovery-phase failure, since no
    such phase exists — disclosed in the fixture's docblock. Also
    disclosed: `delete_txt_record()` treats a `"no_such_record"` failure
    reason as an already-successful no-op (a record that's already gone
    is the desired end state for a cleanup call), tested explicitly.
  - **joker** treats the zone as a trusted, statically-configured
    credential, never verified against any API call — there is no
    zone-discovery request of any kind, confirmed by
    `test_no_zone_discovery_request_precedes_the_write()` (exactly one
    request total, the write itself). Create and delete route through the
    same single-TXT-slot "replace" endpoint (delete sends an empty
    value), architecturally similar in spirit to PowerDNS's RRSet
    REPLACE/DELETE (Batch 3) but via Joker's own simpler, single-value
    Dynamic-DNS-style protocol — no records list or record ID exists at
    all for this provider.
- **alidns, unvalidated write responses** (Batch 6, not fixed here,
  unrelated to the pagination finding below — keep separate). Split
  precisely into what is confirmed and what remains open, per review
  correction (2026-08-21 — the initial classification conflated the two):
  - **Confirmed defect**: `create_txt_record()`'s `AddDomainRecord` call
    and the specific `DeleteDomainRecord` call inside
    `delete_txt_record()` (the write that performs the actual deletion)
    both discard their responses entirely — neither checks the field
    Alibaba Cloud documents in a successful response (`RecordId` for
    both operations —
    [AddDomainRecord](https://www.alibabacloud.com/help/en/dns/api-alidns-2015-01-09-adddomainrecord),
    [DeleteDomainRecord](https://www.alibabacloud.com/help/en/dns/api-alidns-2015-01-09-deletedomainrecord)).
    This is not true of every operation this driver makes — `zone()`'s
    `GetMainDomainName` call does validate (throws if `DomainName` is
    absent), and `delete_txt_record()`'s own `DescribeDomainRecords` call
    does inspect its documented response shape (reads the `Record` array
    and filters by `RR`/`Value`). Only the two write calls skip validating
    their documented success field. Concretely: a malformed or unexpected
    HTTP 200 response to either write call is silently accepted as
    success. Proven directly by
    `test_create_accepts_an_unexpected_2xx_response_without_validating_it()`
    and
    `test_delete_accepts_an_unexpected_2xx_response_without_validating_it()`,
    both of which use a deliberately malformed-shaped body to demonstrate
    the missing validation, not to assert AliDNS genuinely returns that
    specific body.
  - **[Unverified]**: whether AliDNS's `AddDomainRecord`/
    `DeleteDomainRecord` operations specifically can also return a
    *business-error* body (`Code`/`Message` fields, Alibaba Cloud's
    general documented error shape —
    [alibabacloud.com/help/en/doc-detail/25491.html](https://www.alibabacloud.com/help/en/doc-detail/25491.html))
    at HTTP 200, as opposed to the 4xx status their signature/auth
    failures are confirmed to use (which is what makes alidns immune
    specifically to the auth-during-discovery dimension above — a
    separate dimension from this finding). Alibaba Cloud's own
    documentation notes this "may vary by service" and no
    DNS-operation-specific confirmation either way could be established.
    This is a separate, unconfirmed question from the validation gap
    above — the code-level absence of validation is confirmed regardless
    of whether this specific response shape is ever actually returned in
    practice.
- **Batch 6 pagination findings, verified per provider against current
  authoritative documentation**:
  - **No pagination mechanism applicable — glesys**: confirmed directly
    against GleSYS's own API documentation
    ([github.com/GleSYS/API-docs wiki](https://github.com/GleSYS/API-docs/wiki/API-Documentation)) —
    `domain/listrecords` documents no page parameter or pagination
    metadata at all, in explicit contrast to other GleSYS endpoints (e.g.
    `email/overview`) which do document a `page` parameter and `meta`
    pagination info.
  - **[Unverified] — njalla**: Njalla's `list-records` documentation
    requires an authenticated account to access in full; no accessible
    public source could confirm or rule out a pagination mechanism for
    this endpoint.
  - **No pagination mechanism applicable — netcup**: netcup's own
    documentation describes `infoDnsRecords` as "Obtain all DNS records
    of a zone"
    ([netcup.com/en/helpcenter/documentation/domain/our-api](https://netcup.com/en/helpcenter/documentation/domain/our-api)) —
    no page/limit parameter documented anywhere for this operation.
  - **Confirmed pagination defect — alidns**: `DescribeDomainRecords`
    documents `PageNumber` (default 1) and `PageSize` (default 20,
    maximum 500)
    ([alibabacloud.com/help/en/dns/api-alidns-2015-01-09-describedomainrecords](https://www.alibabacloud.com/help/en/dns/api-alidns-2015-01-09-describedomainrecords),
    verified directly). The driver's call is already filtered by
    `RRKeyWord`/`TypeKeyWord`, narrowing results, but sends neither
    pagination parameter, so the mechanism is confirmed to exist and go
    unused.
- **Batch 7 findings** (akamai, ovh, namecheap, azure, mythicbeasts,
  inwx — the final HTTP/API batch; only rfc2136 remains uncovered by a
  mocked-contract fixture after this batch):
  - **Confirmed production defect — azure, destructive delete ignoring
    `$value`**: `delete_txt_record()` issues an unconditional ARM `DELETE`
    of the entire TXT recordset at the resolved name — no body, no
    read-before-write, `$value` plays no part in the request at all.
    Identical in shape to PowerDNS's (Batch 3) and Porkbun's (Batch 4)
    destructive deletes, but a distinct finding for a distinct driver.
    Proven by
    `test_delete_removes_the_entire_txt_recordset_without_checking_the_value()`.
    **[Unverified]**: whether Azure DNS's ARM API offers a safer
    partial-update mechanism (e.g. a reduced-`TXTRecords` PUT) this driver
    could use instead; no operation-specific evidence confirms or rules
    this out.
  - **Confirmed production defect — akamai, destructive delete ignoring
    `$value`**, same shape as azure's: `delete_txt_record()` DELETEs the
    whole recordset at `{zone}/names/{fqdn}/types/TXT` with `$value`
    playing no part in the request. Mitigated in the common case by the
    driver's own code comment ("ACME names are exclusively ours" — an
    `_acme-challenge.*` name is unlikely to hold an unrelated coexisting
    TXT value), but the defect is the same: a coexisting value at that
    exact name would still be destroyed. Proven by
    `test_delete_removes_the_entire_txt_recordset_without_checking_the_value()`
    in akamai's own fixture. **[Unverified]**: whether Akamai's Config DNS
    v2 API offers a per-rdata-value removal mechanism instead.
  - **Confirmed production defect — inwx, cookieless-successful-login
    permanently disables authentication**, a distinct code-level gap from
    the auth-misdiagnosis family above (though it produces the same
    outward symptom): `rpc()` only overwrites `$this->cookie` when the
    login response actually carries a `Set-Cookie` header. A login
    response with a genuine success `code` (1000) but no `Set-Cookie`
    header leaves `$cookie` at its permanently-cached empty-string
    sentinel (assigned by `login()` before its own nested call, "so login
    itself does not recurse") — not `null` — so `login()` is never retried
    for the rest of the instance's lifetime, and every subsequent request
    carries an empty `Cookie` header, which the real server would treat as
    unauthenticated. Proven at the code level by
    `test_a_cookieless_successful_login_response_permanently_disables_authentication()`.
    **[Unverified]**: whether INWX's real API can actually produce this
    exact combination (a documented success code with no session cookie
    attached) on any real request path.
  - **Contrast finding, not a defect — ovh, well-designed list-then-verify
    delete**: `delete_txt_record()` lists candidate record IDs filtered by
    `fieldType`/`subDomain`, fetches each candidate individually, and
    checks its `target` field against `$value` before deleting — genuine
    per-value discrimination, not a whole-recordset delete. Proven by
    `test_delete_verifies_the_target_value_before_deleting_by_id()`.
  - **Contrast finding, not a defect — mythicbeasts, well-designed
    exact-match delete**: `delete_txt_record()` passes host, record type,
    and the TXT value itself as path/query parameters to a single DELETE
    call the API documents as matching all three server-side — no
    client-side list-then-verify step exists or is needed. Proven by
    `test_delete_targets_the_exact_host_type_and_value_not_the_whole_recordset()`.
  - **Contrast finding, not a defect — inwx, well-designed list-then-
    verify delete**: `delete_txt_record()` lists records via
    `nameserver.info` and only calls `nameserver.deleteRecord` for the one
    whose `content` matches `$value` — the same safe pattern as ovh's.
    Proven by
    `test_delete_only_removes_the_record_whose_content_matches_the_value()`.
  - **Contrast finding, not a defect — namecheap, refuses to write on a
    failed read**: `modify_hosts()`'s read-modify-write never calls
    `setHosts` (which replaces the *entire* host list at the domain) if
    its own `getHosts` call didn't return `Status="OK"` — the driver's own
    docblock states the reasoning ("a partial read must never wipe a
    zone"), and this is verified directly, not merely asserted: a failed
    read at the write stage throws distinctly and `setHosts` is never
    called. Proven by
    `test_a_failed_get_hosts_during_the_write_step_refuses_to_call_set_hosts()`.
    Noted but not scored as a defect: `modify_hosts()` re-fetches
    `getHosts` for the winning zone candidate a second time (zone()'s own
    matching call already confirmed `Status="OK"` for that exact SLD/TLD
    pair moments earlier) — a redundant, mildly wasteful round trip, not a
    functional defect.
  - **[Unverified] — ovh pagination**: no accessible authoritative
    documentation for the legacy v1.0 `/domain/zone/{zone}/record`
    endpoint's pagination behaviour could be located (OVH's newer v2 API
    documents cursor pagination via response headers, but this endpoint is
    part of the older, still-current v1.0 API family this driver calls).
  - **[Unverified] — azure zone-list pagination**: Azure Resource Manager
    documents a general `nextLink` convention for large list responses
    across its APIs, but no operation-specific confirmation that
    `dnsZones?api-version=2018-05-01` actually paginates was established
    in this batch's research; `zone()` reads only `value` and never checks
    for a `nextLink` field.
  - **[Unverified] — mythicbeasts zone-list pagination**: no accessible
    documentation confirming or ruling out pagination on `GET /zones` was
    located.
  - **[Unverified] — inwx nameserver.info pagination**: no
    operation-specific documentation for `nameserver.info`'s record-list
    behaviour was located; the only reachable reference described a
    different method (`nameserver.list`, for listing *domains*, not
    records within one domain) defaulting to a 20-entry limit, giving no
    confidence it applies to the endpoint this driver actually calls.
  - **No pagination mechanism applicable — akamai**: `delete_txt_record()`
    addresses the recordset directly by `{zone}/names/{fqdn}/types/TXT` —
    there is no records-list call to paginate at all.
  - **No pagination mechanism applicable — namecheap**: `getHosts` returns
    every host at the domain in a single response; Namecheap's XML API
    documents no page/limit parameter for this call, consistent with the
    driver's own read-modify-write design (a partial host list would
    itself be unsafe to write back).
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
