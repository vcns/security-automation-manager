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

**41/41** have registry/metadata coverage. **30/41** have mocked-contract
(request-level) coverage. **0/41** have live verification.

### Notes

- **Auth-during-discovery misdiagnosis defect — complete, recalculated
  classification across all 30 mocked-contract providers** (last
  recalculated 2026-08-21, after a Batch 5 review correction; see the
  correction note immediately below for what changed and why). Every
  provider falls into exactly one of three groups:

  - **Confirmed defect — 15 providers**: desec, gandi, godaddy, ns1
    (Batch 1); digitalocean, vultr, namecom, easydns, vercel (Batch 2);
    dnsimple, dnsmadeeasy, porkbun (Batch 4); cloudns, namesilo, dnspod
    (Batch 5). Two distinct code shapes produce the identical outcome:
    - deSEC-style (desec/gandi/godaddy/ns1/digitalocean/vultr/namecom/
      easydns/vercel/dnsimple/dnsmadeeasy/porkbun): `zone()` wraps every
      per-candidate lookup in a try/catch that treats *any* response
      status >= 400 as "not this candidate, try the next one." A genuine
      authentication failure (401/403) is caught identically to a 404.
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

    Proven precisely by
    `test_authentication_failure_during_zone_discovery_is_misreported_as_zone_not_found()`
    in each of the fifteen fixtures (asserts both the misleading message
    text and that no write request is attempted), using each provider's
    own authentic failure representation (a real HTTP 401/403 for the
    deSEC-style group; the provider's own documented in-band 200-status
    failure shape for the ClouDNS-style group). The same fix, if
    authorised, would need to land across all fifteen drivers together,
    with two different code changes depending on shape. Per the standing
    rule, production defects are corrected only through an explicit
    regression test plus a clearly disclosed, separate change — not
    silently, and not mixed into batch coverage work.
  - **Contrast finding, not a defect — 12 providers**: cloudflare,
    route53, google-cloud (Phase 6B); scaleway (Batch 1); hetzner, bunny,
    domeneshop (Batch 2); ionos, linode, netlify, powerdns, dynu (Batch
    3). Every one of these discovers its zone via a client-side filter
    over a 200 response's body, or (ionos/linode/netlify/powerdns/dynu)
    a single upfront enumeration, with *no* try/catch around the lookup
    at all — confirmed directly against each provider's source. A
    genuinely throwing HTTP-level error (401/403, or any status >= 400)
    on the very first zone-discovery candidate therefore propagates
    immediately and directly as the shared `request()`/`request_raw()`
    helper's own distinct "API error (HTTP …)" message — it is never
    retried against further candidates, and never collapsed into a "zone
    not found" diagnostic. Proven by
    `test_a_genuine_http_level_error_during_zone_discovery_surfaces_distinctly()`
    (cloudns/namesilo/dnspod's fixtures; renamed from the prior,
    overclaiming name after the correction below) and
    `test_authentication_failure_during_zone_discovery_surfaces_distinctly_not_as_zone_not_found()`
    (the remaining fixtures in this group), deliberately included to
    confirm the test framework distinguishes real defects from correct
    behaviour rather than flagging every provider uniformly. Note this is
    narrower than "immune to auth-misdiagnosis" for cloudns/namesilo/
    dnspod specifically — see the correction below; it only holds when
    the failure is a genuine HTTP-level status, which is not how those
    three providers' real APIs represent an authentication failure.
  - **No applicable mechanism — 3 providers**: acmedns, dreamhost, joker
    (Batch 5) — none has a zone-discovery request resembling either shape
    above (see the dedicated note below for each).

  15 + 12 + 3 = 30, all mocked-contract providers accounted for.

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
