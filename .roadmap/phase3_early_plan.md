# VCNS Security Automation Manager
## Phase 3 Development Roadmap and Requirements Specification

**Product:** VCNS Security Automation Manager  
**Repository:** `vcns/security-automation-manager`  
**Phase:** 3  
**Baseline:** v2.9.24  
**Status:** Draft for development planning  
**Date:** 29 August 2026

---

# 1. Purpose

Phase 3 extends VCNS Security Automation Manager from a strong WordPress security-control plugin into a broader site security and assurance platform.

The existing product already provides substantial local protection and security-policy automation. Phase 3 must preserve that foundation while adding:

- clearer product architecture and navigation;
- behavioural and request intelligence;
- bot, crawler and scanner identification;
- traffic controls;
- security-event classification;
- pattern recognition;
- baseline and drift detection;
- external verification;
- centralised intelligence services;
- evidence and assurance reporting;
- controlled automation;
- optional future commercial and managed-service capability.

The product must remain locally authoritative. A central VCNS service may provide intelligence, aggregation, recommendations and signed updates, but it must not become an unrestricted remote-control channel into customer WordPress installations.

---

# 2. Product Model

Phase 3 formalises three separate concepts which must not be conflated.

## 2.1 Protection Layers

The protection layers describe the architectural capability stack.

### Layer 1: Governance and Operations

This layer provides the control framework around every other capability.

It includes:

- audit evidence;
- capability controls;
- diagnostics;
- readiness checks;
- controlled updates;
- rollback and recovery;
- configuration portability;
- decision provenance;
- exception handling;
- security-event history;
- administrator accountability;
- evidence retention.

### Layer 2: Controlled Automation

This layer governs how the product progresses from human-controlled decisions to automated operation.

Supported maturity states should include:

1. Manual
2. Assisted
3. Controlled automatic
4. Fully automatic, where explicitly permitted

Automation must always use safe fallback mechanisms.

A failed automation decision must not weaken an existing security control.

Higher-risk actions must remain approval-gated unless the administrator has explicitly authorised an automation posture that permits them.

### Layer 3: Continuous Intelligence

This layer observes the site and its inbound traffic, derives security context and produces evidence-backed recommendations.

It includes:

- source discovery;
- request-pattern recognition;
- change detection;
- behavioural analysis;
- scanner recognition;
- crawler and bot recognition;
- confidence scoring;
- threat and security-event classification;
- recommendations;
- known-service intelligence;
- change attribution;
- drift detection.

### Layer 4: Browser Security Policies

This layer contains browser-facing controls and browser security policy management.

It includes, but is not limited to:

- Content Security Policy;
- Cross-Origin Opener Policy;
- Cross-Origin Embedder Policy;
- Cross-Origin Resource Policy;
- X-Permitted-Cross-Domain-Policies;
- X-Frame-Options;
- Referrer-Policy;
- Permissions-Policy;
- X-Content-Type-Options;
- HSTS where appropriate to browser-facing transport policy;
- reverse tabnabbing protection;
- external script governance;
- Subresource Integrity;
- internal script integrity.

### Layer 5: Transport and Certificate Trust

This layer covers transport identity, certificate management and network trust.

It includes:

- HTTPS;
- host and transport checks;
- certificate state;
- ACME;
- DNS-01;
- HTTP-01;
- certificate issuance;
- certificate deployment;
- renewal;
- provider capability checks;
- external certificate verification;
- DNS-provider validation;
- certificate trust evidence.

---

# 3. Operational Lifecycle

The operating lifecycle must be presented consistently across the product:

**Observe → Decide → Control → Verify**

The previous term "Enforce" must be replaced with **Control**.

"Control" is preferred because the correct security action is not always enforcement. A decision may result in:

- observation only;
- notification;
- recommendation;
- throttling;
- challenge;
- temporary blocking;
- permanent blocking;
- allowlisting;
- policy adjustment;
- escalation;
- explicit no-action.

Every significant Phase 3 feature should identify where it sits in this lifecycle.

## 3.1 Observe

Collect evidence without making an enforcement decision.

Examples:

- request behaviour;
- source IP;
- ASN;
- Geo-IP;
- user-agent;
- request path;
- HTTP method;
- known scanner range;
- known crawler identity;
- CSP violations;
- script changes;
- certificate changes;
- policy drift.

## 3.2 Decide

Evaluate evidence using deterministic rules, confidence, policy and administrator configuration.

Examples:

- known scanner versus unknown scanner;
- authorised scanner versus merely recognised scanner;
- genuine Googlebot versus claimed Googlebot;
- likely SQL injection;
- likely reconnaissance;
- likely crawler;
- likely credential attack;
- likely campaign;
- known change versus unexplained drift.

## 3.3 Control

Apply an explicitly permitted response.

Examples:

- observe only;
- log;
- alert;
- rate-limit;
- temporarily block;
- block;
- allow;
- challenge;
- restrict by surface;
- restrict by geography;
- restrict by ASN;
- apply a policy;
- suppress a known false positive.

## 3.4 Verify

Confirm whether the control had the intended effect.

Examples:

- confirm policy is externally visible;
- confirm blocked traffic no longer reaches the protected surface;
- confirm a CSP policy change is present;
- confirm a certificate is correctly deployed;
- confirm a crawler identity;
- confirm a previously detected drift condition has been resolved.

---

# 4. WordPress Surfaces

The product must continue to manage WordPress surfaces independently.

The minimum supported surfaces are:

- Frontend
- Admin
- Login
- API

A capability may apply to one, several or all surfaces.

Controls must be independently configurable per surface where technically meaningful.

Examples:

- public crawler controls may apply only to Frontend;
- `/wp-admin/` protections apply to Admin;
- credential-stuffing controls primarily apply to Login;
- abusive API clients may be controlled specifically on API.

The product must not assume that a control suitable for one surface is appropriate for every surface.

---

# 5. Technology Pillars

Technology pillars are the individual technical control families currently represented in the WordPress administration navigation.

Examples include:

- Certificates
- Cross-Origin Policies
- CSP
- HSTS
- Permissions-Policy
- Referrer-Policy
- Reverse Tabnabbing
- Scripts
- X-Content-Type-Options
- X-Frame-Options

These pillars are not the same as the five protection layers.

The pillars remain useful for technical users and as drill-down destinations.

Phase 3 must preserve direct access to them while introducing a simpler lifecycle-oriented primary experience.

---

# 6. Administration Information Architecture

## 6.1 Primary Navigation

The WordPress administration navigation under VCNS Security Automation Manager should be redesigned around the operational lifecycle.

The intended primary navigation is:

- Observe
- Decide
- Control
- Verify
- Settings

The current technology-standard pages remain available as drill-down destinations rather than acting as the primary mental model for non-technical administrators.

## 6.2 Default Landing Page

The current Overview experience should remain conceptually present, but the product-level navigation entry should become **Settings**.

The existing Overview tab may remain named **Overview** within Settings.

Settings should become the default product workspace.

## 6.3 Settings / Overview Table

The existing Overview table should be reorganised by **Protection Layer**.

Each layer should contain its related technology pillars and controls.

The table should preserve:

- status;
- current configuration state;
- enabled/disabled state;
- automation state;
- surface coverage;
- direct Manage links;
- drill-down links.

The user should be able to see, without opening each individual technology page:

- whether a control is configured;
- whether it is active;
- whether it is report-only;
- whether it is automated;
- whether action is required;
- which surfaces are covered.

## 6.4 Status Vocabulary

Phase 3 should introduce consistent status terms.

Candidate states include:

- Not configured
- Disabled
- Observe only
- Learning
- Manual
- Assisted
- Controlled automatic
- Fully automatic
- Report-only
- Active
- Degraded
- Action required
- Verification pending
- Verified
- Drift detected

Exact labels should be normalised during implementation.

---

# 7. Visitor and Request Intelligence

Phase 3 introduces a new request-intelligence capability within Layer 3.

The objective is not merely to count requests.

The system should determine, where evidence permits:

- who is making the request;
- what the requester claims to be;
- what behaviour is being exhibited;
- what the requester appears to be attempting;
- how confident the classification is;
- what local policy permits the system to do about it.

---

# 8. Identity Verification

User-agent strings alone must never establish trusted identity.

The product should support an identity-verification model.

A candidate identity record should include:

- claimed identity;
- observed user-agent;
- source IP;
- source ASN where available;
- source network;
- authoritative vendor;
- authoritative documentation URL;
- vendor-published IP ranges where available;
- reverse-DNS verification method where applicable;
- forward-confirmed reverse-DNS where applicable;
- verification result;
- confidence level;
- last intelligence update;
- source evidence.

Example result:

- Claimed identity: Googlebot
- User-Agent match: yes
- Published network match: yes/no/not applicable
- rDNS match: yes/no/not checked
- forward verification: yes/no/not checked
- Identity state: verified / probable / claimed only / false claim / unknown

The same architecture should support:

- search engines;
- AI crawlers;
- vulnerability scanners;
- attack-surface-management services;
- uptime monitoring;
- CDN services;
- security researchers;
- known hosted services.

---

# 9. Commercial Scanner Intelligence

Phase 3 should import the existing concept of a reference list of public commercial vulnerability-scanner and attack-surface-management network ranges.

The initial known categories discussed include:

- Qualys
- Tenable Vulnerability Management
- Tenable Web App Scanning
- Rapid7 InsightAppSec
- Detectify
- Intruder
- StackHawk
- Burp Suite DAST
- Acunetix
- ImmuniWeb
- BitSight
- Censys

The intelligence model must preserve the following rule:

> Recognition is not authorisation.

A source IP matching a published vendor range only identifies likely ownership or service association.

It does not prove:

- that the scan is authorised for this customer;
- that the traffic should be allowlisted;
- that the source should bypass security controls;
- that the customer commissioned the activity.

Customer-specific authorisation must be represented separately.

## 9.1 Scanner Trust States

At minimum:

- Unknown
- Known commercial scanner
- Known Internet-wide research scanner
- Customer-authorised scanner
- Explicitly denied scanner
- Previously authorised but expired
- Identity conflict

## 9.2 Authoritative Sources

Every centrally maintained intelligence record should include:

- vendor;
- category;
- network ranges;
- source URL;
- verification method;
- last checked date;
- provenance;
- confidence;
- notes.

The source URL must be retained so administrators can understand where the data came from.

---

# 10. Bot, Crawler and Scraper Detection

Phase 3 should support classification of:

- legitimate search-engine crawlers;
- AI crawlers;
- commercial crawlers;
- scraper services;
- unidentified automation;
- likely botnets;
- browser automation;
- aggressive crawlers;
- impersonated crawlers.

The system should avoid a binary "bot/not bot" model.

Suggested classification should consider:

- user-agent identity;
- IP ownership;
- ASN;
- vendor-published ranges;
- reverse DNS;
- request rate;
- request distribution;
- URI patterns;
- robots.txt behaviour;
- session/cookie behaviour;
- header consistency;
- method use;
- timing;
- repeated errors;
- cross-site intelligence where centrally available.

---

# 11. Pattern Recognition and Detector Families

Phase 3 should not implement an unstructured collection of independent regular expressions.

It should introduce detector families.

Each detector should declare:

- detector ID;
- detector family;
- description;
- evidence inputs;
- pattern version;
- confidence;
- severity;
- applicable surfaces;
- false-positive considerations;
- allowed control actions;
- default action;
- source/provenance;
- last update;
- test fixtures.

Initial detector families should include the following.

## 11.1 Technology Mismatch

Detect attempts to access technologies or platforms not used by the site.

Examples:

- Magento probes against a WordPress-only site;
- Joomla paths;
- Drupal paths;
- unrelated administrative endpoints.

Technology mismatch alone should generally be a reconnaissance signal rather than an automatic permanent-block signal.

## 11.2 Command Injection

Detect common command-injection attempts.

Signals may include:

- shell separators;
- command chaining;
- encoded shell constructs;
- suspicious command substitution;
- known shell utility invocation;
- payloads intended to execute server commands.

## 11.3 SQL Injection

Support deterministic SQL-injection pattern recognition across relevant request data.

The system should distinguish:

- low-confidence keyword matches;
- structural SQL injection;
- encoded patterns;
- repeated exploitation attempts.

## 11.4 HTML Injection

Detect suspicious attempts to inject HTML.

This detector must be treated carefully because legitimate application requests may submit HTML.

Default posture should therefore be observation unless the protected endpoint is known not to accept HTML.

## 11.5 Script and Web-Shell Probes

Detect probing for script-execution files and web shells.

Candidate extensions include:

- `.php`
- `.cgi`
- `.pl`
- `.py`
- `.sh`
- `.asp`
- `.aspx`
- `.jsp`
- `.jsf`
- `.shtm`
- `.shtml`

The system must use context and path semantics rather than assuming every request for one of these extensions is malicious.

## 11.6 PHP and PHPUnit Probes

Detect common probes for:

- PHPUnit;
- exposed PHP development utilities;
- known historical vulnerable test endpoints;
- common web-shell paths.

These should be maintained as versioned intelligence rather than fixed assumptions embedded permanently in code.

## 11.7 Protocol Injection

Detect attempts to inject alternate protocols into parameters or URLs.

Examples may include:

- `file://`
- `ftp://`
- unexpected URI schemes;
- suspicious PHP wrappers;
- unexpected protocol handlers.

The detector must distinguish legitimate application behaviour from exploit attempts.

## 11.8 Sensitive Directory Probing

Detect attempts to access paths associated with host filesystem structure.

Examples:

- `/etc/`
- `/usr/`
- `/var/`

This includes encoded traversal attempts that resolve towards such paths.

## 11.9 Sensitive File Probing

Detect likely attempts to retrieve secrets, credentials or sensitive configuration.

Examples include:

- private keys;
- `id_rsa`;
- `id_dsa`;
- credential files;
- `.secret`;
- `.env`;
- `.aws/credentials`;
- configuration files;
- package lock files;
- composer metadata;
- version-control metadata.

Detection should be path-aware and should not blindly classify every `.json`, `.yaml`, `.conf` or similar file as malicious.

## 11.10 Setup and Installation Probes

Detect requests for:

- setup pages;
- installers;
- test pages;
- obsolete configuration scripts;
- known product installation paths;
- common forgotten deployment artefacts.

## 11.11 Version-Control and Build Artefacts

Detect access attempts involving:

- `.git`;
- `.svn` where appropriate;
- `.env`;
- lock files;
- package metadata;
- Composer artefacts;
- build scripts;
- shell scripts.

## 11.12 Vulnerability Probes

Detect requests for common exposed administrative and vulnerable services.

Examples:

- phpMyAdmin;
- cPanel;
- known database interfaces;
- known management tools;
- known vulnerable plugin paths.

## 11.13 Legacy WordPress Endpoints

Support explicit controls for old or commonly abused WordPress endpoints where applicable.

RPC/XML-RPC controls must be configurable rather than assumed universally safe to block.

---

# 12. HTTP Method Intelligence

The product should classify HTTP methods in context.

Methods such as GET, POST and HEAD are expected.

OPTIONS must not be considered malicious merely because it is OPTIONS.

OPTIONS may be:

- legitimate CORS preflight;
- application/API discovery;
- scanner reconnaissance;
- unusual traffic.

Method classification must therefore combine:

- target surface;
- target URI;
- request rate;
- accompanying headers;
- origin;
- subsequent behaviour.

---

# 13. Traffic Protection Controls

Phase 3 should introduce a coherent traffic-protection capability.

## 13.1 Rate Limiting

Support rate limits based on combinations of:

- source IP;
- subnet;
- ASN;
- identity;
- endpoint;
- surface;
- HTTP method;
- request classification;
- authenticated/unauthenticated state.

Controls should support:

- observation;
- threshold warnings;
- progressive throttling;
- temporary blocks;
- escalating temporary blocks.

## 13.2 Excessive Request Detection

The product should distinguish between:

- high legitimate traffic;
- crawler behaviour;
- brute force;
- scraping;
- scanning;
- endpoint abuse;
- distributed activity.

## 13.3 Firewalling

Phase 3 may introduce application-level request blocking.

This must not be represented as equivalent to a network firewall.

Controls may include:

- source IP;
- CIDR;
- ASN;
- country;
- identity;
- detector family;
- target surface;
- request rate.

## 13.4 Geo-IP Controls

Optional Geo-IP controls may support:

- observe;
- alert;
- allow;
- deny;
- rate limit;
- challenge where technically feasible.

Geo-IP data must be treated as probabilistic location intelligence, not proof of a person's physical location.

Geo-IP blocking should not be enabled by default.

## 13.5 ASN Controls

Support classification and optional policy by ASN.

This may be particularly useful for:

- hosting providers;
- cloud platforms;
- VPN providers;
- scanning infrastructure;
- known bot networks.

## 13.6 Tor Awareness

Phase 3 may identify known Tor exit nodes.

Tor identity must not imply malicious intent.

Default treatment should be observation only.

## 13.7 Progressive Response

Where appropriate, controls may escalate through stages:

1. observe;
2. warn;
3. throttle;
4. temporary block;
5. longer temporary block;
6. administrator-reviewed persistent block.

---

# 14. Campaign Detection

Campaign detection is an advanced optional capability.

It must not be enabled for automatic control by default.

The system may correlate multiple individual events into a likely campaign where there is sufficient evidence.

Signals may include:

- repeated identical paths;
- repeated payload fingerprints;
- common user-agents;
- common timing;
- distributed source IPs;
- multiple cloud providers;
- repeated detector-family matches;
- coordinated path sequencing.

Example:

Fifty IP addresses across several infrastructure providers making the same unusual request sequence should be represented as a possible coordinated campaign rather than merely fifty unrelated alerts.

Default behaviour:

- observe;
- correlate;
- explain;
- notify.

Automatic blocking of a correlated campaign requires explicit opt-in.

---

# 15. Deception and Honey Paths

Optional deception capability may include endpoints which legitimate users should never request.

Examples:

- fake administrative paths;
- fake sensitive files;
- canary paths.

Requests to these resources may produce high-confidence reconnaissance signals.

Requirements:

- disabled by default;
- no interference with legitimate routes;
- clear administrative explanation;
- evidence recorded;
- no uncontrolled exposure of sensitive content;
- no active exploitation of the requester.

---

# 16. Integrity Monitoring

Phase 3 should extend beyond inbound request inspection into local integrity observation.

Candidate signals include:

- unexpected PHP files;
- unexpected executable files;
- new administrator accounts;
- suspicious role changes;
- unexpected scheduled tasks;
- unusual WordPress cron entries;
- unexpected plugin/theme file changes;
- new third-party script origins;
- changes to critical configuration.

Integrity monitoring should correlate, where possible, with legitimate events such as:

- plugin update;
- theme update;
- WordPress core update;
- administrator action.

---

# 17. Change Attribution

Phase 3 should attempt to explain security changes in relation to site changes.

Example:

- 14:03 Elementor upgraded;
- 14:04 new script origin observed;
- 14:04 CSP violations begin;
- 14:06 external verification confirms resource-graph change.

The product must not claim causation where only correlation exists.

Where causation cannot be established, the UI should describe the relationship as correlated evidence.

---

# 18. Security Change Window

Phase 3 should consider a controlled security change-window workflow.

An administrator should be able to indicate an intentional change event, for example:

- plugin upgrade;
- theme upgrade;
- deployment;
- major configuration change.

The product may then:

1. snapshot current security state;
2. increase observation;
3. record application changes;
4. collect new behaviour;
5. run external verification;
6. present the delta;
7. allow the administrator to accept the new state as baseline;
8. retain a rollback point where technically possible.

---

# 19. Baseline and Drift

Known-good baselines are a major Phase 3 requirement.

A baseline may include:

- security headers;
- CSP;
- external origins;
- scripts;
- SRI state;
- certificate;
- redirects;
- selected DNS records;
- cookies;
- WordPress/plugin versions;
- representative URLs;
- externally visible technology;
- relevant configuration state.

Future verification must compare current state against the approved baseline.

A drift record should show:

- exact change;
- first observed;
- latest observed;
- affected surface;
- associated control;
- risk classification;
- supporting evidence;
- known correlated change;
- recommendation;
- administrator disposition.

The product must distinguish:

- expected change;
- approved change;
- unexplained drift;
- resolved drift.

---

# 20. External Verification

Local configuration alone cannot prove what an external client receives.

Phase 3 should therefore build towards optional VCNS external verification.

Candidate verification targets include:

- public home page;
- representative public pages;
- WordPress login;
- REST API;
- redirects;
- error responses;
- cached responses;
- uncached responses where technically possible;
- selected public application endpoints.

Verification may inspect:

- expected security headers;
- duplicate headers;
- proxy or CDN replacement;
- report-only versus enforced CSP;
- external scripts;
- external styles;
- SRI;
- certificate state;
- HTTP to HTTPS redirection;
- cross-origin controls;
- reporting endpoints;
- unexpected externally observable technology;
- drift from baseline.

Authenticated administration pages must not be externally crawled unless a separate secure design is approved.

---

# 21. Site Security Health

Phase 3 should avoid arbitrary gamified security scoring as the primary interface.

The preferred model is a defensible operational health summary.

Example categories:

- Enforcement: Healthy
- External verification: Healthy
- Drift: 2 items requiring review
- Certificates: Healthy
- Third-party dependencies: 1 unclassified
- Exceptions: 3 active, 1 expiring
- Automation: Controlled automatic
- Evidence freshness: 17 hours

A numeric score may only be introduced later if its methodology is explainable and defensible.

---

# 22. Recommendations

Recommendations must be evidence-backed.

Each recommendation should, where relevant, state:

- what was observed;
- why it matters;
- affected layer;
- affected pillar;
- affected surface;
- confidence;
- risk;
- evidence;
- recommended action;
- alternative action;
- automation eligibility;
- rollback position.

Deterministic rules remain authoritative for:

- risk classification;
- source validation;
- approval requirements;
- enforcement decisions;
- hard exclusions;
- automation limits.

AI-generated content may assist with explanation, summarisation or recommendation wording.

AI must not independently bypass deterministic controls or directly alter enforced security policy.

---

# 23. Federated Intelligence Service

Phase 3 should define a central VCNS intelligence architecture.

The central service may:

- receive limited site observations where explicitly enabled;
- aggregate patterns;
- maintain scanner/vendor network intelligence;
- maintain crawler intelligence;
- maintain detector patterns;
- maintain known exploit signatures;
- maintain compatibility intelligence;
- identify emerging campaigns;
- provide recommendations;
- provide external verification;
- return signed intelligence updates.

The central service must amplify local decision-making rather than replace it.

## 23.1 Local Authority

The WordPress plugin remains locally authoritative.

A central service must not:

- execute arbitrary PHP;
- deliver executable code through an intelligence channel;
- silently override local high-risk decisions;
- disable existing local protections because the service is unavailable;
- act as an unrestricted remote shell.

## 23.2 Data Sent Centrally

Data collection must be minimised.

Candidate telemetry may include:

- pseudonymous site identifier;
- event type;
- detector ID;
- timestamp;
- source network data where permitted;
- request fingerprint;
- target class;
- surface;
- confidence;
- action;
- outcome.

Sensitive request bodies, credentials and customer content should not be transmitted unless explicitly required, justified and approved.

## 23.3 Signed Intelligence

Central intelligence delivered to sites should be:

- versioned;
- signed;
- authenticated;
- provenance-aware;
- replay-resistant;
- locally validated;
- auditable.

## 23.4 Offline Behaviour

Loss of the VCNS service must not remove locally enforceable protection.

Existing controls must continue operating using the last valid local configuration and intelligence cache.

---

# 24. Managed Intelligence Updates

A future managed update service may distribute:

- vendor IP ranges;
- crawler definitions;
- AI crawler identities;
- scanner identities;
- detector signatures;
- known exploit probes;
- compatibility intelligence;
- known infrastructure metadata;
- risk-rule updates.

The value proposition should centre on maintained security intelligence and assurance rather than merely unlocking local interface options.

---

# 25. Commercial Product Boundary

Phase 3 should allow for future product tiers without requiring the entire architecture to be duplicated.

Potential packaging:

## Community

- local baseline security controls;
- local observation;
- local deterministic detection;
- manual/assisted workflows;
- core certificate management;
- core browser-security controls.

## Professional

Potential future capabilities:

- advanced detector packs;
- richer automated controls;
- advanced request intelligence;
- extended Geo-IP/ASN policy;
- deeper integrity monitoring;
- advanced baseline/drift workflows.

## Managed

Potential future capabilities:

- federated intelligence;
- external verification;
- central reporting;
- fleet posture;
- cross-site pattern intelligence;
- managed detector updates;
- evidence aggregation;
- managed recommendations.

Exact commercial boundaries remain a packaging decision and must be reconciled with WordPress.org distribution requirements.

---

# 26. Evidence and Assurance

Phase 3 should evolve SAM towards continuous security assurance.

The assurance model should connect:

**Control configured locally → Observed → Decided → Controlled → Externally verified → Evidenced**

Evidence should support:

- security reviews;
- MSP service reporting;
- customer assurance;
- audit preparation;
- technical control review.

Potential mappings may include:

- Cyber Essentials;
- ISO/IEC 27001;
- PCI DSS;
- OWASP ASVS;
- CIS Controls.

The product must not claim that technical evidence alone establishes compliance or certification.

---

# 27. Fleet Management

Fleet management is explicitly later-phase capability.

The central architecture should not be overbuilt before sufficient operational evidence exists.

Future fleet views may show:

- sites;
- version;
- update state;
- protection posture;
- drift;
- outstanding approvals;
- certificate risk;
- active exceptions;
- failed verification;
- scanner/crawler activity;
- intelligence freshness;
- entitlement state.

Example estate view:

- 83 sites
- 76 healthy
- 4 security drift events
- 2 certificate risks
- 1 CSP enforcement regression
- 7 outstanding administrator decisions

Fleet management must be built after real-world independent deployments establish the actual support and operational requirements.

---

# 28. UX Principles

Phase 3 administration must support both technical and non-technical users.

Requirements:

- plain-language lifecycle navigation;
- standards remain visible for technical users;
- technical terms are explained in context;
- no unexplained acronym-only primary navigation;
- evidence is available behind decisions;
- direct technology drill-down remains fast;
- status is understandable without opening every control;
- automation posture is visible;
- surface scope is visible;
- confidence is visible;
- central versus local evidence is distinguishable.

---

# 29. Explainability

Every significant automated action should be explainable.

An action record should answer:

- What happened?
- What evidence was observed?
- Which detector matched?
- How confident was the classification?
- Which policy authorised the action?
- What action was taken?
- Which surface was affected?
- Was the identity independently verified?
- Was the source merely recognised or explicitly authorised?
- How can the action be reversed?
- Was the outcome verified?

This is mandatory for security automation and future MSP/assurance use.

---

# 30. Default-Safety Requirements

Phase 3 must maintain conservative defaults.

The following should not automatically block by default:

- Geo-IP;
- ASN;
- Tor;
- campaign correlation;
- crawler classification;
- commercial scanner recognition;
- technology mismatch;
- HTML injection where legitimate HTML input may exist;
- generic OPTIONS requests;
- uncertain behavioural classifications.

New detector families should normally begin in Observe mode.

Automation may increase only when:

- confidence is sufficient;
- false-positive risk is understood;
- explicit administrator policy permits it;
- rollback or recovery is available where applicable.

---

# 31. Technical Architecture Requirements

The detector subsystem should use reusable interfaces rather than embedding isolated regular expressions throughout request hooks.

Suggested logical components:

- Request Observer
- Surface Classifier
- Identity Resolver
- Network Intelligence Resolver
- Detector Registry
- Detector Engine
- Confidence Engine
- Policy Engine
- Control Engine
- Verification Engine
- Audit/Evidence Store
- Intelligence Update Client

Detector data should be versionable independently from the core detection engine where practical.

---

# 32. Detector Test Requirements

Every detector should have regression fixtures.

Testing should include:

- positive match;
- negative match;
- encoded variant;
- benign lookalike;
- surface applicability;
- action eligibility;
- confidence outcome;
- false-positive regression cases.

Changes to managed detector data should be testable before release.

---

# 33. Performance Requirements

Request inspection must not impose uncontrolled overhead on normal WordPress traffic.

Requirements:

- fast-path rejection of irrelevant detectors;
- avoid repeated external lookups during requests;
- cache network intelligence;
- perform heavy correlation asynchronously;
- bound event storage;
- bound queues;
- configurable retention;
- avoid blocking page delivery on central-service availability.

---

# 34. Privacy Requirements

Security telemetry can contain personal data.

Phase 3 must:

- minimise stored request data;
- avoid storing credentials;
- avoid storing full sensitive request bodies by default;
- document retention;
- support deletion;
- distinguish local and central data;
- document third-party intelligence services;
- provide administrator controls over telemetry sharing.

---

# 35. Development Roadmap

## Phase 3A: Information Architecture and Product Model

Deliver:

- formal protection-layer model;
- operational lifecycle;
- navigation redesign;
- Settings overview grouped by layer;
- consistent status model;
- surface visibility;
- preserved technology-pillar drill-down.

Exit criteria:

- a non-technical administrator can understand the product structure without knowing individual HTTP security-header names;
- technical users retain direct access to individual pillars.

## Phase 3B: Request Observation Framework

Deliver:

- request observer;
- surface classifier;
- event schema;
- detector registry;
- confidence model;
- audit/evidence integration;
- Observe-only initial mode.

Exit criteria:

- detectors can be added without rewriting core request-flow architecture.

## Phase 3C: Initial Detector Families

Deliver initial deterministic detectors for:

- technology mismatch;
- command injection;
- SQL injection;
- sensitive directories;
- sensitive files;
- setup/install probes;
- script/web-shell probes;
- protocol injection;
- version-control artefacts;
- vulnerability probes.

Exit criteria:

- all detectors have regression tests and explainable evidence.

## Phase 3D: Identity and Scanner Intelligence

Deliver:

- user-agent extraction;
- known crawler identities;
- scanner vendor registry;
- CIDR matching;
- authoritative source URLs;
- customer-specific authorisation state;
- verified-versus-claimed identity model;
- reverse-DNS verification framework.

Exit criteria:

- recognised vendor traffic is never automatically treated as authorised.

## Phase 3E: Traffic Controls

Deliver:

- rate limiting;
- excessive-request detection;
- IP/CIDR control;
- ASN observation/control;
- Geo-IP observation/control;
- progressive temporary blocking;
- per-surface policy.

Exit criteria:

- all new controls default safely;
- administrators can independently configure Frontend, Admin, Login and API behaviour.

## Phase 3F: Baseline and Drift

Deliver:

- approved baseline;
- change capture;
- drift records;
- risk classification;
- administrator disposition;
- correlation with WordPress updates;
- evidence history.

Exit criteria:

- administrators can answer "what changed?" rather than only "what is configured?"

## Phase 3G: External Verification

Deliver:

- external verification service design;
- ownership/authentication model;
- representative target management;
- external header verification;
- certificate verification;
- redirect verification;
- script/SRI observation;
- drift comparison.

Exit criteria:

- local intended state can be compared with externally observed state.

## Phase 3H: Federated Intelligence

Deliver:

- central intelligence data model;
- signed intelligence bundles;
- local validation;
- scanner/crawler updates;
- managed detector updates;
- privacy controls;
- offline caching;
- service failure handling.

Exit criteria:

- central service enhances intelligence without becoming a remote-control dependency.

## Phase 3I: Assurance and Reporting

Deliver:

- site security health;
- evidence exports;
- control-to-evidence mapping;
- exception state;
- evidence freshness;
- assurance reporting.

Exit criteria:

- output is useful to administrators, MSPs and assurance reviewers without making unsupported compliance claims.

## Phase 3J: Advanced Optional Intelligence

Consider:

- campaign detection;
- deception/honey paths;
- advanced integrity monitoring;
- adaptive controls;
- security change windows;
- richer change attribution.

These capabilities should follow operational validation of the core Phase 3 detection model.

---

# 36. Phase 3 Non-Goals

Phase 3 is not intended to:

- replace a dedicated network firewall;
- claim equivalence with a full enterprise WAF;
- become an unrestricted remote administration agent;
- treat known commercial scanners as inherently trusted;
- automatically block all bot traffic;
- automatically block by geography by default;
- infer malicious intent solely from Tor use;
- treat every unusual HTTP method as malicious;
- claim compliance certification;
- rely on AI as the authority for enforcement;
- build full fleet management before operational requirements are validated.

---

# 37. Definition of Done for Phase 3 Core

The Phase 3 core should be considered complete when:

- the product architecture clearly separates layers, lifecycle, surfaces and technology pillars;
- the primary administration experience uses Observe, Decide, Control, Verify and Settings;
- the Settings overview is grouped by protection layer;
- request observation is implemented through a reusable detector architecture;
- key attack/reconnaissance detector families are available;
- crawler/scanner identities can be recognised and evidence-backed;
- recognition and authorisation are explicitly distinct;
- traffic controls are surface-aware;
- controlled automation applies to detection and traffic controls;
- baselines and drift records are supported;
- external verification can compare intended and observed state;
- central intelligence updates are signed and locally validated;
- loss of the central service does not remove local protections;
- actions and recommendations are explainable and auditable;
- evidence can be exported for security assurance purposes.

---

# 38. Strategic Outcome

Phase 1 establishes the protection core.

Phase 3 changes the product from:

> A WordPress plugin that configures and automates security controls.

Into:

> A WordPress site security platform that observes, decides, controls and verifies security state across multiple protection layers.

The longer-term managed-service direction becomes:

> A federated security assurance platform in which each WordPress installation remains locally authoritative while VCNS provides shared threat intelligence, external verification, aggregated pattern recognition and managed security knowledge.

The design principle remains:

**Local autonomy first. Central intelligence as an amplifier.**
