# SAM Edge Integration with VCNS Fleet Management

**Status:** Agreed requirements, not a claim of implementation  
**Decision date:** 4 November 2026  
**Owner:** `vcns/security-automation-manager` (WordPress plugin)

This specification covers changes to **SAM itself**. Fleet orchestration, VCNS Portal identity and UI, Platform shared services, central Zabbix operations, and entitlement issuance belong to their respective products. Do not implement those services inside the WordPress plugin.

## Service boundaries

- `https://fleet.vcns.tech`: SAM's authenticated Fleet Management API, policy distribution, evidence and state exchange.
- `https://portal.vcns.tech`: operator-facing UI, **not** an alternative configuration channel into SAM.
- `https://platform.vcns.tech`: shared organisation, identity, role, notification and product-subscription capabilities, **not** a SAM policy authority.
- `https://licensing.vcns.tech`: existing commercial entitlement authority. A Fleet connection and a commercial licence are independent.

SAM continues to function locally without Fleet or Portal. Loss of hosted services must not remove enforced protection, revoke locally approved policies, or block local administration.

## Enrolment, authority and identity

1. An installation generates and retains its **own** asymmetric key pair and installation GUID; private keys are not exported.
2. Enrolment binds the installation to an **agency GUID**, a canonical site origin, and an agency-specific trusted Fleet policy-signing public key. The agency policy key is different from the installation's identity key and from entitlement-signing keys.
3. Policy resources are agency-scoped (for example, `/api/v1/agencies/{agencyGUID}/...`). SAM must reject a policy if its signed agency scope, API path scope or enrolled agency identity differ. This is an authentication/authorisation failure, not a best-effort warning.
4. A SHA-384 content digest supports integrity comparisons and policy diffs, **not authorisation on its own**. Agency policy authorisation requires a separately verified digital signature. ECDSA P-384 with SHA-384 is the proposed profile, subject to an interoperability/security review and fixtures.
5. A routine key rotation can be authorised by the existing trusted key and is auditable. A compromised trust root requires unlinking and fresh enrolment with new identities and keys. Do not add an undocumented recovery or master signing key.
6. During enrolment the site's local administrator chooses **trusted Fleet policy application** or **local manual approval**. This existing choice is sufficient. Do not introduce another mandatory customer approval workflow for ordinary agency changes. Re-enrolment requires a fresh choice.

## Clones, migrations and reset

A cloned WordPress database may inherit the installation GUID and private keys. An unexpected canonical-origin change must therefore invalidate the prior Fleet identity and stop policy acceptance. SAM must distinguish a verified, authorised site migration from a newly cloned installation.

For a confirmed clone, provide a safe **full-product reinitialisation**, clearing inherited Fleet identity, policy and SAM-owned state before issuing new keys and enrolment. Use the existing Recovery / Reset Plugin Data semantics, including the fact that a fresh setup reseeds its own security defaults; do not interpret a reset as permission to weaken an unrelated website or manipulate third-party plugin data. Do not irreversibly reset on a transient URL or reverse-proxy anomaly alone. The source installation is unaffected.

A clone of production into development becomes a **new** Fleet installation with a new environment and policy inheritance chain.

## Effective policy application

SAM shall receive a typed, versioned and authenticated **effective policy bundle**, including its provenance, relevant inherited/mandatory constraints, agency scope, environment, installation, validity and rollback reference. Resolution and manual impact preview are Fleet responsibilities, not WordPress tasks.

The source policy model uses per-setting precedence through organisation, arbitrarily nested single-parent agency groups, environment, installation and local administrative layers. Complementary settings accumulate. Mandatory upper-level constraints cannot be overridden by lower-level policies; mandatory denies take precedence over allowlist exceptions. SAM must reject attempts to apply a prohibited local override. A separately defined local emergency break-glass process may be supported; it must be evident and audited.

SAM validates support and safety, stages/applies its **own** settings, reports what actually applied, and retains sufficient local recovery and rollback state. Signed Fleet instructions never authorise arbitrary shell/PHP execution.

## Ownership and drift

SAM is authoritative only for data, tables, files and configuration it owns. It may detect and report changes to other plugins, themes or server configuration, but **must not restore or rewrite them**. For its own managed controls, default remediation may restore desired state with safeguards against loops and repeated unsafe changes; every attempt and outcome is evidenced.

Fleet should be able to distinguish intended configuration, reported applied state and independently observed runtime behaviour. SAM supplies the second of these; independent external observation belongs to monitoring infrastructure.

## CSP approval postures and entitlement

Approval automation and CSP report-only/enforce mode are **separate dimensions**. The target approval postures (configured per surface) are:

| Level | Name | Decision behaviour | Entitlement |
| --- | --- | --- | --- |
| 3 | Administrator-controlled | Manual approval for low, medium and high risk proposals | Free |
| 2 | Restricted autonomy | Auto-approve eligible low-risk proposals only | Free |
| 1 | Supervised automation | Auto-approve eligible low/medium-risk proposals; high-risk manual | Free |
| 0 | Fully autonomous | Auto-approve otherwise eligible proposals within non-negotiable safety restrictions | Paid |

When a Level 0 entitlement expires or is revoked after applicable grace handling, **effective approval posture becomes Level 3**. Preserve the configured Level 0 selection for display and possible reactivation. Re-evaluate pending proposals against the effective posture. Never remove previously enforced protections or silently revert CSP configuration as a licensing consequence.

This is a **target change** to the plugin's existing documented fallback, which currently describes a weaker downgrade. The entitlement service establishes entitlement truth; SAM alone determines effective approval behaviour.

## Evidence, policy alignment and diagnostics

SAM shall report installation ID, agency binding, control ID/surface, effective policy ID and version, effective setting values, observed local application status, timestamps, compatibility warnings and audit references. Evidence must distinguish **delivered**, **configured**, **applied** and **independently verified**, and preserve uncertainty where an external check is impossible.

The product and integration UI should use **Policy Alignment**, not regulatory compliance: aligned, misaligned, unverified or not applicable against the **policy in effect**. Standards and Framework Compliance is a distinct, deferred module outside SAM/Fleet's initial scope.

A live header change that matches the effective policy is successful verification evidence, **not** by itself a security incident or policy misalignment.

## Compatibility and acceptance requirements

- Existing local security functions and default safe headers survive normal Fleet outages and commercial entitlement changes.
- Local administrator approval choice, agency signature checks, mandatory restrictions and rollback are enforced locally even when Fleet requests an update.
- No write access to Zabbix is required by SAM; it does not own multi-tenant monitoring or agency UI.
- Contract tests cover enrolment, agency mismatch, replay/reordering, signing-key rotation, compromised trust requiring re-enrolment, clone versus legitimate migration, mandatory overrides, denied actions, licence expiry, drift ownership, and offline operation.
- No implementation status should be inferred from this proposed requirements document.
