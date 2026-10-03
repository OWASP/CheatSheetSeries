# Dependency Graph & SBOM Best Practices Cheat Sheet

## Introduction

A software bill of materials (SBOM) inventories software components; a dependency graph records their relationships. Use both to locate vulnerable components in releases and deployments. The [CycloneDX SBOM guide](https://cyclonedx.org/guides/OWASP_CycloneDX-Authoritative-Guide-to-SBOM-en.pdf) describes these capabilities.

## Capture components and relationships

Use a standard machine-readable format such as CycloneDX. Capture:

- Component names, versions, suppliers, package identifiers, and hashes where available.
- Direct and transitive dependency relationships: components used directly and those brought in by other components.
- The product described, SBOM author, generation time, and generator identity/version.

Record incomplete or unknown coverage explicitly. A component missing from an SBOM is not evidence that it is absent from the software. The [CycloneDX guide](https://cyclonedx.org/guides/OWASP_CycloneDX-Authoritative-Guide-to-SBOM-en.pdf) covers metadata and completeness declarations.

## Generate for each release

Automate generation after dependency resolution, then reconcile the inventory with the final package or container image. Include bundled libraries and operating system packages where applicable; manifests alone can misrepresent shipped contents. Record generation scope and known gaps. The [CycloneDX generation guidance](https://cyclonedx.org/guides/OWASP_CycloneDX-Authoritative-Guide-to-SBOM-en.pdf) recommends comparing build artifacts with the SBOM and correcting discrepancies.

Validate the document against its format's schema before publication or ingestion, and separately check the metadata and relationships listed above. Passing these checks does not establish inventory completeness.

Keep each release's inventory distinct. For pipeline hardening, follow the [CI/CD Security Cheat Sheet](CI_CD_Security_Cheat_Sheet.md).

## Bind and verify release evidence

Bind the SBOM to the final artifact's cryptographic digest through a signed attestation: a signed statement identifying the artifact and its SBOM. Signing the artifact and SBOM separately does not establish that relationship. An SBOM attestation describes inventory; build provenance separately records how the artifact was produced.

Use [SLSA's provenance verification checks](https://slsa.dev/spec/v1.2/verifying-artifacts) as a model for verifying release evidence before installation or deployment: validate signatures, allowed signer identities, the artifact digest, and the expected attestation type. For build provenance, also check the expected builder identity, source repository, build type, and parameters. Reject missing, invalid, or unexpected evidence when your trust policy requires it.

Valid signatures authenticate claims and protect their integrity. They do not prove that an SBOM is accurate or complete, that software is safe, or that a trusted builder has not been compromised.

Preserve original SBOMs and signed evidence alongside each release, even when importing inventory into another system. Restrict write access and limit sharing of sensitive metadata. [CISA's SBOM consumption guidance](https://www.cisa.gov/sites/default/files/2024-08/SECURING_THE_SOFTWARE_SUPPLY_CHAIN_RECOMMENDED_PRACTICES_FOR_SOFTWARE_BILL_OF_MATERIALS_CONSUMPTION-508.pdf) covers validation and original-document retention. See the [Software Supply Chain Security Cheat Sheet](Software_Supply_Chain_Security_Cheat_Sheet.md) for broader controls.

## Use inventory for vulnerability response

Map release SBOMs to deployed systems and reassess components when new advisories arrive. Prioritize direct and transitive dependencies by exploitability, exposure, and impact; dependency depth alone does not determine risk. Use the graph to identify which parent dependency brings in an affected component.

Vulnerability Exploitability eXchange (VEX) documents state whether a vulnerability affects a particular product. Before accepting a "not affected" claim, authenticate the issuer, verify document integrity, and assess its justification against the exact product version and deployment conditions. [CISA's consumption guidance](https://www.cisa.gov/sites/default/files/2024-08/SECURING_THE_SOFTWARE_SUPPLY_CHAIN_RECOMMENDED_PRACTICES_FOR_SOFTWARE_BILL_OF_MATERIALS_CONSUMPTION-508.pdf) recommends checking VEX veracity and reassessing risk over time.

Use the [Vulnerable Dependency Management Cheat Sheet](Vulnerable_Dependency_Management_Cheat_Sheet.md) to select and verify remediation. After rebuilding, compare the new SBOM with the previous release and update deployment mappings. An updated inventory does not by itself prove that the vulnerability is fixed or the mitigations work.

## References

- [OWASP CycloneDX: Authoritative Guide to SBOM](https://cyclonedx.org/guides/OWASP_CycloneDX-Authoritative-Guide-to-SBOM-en.pdf)
- [CISA: Recommended Practices for Software Bill of Materials Consumption](https://www.cisa.gov/sites/default/files/2024-08/SECURING_THE_SOFTWARE_SUPPLY_CHAIN_RECOMMENDED_PRACTICES_FOR_SOFTWARE_BILL_OF_MATERIALS_CONSUMPTION-508.pdf)
