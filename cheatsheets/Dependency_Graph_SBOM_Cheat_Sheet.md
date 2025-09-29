# Dependency Graph & SBOM Best Practices Cheat Sheet

## Introduction

Modern software is built from hundreds — often thousands — of third-party components: packages, libraries, container layers, and binaries. A Software Bill of Materials (SBOM) is the canonical, machine-readable inventory of those components; a dependency graph maps how those components relate to one another. Together they turn opaque supply-chain complexity into actionable data.

### TL;DR — Quick checklist

- Generate SBOMs **during build** (not ad-hoc) to capture exact resolved dependencies and metadata.
- Use standard formats (SPDX or CycloneDX) and publish at least one machine-readable SBOM per release.
- Sign SBOMs and artifacts (cosign / sigstore / in-toto) to bind SBOMs to the built artifact.
- Version and store SBOMs in a trusted artifact store or SBOM management system (e.g., Dependency-Track).
- Automate vulnerability enrichment & triage (Grype, OSS Index, Snyk, commercial feeds) and integrate with ticketing/incident flows.
- Maintain a policy that defines required SBOM elements, retention, and sharing rules.

## 1. Why SBOMs and dependency graphs matter

An SBOM is a structured inventory of software components that make up a product. It helps teams: discover vulnerable components, manage license risk, respond to incidents, and meet regulatory or customer transparency requirements. A dependency graph complements SBOMs by mapping relationships (direct and transitive) so you can reason about impact and remediation paths.

## 2. Definitions (short)

- **SBOM** — Software Bill of Materials; machine-readable list of components, versions, checksums, and metadata.
- **Component** — A package, library, container image layer, binary, or module included in the product.
- **Dependency graph** — Directed graph of components showing dependency relationships.
- **Provenance / Attestation** — Evidence that the SBOM was produced by the claimed build process and is bound to the artifact.

## 3. Minimum SBOM elements you should capture (practical)

At a minimum capture:

1. Component name and version (canonicalized)
2. Unique package identifiers (purl / package URL) where available
3. Package type/ecosystem (npm, maven, pypi, deb, rpm, apk, OS image)
4. Checksum(s) (SHA256 preferred) of the package or artifact
5. Component supplier / origin (URL or VCS) where known
6. License information (if available)
7. Timestamps (generation time) and build identifiers (CI run ID)
8. Relationship edges: direct vs transitive dependency
9. SBOM generator metadata (tool, version, command)

## 4. Choose the right format(s)

- **CycloneDX** — Lightweight, extensible, friendly for vulnerability tools and supported widely in SCA and Dependency-Track ecosystems.
- **SPDX** — Rich and widely-adopted, especially for licensing and compliance workflows. Good for legal/audit scenarios.

Recommendation: **Emit at least one of CycloneDX or SPDX**. If you need cross-team compatibility, produce both. Keep SBOMs machine-readable (JSON / XML) and avoid bespoke CSVs for automation.

## 5. When & where to generate SBOMs

**Best place:** The canonical time to generate an SBOM is *during the build step*, after dependency resolution and before packaging or publishing. Reasons:

- The build has the exact dependency graph and resolved versions.
- You can capture build metadata (CI job, artifact digest, builder identity).
- You reduce the risk of mismatches between what was scanned and what shipped.

**Other useful times/places:**

- **Local** (developer) SBOMs are useful for early validation — but treat them as best-effort.
- **Container image** SBOMs: generate both a build-time SBOM and an image-inspection SBOM (scanning the final image layers) to catch injected/packaged content.
- **Runtime / Deployed** SBOMs: collect via runtime telemetry or instrumentation where feasible to validate what actually executes in production.

## 6. Tooling & automation — pragmatic recommendations

**Generate**: Syft (anchore), CycloneDX CLI, SPDX tools, package-manager native exporters (e.g., `mvn --describe-plugin` ecosystem exporters). Generate SBOMs in the build container/agent.

**Sign / Attest**: Cosign / Sigstore & in-toto attestations. Artifact signing binds artifact <-> SBOM and reduces tampering risk.

**Scan / Enrich**: Grype (anchore), OSS Index, Snyk, Dependabot. Automate vulnerability enrichment and map CVEs to SBOM components.

**Store & Analyze**: OWASP Dependency-Track, commercial SBOM managers, or artifact registries with SBOM support. These systems ingest SBOMs, track component changes, and support notifications/alerting.

**Example commands (generation):**

- Syft to CycloneDX JSON:

```bash
syft packages dir:. -o cyclonedx-json > sbom-cyclonedx.json
```

- Syft to SPDX JSON:

```bash
syft packages dir:. -o spdx-json > sbom-spdx.json
```

- CycloneDX CLI (from a built artifact):

```bash
cyclonedx-bom -o bom.xml --input-pkg target/my-app.jar
```

(Place generator commands in your build scripts or CI job and fail the build if SBOM generation fails.)

## 7. Bind SBOM to artifacts (signing & provenance)

**Why:** An unsigned SBOM can be replaced or forged. Signing/attestation proves the SBOM came from the same trusted build process as the artifact.

**How:**

- Produce the artifact (container image, package, binary) and the SBOM in the same CI job.
- Use Sigstore / Cosign to sign the artifact and create an attestation that includes the SBOM (or references it by digest).
- Optionally use in-toto and SLSA provenance to record each step and who performed it.

**Practical flow:**

1. Build -> produce artifact and SBOM (versioned).
2. Compute digests for artifact and SBOM.
3. Create an in-toto attestation tying the artifact digest to the SBOM digest and sign with cosign.
4. Push artifact, SBOM, and attestation to the artifact registry.

## 8. Ingesting & managing SBOMs at scale

**Centralize consumption**: Use a dedicated SBOM management system (Dependency-Track, commercial SBOM managers) or at least a searchable artifact registry that supports SBOM attachments.

**Versioning:** Treat SBOMs like code: store them with release tags and keep historical SBOMs for audit and incident response. Prefer storing SBOMs in an immutable artifact store or an SBOM datastore that maintains history.

**Normalization & deduplication:** When ingesting SBOMs from many suppliers, normalize package identifiers (purl) and deduplicate transitive component records where possible.

**Enrichment:** After ingestion, enrich SBOM entries with vulnerability databases, license info, and known-good policy tags to enable automated triage.

## 9. Vulnerability triage & remediation workflow

- **Map CVE -> SBOM component(s)** to identify direct vs transitive exposure.
- **Prioritize**: direct dependencies and high-severity CVEs affecting runtime libraries score higher. Use exploitability and ease-of-remediation as tie-breakers.
- **Patch vs Mitigate**: for transitive dependencies that can't be patched upstream quickly, use mitigations — upgrade direct dependency, apply runtime mitigations, or isolate the vulnerable component.
- **Track**: create an issue in your tracker with SBOM evidence (component, version, occurrences, artifact digest).
- **Verify**: after remediation, generate a new SBOM and confirm the vulnerable component no longer appears in the new artifact.

## 10. Handling transitive dependencies and supply chain depth

- **Visualize** with dependency graphs to show why a vulnerable transitive package is included.
- **Prefer explicit direct upgrades** where possible (bump direct dependency to a version that pulls a fixed transitive release).
- **Consider mitigation patterns**: dependency replacement, patching (if legal and feasible), or runtime limitations.
- **Long-lived third-party binaries**: include policy to monitor and re-evaluate older dependencies that receive no updates.

## 11. SBOM quality — common pitfalls & how to avoid them

- **Incomplete generation**: running SBOM tooling in the wrong directory or before dependency resolution -> generate in build after resolution.
- **Missing metadat**A: no timestamps, missing checksums, or no tool metadata. Always include generator tooling metadata.
- **Inconsistent formats**: mixing custom fields that break parsers — stick to SPDX/CycloneDX fields and use extensions only when necessary.
- **Unsigned SBOMs and no provenance**: makes SBOMs less trustworthy. Sign and attestate.
- **No versioning or archival**: losing historical SBOMs hinders incident response — enforce retention.

## 12. Policy & governance (what to write into your SBOM policy)

Minimum policy items:

- **Required formats** (CycloneDX vX or SPDX vY), and acceptable alternates
- **Required fields** (see section 3)
- **Where to store** (artifact registry, SBOM manager) and retention policy
- **Signing & attestation requirement** (e.g., all public releases must be signed)
- **SLA for vulnerability response** based on severity and impact
- **Supplier SBOM acceptance rules** (e.g., third-party vendors must supply SBOMs in a supported spec)
- **Access controls** for SBOMs containing sensitive metadata (avoid leaking internal repo URLs if not necessary)

## 13. Contractual & procurement considerations

- Require SBOMs as part of software delivery (per-release) and include minimum element requirements in contracts.
- Define acceptable SBOM formats and delivery mechanism (artifact registry link, signed attestation).
- Request evidence of build provenance (e.g., signed attestations or SLSA level) for high-risk components.

## 14. Incident response playbook (SBOM-centered)

1. **Ingest** the vendor-provided SBOM (or generate from your deployed artifact).
2. **Map** CVE/indicator to components and affected artifacts.
3. **Assess** blast radius using dependency graph (services, containers, devices affected).
4. **Contain** with mitigations (network ACLs, hotfixes, rolling re-deploys, feature flags).
5. **Remediate**: patch/update, or replace component.
6. **Verify**: produce new SBOM and confirm removal of vulnerable component.
7. **Document**: record timelines, SBOM evidence, and lessons learned.

## 15. Practical CI/CD snippets & patterns

**GitHub Actions (example)** — generate CycloneDX and upload as artifact, then sign with cosign.

```yaml
name: Build and SBOM
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build
        run: ./gradlew assemble
      - name: Generate SBOM
        run: |
          syft packages dir:./build/libs -o cyclonedx-json > sbom.json
      - name: Upload SBOM
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom.json
      - name: Sign Artifact & SBOM
        run: |
          cosign sign --key ${{ secrets.COSIGN_KEY }} my-registry/my-app:${{ github.sha }}
          cosign sign-blob --key ${{ secrets.COSIGN_KEY }} --output-signature sbom.json.sig sbom.json
      - name: Push image
        run: ./push-image.sh
```

**Fail-fast vs Warn**: In CI, fail the pipeline if SBOM generation fails, but avoid failing builds on non-actionable low-severity findings — instead surface results to triage dashboards.

## 16. Privacy & confidentiality considerations

SBOMs can reveal internal repository URLs, private package names, or dev machine paths. Treat SBOMs as sensitive when they contain internal details. Options:

- Strip or redact sensitive fields before public distribution.
- Keep detailed SBOMs in a private registry and publish a redacted SBOM for external customers.

## 17. Metrics & KPIs to measure SBOM program health

- % of releases with a signed SBOM attached
- Time from vulnerability publication to detection in your SBOMs (mean time to detect)
- Time to remediate vulnerabilities tied to SBOM components (MTTR)
- % of SBOMs that meet required minimum elements
- Number of third-party suppliers providing SBOMs on request

## 18. Example workflows (short)

**Supplier intake**: Vendor provides signed SBOM -> ingest into DT -> auto-enrich -> if critical CVE found, create ticket and notify procurement + security.

**Internal release**: CI builds artifact + sbom -> sign & push -> SBOM ingested to DT -> scheduled scan enrich -> policy engine flags high-sev/forbidden licenses -> create PR to remediate.

## 19. Appendix — example commands & tools (quick)

**Tools**: Syft, Grype, CycloneDX CLI, SPDX tools, Dependency-Track, Cosign/Sigstore, in-toto, Grype, Snyk, OSS Index, Anchore, Syft.

**Syft generation examples:**

```bash
# Generate CycloneDX
syft packages dir:. -o cyclonedx-json > sbom-cdx.json
# Generate SPDX
syft packages dir:. -o spdx-json > sbom-spdx.json
```

**Grype scan from SBOM**:

```bash
grype sbom:sbom-cdx.json
```

**Cosign sign an SBOM (example)**:

```bash
cosign sign-blob --key cosign.key --output-signature sbom.json.sig sbom.json
```

## References

- [CycloneDX specification and Authoritative Guide](https://cyclonedx.org/guides/OWASP_CycloneDX-Authoritative-Guide-to-SBOM-en.pdf)
- [SPDX and NTIA Minimum Elements for SBOM HOWTO](https://spdx.github.io/spdx-ntia-sbom-howto/)
- [CISA SBOM guidance](https://www.cisa.gov/sbom)
- [OWASP SBOM Forum](https://owasp.org/www-project-sbom-forum/)
- [Software Supply Chain Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html)
