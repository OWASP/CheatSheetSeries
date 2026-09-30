# Dependency Graph & SBOM Best Practices Cheat Sheet

## Introduction

Modern software relies on hundreds of third-party components. A Software Bill of Materials (SBOM) provides a machine-readable inventory of those components, while a dependency graph shows how they relate. Together, they enable accurate vulnerability management, compliance checks, and faster incident response.

### TL;DR — Quick checklist

- Generate SBOMs **during build** (not ad-hoc) to capture exact resolved dependencies and metadata.
- Use standard formats (SPDX or CycloneDX) and publish at least one machine-readable SBOM per release.
- Sign SBOMs and artifacts (cosign / sigstore / in-toto) to bind SBOMs to the built artifact.
- Version and store SBOMs in a trusted artifact store or SBOM management system (e.g., Dependency-Track).
- Automate vulnerability enrichment & triage (Grype, OSS Index, Snyk, commercial feeds) and integrate with ticketing/incident flows.
- Maintain a policy that defines required SBOM elements, retention, and sharing rules.

## Definitions (short)

- **SBOM** — Software Bill of Materials; machine-readable list of components, versions, checksums, and metadata.
- **Component** — A package, library, container image layer, binary, or module included in the product.
- **Dependency graph** — Directed graph of components showing dependency relationships.
- **Provenance / Attestation** — Evidence that the SBOM was produced by the claimed build process and is bound to the artifact.
- **VEX (Vulnerability Exploitability eXchange)** — A machine-readable document that states whether a known vulnerability actually affects a given product/component, and under what conditions.

## Minimum SBOM elements you should capture (practical)

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

## SBOM Formats & Generations

- Generate SBOMs during build (after dependency resolution, before packaging) to capture exact versions and metadata.
- Use standard formats:
    1. CycloneDX — lightweight, widely supported in SCA and Dependency-Track.
    2. SPDX — rich, common in compliance/legal workflows.
- Other useful points of generation:
    1. Local/dev for early validation (best-effort).
    2. Container images: build-time + image scan to catch injected content.
    3. Runtime/deployed: telemetry to validate what executes in production.

## Tooling & automation — pragmatic recommendations

**Generate**: Syft, CycloneDX CLI, SPDX tools, or ecosystem exporters. Run in build container/agent.

**Sign / Attest**: Cosign, Sigstore, in-toto — bind SBOM ↔ artifact to prevent tampering.

**Scan / Enrich**: Grype, OSS Index, Snyk, Dependabot — map CVEs to SBOM components.

**Store & Analyze**: Dependency-Track, SBOM managers, or registries with SBOM support.

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

## Bind SBOM to artifacts (signing & provenance)

**Why:** Unsigned SBOMs can be forged; signing/attestation proves they come from the same trusted build.

**How:**

- Generate artifact + SBOM in the same CI job.
- Use Cosign/Sigstore to sign both; optionally add in-toto/SLSA provenance.
- Push artifact, SBOM, and signatures/attestations to your registry.

**Practical flow:**

build → generate image SBOM → scan → publish image → sign and attest by digest → publish SBOM.

## Ingesting & managing SBOMs at scale

Centralize in an SBOM manager (e.g., Dependency-Track) or registry with SBOM support.

Version & retain SBOMs like code for audit/incident response.

Normalize/deduplicate package IDs (purl) across suppliers.

Enrich with vulnerability, license, and policy data for automated triage.

## Vulnerability triage & remediation workflow

- **Map CVE → SBOM component(s)** to see direct vs transitive exposure.
- **Use VEX** where available to understand exploitability — suppliers or tooling may provide VEX documents that indicate whether a CVE is relevant, non-exploitable, or has available mitigations.
- **Prioritize** direct dependencies and high-severity runtime libraries.
- **Patch or Mitigate**: patch if possible; otherwise upgrade, isolate, or apply runtime controls.
- **Track** issues in your system with SBOM + VEX evidence (component, version, digest, exploitability status)
- **Verify** by regenerating SBOM to confirm the vulnerable component is gone.

## Handling transitive dependencies and supply chain depth

- **Visualize** with dependency graphs to show why a vulnerable transitive package is included.
- **Prefer explicit direct upgrades** where possible (bump direct dependency to a version that pulls a fixed transitive release).
- **Consider mitigation patterns**: dependency replacement, patching (if legal and feasible), or runtime limitations.
- **Long-lived third-party binaries**: include policy to monitor and re-evaluate older dependencies that receive no updates.

## SBOM quality — common pitfalls & how to avoid them

Incomplete generation → generate SBOM in build after dependency resolution.

Missing metadata → always include timestamps, checksums, and tool info.

Inconsistent formats → stick to SPDX/CycloneDX; use extensions sparingly.

Unsigned SBOMs / no provenance → sign and attest artifacts.

No versioning or archival → retain historical SBOMs for audit/incident response.

## Policy & governance (what to write into your SBOM policy)

Minimum policy items:

- **Required formats** (CycloneDX vX or SPDX vY), and acceptable alternates
- **Required fields** (see section 3)
- **Where to store** (artifact registry, SBOM manager) and retention policy
- **Signing & attestation requirement** (e.g., all public releases must be signed)
- **SLA for vulnerability response** based on severity and impact
- **Supplier SBOM acceptance rules** (e.g., third-party vendors must supply SBOMs in a supported spec)
- **Access controls** for SBOMs containing sensitive metadata (avoid leaking internal repository URLs if not necessary)

## Practical CI/CD snippets & patterns

**GitHub Actions (container example)** — this assumes a Dockerfile at the repository root. Build a local image, generate its CycloneDX SBOM, and fail on high or critical findings before publication. The [Anchore SBOM action](https://github.com/anchore/sbom-action/blob/main/README.md) generates the file; the [Anchore scan action](https://github.com/anchore/scan-action/blob/main/README.md) supplies the severity gate.

```yaml
name: Build, scan, and publish SBOM
on:
  push:
    branches: [main]
jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
      id-token: write
      attestations: write
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
      - name: Build local image
        run: docker build -t "local/sbom-example:${GITHUB_SHA}" .
      - name: Generate CycloneDX SBOM from the built image
        uses: anchore/sbom-action@e22c389904149dbc22b58101806040fa8d37a610 # v0
        with:
          image: local/sbom-example:${{ github.sha }}
          format: cyclonedx-json
          output-file: sbom.cdx.json
          upload-artifact: false
      - name: Scan before publishing the image
        uses: anchore/scan-action@e1165082ffb1fe366ebaf02d8526e7c4989ea9d2 # v7
        with:
          sbom: sbom.cdx.json
          fail-build: true
          severity-cutoff: high
      - name: Install cosign
        uses: sigstore/cosign-installer@ba7bc0a3fef59531c69a25acd34668d6d3fe6f22 # v4.1.0
      - name: Sign in to GitHub Container Registry
        env:
          GHCR_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: printf '%s' "$GHCR_TOKEN" | docker login ghcr.io -u "$GITHUB_ACTOR" --password-stdin
      - name: Push the scanned image and capture its digest
        id: push
        shell: bash
        run: |
          set -euo pipefail
          image="ghcr.io/${GITHUB_REPOSITORY,,}"
          docker tag "local/sbom-example:${GITHUB_SHA}" "${image}:${GITHUB_SHA}"
          docker push "${image}:${GITHUB_SHA}"
          ref="$(docker image inspect "${image}:${GITHUB_SHA}" --format '{{range .RepoDigests}}{{println .}}{{end}}' | grep -F "${image}@sha256:" | head -n 1)"
          test -n "$ref"
          echo "image_ref=$ref" >> "$GITHUB_OUTPUT"
          echo "image_name=$image" >> "$GITHUB_OUTPUT"
          echo "digest=${ref#*@}" >> "$GITHUB_OUTPUT"
      - name: Sign image and attest its SBOM
        env:
          IMAGE_REF: ${{ steps.push.outputs.image_ref }}
        run: |
          cosign sign --yes "$IMAGE_REF"
          cosign attest --yes --type cyclonedx --predicate sbom.cdx.json "$IMAGE_REF"
          cosign verify --certificate-identity="${GITHUB_SERVER_URL}/${GITHUB_WORKFLOW_REF}" --certificate-oidc-issuer=https://token.actions.githubusercontent.com "$IMAGE_REF" > /dev/null
          cosign verify-attestation --type cyclonedx --certificate-identity="${GITHUB_SERVER_URL}/${GITHUB_WORKFLOW_REF}" --certificate-oidc-issuer=https://token.actions.githubusercontent.com "$IMAGE_REF" > /dev/null
      - name: Attest build provenance
        uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4
        with:
          subject-name: ${{ steps.push.outputs.image_name }}
          subject-digest: ${{ steps.push.outputs.digest }}
          push-to-registry: true
          create-storage-record: false
      - name: Publish SBOM to Dependency-Track
        env:
          DT_URL: ${{ vars.DT_URL }}
          DT_PROJECT_UUID: ${{ vars.DT_PROJECT_UUID }}
          DT_API_KEY: ${{ secrets.DT_API_KEY }}
        run: |
          set -euo pipefail
          test -n "$DT_URL" && test -n "$DT_PROJECT_UUID" && test -n "$DT_API_KEY"
          curl --fail-with-body --show-error --silent \
            -H "X-Api-Key: ${DT_API_KEY}" \
            -F "project=${DT_PROJECT_UUID}" \
            -F "bom=@sbom.cdx.json" \
            "${DT_URL%/}/api/v1/bom"
```

The image is signed by digest with keyless Cosign, and the CycloneDX document is attached as a signed SBOM attestation. The separate GitHub attestation records actual build provenance; an SBOM attestation alone is not build provenance. See [Sigstore container signing](https://docs.sigstore.dev/cosign/signing/signing_with_containers/), [Cosign attestation types](https://github.com/sigstore/cosign/blob/main/doc/cosign_attest.md), and [GitHub artifact attestations](https://github.com/actions/attest/blob/main/README.md). Confirm that your repository can publish to GHCR and that [artifact attestations are available](https://docs.github.com/en/actions/concepts/security/artifact-attestations) for its GitHub plan.

Set `DT_URL` and `DT_PROJECT_UUID` as GitHub variables and `DT_API_KEY` as a secret. The upload uses Dependency-Track's multipart BOM endpoint; it does not verify the Cosign attestation for consumers. See [Dependency-Track CI/CD guidance](https://docs.dependencytrack.org/usage/cicd/). A consumer should verify the image signature, signing identity, and required attestations before trusting the release.

**Validation:** Run this workflow in a disposable repository with a Dockerfile and test registry/Dependency-Track project. Confirm that a high-severity finding stops the job before the push step, then verify the published image and attestation by digest. Static lint alone does not establish that the release flow works.

## Example workflows (short)

**Supplier intake**: Vendor provides signed SBOM -> ingest into DT -> auto-enrich -> if critical CVE found, create ticket and notify procurement + security.

**Internal release**: CI builds image + SBOM -> scan before push -> sign and attest by digest -> ingest SBOM into Dependency-Track -> triage findings.

## References

- [CycloneDX specification and Authoritative Guide](https://cyclonedx.org/guides/OWASP_CycloneDX-Authoritative-Guide-to-SBOM-en.pdf)
- [SPDX and NTIA Minimum Elements for SBOM HOWTO](https://spdx.github.io/spdx-ntia-sbom-howto/)
- [CISA SBOM guidance](https://www.cisa.gov/sbom)
- [OWASP SBOM Forum](https://owasp.org/www-project-sbom-forum/)
- [Software Supply Chain Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html)
- [Vulnerable Dependency Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html)
