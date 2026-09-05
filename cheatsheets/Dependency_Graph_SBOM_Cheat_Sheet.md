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

build → generate SBOM → compute digests → sign/attest → publish.

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

**GitHub Actions (example)** — build, scan, generate SBOM from built image, sign with [keyless/OIDC cosign](https://docs.sigstore.dev/cosign/signing/overview/), attest, and publish to Dependency-Track.

This example demonstrates a complete secure SBOM workflow using [keyless signing](https://docs.sigstore.dev/cosign/signing/overview/) (no static keys), [vulnerability scanning with Grype](https://oss.anchore.com/docs/guides/vulnerability/getting-started/), [SBOM attestation](https://github.com/aquasecurity/trivy/blob/main/docs/guide/supply-chain/attestation/sbom.md), and [Dependency-Track integration](https://docs.dependencytrack.org/usage/cicd/).

```yaml
name: Build, Scan, and SBOM
on: [push]

permissions:
  contents: read
  id-token: write  # Required for keyless cosign signing
  packages: write  # Required to push signature layers to registry

jobs:
  build-scan-attest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

      - name: Build application
        run: ./gradlew assemble

      - name: Build and push container image
        id: build-push
        run: |
          # Build image
          docker build -t ghcr.io/${{ github.repository }}:latest .
          # Login to registry (required before signing)
          echo "${{ secrets.GITHUB_TOKEN }}" | docker login ghcr.io -u ${{ github.actor }} --password-stdin
          # Push and capture digest
          DIGEST=$(docker push ghcr.io/${{ github.repository }}:latest | grep 'digest:' | awk '{print $3}')
          echo "digest=${DIGEST}" >> $GITHUB_OUTPUT
          echo "Pushed image with digest: ${DIGEST}"

      - name: Generate SBOM from built image
        env:
          IMAGE_REF: ghcr.io/${{ github.repository }}@${{ steps.build-push.outputs.digest }}
        run: |
          # Generate SBOM from the BUILT IMAGE (not local build dir) to include OS packages and base image layers
          syft packages "${IMAGE_REF}" -o cyclonedx-json > sbom.json

      - name: Scan image for vulnerabilities with Grype
        env:
          IMAGE_REF: ghcr.io/${{ github.repository }}@${{ steps.build-push.outputs.digest }}
        run: |
          # Fail pipeline if high or critical vulnerabilities found
          grype "${IMAGE_REF}" --fail-on high -o json > grype-results.json || exit 1

      - name: Install Cosign
        uses: sigstore/cosign-installer@dc72c7d5c4d10cd6bcb8cf6e3fd625a9e5e537da # v3.7.0

      - name: Sign container image by digest (keyless)
        env:
          IMAGE_REF: ghcr.io/${{ github.repository }}@${{ steps.build-push.outputs.digest }}
        run: |
          # Sign by DIGEST (not tag) using keyless/OIDC flow
          # WARNING: --yes suppresses confirmation and publishes image digest, repo name, and workflow identity to public Rekor log
          cosign sign --yes "${IMAGE_REF}"

      - name: Attest SBOM to image (CycloneDX)
        env:
          IMAGE_REF: ghcr.io/${{ github.repository }}@${{ steps.build-push.outputs.digest }}
        run: |
          # Attach SBOM as a CycloneDX attestation (NOT SLSA provenance)
          cosign attest --yes --type cyclonedx --predicate sbom.json "${IMAGE_REF}"

      - name: Sign SBOM blob (keyless)
        run: |
          # Sign SBOM using bundle format (includes signature, cert, and Rekor proof)
          cosign sign-blob --yes --bundle sbom.json.sigstore.json sbom.json

      - name: Upload SBOM to Dependency-Track
        env:
          DT_API_KEY: ${{ secrets.DT_API_KEY }}
          DT_PROJECT_UUID: ${{ secrets.DT_PROJECT_UUID }}
          DT_URL: ${{ secrets.DT_URL }}
        run: |
          # Use --fail-with-body so auth/size failures don't leave step green
          curl --fail-with-body -X "POST" "${DT_URL}/api/v1/bom" \
            -H "Content-Type: multipart/form-data" \
            -H "X-Api-Key: ${DT_API_KEY}" \
            -F "project=${DT_PROJECT_UUID}" \
            -F "bom=@sbom.json"

      - name: Verification example - Image signature
        env:
          IMAGE_REF: ghcr.io/${{ github.repository }}@${{ steps.build-push.outputs.digest }}
          WORKFLOW_IDENTITY: ${{ github.server_url }}/${{ github.repository }}/.github/workflows/${{ github.workflow }}@${{ github.ref }}
        run: |
          # Verify image signature with explicit identity pinning
          # Without these flags, ANY keyless signature from ANY GitHub Actions workflow would verify
          cosign verify \
            --certificate-identity="${WORKFLOW_IDENTITY}" \
            --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
            "${IMAGE_REF}"

      - name: Verification example - SBOM blob
        run: |
          # Verify SBOM blob signature using bundle
          cosign verify-blob \
            --bundle sbom.json.sigstore.json \
            --certificate-identity="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/.github/workflows/${GITHUB_WORKFLOW}@${GITHUB_REF}" \
            --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
            sbom.json
```

**Key security controls explained:**

1. **No command injection**: Untrusted values (`github.repository`, `github.ref`, etc.) are [passed through `env:` blocks](https://securitylab.github.com/resources/github-actions-untrusted-input/), never interpolated directly into `run:` shell blocks, preventing `$(...)` command execution.

2. **Sign by digest, not tag**: Image is [signed by immutable digest](https://github.com/sigstore/cosign/blob/main/doc/cosign_sign.md) (`@sha256:...`) after push resolves it, preventing race conditions and tag tampering.

3. **Current bundle format**: SBOM blob signing uses [`--bundle` format](https://docs.sigstore.dev/cosign/signing/signing_with_blobs/) (signature + certificate + Rekor proof), not deprecated `--output-signature`.

4. **Explicit verification**: Includes [`cosign verify`](https://github.com/sigstore/cosign/blob/main/doc/cosign_verify.md) examples that pin `--certificate-identity` and `--certificate-oidc-issuer` — without these, any GitHub Actions signature would verify, defeating origin verification.

5. **SBOM from built image**: SBOM is generated from the pushed image (via digest), not from `dir:./build/libs`, ensuring base image and OS packages are included in scan scope.

6. **Fail-with-body on Dependency-Track upload**: `curl --fail-with-body` ensures [401/403/500 errors fail the step](https://docs.dependencytrack.org/usage/cicd/), not silently succeed.

7. **Correct permissions**: Declares `id-token: write` (for OIDC signing) and `packages: write` (to push signature layers), plus explicit registry login before signing.

8. **Rekor transparency caveat**: Documents that `--yes` [publishes image digest and workflow identity to the public Rekor log](https://docs.sigstore.dev/cosign/signing/overview/).

9. **Correct attestation type**: Uses `--type cyclonedx` for [SBOM attestation](https://github.com/aquasecurity/trivy/blob/main/docs/guide/supply-chain/attestation/sbom.md), not `slsaprovenance` (only for actual SLSA generators).

10. **Pinned actions**: Pins `actions/checkout` and `sigstore/cosign-installer` to commit SHAs, not floating tags.

**Fail-fast vs Warn**: The [Grype scan with `--fail-on high`](https://oss.anchore.com/docs/guides/vulnerability/filter-results/) gates the pipeline (exits non-zero if high/critical CVEs found), running BEFORE push/sign steps. Low-severity findings can be surfaced to dashboards without blocking.

## Example workflows (short)

**Supplier intake**: Vendor provides signed SBOM -> ingest into DT -> auto-enrich -> if critical CVE found, create ticket and notify procurement + security.

**Internal release**: CI builds artifact + sbom -> sign & push -> SBOM ingested to DT -> scheduled scan enrich -> policy engine flags high-sev/forbidden licenses -> create PR to remediate.

## References

- [CycloneDX specification and Authoritative Guide](https://cyclonedx.org/guides/OWASP_CycloneDX-Authoritative-Guide-to-SBOM-en.pdf)
- [SPDX and NTIA Minimum Elements for SBOM HOWTO](https://spdx.github.io/spdx-ntia-sbom-howto/)
- [CISA SBOM guidance](https://www.cisa.gov/sbom)
- [OWASP SBOM Forum](https://owasp.org/www-project-sbom-forum/)
- [Software Supply Chain Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html)
- [Vulnerable Dependency Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html)
