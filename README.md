# SDLC — Unified Supply Chain Security Toolchain

> **Reusable platform** for container image build, SBOM generation, vulnerability scanning, policy enforcement, signing, and monitoring.
> One workflow replaces `poc-build-sign` + `poc-sbom` with a **shift-left** approach: scan **before** publishing.

[![Validate Toolchain](https://github.com/cuspofaries/sdlc/actions/workflows/validate-toolchain.yml/badge.svg)](https://github.com/cuspofaries/sdlc/actions/workflows/validate-toolchain.yml)

---

## Why this repo exists

Three separate repos (`poc-build-sign`, `poc-sbom`, `poc-sbom-build`) formed a supply chain pipeline but suffered from:

| Problem | Impact |
|---------|--------|
| **SBOM/digest mismatch** | SBOM generated *after* push could describe a different image |
| **Tool version drift** | Trivy, Cosign, OPA versions desynchronized across repos |
| **Scattered maintenance** | Bug fixes required PRs in multiple repos |
| **Two-job overhead** | Caller repos needed two `workflow_call` jobs chained together |

**SDLC** merges everything into a single reusable workflow with a strict order: **build → analyze → GATE → publish**.

---

## Pipeline — Step-by-step checklist

### PHASE 1 — BUILD (nothing leaves the runner)

| # | Step | Tool | Explanation |
|---|------|------|-------------|
| 1 | **Checkout code** | `actions/checkout` | Clones the application repo (Dockerfile, source code, custom policies). |
| 2 | **Checkout toolchain** | `actions/checkout` | Clones the `sdlc` repo into `.sdlc/` to access baseline policies and scripts. |
| 3 | **Build image** | `docker/build-push-action` | Builds the container image **locally** (`load: true`, `push: false`). Nothing leaves the runner at this stage. |

### PHASE 2 — ANALYZE (on the local image, before any publish)

| # | Step | Tool | Explanation |
|---|------|------|-------------|
| 4 | **Generate SBOM** | `trivy image --format cyclonedx` | Scans the local image and produces a full inventory (OS packages, libraries, versions, licenses) in CycloneDX JSON format. The SBOM SHA256 hash and the image ID (`aquasecurity:trivy:ImageID`) are recorded at this point for integrity verification before attestation. |
| 5 | **Verify image-SBOM alignment** | `docker inspect` + `jq` | Compares the actual Docker image ID with the image ID embedded in the SBOM. If they differ, the pipeline stops immediately — the SBOM must describe the exact image that was built. |
| 6 | **Scan vulnerabilities** | `trivy image --exit-code` | Scans the image **directly** (not the SBOM) for HIGH and CRITICAL CVEs. Uses `--exit-code 1` to block or `0` to warn without blocking. Direct image scan is the **security gate**: more reliable than scanning the SBOM because Trivy accesses filesystem metadata. |
| 7 | **Scan SBOM** | `trivy sbom --exit-code 0` | Scans the SBOM itself for vulnerabilities (advisory, **non-blocking**). This ensures the attested SBOM has been verified: what we sign = what we scanned. Any delta with step 6 reveals SBOM inventory gaps. Results are archived regardless of outcome. |
| 8 | **Evaluate OPA policies** | `opa eval` | Evaluates the SBOM against Rego rules at two levels: **deny** (blocking — fails the pipeline) and **warn** (advisory — displays a warning). Baseline policies (`sdlc/policies/`) are automatically merged with custom policies from the app repo (`policies/`) if they exist. Example rules: blocked packages (known supply chain attacks), components without versions, unapproved licenses. |

```
══════════════════════════════════════════════════════
  GATE: if step 5, 6 or 8 fails → PIPELINE STOPS
  Nothing is published. The image stays local.
══════════════════════════════════════════════════════
```

### PHASE 3 — PUBLISH (only if gate passes)

| # | Step | Tool | Explanation |
|---|------|------|-------------|
| 9 | **Login to registry** | `docker/login-action` | Authenticates to the container registry (GHCR, ACR, etc.) with the provided token. |
| 10 | **Push image** | `docker push` | Pushes the image to the registry. At this point, we know it passed scanning and policies. |
| 11 | **Resolve registry digest** | `docker inspect` | Retrieves the **RepoDigest** (`sha256:...`) from the registry after push. All subsequent signing and attestation operations target this immutable digest, not the mutable tag. |
| 12 | **Verify SBOM integrity** | `sha256sum` | Recomputes the SHA256 of the SBOM file and compares it to the hash recorded at generation (step 4). If the file was modified between generation and attestation, the pipeline stops. |
| 13 | **Sign digest** | `cosign sign --yes` | Signs the **registry digest** (not the tag) with Cosign. GitHub Actions uses **keyless** mode (OIDC via Sigstore). Azure DevOps uses **Azure Key Vault KMS** (`azurekms://`) as primary method with keyless as fallback. The signature proves the image was produced by this CI/CD pipeline and has not been tampered with. |
| 14 | **Attest SBOM** | `cosign attest --type cyclonedx` | Cryptographically binds the SBOM to the **registry digest** via an In-Toto attestation. The SBOM attested is the exact same file generated in step 4 — never regenerated or modified (verified by step 12). This is the **strongest guarantee**: it proves that THIS SBOM describes exactly THIS image. |
| 15 | **Verify in registry** | `cosign verify` + `cosign verify-attestation` | Automated proof that signature and attestation are actually retrievable from the registry. Catches silent failures, accidental `--no-upload`, or registry persistence issues. **Blocking**: if verification fails, the pipeline stops before declaring success. |
| 16 | **Upload to Dependency-Track** | `DependencyTrack/gh-upload-sbom` | Sends the attested SBOM to Dependency-Track for continuous monitoring, linked to the **registry digest** (not the git SHA). **Non-blocking** (`continue-on-error`): DTrack is governance/monitoring, not a CI gate. If DTrack is down, the signed image still ships. Optional (skipped if `dtrack-hostname` is empty). |

### Visual summary

```
  Code + Dockerfile
        |
        v
  [1-3] BUILD ──────────────> Local image
        |
        v
  [4]   SBOM ──────────────> sbom-image-trivy.json + SHA256 + ImageID
        |
        v
  [5]   IMAGE ↔ SBOM ─────> ImageID match?
        |                         |
        | OK                      | MISMATCH → STOP
        v
  [6]   SCAN (trivy image) ─> HIGH/CRITICAL vulnerabilities?
        |                         |
        | OK                      | FAIL → STOP
        v
  [7]   SCAN SBOM (trivy sbom) ─> Advisory (governance, archived)
        |
        v
  [8]   POLICY (OPA) ──────> deny / warn?
        |                         |
        | OK                      | FAIL → STOP
        v
  ═══ GATE PASSED ═══
        |
        v
  [9-10] PUSH ─────────────> Image in registry
        |
        v
  [11]  RESOLVE DIGEST ────> RepoDigest (sha256:...)
        |
        v
  [12]  VERIFY SBOM SHA256 ─> Untouched since step 4?
        |                         |
        | OK                      | MODIFIED → STOP
        v
  [13]  SIGN ──────────────> Cosign signature on digest
        |
        v
  [14]  ATTEST ────────────> SBOM bound to digest (In-Toto)
        |
        v
  [15]  VERIFY ────────────> Signature + attestation in registry?
        |                         |
        | OK                      | FAIL → STOP
        v
  [16]  DTRACK ────────────> Monitoring (non-blocking, linked to digest)
```

---

## Design decisions

This section explains **why** the pipeline works the way it does. Each mechanism exists for a specific reason — understanding the rationale helps you make informed decisions when customizing or extending the pipeline.

### Why scan before push (shift-left)

The previous pipeline (`poc-build-sign` + `poc-sbom`) pushed the image first, then generated the SBOM and scanned it. This created a window where a vulnerable or non-compliant image was already in the registry. Shift-left means the image is analyzed **locally** before any publish — if it fails, nothing leaves the runner.

### Why dual scan (trivy image + trivy sbom)

Two separate scans serve two different purposes:

- **`trivy image`** (step 6) is the **security gate**. It scans the image directly, accessing filesystem metadata, OS package databases, and binary analysis. This is the most complete and reliable vulnerability assessment because Trivy sees everything the container runtime would see. This step is **blocking** (`--exit-code 1`).

- **`trivy sbom`** (step 7) is the **governance scan**. It scans the SBOM file that will be attested and published. This proves that the SBOM we sign has been verified — "what we sign = what we scanned". Any delta between step 6 and step 7 reveals gaps in the SBOM inventory (packages that Trivy sees in the image but are missing from the SBOM). This step is **non-blocking** (`--exit-code 0`) because SBOM-based scanning can produce false positives or miss packages that direct image scanning catches.

### Why sign on digest, not tag

Tags are mutable — `myimage:v1.0` can be overwritten at any time. Digests (`sha256:abc123...`) are immutable content-addressed references. Signing a tag provides no guarantee because the tag can be repointed to a different image after signing. The pipeline resolves the **RepoDigest** after push and all signing/attestation targets this digest. On Azure DevOps, if `docker inspect` cannot resolve the digest (timing issues with some registries), we fall back to `az acr repository show` and **refuse to sign** if no digest can be resolved — we never fall back to a mutable tag.

### The SBOM integrity invariant

> **Invariant**: The SBOM is generated, scanned, evaluated, and attested from the **exact same image**. Never regenerate or modify the SBOM between generation and attestation.

This is enforced by three mechanisms:

1. **ImageID cross-check** (step 5): The image ID embedded in the SBOM (`aquasecurity:trivy:ImageID`) is compared with `docker inspect` of the actual built image. If they differ, the pipeline stops.

2. **SHA256 hash** (step 12): The SHA256 of the SBOM file is recorded at generation (step 4) and re-verified just before attestation. If the file was modified (even a single byte), the pipeline stops.

3. **No rebuild between stages** (Azure DevOps): Since Azure DevOps uses separate stages for BuildAndAnalyze and Publish, the image is transferred via `docker save` → artifact → `docker load` to guarantee binary identity. The loaded image's ID is explicitly verified against the expected value.

### Why KMS over keyless (enterprise context)

The signing strategy follows a priority order: **KMS > keyless > keypair**.

- **Azure Key Vault KMS** (`azurekms://`): Recommended for enterprise. The private key never leaves the HSM, signing is audited in Azure, and the key can be rotated without changing the pipeline. Requires an Azure service connection with `sign`, `verify`, `get` permissions on the key.

- **Keyless** (OIDC via Sigstore): Zero-key-management approach. The CI runner gets an ephemeral certificate from Fulcio based on its OIDC identity. Signatures are recorded in the Rekor transparency log. Great for open source, but requires public Sigstore infrastructure and trusting the Rekor log.

- **Keypair**: Local `.pem` files. Simplest but hardest to manage (key rotation, secure storage). Reserved for development or air-gapped environments.

### Why restrict `--certificate-identity-regexp`

In keyless mode, `cosign verify` uses `--certificate-identity-regexp` to filter which OIDC identities are accepted. A permissive value like `".*"` would accept signatures from **any** pipeline on **any** organization — defeating the purpose of verification. The regexp should be as specific as possible:

- **GitHub Actions**: `"github.com/cuspofaries/"` — scoped to the organization. GitHub's OIDC subject includes the repo name, so org-level scoping is already quite restrictive.
- **Azure DevOps**: `"https://dev.azure.com/cuspofaries/sdlc/_build"` — scoped to org + project + pipeline definitions. Scoping only to the org (`cuspofaries/`) would allow **any pipeline in any project** of that org to pass verification. Adding the project name (`sdlc/`) and `_build` ensures only pipelines from this specific project are accepted.

When porting to your organization, this is the **first thing to change**. See [docs/azure-devops-porting.md](docs/azure-devops-porting.md) for the full list.

### Why post-attestation verification (step 15)

Signing and attesting can silently fail — a `--no-upload` flag, a network glitch, or a registry persistence issue can result in a pipeline that declares success while the signature never made it to the registry. Step 15 runs `cosign verify` and `cosign verify-attestation` against the registry to **prove** the artifacts are retrievable. This step is **blocking**: if verification fails, the pipeline stops before declaring success. Full output is archived in `output/verify/` for audit trail.

### Why Dependency-Track is non-blocking

Dependency-Track is a governance and monitoring tool, not a CI gate. If DTrack is down, unreachable, or misconfigured, the signed and attested image should still ship — the security guarantees come from the pipeline gates (scan + policy + signature), not from DTrack. The SBOM is linked to the **registry digest** (not the git SHA) so that DTrack's inventory maps directly to the published artifact.

### Why DailyRescan uses cosign attestation

The DailyRescan stage (Azure DevOps) needs the original SBOM to rescan it with the latest CVE data. Rather than relying on a pipeline artifact (which can expire, be deleted, or become stale), the rescan extracts the SBOM from the **cosign attestation** attached to the image digest. This is the cryptographic source of truth — the attestation proves the SBOM has not been tampered with since the original pipeline run. If no attestation exists yet (first run), the stage falls back to the pipeline artifact.

### Why every cosign operation logs the digest

Every `cosign sign`, `cosign attest`, `cosign verify`, and `cosign verify-attestation` call is preceded by an explicit `echo` of the target digest. This is an **audit trail** requirement: if an incident occurs, the CI logs provide an unambiguous record of exactly which digest was signed, attested, and verified. Verify outputs are stored as `.log` files because cosign produces human-readable text; JSON parsing is intentionally avoided to keep the verify step platform-agnostic. These files are archived in `output/verify/` and uploaded as artifacts with 30-day retention. The artifact upload uses `if: always()` / `condition: always()` so that scan results and SBOM data are preserved **even if the pipeline fails** — critical for post-incident analysis.

### Why Rekor transparency by default

All cosign signing and attestation operations upload entries to the [Rekor transparency log](https://docs.sigstore.dev/logging/overview/) by default. We deliberately removed `--no-upload=true` from all code paths (it was present in early iterations for keypair mode). Rekor provides a public, immutable, append-only log of all signatures — anyone can independently verify that a specific image was signed at a specific time by a specific identity. The `--no-upload` flag is documented as an option **only** for air-gapped or offline environments.

### Why baseline + custom policy merging

The OPA evaluation step loads policies from two sources simultaneously:

1. **Baseline policies** (`sdlc/policies/`): Maintained in this repo, applied to all consumer repos. These enforce universal rules (known supply chain attack packages, components without versions).
2. **Custom policies** (`policies/` in the consumer repo): Project-specific rules (blocked libraries, license restrictions, org-specific requirements).

Both are passed to `opa eval` via `-d` flags and share the same `package sbom` namespace. Rules from both sources are automatically merged — no configuration needed. A consumer repo can add `deny` rules to block additional packages or `warn` rules for advisory checks without modifying the baseline.

The baseline policies (`policies/sbom-compliance.rego`) include:

| Level | Rule | Rationale |
|-------|------|-----------|
| **deny** | Blocked packages (`event-stream`, `colors`, `faker`...) | Known supply chain attacks or maintainer sabotage |
| **deny** | Components without version | Cannot track vulnerabilities without version |
| **deny** | Libraries without Package URL (purl) | Cannot cross-reference in vulnerability databases |
| **deny** | Copyleft licenses (GPL, AGPL, SSPL) | Incompatible with proprietary distribution |
| **deny** | Missing SBOM timestamp | Cannot verify freshness |
| **deny** | Zero components | SBOM generation likely failed |
| **deny** | Missing generation tool metadata | Cannot audit how SBOM was produced |
| **deny** | CycloneDX spec < 1.4 | Older specs lack required fields for compliance |
| **warn** | Unapproved licenses | Flagged for legal review, not blocking |
| **warn** | Missing license information | Traceability gap |
| **warn** | High component count (> 500) | Possible dependency bloat |
| **warn** | Deprecated/abandoned packages | Should be replaced |
| **warn** | Missing supplier/publisher metadata | Reduced traceability |

### Why resilient tool installation

The Trivy installation step uses a **retry loop with backoff** (3 attempts, 5-second delay between failures). This guards against transient network failures during `curl` downloads in CI environments, where shared runners can experience intermittent connectivity issues. A single failed download does not fail the entire pipeline — only 3 consecutive failures do.

### Cross-platform consistency

The pipeline is implemented on three platforms with the **same logical flow**:

| Platform | Implementation | Notes |
|----------|---------------|-------|
| **GitHub Actions** | `.github/workflows/supply-chain-reusable.yml` | Single job, `workflow_call` reusable workflow |
| **Azure DevOps** | `azure-pipelines/pipeline.yml` | Multi-stage (BuildAndAnalyze → Publish → DailyRescan) |
| **Local / any CI** | `Taskfile.yml` + `scripts/` | Portable tasks, called by both GH and ADO |

All three share the same order (build → analyze → gate → publish), the same tools (Trivy, Cosign, OPA), the same signing priority (KMS > keyless > keypair), and the same invariants (SBOM integrity, digest-only signing, post-publish verification). When a mechanism is added to one, it is added to all three. The `validate-toolchain.yml` workflow includes an **end-to-end test** (`e2e-test` job) that builds a test image, generates SBOM, runs all scans and policy checks, verifies the SBOM integrity invariant, then signs, attests, and verifies using a local registry. This catches integration regressions that unit-level checks would miss.

### Workflow output for downstream consumption

The reusable GitHub Actions workflow exposes an `image` output containing the **full image reference with digest** (`registry/owner/name@sha256:...`). Downstream jobs can use this output to deploy, scan, or reference the exact image that was built, signed, and attested — without needing to resolve the digest themselves.

---

## Security guarantees

This pipeline provides the following verifiable guarantees:

| Guarantee | Mechanism | Failure mode |
|-----------|-----------|-------------|
| **Nothing is published until scanned** | Shift-left: build → analyze → GATE → publish | Pipeline stops at gate |
| **SBOM describes the exact image** | ImageID cross-check (step 5) | `FATAL: Image ID mismatch` |
| **SBOM was not modified after scan** | SHA256 recorded at generation, verified before attestation (step 12) | `FATAL: SBOM was modified` |
| **Same binary across stages** (ADO) | `docker save` → artifact → `docker load` + ImageID verification | `Loaded image does not match SBOM` |
| **Signatures target immutable digests** | RepoDigest resolved after push, tag fallback refused | `Cannot resolve registry digest` |
| **Signatures are actually in the registry** | Post-publish `cosign verify` + `cosign verify-attestation` (step 15) | Pipeline stops before declaring success |
| **Only this project's pipeline can pass verify** | `--certificate-identity-regexp` scoped to org/project | Signature from other pipelines rejected |
| **SBOM content is cryptographically bound to image** | In-Toto attestation via `cosign attest --type cyclonedx` | Attestation tampering detectable |
| **All signatures are publicly auditable** | Rekor transparency log (no `--no-upload`) | Independent verification possible |
| **Known-bad packages are blocked** | OPA `deny` rules (baseline + custom) | `POLICY CHECK FAILED` |
| **Copyleft licenses are caught** | OPA `deny` for GPL/AGPL/SSPL in baseline | `Copyleft license ... incompatible` |
| **Outdated SBOM specs are rejected** | OPA `deny` for CycloneDX < 1.4 | `spec version too old` |
| **Pipeline chain is tested end-to-end** | `e2e-test` job: build → SBOM → scan → policy → sign → attest → verify | CI fails on any broken step |
| **New CVEs are caught post-deploy** | DailyRescan extracts SBOM from attestation, rescans with fresh data | Advisory (non-blocking) |
| **DTrack failure doesn't block delivery** | `continue-on-error: true`, linked to digest | Signed image ships regardless |

---

## Quick start — consumer repo

Any repo with a Dockerfile can consume this pipeline with a single workflow file:

```yaml
# .github/workflows/build.yml
name: Supply Chain Pipeline

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read
  packages: write
  id-token: write

jobs:
  supply-chain:
    uses: cuspofaries/sdlc/.github/workflows/supply-chain-reusable.yml@main
    with:
      context: ./app
      image-name: my-app
      dtrack-hostname: dep-api.example.com  # optional
    secrets:
      REGISTRY_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      DTRACK_API_KEY: ${{ secrets.DTRACK_API_KEY }}  # optional
```

### Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `context` | Yes | — | Path to Docker build context |
| `image-name` | Yes | — | Image name (without registry prefix) |
| `dockerfile` | No | `Dockerfile` | Dockerfile path relative to context |
| `registry` | No | `ghcr.io` | Container registry |
| `dtrack-hostname` | No | `""` | Dependency-Track hostname (skip if empty) |
| `trivy-severity` | No | `HIGH,CRITICAL` | Severity filter for vulnerability scan |
| `trivy-exit-code` | No | `"1"` | Exit code on findings (`1` = fail, `0` = warn) |

### Custom policies

Place a `policies/` directory in your repo with `.rego` files using `package sbom`. They are automatically merged with baseline policies via OPA:

```rego
# policies/project-policies.rego
package sbom
import rego.v1

project_blocked_packages := {"moment", "request"}

deny contains msg if {
    some component in input.components
    component.name in project_blocked_packages
    msg := sprintf("[project] Package '%s' is not allowed", [component.name])
}
```

---

## Local development

### Prerequisites

- Docker
- [Task](https://taskfile.dev/) (go-task)

### Install toolchain

```bash
sudo task install
task install:verify
```

### Run local pipeline

```bash
task pipeline:local \
  IMAGE_NAME=my-app \
  CONTEXT=../my-app-repo/app
```

This runs **build → generate → scan → policy** without pushing or signing.

### Full pipeline (with publish)

```bash
task pipeline \
  REGISTRY=ghcr.io/myorg \
  IMAGE_NAME=my-app \
  CONTEXT=../my-app-repo/app \
  DTRACK_URL=http://localhost:8081 \
  DTRACK_API_KEY=odt_xxx
```

### Task reference

| Task | Description |
|------|-------------|
| `install` | Install all tools (trivy, cosign, cdxgen, opa, oras) |
| `install:verify` | Show installed tool versions |
| `build` | Build image locally (no push) |
| `sbom:generate` | Generate image SBOM (CycloneDX) |
| `sbom:generate:source` | Generate source SBOM (declared deps) |
| `sbom:scan` | Scan image for vulnerabilities (trivy image — security gate) |
| `sbom:scan:sbom` | Scan SBOM for vulnerabilities (trivy sbom — governance, advisory) |
| `sbom:policy` | Evaluate SBOM against OPA policies |
| `push` | Push image to registry |
| `image:sign` | Sign image digest (cosign) |
| `image:verify` | Verify image signature |
| `sbom:attest` | Attest SBOM to image digest |
| `sbom:attest:verify` | Verify signature and attestation are published in the registry |
| `sbom:sign:blob` | Sign SBOM as standalone file |
| `sbom:verify` | Verify SBOM signature and integrity |
| `sbom:store` | Store SBOM as OCI artifact in registry (ORAS) |
| `sbom:fetch` | Fetch SBOM from OCI registry (ORAS) |
| `sbom:upload` | Upload SBOM to Dependency-Track |
| `sbom:tamper:test` | Demo SBOM tampering detection |
| `pipeline` | Full pipeline (build → analyze → publish) |
| `pipeline:local` | Local pipeline (build → analyze only) |
| `dtrack:up` | Start local Dependency-Track |
| `dtrack:down` | Stop local Dependency-Track |
| `clean` | Remove generated files |

---

## Dependency-Track

See [docs/dependency-track.md](docs/dependency-track.md) for setup and integration details.

```bash
task dtrack:up        # Start local instance
task sbom:upload      # Upload SBOM
```

---

## Azure DevOps

An Azure Pipelines template is available at `azure-pipelines/pipeline.yml` implementing the same pipeline with Azure-specific adaptations.

### Stages

| Stage | Trigger | Description |
|-------|---------|-------------|
| **BuildAndAnalyze** | Every CI run | Build + SBOM generation + vulnerability scan + policy evaluation. Nothing is pushed. Image is saved as artifact via `docker save` for the next stage. |
| **Publish** | Only if BuildAndAnalyze succeeds | `docker load` from artifact (no rebuild), push, sign, attest, verify in registry, upload to DTrack. |
| **DailyRescan** | Scheduled (cron) | Extracts SBOM from cosign attestation (source of truth), rescans with latest CVE data, uploads fresh results to DTrack. |

### Azure-specific mechanisms

- **Image transfer between stages**: `docker save` in BuildAndAnalyze → pipeline artifact → `docker load` in Publish. No rebuild, guaranteed binary identity.
- **Digest resolution**: `docker inspect` with `az acr repository show` as fallback. Refuses to sign if no immutable digest is resolved.
- **Signing**: Azure Key Vault KMS (`azurekms://`) as primary, keyless (OIDC via `vstoken.dev.azure.com`) as fallback.
- **Keyless identity**: `--certificate-identity-regexp` scoped to `"https://dev.azure.com/cuspofaries/sdlc/_build"` (org + project + pipeline scope).
- **SBOM integrity across stages**: SHA256 + ImageID recorded as files in artifact, verified after `docker load` in Publish stage.
- **DailyRescan SBOM source**: Extracted from cosign attestation (`cosign verify-attestation | jq`), falls back to pipeline artifact.

### Porting guide

See [docs/azure-devops-porting.md](docs/azure-devops-porting.md) for a complete checklist of files and lines to modify when deploying this pipeline in your own Azure DevOps organization (identity-regexp, service connections, variable group, KMS setup, etc.).

---

## Repository structure

```
sdlc/
├── .github/workflows/
│   ├── supply-chain-reusable.yml     ← Unified workflow (consumed by app repos)
│   ├── daily-rescan.yml              ← Scheduled rescan with latest CVE data
│   └── validate-toolchain.yml        ← CI + end-to-end pipeline test
├── azure-pipelines/
│   └── pipeline.yml                  ← Azure DevOps template
├── scripts/                          ← Shell scripts for each pipeline step
│   ├── sbom-attest.sh
│   ├── sbom-generate-source.sh
│   ├── sbom-policy.sh
│   ├── sbom-sign.sh
│   ├── sbom-tamper-test.sh
│   ├── sbom-upload-dtrack.sh
│   └── sbom-verify.sh
├── policies/
│   └── sbom-compliance.rego          ← Baseline OPA policies
├── docs/
│   ├── azure-devops-porting.md       ← Porting checklist for Azure DevOps
│   ├── dependency-track.md
│   └── dependency-track.fr.md
├── docker-compose.dtrack.yml
├── Taskfile.yml
├── renovate.json
├── POSTMORTEM.md
└── README.md
```

---

## Migration from poc-build-sign + poc-sbom

**Before** (caller needed 2 jobs):
```yaml
jobs:
  build:
    uses: cuspofaries/poc-build-sign/.github/workflows/build-sign-reusable.yml@main
    # ...
  sbom:
    needs: build
    uses: cuspofaries/poc-sbom/.github/workflows/sbom-reusable.yml@main
    # ...
```

**After** (single job):
```yaml
jobs:
  supply-chain:
    uses: cuspofaries/sdlc/.github/workflows/supply-chain-reusable.yml@main
    with:
      context: ./app
      image-name: my-app
    secrets:
      REGISTRY_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

Key changes:
- Image is scanned **before** push (shift-left)
- SBOM is guaranteed to match the published digest
- Single atomic workflow — no race conditions between jobs
- Tool versions are managed in one place

---

## References

- [CycloneDX Specification](https://cyclonedx.org/specification/overview/)
- [Sigstore / Cosign](https://docs.sigstore.dev/)
- [Open Policy Agent](https://www.openpolicyagent.org/)
- [Dependency-Track](https://dependencytrack.org/)
- [SLSA Framework](https://slsa.dev/)
- [NIST SSDF](https://csrc.nist.gov/Projects/ssdf)
