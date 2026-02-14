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

An Azure Pipelines template is available at `azure-pipelines/pipeline.yml` with:

- **BuildAndAnalyze** stage: build + SBOM + scan + policy (nothing pushed)
- **Publish** stage: push + sign + attest (only if BuildAndAnalyze succeeds)
- **DailyRescan** stage: scheduled rescan with latest CVE data

---

## Repository structure

```
sdlc/
├── .github/workflows/
│   ├── supply-chain-reusable.yml     ← Unified workflow (consumed by app repos)
│   └── validate-toolchain.yml        ← CI for the toolchain itself
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
