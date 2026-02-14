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

## Pipeline flow

```
PHASE 1 — BUILD (nothing leaves the runner)
  1. Checkout
  2. Build image (--load, no push)

PHASE 2 — ANALYZE (on the local image)
  3. Generate SBOM (trivy image --format cyclonedx)
  4. Scan vulnerabilities (trivy image direct)
  5. Evaluate OPA policies (baseline + custom)
  ══ GATE: if 4 or 5 fails → STOP ══

PHASE 3 — PUBLISH (only if gate passes)
  6. Push image to registry
  7. Sign digest (Cosign keyless)
  8. Attest SBOM to digest (Cosign attest)
  9. Upload SBOM to Dependency-Track
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
| `sbom:scan` | Scan image for vulnerabilities (trivy image) |
| `sbom:policy` | Evaluate SBOM against OPA policies |
| `push` | Push image to registry |
| `image:sign` | Sign image digest (cosign) |
| `image:verify` | Verify image signature |
| `sbom:attest` | Attest SBOM to image digest |
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
