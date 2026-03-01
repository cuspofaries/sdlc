# SDLC — Unified Supply Chain Security Toolchain

> **Reusable platform** for container image build, SAST, SBOM generation, vulnerability scanning, policy enforcement, signing, and monitoring.
> Shift-left approach: scan **before** publishing. Strict order: **SAST + build → analyze → GATE → publish**.

[![Validate Toolchain](https://github.com/cuspofaries/sdlc/actions/workflows/validate-toolchain.yml/badge.svg)](https://github.com/cuspofaries/sdlc/actions/workflows/validate-toolchain.yml)

---

## Pipeline — Step-by-step checklist

### PHASE 1 — SAST + BUILD (nothing leaves the runner)

| # | Step | Tool | Explanation |
|---|------|------|-------------|
| 1 | **Checkout code** | `actions/checkout` | Clones the application repo (Dockerfile, source code, custom policies). |
| 2 | **Checkout toolchain** | `actions/checkout` | Clones the `sdlc` repo into `.sdlc/` to access baseline policies and scripts. |
| 3 | **SAST scan** | `returntocorp/semgrep` (Docker) | Scans source code for security vulnerabilities (OWASP Top 10) using Semgrep. Runs **before** build: only needs source code, not the image. Fail-fast: blocks the pipeline if findings are detected. In Taskfile, runs **in parallel** with build via `deps:`. |
| 4 | **Build image** | `docker/build-push-action` | Builds the container image **locally** (`load: true`, `push: false`). Nothing leaves the runner at this stage. |

### PHASE 2 — ANALYZE (on the local image, before any publish)

| # | Step | Tool | Explanation |
|---|------|------|-------------|
| 5 | **Generate SBOM** | `trivy image --format cyclonedx` | Scans the local image and produces a full inventory (OS packages, libraries, versions, licenses) in CycloneDX JSON format. The SBOM SHA256 hash and the image ID (`aquasecurity:trivy:ImageID`) are recorded at this point for integrity verification before attestation. |
| 6 | **Verify image-SBOM alignment** | `docker inspect` + `jq` | Compares the actual Docker image ID with the image ID embedded in the SBOM. If they differ, the pipeline stops immediately — the SBOM must describe the exact image that was built. |
| 7 | **Scan vulnerabilities** | `trivy image --exit-code` | Scans the image **directly** (not the SBOM) for HIGH and CRITICAL CVEs. Uses `--exit-code 1` to block or `0` to warn without blocking. Direct image scan is the **security gate**: more reliable than scanning the SBOM because Trivy accesses filesystem metadata. |
| 8 | **Scan SBOM** | `trivy sbom --exit-code 0` | Scans the SBOM itself for vulnerabilities (advisory, **non-blocking**). This ensures the attested SBOM has been verified: what we sign = what we scanned. Any delta with step 6 reveals SBOM inventory gaps. Results are archived regardless of outcome. |
| 9 | **Evaluate OPA policies** | `opa eval` | Evaluates the SBOM against Rego rules at two levels: **deny** (blocking — fails the pipeline) and **warn** (advisory — displays a warning). Baseline policies (`sdlc/policies/`) are automatically merged with custom policies from the app repo (`policies/`) if they exist. Example rules: blocked packages (known supply chain attacks), components without versions, unapproved licenses. |

```
══════════════════════════════════════════════════════
  GATE: if step 3, 7 or 9 fails → PIPELINE STOPS
  Nothing is published. The image stays local.
══════════════════════════════════════════════════════
```

### PHASE 3 — PUBLISH (only if gate passes)

| # | Step | Tool | Explanation |
|---|------|------|-------------|
| 10 | **Login to registry** | `docker/login-action` | Authenticates to the container registry (GHCR, ACR, etc.) with the provided token. |
| 11 | **Push image** | `docker push` | Pushes the image to the registry. At this point, we know it passed scanning and policies. |
| 12 | **Resolve registry digest** | `docker inspect` | Retrieves the **RepoDigest** (`sha256:...`) from the registry after push. All subsequent signing and attestation operations target this immutable digest, not the mutable tag. |
| 13 | **Verify SBOM integrity** | `sha256sum` | Recomputes the SHA256 of the SBOM file and compares it to the hash recorded at generation (step 5). If the file was modified between generation and attestation, the pipeline stops. |
| 14 | **Sign digest** | `cosign sign --yes` | Signs the **registry digest** (not the tag) with Cosign. GitHub Actions uses **keyless** mode (OIDC via Sigstore). Azure DevOps uses **Azure Key Vault KMS** (`azurekms://`) as primary method with keyless as fallback. The signature proves the image was produced by this CI/CD pipeline and has not been tampered with. |
| 15 | **Attest SBOM** | `cosign attest --type cyclonedx` | Cryptographically binds the SBOM to the **registry digest** via an In-Toto attestation. The SBOM attested is the exact same file generated in step 5 — never regenerated or modified (verified by step 13). This is the **strongest guarantee**: it proves that THIS SBOM describes exactly THIS image. |
| 16 | **Attest SLSA provenance** | `actions/attest-build-provenance` | Generates and attests a [SLSA](https://slsa.dev/) build provenance predicate to the image digest. Records builder identity, source repo, revision, and build metadata. On GitHub Actions this uses the native attestation action; on Azure DevOps and local, a cosign-based provenance predicate is used via `scripts/slsa-provenance.sh`. |
| 17 | **Verify all in registry (fail-closed)** | `cosign verify` + `cosign verify-attestation` x2 | **Fail-closed**: verifies all three artifacts (signature, SBOM attestation, SLSA provenance) on the same `image@sha256:...` digest. If **any** is missing or invalid, the pipeline stops. Identity constraints (`--certificate-oidc-issuer` + `--certificate-identity-regexp`) are enforced on every verify — including SLSA provenance, which is the proof of who built it. `cosign tree` is run first (debug) to show all referrers. All outputs are archived as CI artifacts in `output/verify/` for audit trail. |
| 18 | **Upload to Dependency-Track** | `DependencyTrack/gh-upload-sbom` | Sends the attested SBOM to Dependency-Track for continuous monitoring, linked to the **registry digest** (not the git SHA). **Non-blocking** (`continue-on-error`): DTrack is governance/monitoring, not a CI gate. If DTrack is down, the signed image still ships. Optional (skipped if `dtrack-hostname` is empty). |

### Visual summary

```
  Code + Dockerfile
        |
        v
  [1-2] CHECKOUT ────────────> Source code + toolchain
        |
        v
  [3]   SAST (Semgrep) ─────> Security findings?
        |                         |
        | OK                      | FAIL → STOP
        v
  [4]   BUILD ──────────────> Local image
        |
        v
  [5]   SBOM ──────────────> sbom-image-trivy.json + SHA256 + ImageID
        |
        v
  [6]   IMAGE ↔ SBOM ─────> ImageID match?
        |                         |
        | OK                      | MISMATCH → STOP
        v
  [7]   SCAN (trivy image) ─> HIGH/CRITICAL vulnerabilities?
        |                         |
        | OK                      | FAIL → STOP
        v
  [8]   SCAN SBOM (trivy sbom) ─> Advisory (governance, archived)
        |
        v
  [9]   POLICY (OPA) ──────> deny / warn?
        |                         |
        | OK                      | FAIL → STOP
        v
  ═══ GATE PASSED ═══
        |
        v
  [10-11] PUSH ────────────> Image in registry
        |
        v
  [12]  RESOLVE DIGEST ────> RepoDigest (sha256:...)
        |
        v
  [13]  VERIFY SBOM SHA256 ─> Untouched since step 5?
        |                         |
        | OK                      | MODIFIED → STOP
        v
  [14]  SIGN ──────────────> Cosign signature on digest
        |
        v
  [15]  ATTEST SBOM ───────> SBOM bound to digest (In-Toto)
        |
        v
  [16]  ATTEST SLSA ───────> Build provenance bound to digest
        |
        v
  [17]  VERIFY ────────────> Signature + attestation in registry?
        |                         |
        | OK                      | FAIL → STOP
        v
  [18]  DTRACK ────────────> Monitoring (non-blocking, linked to digest)
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

The signing strategy follows a priority order: **KMS > CI keyless > keypair**.

All signing scripts (`image-sign.sh`, `slsa-provenance.sh`, `sbom-attest.sh`) use the same detection logic:

1. **Azure Key Vault KMS** (`azurekms://`): If `COSIGN_KMS_KEY` is set. Recommended for enterprise. The private key never leaves the HSM, signing is audited in Azure, and the key can be rotated without changing the pipeline.

2. **Keyless** (OIDC via Sigstore): If a CI OIDC provider is detected — `ACTIONS_ID_TOKEN_REQUEST_URL` (GitHub Actions) or `SYSTEM_OIDCREQUESTURI` (Azure DevOps). The runner gets an ephemeral certificate from Fulcio. **Keyless is never attempted blindly**: the scripts check for CI-specific env vars first, so it never triggers an interactive browser login in local or e2e contexts.

3. **Keypair**: If a `cosign.key` file exists. Simplest but hardest to manage (key rotation, secure storage). Reserved for development, e2e tests, or air-gapped environments.

If none of the above is available, the script fails with a clear error listing the options.

### Why restrict `--certificate-identity-regexp`

In keyless mode, `cosign verify` uses `--certificate-identity-regexp` to filter which OIDC identities are accepted. A permissive value like `".*"` would accept signatures from **any** pipeline on **any** organization — defeating the purpose of verification. The regexp should be as specific as possible:

- **GitHub Actions**: `"github.com/cuspofaries/"` — scoped to the organization. GitHub's OIDC subject includes the repo name, so org-level scoping is already quite restrictive.
- **Azure DevOps**: `"https://dev.azure.com/cuspofaries/sdlc/_build"` — scoped to org + project + pipeline definitions. Scoping only to the org (`cuspofaries/`) would allow **any pipeline in any project** of that org to pass verification. Adding the project name (`sdlc/`) and `_build` ensures only pipelines from this specific project are accepted.

When porting to your organization, this is the **first thing to change**. See [docs/azure-devops-porting.md](docs/azure-devops-porting.md) for the full list.

### Why post-attestation verification is fail-closed (step 16)

Signing and attesting can silently fail — a `--no-upload` flag, a network glitch, or a registry persistence issue can result in a pipeline that declares success while the signature never made it to the registry. Step 16 runs three separate verifications on the **same digest** (`image@sha256:...`, never a mutable tag):

1. `cosign verify` — image signature
2. `cosign verify-attestation --type cyclonedx` — SBOM attestation
3. `cosign verify-attestation --type slsaprovenance` — SLSA provenance

**All three must pass.** There is no "at least one" mode — if the SLSA provenance is missing, the pipeline fails even if the SBOM attestation is present. This is deliberate: the SBOM proves **what** is in the image, and the SLSA provenance proves **who** built it and **from what** source. Both are needed for a complete supply chain guarantee.

Identity constraints (`--certificate-oidc-issuer` + `--certificate-identity-regexp`) are enforced on **every** verification including SLSA provenance — this is the proof that the build came from the expected CI pipeline, not from an attacker with access to the registry.

A `cosign tree` command runs first (non-blocking, debug) to display all referrers (signature + attestations) attached to the digest — useful for troubleshooting when a verification fails.

All outputs are archived in `output/verify/`:
- `cosign-tree.log` — referrer listing (debug)
- `verify-signature.log` — signature verification
- `verify-attestation-sbom.log` — SBOM attestation
- `verify-attestation-slsa.log` — SLSA provenance

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
| **deny** | Copyleft licenses (GPL, AGPL, SSPL) in app libraries | Incompatible with proprietary distribution (OS packages excluded — expected in base images) |
| **deny** | Missing SBOM timestamp | Cannot verify freshness |
| **deny** | Zero components | SBOM generation likely failed |
| **deny** | Missing generation tool metadata | Cannot audit how SBOM was produced |
| **deny** | CycloneDX spec < 1.4 | Older specs lack required fields for compliance |
| **warn** | Unapproved licenses | Flagged for legal review, not blocking |
| **warn** | Missing license information | Traceability gap |
| **warn** | High component count (> 500) | Possible dependency bloat |
| **warn** | Deprecated/abandoned packages | Should be replaced |
| **warn** | Missing supplier/publisher metadata | Reduced traceability |

### Pinned tool versions

All tools are pinned to specific versions in `Taskfile.yml` (variables `TRIVY_VERSION`, `COSIGN_VERSION`, `OPA_VERSION`, `CDXGEN_VERSION`, `ORAS_VERSION`). This ensures:
- **Reproducibility**: same versions across dev, CI, and all consumer repos
- **No surprise breaking changes**: a new trivy/cosign release cannot silently change scan results or signing behavior
- **Auditability**: the exact tool versions are visible in `task install:verify` output

Renovate monitors these versions and opens PRs when updates are available, so pinning does not mean stale.

### Why resilient tool installation

The Trivy installation step uses a **retry loop with backoff** (3 attempts, 5-second delay between failures). This guards against transient network failures during `curl` downloads in CI environments, where shared runners can experience intermittent connectivity issues. A single failed download does not fail the entire pipeline — only 3 consecutive failures do.

### Taskfile orchestrates, scripts do the work

Business logic (digest resolution, signing mode detection, attestation, policy evaluation) lives in `scripts/*.sh` — never inline in Taskfile YAML. Each script follows the same contract:
- `set -euo pipefail` at the top
- Inputs via positional args and env vars (no hardcoded paths)
- Explicit logging of every digest, file, and mode before acting
- Exit 1 on failure (fail-closed)

The Taskfile only orchestrates: it calls scripts with the right variables. This prevents logic duplication and makes scripts testable independently of the task runner.

### Cross-platform consistency

The pipeline is implemented on three platforms with the **same logical flow**:

| Platform | Implementation | Notes |
|----------|---------------|-------|
| **GitHub Actions** | `.github/workflows/supply-chain-reusable.yml` | Single job, `workflow_call` reusable workflow |
| **Azure DevOps** | `azure-pipelines/pipeline.yml` | Multi-stage (BuildAndAnalyze → Publish → DailyRescan) |
| **Local / any CI** | `Taskfile.yml` + `scripts/` | Portable tasks, called by both GH and ADO |

All three share the same order (SAST + build → analyze → gate → publish), the same tools (Semgrep, Trivy, Cosign, OPA), the same signing priority (KMS > CI keyless > keypair), and the same invariants (SBOM integrity, digest-only signing, post-publish verification). When a mechanism is added to one, it is added to all three. The `validate-toolchain.yml` workflow includes an **end-to-end test** (`e2e-test` job) that scans source code (SAST), builds a test image, generates SBOM, runs all scans and policy checks, verifies the SBOM integrity invariant, then signs, attests, and verifies using a local registry. This catches integration regressions that unit-level checks would miss.

**E2E test philosophy: as strict as prod, fail-closed.** The e2e runs the exact same Taskfile tasks with the same defaults — no `TRIVY_EXIT_CODE=0`, no `--ignore-unfixed`, no relaxed identity regexp. If the test image has HIGH/CRITICAL CVEs, the e2e fails; fix the base image, don't relax the test.

Known relaxations (inherent to CI, each documented inline in the workflow):

| Relaxation | Why unavoidable | Where the real behavior is tested |
|------------|----------------|-----------------------------------|
| Keypair signing (not keyless) | Keyless requires OIDC from a CI provider; scripts detect env vars (`ACTIONS_ID_TOKEN_REQUEST_URL`, `SYSTEM_OIDCREQUESTURI`) and only attempt keyless when available | Consumer repos using `supply-chain-reusable.yml` with real registries |
| Local `registry:2` + `COSIGN_ALLOW_INSECURE_REGISTRY` | No TLS without external certs in CI; this is the only env override | Consumer repos pushing to ghcr.io / ACR |
| Single runner (no save/load) | ADO multi-stage pattern is platform-specific | `azure-pipelines/pipeline.yml` with docker save/load + ImageID re-check |

Not relaxed (same as prod): `TRIVY_EXIT_CODE=1`, `TRIVY_SEVERITY=HIGH,CRITICAL`, OPA deny rules, digest resolution via tasks, same scripts, same policies.

**Rule: every relaxation must answer WHY it can't be avoided and WHERE the real behavior is tested. If you can't answer both, don't relax.**

### SLSA build provenance

[SLSA](https://slsa.dev/) (Supply chain Levels for Software Artifacts) provenance records **who** built an image, **from what** source, and **how**. The pipeline attests a SLSA provenance predicate to the image digest alongside the SBOM attestation:

- **GitHub Actions**: Uses `actions/attest-build-provenance@v2` (native GitHub attestation, stored in the package registry).
- **Azure DevOps / local**: Uses `scripts/slsa-provenance.sh` which generates a SLSA v0.2 predicate (builder ID, source repo, revision, build URL) and attests it via cosign with the same KMS > CI keyless > keypair priority.

This provides a verifiable chain from the published image back to the exact source commit and CI run that produced it.

### Semantic versioning

The toolchain uses [semantic versioning](https://semver.org/) via git tags (`v1.0.0`, `v1.2.3`). Pushing a version tag triggers the `release.yml` workflow which:

1. Validates the tag format (`vX.Y.Z`)
2. Generates a changelog from commit history
3. Creates a GitHub Release
4. Updates a floating major tag (`v1`) pointing to the latest `v1.x.y`

Consumer repos can pin to:
- `@v1` — automatic minor/patch updates (recommended)
- `@v1.2.0` — exact version (maximum reproducibility)
- `@main` — latest development (not recommended for production)

### Security exceptions (CRA/NIS2 audit-ready)

When a vulnerability cannot be immediately fixed but is assessed as temporarily acceptable, the pipeline supports **structured, time-bound, auditable exceptions** via `security-exceptions.yaml`. This answers the auditor question: "How do you handle a temporarily acceptable vulnerability?"

**Where does the file live?** In the **consumer repo** (e.g. `charly/`), not in `sdlc`. Each project owns its own risk — a CVE acceptable for one app may not be for another. The `sdlc` repo provides the **mechanisms** (scripts + rego rules), the consumer repo provides the **data** (which CVEs are accepted, by whom, until when).

```
charly/                              ← consumer repo
├── app/
│   └── Dockerfile
├── security-exceptions.yaml         ← exceptions live HERE
├── policies/                        ← optional custom OPA rules
└── .github/workflows/
    └── build.yml                    ← passes exceptions-file to sdlc
```

The file is git-versioned in `charly` — every addition, modification, or removal goes through a PR, creating a complete audit trail (who added the exception, when, approved by whom).

```yaml
# charly/security-exceptions.yaml
exceptions:
  - id: CVE-2024-32002
    package: "git"
    reason: "Not exploitable in our context (no submodule clone)"
    approved_by: "security@example.com"
    expires: "2025-06-30"
    ticket: "JIRA-1234"
```

**All 6 fields are mandatory.** No permanent exceptions — `expires` is required.

The consumer workflow passes the file to the reusable workflow:

```yaml
# charly/.github/workflows/build.yml
jobs:
  supply-chain:
    uses: cuspofaries/sdlc/.github/workflows/supply-chain-reusable.yml@v1
    with:
      context: ./app
      image-name: charly
      exceptions-file: security-exceptions.yaml  # ← passed to both gates
    secrets:
      REGISTRY_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

The mechanism operates at **two independent gates**:

1. **Trivy gate**: `scripts/trivy-exceptions.sh` reads the YAML and generates `.trivyignore` containing **only non-expired** CVE IDs. When an exception expires, it disappears from `.trivyignore` and Trivy blocks it again automatically.

2. **OPA gate** (defense in depth): `policies/security-exceptions.rego` reads the same YAML (converted to JSON) and adds rules:
   - **deny** if an exception has missing or empty required fields
   - **deny** if an exception has expired (catches stale files even if Trivy missed)
   - **warn** if an exception expires within 7 days (renewal reminder)
   - **warn** listing all active exceptions (audit visibility in every pipeline run)

**Critical invariant**: The SBOM file is **never modified**. Exceptions live at the gate level only. SBOM integrity (SHA256 + ImageID) is untouched.

The data flow:
```
security-exceptions.yaml (consumer repo, git-versioned)
        |
        +---> trivy-exceptions.sh ---> .trivyignore (non-expired CVEs)
        |                                  |
        |                           trivy image --ignorefile .trivyignore
        |
        +---> sbom-policy.sh ---> yq -o json ---> OPA --data exceptions.json
                                                    |
                                                    +-- deny: expired, missing fields
                                                    +-- warn: expiring < 7 days
                                                    +-- warn: active exceptions (audit)
```

For local use with Taskfile: place `security-exceptions.yaml` at the project root and run `task sbom:scan` / `task sbom:policy` — the default `EXCEPTIONS_FILE` variable picks it up automatically. To override: `task sbom:scan EXCEPTIONS_FILE=path/to/exceptions.yaml`.

### OPA unit tests

Baseline OPA policies are covered by unit tests in `policies/sbom-compliance_test.rego` (run via `task opa:test` or `opa test policies/ -v`). Tests verify both deny and warn rules using `json.patch`/`json.remove` on a minimal valid SBOM fixture. The `validate-toolchain.yml` CI runs these tests on every push.

### Workflow output for downstream consumption

The reusable GitHub Actions workflow exposes an `image` output containing the **full image reference with digest** (`registry/owner/name@sha256:...`). Downstream jobs can use this output to deploy, scan, or reference the exact image that was built, signed, and attested — without needing to resolve the digest themselves.

---

## Security guarantees

This pipeline provides the following verifiable guarantees:

| Guarantee | Mechanism | Failure mode |
|-----------|-----------|-------------|
| **Nothing is published until scanned** | Shift-left: SAST + build → analyze → GATE → publish | Pipeline stops at gate |
| **SBOM describes the exact image** | ImageID cross-check (step 5) | `FATAL: Image ID mismatch` |
| **SBOM was not modified after scan** | SHA256 recorded at generation, verified before attestation (step 12) | `FATAL: SBOM was modified` |
| **Same binary across stages** (ADO) | `docker save` → artifact → `docker load` + ImageID verification | `Loaded image does not match SBOM` |
| **Signatures target immutable digests** | RepoDigest resolved after push, tag fallback refused | `Cannot resolve registry digest` |
| **All 3 artifacts verified in registry (fail-closed)** | `cosign verify` + `verify-attestation --type cyclonedx` + `--type slsaprovenance` on same digest (step 16) | Pipeline stops if ANY is missing |
| **Only this project's pipeline can pass verify** | `--certificate-identity-regexp` scoped to org/project | Signature from other pipelines rejected |
| **SBOM content is cryptographically bound to image** | In-Toto attestation via `cosign attest --type cyclonedx` | Attestation tampering detectable |
| **All signatures are publicly auditable** | Rekor transparency log (no `--no-upload`) | Independent verification possible |
| **Build provenance is attested** | SLSA provenance predicate attested to image digest | Builder, source, and revision are cryptographically bound |
| **Expired security exceptions are blocked** | Trivy gate (.trivyignore) + OPA deny (defense in depth) | `EXPIRED on ...` + Trivy blocks CVE |
| **Active exceptions are auditable** | OPA warn lists all active exceptions in every pipeline run | Audit trail in CI logs |
| **No permanent exceptions** | All 6 fields mandatory, `expires` required | `missing required field` |
| **Known-bad packages are blocked** | OPA `deny` rules (baseline + custom) | `POLICY CHECK FAILED` |
| **Copyleft licenses are caught** | OPA `deny` for GPL/AGPL/SSPL in app libraries (OS packages warn only) | `Copyleft license ... incompatible` |
| **Outdated SBOM specs are rejected** | OPA `deny` for CycloneDX < 1.4 | `spec version too old` |
| **Source code is scanned for vulnerabilities** | SAST (Semgrep) runs before build — fail-fast on OWASP findings | `SAST scan failed` |
| **Pipeline chain is tested end-to-end** | `e2e-test` job: SAST → build → SBOM → scan → policy → sign → attest → verify | CI fails on any broken step |
| **New CVEs are caught post-deploy** | DailyRescan extracts SBOM from attestation, rescans with fresh data | Advisory (non-blocking) |
| **DTrack failure doesn't block delivery** | `continue-on-error: true`, linked to digest | Signed image ships regardless |

---

## Governance / Compliance (CRA, NIS2)

This pipeline is designed to answer auditor questions with documented evidence. Four governance documents complement the technical guarantees above:

| Document | Content | Auditor question it answers |
|----------|---------|----------------------------|
| [docs/executive-summary.md](docs/executive-summary.md) | 2-page slides-ready summary: business value, compliance mapping (CRA/NIS2/SSDF), evidence for auditors | "Give me the big picture in 5 minutes" |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting, SLA, coordinated disclosure, safe harbor | "How do stakeholders report a security issue?" |
| [docs/psirt-policy.md](docs/psirt-policy.md) | Triage workflow, remediation SLA by severity, exception management, RACI | "What is your vulnerability response process?" |
| [docs/access-governance.md](docs/access-governance.md) | Least privilege model, KMS access, OIDC identity constraints, periodic review | "Who can sign images? How are keys managed?" |
| [docs/logging-retention.md](docs/logging-retention.md) | Events logged, retention table, integrity guarantees, audit extraction procedure | "What is your log retention? How do you prove integrity?" |

**Key principles across all documents:**
- **Digest-only** — never sign a mutable tag, never reference a tag as source of truth
- **Fail-closed** — if a verification fails, the pipeline stops (no degraded mode)
- **SBOM integrity invariant** — the SBOM is never modified between generation and attestation (SHA256 + ImageID)
- **KMS > CI keyless > keypair** — signing priority, enforced by all scripts
- **Double gate for exceptions** — Trivy (`.trivyignore`) + OPA (`security-exceptions.rego`), defense in depth

## Evidence

Every pipeline run produces verifiable artifacts proving compliance:

| Evidence | Location | Verification |
|----------|----------|-------------|
| Image signature | Registry referrers | `cosign verify <image>@sha256:...` |
| SBOM attestation | Registry referrers | `cosign verify-attestation --type cyclonedx <image>@sha256:...` |
| SLSA provenance | Registry referrers | `cosign verify-attestation --type slsaprovenance <image>@sha256:...` |
| Referrer listing | Registry | `cosign tree <image>@sha256:...` |
| Scan results | CI artifacts (`output/`) | Download from pipeline run |
| OPA policy results | CI artifacts (`output/`) | Download from pipeline run |
| Verify logs | CI artifacts (`output/verify/`) | `verify-signature.log`, `verify-attestation-sbom.log`, `verify-attestation-slsa.log` |
| Transparency log | Rekor (public, append-only) | `rekor-cli search --sha sha256:...` |
| Vulnerability monitoring | Dependency-Track | Dashboard linked to registry digest |
| Exception audit trail | Git history | `git log -- security-exceptions.yaml` |

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
    uses: cuspofaries/sdlc/.github/workflows/supply-chain-reusable.yml@v1
    with:
      context: ./app
      image-name: my-app
      exceptions-file: security-exceptions.yaml  # optional — see "Security exceptions"
      dtrack-hostname: dep-api.example.com        # optional
    secrets:
      REGISTRY_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      DTRACK_API_KEY: ${{ secrets.DTRACK_API_KEY }}  # optional
```

Pin to `@v1` for automatic minor/patch updates, or `@v1.2.0` for exact version pinning.

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
| `exceptions-file` | No | `""` | Path to `security-exceptions.yaml` in caller repo (empty = no exceptions) |
| `airgap` | No | `false` | Generate air-gap deployment package (cosign bundles + archive) |

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

This runs **SAST + build → generate → scan → policy** without pushing or signing.

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
| `install` | Install all supply chain tools (trivy, cosign, cdxgen, opa, oras, yq) |
| `install:verify` | Show installed tool versions |
| `build` | Build image locally (no push) |
| `sast:scan` | Scan source code for vulnerabilities (Semgrep via Docker) |
| `sbom:generate` | Generate image SBOM (CycloneDX) |
| `sbom:generate:source` | Generate source SBOM (declared deps) |
| `sbom:scan` | Scan image for vulnerabilities (trivy image — security gate) |
| `sbom:scan:sbom` | Scan SBOM for vulnerabilities (trivy sbom — governance, advisory) |
| `sbom:policy` | Evaluate SBOM against OPA policies |
| `opa:test` | Run OPA unit tests on policy rules |
| `exceptions:validate` | Validate security-exceptions.yaml format and expiry |
| `push` | Push image to registry |
| `image:sign` | Sign image digest (cosign) |
| `image:verify` | Verify image signature |
| `sbom:attest` | Attest SBOM to image digest |
| `slsa:attest` | Attest SLSA build provenance to image digest |
| `sbom:attest:verify` | Verify signature and attestation are published in the registry |
| `sbom:sign:blob` | Sign SBOM as standalone file |
| `sbom:verify` | Verify SBOM signature and integrity |
| `sbom:store` | Store SBOM as OCI artifact in registry (ORAS) |
| `sbom:fetch` | Fetch SBOM from OCI registry (ORAS) |
| `sbom:upload` | Upload SBOM to Dependency-Track |
| `sbom:tamper:test` | Demo SBOM tampering detection |
| `airgap:export` | Package signed image + cosign bundles for air-gapped deployment |
| `airgap:verify` | Verify image signature + attestations from air-gap package (offline) |
| `pipeline` | Full pipeline (SAST + build → analyze → publish) |
| `pipeline:local` | Local pipeline (SAST + build → analyze only) |
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
│   ├── validate-toolchain.yml        ← CI + end-to-end pipeline test
│   └── release.yml                   ← Semantic versioning (tag → GitHub Release)
├── azure-pipelines/
│   └── pipeline.yml                  ← Azure DevOps template
├── scripts/                          ← Shell scripts (Taskfile orchestrates, scripts do the work)
│   ├── image-sign.sh
│   ├── image-verify.sh
│   ├── sbom-attest.sh
│   ├── sbom-integrity.sh
│   ├── sbom-generate-source.sh
│   ├── sbom-policy.sh
│   ├── trivy-exceptions.sh
│   ├── sbom-sign.sh
│   ├── sbom-tamper-test.sh
│   ├── sbom-upload-dtrack.sh
│   ├── sbom-verify.sh
│   ├── slsa-provenance.sh
│   ├── airgap-export.sh              ← Package image + bundles for air-gap
│   └── airgap-verify.sh              ← Offline verification on air-gapped env
├── policies/
│   ├── sbom-compliance.rego          ← Baseline OPA policies
│   ├── sbom-compliance_test.rego     ← OPA unit tests
│   ├── security-exceptions.rego      ← Exception validation rules (CRA/NIS2)
│   └── security-exceptions_test.rego ← Exception tests
├── docs/
│   ├── access-governance.md          ← Access control, KMS, RACI, periodic review
│   ├── airgap-deployment.md          ← Air-gap deployment: export, transfer, offline verify
│   ├── azure-devops-porting.md       ← Porting checklist for Azure DevOps
│   ├── executive-summary.md          ← 2-page slides-ready summary for RSSI/auditors
│   ├── dependency-track.md
│   ├── dependency-track.fr.md
│   ├── logging-retention.md          ← Log retention, integrity, audit extraction
│   └── psirt-policy.md               ← Vulnerability response workflow, SLA, exceptions
├── docker-compose.dtrack.yml
├── Taskfile.yml
├── renovate.json
├── POSTMORTEM.md
├── README.md
└── SECURITY.md                      ← Vulnerability reporting policy
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
    uses: cuspofaries/sdlc/.github/workflows/supply-chain-reusable.yml@v1
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
