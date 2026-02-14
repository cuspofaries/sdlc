#!/usr/bin/env bash
# =============================================================================
# image-verify.sh - Verify image signature + SBOM + SLSA provenance
#
# Usage: ./scripts/image-verify.sh <image> <scan-dir> [cosign-pub]
#
# FAIL-CLOSED: all three verifications must pass. If ANY is missing or
# invalid, the script exits 1. There is no "at least one" mode.
#
#   1. Image signature         → verify-signature.log
#   2. SBOM attestation        → verify-attestation-sbom.log
#   3. SLSA provenance         → verify-attestation-slsa.log
#
# Refuses to verify a mutable tag — resolves RepoDigest and logs it.
# All verify outputs are archived in <scan-dir>/ for audit trail.
#
# Identity constraints (keyless mode):
#   --certificate-oidc-issuer      → proves the CI provider
#   --certificate-identity-regexp  → proves which org/project built it
#
# Supports (in priority order):
#   - Azure Key Vault KMS   (COSIGN_KMS_KEY env)
#   - Keypair               (cosign.pub file)
#   - Keyless               (GitHub/ADO OIDC — Fulcio + Rekor)
# =============================================================================
set -euo pipefail

IMAGE="${1:?Usage: $0 <image> <scan-dir> [cosign-pub]}"
SCAN_DIR="${2:?Usage: $0 <image> <scan-dir> [cosign-pub]}"
COSIGN_PUB="${3:-cosign.pub}"

mkdir -p "$SCAN_DIR"

# ── Resolve immutable digest (refuse mutable tags) ──────────────────────────
DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "$IMAGE" 2>/dev/null || true)

if [ -z "$DIGEST" ]; then
    echo "FATAL: Cannot resolve registry digest for ${IMAGE}" >&2
    echo "   Refusing to verify a mutable tag. Was the image pushed?" >&2
    exit 1
fi

echo "🔍 Verifying image: ${DIGEST}"
echo "   (resolved from: ${IMAGE})"
echo ""

# ── Debug: show all referrers (signature + attestations) ────────────────────
echo "── cosign tree (referrers) ──"
cosign tree "$DIGEST" 2>&1 | tee "${SCAN_DIR}/cosign-tree.log" || true
echo ""

# ── Helper: run a verify command, fail-closed ───────────────────────────────
# tee can mask exit codes in a pipe. We use PIPESTATUS to catch cosign failures.
verify_cmd() {
    local label="$1"
    local logfile="$2"
    shift 2

    echo "── ${label} ──"
    echo "   Digest: ${DIGEST}"

    # Run command, capture exit code through pipe
    set +e
    "$@" 2>&1 | tee "${logfile}"
    local rc=${PIPESTATUS[0]}
    set -e

    if [ "$rc" -ne 0 ]; then
        echo "" >&2
        echo "FATAL: ${label} FAILED (exit code ${rc})" >&2
        echo "   Digest: ${DIGEST}" >&2
        echo "   Log:    ${logfile}" >&2
        exit 1
    fi

    echo "   ✅ ${label} passed"
    echo ""
}

# ── Detect environment and verify ───────────────────────────────────────────

if [ -n "${COSIGN_KMS_KEY:-}" ]; then
    MODE="Azure Key Vault KMS"
    KEY_ARGS=(--key "azurekms://${COSIGN_KMS_KEY}")
    VERIFY_ARGS=("${KEY_ARGS[@]}")
    ATTEST_ARGS=("${KEY_ARGS[@]}")

elif [ -f "$COSIGN_PUB" ]; then
    MODE="Keypair (${COSIGN_PUB})"
    KEY_ARGS=(--key "$COSIGN_PUB")
    VERIFY_ARGS=("${KEY_ARGS[@]}")
    ATTEST_ARGS=("${KEY_ARGS[@]}")

else
    MODE="Keyless (OIDC)"
    VERIFY_ARGS=(
        --certificate-oidc-issuer https://token.actions.githubusercontent.com
        --certificate-identity-regexp "github.com/cuspofaries/"
    )
    ATTEST_ARGS=("${VERIFY_ARGS[@]}")
fi

echo "Mode: ${MODE}"
echo ""

# 1/3 — Image signature
verify_cmd "Verify signature" \
    "${SCAN_DIR}/verify-signature.log" \
    cosign verify "${VERIFY_ARGS[@]}" "$DIGEST"

# 2/3 — SBOM attestation (CycloneDX)
verify_cmd "Verify SBOM attestation (cyclonedx)" \
    "${SCAN_DIR}/verify-attestation-sbom.log" \
    cosign verify-attestation "${ATTEST_ARGS[@]}" --type cyclonedx "$DIGEST"

# 3/3 — SLSA provenance attestation
verify_cmd "Verify SLSA provenance (slsaprovenance)" \
    "${SCAN_DIR}/verify-attestation-slsa.log" \
    cosign verify-attestation "${ATTEST_ARGS[@]}" --type slsaprovenance "$DIGEST"

# ── Summary ─────────────────────────────────────────────────────────────────
echo "════════════════════════════════════════════════════════"
echo "✅ ALL VERIFICATIONS PASSED (fail-closed)"
echo "   Digest:     ${DIGEST}"
echo "   Mode:       ${MODE}"
echo "   Signature:  ${SCAN_DIR}/verify-signature.log"
echo "   SBOM:       ${SCAN_DIR}/verify-attestation-sbom.log"
echo "   SLSA:       ${SCAN_DIR}/verify-attestation-slsa.log"
echo "   Tree:       ${SCAN_DIR}/cosign-tree.log"
echo "════════════════════════════════════════════════════════"
