#!/usr/bin/env bash
# =============================================================================
# image-verify.sh - Verify image signature and attestation in the registry
#
# Usage: ./scripts/image-verify.sh <image> <scan-dir> [cosign-pub]
#
# Resolves the immutable RepoDigest, then verifies all three:
#   1. Image signature
#   2. SBOM attestation (CycloneDX)
#   3. SLSA build provenance attestation
# Outputs are logged to <scan-dir>/.
#
# Supports (in priority order):
#   - Azure Key Vault KMS (set COSIGN_KMS_KEY env)
#   - Keypair (cosign.pub)
#   - Keyless (GitHub OIDC — Fulcio + Rekor)
# =============================================================================
set -euo pipefail

IMAGE="${1:?Usage: $0 <image> <scan-dir> [cosign-pub]}"
SCAN_DIR="${2:?Usage: $0 <image> <scan-dir> [cosign-pub]}"
COSIGN_PUB="${3:-cosign.pub}"

mkdir -p "$SCAN_DIR"

echo "🔍 Verifying image signature and attestation..."
echo "   Image: ${IMAGE}"

# --- Resolve immutable digest ---
DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "$IMAGE" 2>/dev/null || true)
TARGET="${DIGEST:-$IMAGE}"
echo "   Target: ${TARGET}"
echo ""

# --- Detect environment and verify ---
# Priority: KMS > Keypair > Keyless

if [ -n "${COSIGN_KMS_KEY:-}" ]; then
    echo "── Verify signature (KMS) ──"
    cosign verify --key "azurekms://${COSIGN_KMS_KEY}" "$TARGET" 2>&1 | tee "${SCAN_DIR}/verify-signature.log"
    echo ""
    echo "── Verify SBOM attestation (KMS) ──"
    cosign verify-attestation \
        --key "azurekms://${COSIGN_KMS_KEY}" \
        --type cyclonedx \
        "$TARGET" 2>&1 | tee "${SCAN_DIR}/verify-attestation-sbom.log"
    echo ""
    echo "── Verify SLSA provenance attestation (KMS) ──"
    cosign verify-attestation \
        --key "azurekms://${COSIGN_KMS_KEY}" \
        --type slsaprovenance \
        "$TARGET" 2>&1 | tee "${SCAN_DIR}/verify-attestation-slsa.log"

elif [ -f "$COSIGN_PUB" ]; then
    echo "── Verify signature (keypair) ──"
    cosign verify --key "$COSIGN_PUB" "$TARGET" 2>&1 | tee "${SCAN_DIR}/verify-signature.log"
    echo ""
    echo "── Verify SBOM attestation (keypair) ──"
    cosign verify-attestation \
        --key "$COSIGN_PUB" \
        --type cyclonedx \
        "$TARGET" 2>&1 | tee "${SCAN_DIR}/verify-attestation-sbom.log"
    echo ""
    echo "── Verify SLSA provenance attestation (keypair) ──"
    cosign verify-attestation \
        --key "$COSIGN_PUB" \
        --type slsaprovenance \
        "$TARGET" 2>&1 | tee "${SCAN_DIR}/verify-attestation-slsa.log"

else
    echo "── Verify signature (keyless) ──"
    cosign verify \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        --certificate-identity-regexp "github.com/cuspofaries/" \
        "$TARGET" 2>&1 | tee "${SCAN_DIR}/verify-signature.log"
    echo ""
    echo "── Verify SBOM attestation (keyless) ──"
    cosign verify-attestation \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        --certificate-identity-regexp "github.com/cuspofaries/" \
        --type cyclonedx \
        "$TARGET" 2>&1 | tee "${SCAN_DIR}/verify-attestation-sbom.log"
    echo ""
    echo "── Verify SLSA provenance attestation (keyless) ──"
    cosign verify-attestation \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        --certificate-identity-regexp "github.com/cuspofaries/" \
        --type slsaprovenance \
        "$TARGET" 2>&1 | tee "${SCAN_DIR}/verify-attestation-slsa.log"
fi

echo ""
echo "✅ Signature + SBOM attestation + SLSA provenance verified in registry"
