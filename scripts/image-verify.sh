#!/usr/bin/env bash
# =============================================================================
# image-verify.sh - Verify image signature and attestation in the registry
#
# Usage: ./scripts/image-verify.sh <image> <scan-dir> [cosign-pub]
#
# Resolves the immutable RepoDigest, then verifies both the image signature
# and the CycloneDX SBOM attestation. Outputs are logged to <scan-dir>/.
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
    echo "── Verify attestation (KMS) ──"
    cosign verify-attestation \
        --key "azurekms://${COSIGN_KMS_KEY}" \
        --type cyclonedx \
        "$TARGET" 2>&1 | tee "${SCAN_DIR}/verify-attestation.log"

elif [ -f "$COSIGN_PUB" ]; then
    echo "── Verify signature (keypair) ──"
    cosign verify --key "$COSIGN_PUB" "$TARGET" 2>&1 | tee "${SCAN_DIR}/verify-signature.log"
    echo ""
    echo "── Verify attestation (keypair) ──"
    cosign verify-attestation \
        --key "$COSIGN_PUB" \
        --type cyclonedx \
        "$TARGET" 2>&1 | tee "${SCAN_DIR}/verify-attestation.log"

else
    echo "── Verify signature (keyless) ──"
    cosign verify \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        --certificate-identity-regexp "github.com/cuspofaries/" \
        "$TARGET" 2>&1 | tee "${SCAN_DIR}/verify-signature.log"
    echo ""
    echo "── Verify attestation (keyless) ──"
    cosign verify-attestation \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        --certificate-identity-regexp "github.com/cuspofaries/" \
        --type cyclonedx \
        "$TARGET" 2>&1 | tee "${SCAN_DIR}/verify-attestation.log"
fi

echo ""
echo "✅ Signature and attestation verified in registry"
