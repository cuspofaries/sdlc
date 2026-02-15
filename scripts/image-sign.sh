#!/usr/bin/env bash
# =============================================================================
# image-sign.sh - Sign a container image digest with cosign
#
# Usage: ./scripts/image-sign.sh <image> [cosign-key]
#
# Resolves the immutable RepoDigest from the local Docker daemon and signs it.
# Refuses to sign a mutable tag — the image must be pushed first.
#
# Supports (in priority order):
#   - Azure Key Vault KMS (set COSIGN_KMS_KEY env)
#   - GitHub Actions keyless (OIDC → Fulcio + Rekor)
#   - Azure DevOps keyless (Azure AD Workload Identity)
#   - Keypair (POC / air-gapped)
# =============================================================================
set -euo pipefail

IMAGE="${1:?Usage: $0 <image> [cosign-key]}"
COSIGN_KEY="${2:-cosign.key}"

echo "🔏 Signing image..."
echo "   Image: ${IMAGE}"

# --- Air-gap bundle output (optional) ---
# When AIRGAP_BUNDLE_DIR is set, save a cosign bundle file alongside
# the registry signature. This bundle enables offline verification
# on air-gapped environments via: cosign verify --bundle --offline
BUNDLE_ARGS=()
if [ -n "${AIRGAP_BUNDLE_DIR:-}" ]; then
    mkdir -p "$AIRGAP_BUNDLE_DIR"
    BUNDLE_ARGS=(--bundle "${AIRGAP_BUNDLE_DIR}/image-signature.bundle")
    echo "   Bundle: ${AIRGAP_BUNDLE_DIR}/image-signature.bundle"
fi

# --- Resolve immutable digest ---
DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "$IMAGE" 2>/dev/null || true)

if [ -z "$DIGEST" ]; then
    echo "❌ Cannot resolve registry digest for ${IMAGE}"
    echo "   Make sure the image has been pushed (task push) before signing."
    exit 1
fi

echo "   Digest: ${DIGEST}"
echo ""

# --- Detect environment and sign ---
# Priority: KMS > GitHub keyless > Azure keyless > Keypair

if [ -n "${COSIGN_KMS_KEY:-}" ]; then
    echo "── Mode: Azure Key Vault KMS ──"
    cosign sign --yes --key "azurekms://${COSIGN_KMS_KEY}" ${BUNDLE_ARGS[@]+"${BUNDLE_ARGS[@]}"} "$DIGEST"

elif [ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ]; then
    echo "── Mode: GitHub Actions keyless (OIDC) ──"
    cosign sign --yes ${BUNDLE_ARGS[@]+"${BUNDLE_ARGS[@]}"} "$DIGEST"

elif [ -n "${SYSTEM_OIDCREQUESTURI:-}" ]; then
    echo "── Mode: Azure DevOps keyless (Workload Identity) ──"
    cosign sign --yes ${BUNDLE_ARGS[@]+"${BUNDLE_ARGS[@]}"} "$DIGEST"

elif [ -f "$COSIGN_KEY" ]; then
    echo "── Mode: Keypair (${COSIGN_KEY}) ──"
    cosign sign --key "$COSIGN_KEY" --yes ${BUNDLE_ARGS[@]+"${BUNDLE_ARGS[@]}"} "$DIGEST"

else
    echo "❌ No signing method available."
    echo "   Options:"
    echo "   - Set COSIGN_KMS_KEY for Azure Key Vault KMS"
    echo "   - Run in GitHub Actions or Azure DevOps (keyless)"
    echo "   - Generate a keypair: task signing:init"
    exit 1
fi

echo ""
echo "✅ Image signed: ${DIGEST}"
