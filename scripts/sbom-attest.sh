#!/usr/bin/env bash
# =============================================================================
# sbom-attest.sh - Attest SBOM to a specific image digest
#
# Usage: ./scripts/sbom-attest.sh <image> <sbom-file> <cosign-key>
#
# This is the STRONGEST form of SBOM signing:
#   - Cryptographically binds the SBOM to the exact image digest
#   - Proves THIS SBOM describes THIS image (not just "some file was signed")
#   - Attestation is stored IN the registry alongside the image
#   - Verifiable by anyone with access to the registry + public key
#
# Requires: image must be pushed to a registry first.
# For local-only work without registry, use sbom:sign:blob instead.
#
# Supports:
#   - Keypair (POC / air-gapped)
#   - GitHub Actions keyless (OIDC → Fulcio + Rekor)
#   - Azure DevOps keyless (Azure AD Workload Identity)
# =============================================================================
set -euo pipefail

IMAGE="${1:?Usage: $0 <image> <sbom-file> [cosign-key]}"
SBOM_FILE="${2:?Usage: $0 <image> <sbom-file> [cosign-key]}"
COSIGN_KEY="${3:-cosign.key}"

echo "🔏 Attesting SBOM to image digest..."
echo "   Image: ${IMAGE}"
echo "   SBOM:  ${SBOM_FILE}"
echo ""

if [ ! -f "$SBOM_FILE" ]; then
    echo "❌ SBOM file not found: $SBOM_FILE"
    exit 1
fi

# --- Resolve image digest ---
echo "── Resolving image digest ──"
IMAGE_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "$IMAGE" 2>/dev/null || true)

if [ -z "$IMAGE_DIGEST" ]; then
    # Try crane if available (works with remote registries)
    if command -v crane &>/dev/null; then
        IMAGE_DIGEST=$(crane digest "$IMAGE" 2>/dev/null || true)
        if [ -n "$IMAGE_DIGEST" ]; then
            IMAGE_DIGEST="${IMAGE}@${IMAGE_DIGEST}"
        fi
    fi
fi

if [ -n "$IMAGE_DIGEST" ]; then
    echo "   Digest: ${IMAGE_DIGEST}"
else
    echo "   ⚠️  Could not resolve digest, using tag reference"
    IMAGE_DIGEST="$IMAGE"
fi

SBOM_SHA=$(sha256sum "$SBOM_FILE" | cut -d' ' -f1)
echo "   SBOM SHA256: ${SBOM_SHA}"
echo ""

# --- Detect environment and attest ---

if [ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ]; then
    # ── GitHub Actions: keyless via Fulcio + Rekor ──
    echo "── Mode: GitHub Actions keyless (OIDC) ──"
    cosign attest --yes \
        --predicate "$SBOM_FILE" \
        --type cyclonedx \
        "$IMAGE_DIGEST"

elif [ -n "${SYSTEM_OIDCREQUESTURI:-}" ]; then
    # ── Azure DevOps: keyless via Azure AD Workload Identity ──
    echo "── Mode: Azure DevOps keyless (Workload Identity) ──"

    AZURE_TOKEN=$(curl -s \
        -H "Content-Type: application/json" \
        -d '{}' \
        "${SYSTEM_OIDCREQUESTURI}?api-version=7.1&audience=sigstore" \
        -H "Authorization: Bearer ${SYSTEM_ACCESSTOKEN}" \
        | jq -r '.oidcToken')

    COSIGN_EXPERIMENTAL=1 cosign attest --yes \
        --predicate "$SBOM_FILE" \
        --type cyclonedx \
        --identity-token "$AZURE_TOKEN" \
        "$IMAGE_DIGEST"

elif [ -f "$COSIGN_KEY" ]; then
    # ── Local / POC: keypair ──
    echo "── Mode: Keypair (${COSIGN_KEY}) ──"
    cosign attest \
        --key "$COSIGN_KEY" \
        --predicate "$SBOM_FILE" \
        --type cyclonedx \
        --no-upload=true \
        "$IMAGE_DIGEST"

else
    echo "❌ No signing method available."
    echo "   Options:"
    echo "   - Run in GitHub Actions or Azure DevOps (keyless)"
    echo "   - Generate a keypair: task signing:init"
    echo "   - Use blob signing: task sbom:sign:blob"
    exit 1
fi

echo ""
echo "✅ SBOM attested to image digest"
echo "   Verify with: cosign verify-attestation --key cosign.pub --type cyclonedx ${IMAGE_DIGEST}"
