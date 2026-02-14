#!/usr/bin/env bash
# =============================================================================
# sbom-sign.sh - Smart SBOM signing (attestation-first, blob fallback)
#
# Usage: ./scripts/sbom-sign.sh <image> <sbom-file> <cosign-key>
#
# Strategy:
#   1. Try cosign attest (links SBOM to image digest — strongest)
#   2. Fall back to cosign sign-blob if registry unavailable
#
# Both methods are valid; attestation is preferred for supply chain proof.
# =============================================================================
set -euo pipefail

IMAGE="${1:?Usage: $0 <image> <sbom-file> <cosign-key>}"
SBOM_FILE="${2:?Usage: $0 <image> <sbom-file> <cosign-key>}"
COSIGN_KEY="${3:-cosign.key}"

echo "🔐 Signing SBOM for ${IMAGE}..."

if [ ! -f "$SBOM_FILE" ]; then
    echo "❌ SBOM file not found: $SBOM_FILE"
    exit 1
fi

SBOM_DIGEST=$(sha256sum "$SBOM_FILE" | cut -d' ' -f1)
echo "   SBOM SHA256: ${SBOM_DIGEST}"

# --- Attempt 1: Attestation (preferred) ---
echo ""
echo "── Attempting attestation (digest-linked) ──"

ATTEST_OK=false

# Check if image is in a reachable registry
if docker inspect "$IMAGE" &>/dev/null; then
    IMAGE_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "$IMAGE" 2>/dev/null || true)

    if [ -n "$IMAGE_DIGEST" ]; then
        echo "   Image digest found: ${IMAGE_DIGEST}"

        if [ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ]; then
            echo "   Mode: GitHub Actions keyless"
            cosign attest --yes \
                --predicate "$SBOM_FILE" \
                --type cyclonedx \
                "$IMAGE_DIGEST" && ATTEST_OK=true

        elif [ -n "${SYSTEM_OIDCREQUESTURI:-}" ]; then
            echo "   Mode: Azure DevOps keyless"
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
                "$IMAGE_DIGEST" && ATTEST_OK=true

        elif [ -f "$COSIGN_KEY" ]; then
            echo "   Mode: Keypair"
            cosign attest \
                --key "$COSIGN_KEY" \
                --predicate "$SBOM_FILE" \
                --type cyclonedx \
                --no-upload=true \
                "$IMAGE_DIGEST" 2>/dev/null && ATTEST_OK=true
        fi
    fi
fi

if [ "$ATTEST_OK" = true ]; then
    echo ""
    echo "✅ SBOM attested to image digest (strongest guarantee)"
    exit 0
fi

# --- Attempt 2: Blob signing (fallback) ---
echo ""
echo "── Attestation unavailable, falling back to blob signing ──"
echo "   (image not pushed to registry, or registry unreachable)"

if [ -f "$COSIGN_KEY" ]; then
    # Use bundle format (newer cosign versions) and rename to .sig for compatibility
    COSIGN_PASSWORD="" cosign sign-blob \
        --key "$COSIGN_KEY" \
        --bundle "${SBOM_FILE}.bundle" \
        "$SBOM_FILE" --yes
    # Create a .sig file for backward compatibility (copy of bundle)
    cp "${SBOM_FILE}.bundle" "${SBOM_FILE}.sig" 2>/dev/null || true
    echo ""
    echo "✅ SBOM signed as blob → ${SBOM_FILE}.bundle"
    echo "   ℹ️  For stronger guarantees, push image to registry and use: task sbom:attest"

elif [ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] || [ -n "${SYSTEM_OIDCREQUESTURI:-}" ]; then
    cosign sign-blob --yes \
        --output-signature "${SBOM_FILE}.sig" \
        "$SBOM_FILE" 2>/dev/null
    echo ""
    echo "✅ SBOM signed as blob (keyless) → ${SBOM_FILE}.sig"

else
    echo "❌ No signing method available."
    echo "   Run: task signing:init"
    exit 1
fi
