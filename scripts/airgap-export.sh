#!/usr/bin/env bash
# =============================================================================
# airgap-export.sh - Package signed image for air-gapped deployment
#
# Usage: ./scripts/airgap-export.sh <image> <sbom-file> <bundle-dir> [cosign-pub]
#
# Creates a self-contained deployment package containing:
#   - image.tar         (docker save)
#   - cosign.pub        (public key for verification)
#   - sbom.json         (CycloneDX SBOM)
#   - *.bundle          (cosign bundles for offline verification)
#   - manifest.json     (metadata: digest, SHA256, build info)
#
# Prerequisites:
#   - Image must be pushed, signed, and attested (run the full pipeline first)
#   - Pipeline must have been run with AIRGAP_BUNDLE_DIR set to <bundle-dir>
#     so that cosign bundles were generated during sign/attest steps
#
# The output archive can be transferred to an air-gapped environment
# and verified with: ./scripts/airgap-verify.sh <extracted-dir> [registry]
# =============================================================================
set -euo pipefail

IMAGE="${1:?Usage: $0 <image> <sbom-file> <bundle-dir> [cosign-pub]}"
SBOM_FILE="${2:?Usage: $0 <image> <sbom-file> <bundle-dir> [cosign-pub]}"
BUNDLE_DIR="${3:?Usage: $0 <image> <sbom-file> <bundle-dir> [cosign-pub]}"
COSIGN_PUB="${4:-cosign.pub}"

# ── Resolve immutable digest ────────────────────────────────────────────────
DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "$IMAGE" 2>/dev/null || true)

if [ -z "$DIGEST" ]; then
    echo "FATAL: Cannot resolve registry digest for ${IMAGE}" >&2
    echo "   Make sure the image has been pushed before exporting." >&2
    exit 1
fi

DIGEST_HASH=$(echo "$DIGEST" | cut -d'@' -f2)
IMAGE_BASE=$(echo "$DIGEST" | cut -d'@' -f1)
IMAGE_NAME=$(echo "$IMAGE_BASE" | rev | cut -d'/' -f1 | rev)

echo "📦 Exporting air-gap deployment package..."
echo "   Image:  ${DIGEST}"
echo "   SBOM:   ${SBOM_FILE}"
echo "   Output: ${BUNDLE_DIR}"
echo ""

# ── Verify bundles exist ────────────────────────────────────────────────────
echo "── Checking bundles ──"
REQUIRED_BUNDLES=(image-signature.bundle sbom-attestation.bundle slsa-attestation.bundle)
MISSING=0

for bundle in "${REQUIRED_BUNDLES[@]}"; do
    if [ -f "${BUNDLE_DIR}/${bundle}" ]; then
        echo "   ✅ ${bundle}"
    else
        echo "   ❌ ${bundle} NOT FOUND" >&2
        MISSING=$((MISSING + 1))
    fi
done

if [ "$MISSING" -gt 0 ]; then
    echo "" >&2
    echo "FATAL: ${MISSING} bundle(s) missing." >&2
    echo "   Run the pipeline with AIRGAP_DIR=${BUNDLE_DIR} to generate bundles:" >&2
    echo "   task pipeline AIRGAP_DIR=${BUNDLE_DIR}" >&2
    exit 1
fi
echo ""

# ── Save image ──────────────────────────────────────────────────────────────
echo "── Saving image (docker save) ──"
docker save "$IMAGE" -o "${BUNDLE_DIR}/image.tar"
IMAGE_TAR_SHA=$(sha256sum "${BUNDLE_DIR}/image.tar" | cut -d' ' -f1)
echo "   ✅ image.tar (SHA256: ${IMAGE_TAR_SHA})"
echo ""

# ── Copy SBOM ───────────────────────────────────────────────────────────────
echo "── Copying SBOM ──"
cp "$SBOM_FILE" "${BUNDLE_DIR}/sbom.json"
SBOM_SHA=$(sha256sum "${BUNDLE_DIR}/sbom.json" | cut -d' ' -f1)
echo "   ✅ sbom.json (SHA256: ${SBOM_SHA})"
echo ""

# ── Detect signing mode and export public key ──────────────────────────────
echo "── Exporting public key ──"
SIGNING_MODE="unknown"

if [ -n "${COSIGN_KMS_KEY:-}" ]; then
    SIGNING_MODE="kms"
    cosign public-key --key "azurekms://${COSIGN_KMS_KEY}" > "${BUNDLE_DIR}/cosign.pub"
    echo "   ✅ cosign.pub (exported from KMS)"
elif [ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ]; then
    SIGNING_MODE="keyless"
    echo "   ℹ️  Keyless mode (GitHub Actions OIDC) — certificate embedded in bundles"
elif [ -n "${SYSTEM_OIDCREQUESTURI:-}" ]; then
    SIGNING_MODE="keyless"
    echo "   ℹ️  Keyless mode (Azure DevOps OIDC) — certificate embedded in bundles"
elif [ -f "$COSIGN_PUB" ]; then
    SIGNING_MODE="keypair"
    cp "$COSIGN_PUB" "${BUNDLE_DIR}/cosign.pub"
    echo "   ✅ cosign.pub (copied from ${COSIGN_PUB})"
else
    echo "   ⚠️  No public key available and no OIDC detected." >&2
fi
echo ""

# ── Build verification block for manifest ────────────────────────────────────
OIDC_ISSUER="${COSIGN_OIDC_ISSUER:-}"
IDENTITY_REGEXP="${COSIGN_IDENTITY_REGEXP:-}"

if [ "$SIGNING_MODE" = "keyless" ] && [ -z "$OIDC_ISSUER" ]; then
    # Auto-detect OIDC issuer from CI environment
    if [ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ]; then
        OIDC_ISSUER="https://token.actions.githubusercontent.com"
        IDENTITY_REGEXP="${IDENTITY_REGEXP:-github.com/${GITHUB_REPOSITORY_OWNER:-}}"
    elif [ -n "${SYSTEM_OIDCREQUESTURI:-}" ]; then
        OIDC_ISSUER="https://vstoken.dev.azure.com/${SYSTEM_TEAMFOUNDATIONCOLLECTIONURI##*/}"
        IDENTITY_REGEXP="${IDENTITY_REGEXP:-${SYSTEM_TEAMPROJECT:-}}"
    fi
fi

# ── Create manifest ─────────────────────────────────────────────────────────
echo "── Creating manifest ──"
cat > "${BUNDLE_DIR}/manifest.json" <<MANIFEST
{
  "version": "1.1",
  "created": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "image": {
    "reference": "${IMAGE_BASE}",
    "digest": "${DIGEST_HASH}",
    "tar_sha256": "${IMAGE_TAR_SHA}"
  },
  "sbom": {
    "file": "sbom.json",
    "sha256": "${SBOM_SHA}",
    "format": "cyclonedx"
  },
  "bundles": {
    "signature": "image-signature.bundle",
    "sbom_attestation": "sbom-attestation.bundle",
    "slsa_attestation": "slsa-attestation.bundle"
  },
  "verification": {
    "mode": "${SIGNING_MODE}",
    "public_key": $([ "$SIGNING_MODE" != "keyless" ] && echo '"cosign.pub"' || echo 'null'),
    "oidc_issuer": $([ -n "$OIDC_ISSUER" ] && echo "\"${OIDC_ISSUER}\"" || echo 'null'),
    "identity_regexp": $([ -n "$IDENTITY_REGEXP" ] && echo "\"${IDENTITY_REGEXP}\"" || echo 'null')
  },
  "tools": {
    "cosign_version": "$(cosign version 2>/dev/null | head -1 || echo 'unknown')"
  }
}
MANIFEST
echo "   ✅ manifest.json"
echo ""

# ── Create archive ──────────────────────────────────────────────────────────
echo "── Creating archive ──"
ARCHIVE_NAME="airgap-${IMAGE_NAME}-$(echo "$DIGEST_HASH" | cut -c8-19).tar.gz"
ARCHIVE_FILES=(image.tar sbom.json manifest.json
    image-signature.bundle sbom-attestation.bundle slsa-attestation.bundle)

# Include cosign.pub only if it exists (not present in keyless mode)
if [ -f "${BUNDLE_DIR}/cosign.pub" ]; then
    ARCHIVE_FILES+=(cosign.pub)
fi

tar -czf "${BUNDLE_DIR}/${ARCHIVE_NAME}" \
    -C "$BUNDLE_DIR" \
    "${ARCHIVE_FILES[@]}"

ARCHIVE_SHA=$(sha256sum "${BUNDLE_DIR}/${ARCHIVE_NAME}" | cut -d' ' -f1)

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "✅ Air-gap package ready"
echo "   Archive:  ${BUNDLE_DIR}/${ARCHIVE_NAME}"
echo "   SHA256:   ${ARCHIVE_SHA}"
echo "   Size:     $(du -h "${BUNDLE_DIR}/${ARCHIVE_NAME}" | cut -f1)"
echo ""
echo "   Transfer this file to the isolated environment."
echo "   Verify with:"
echo "     tar -xzf ${ARCHIVE_NAME}"
echo "     ./scripts/airgap-verify.sh <extracted-dir> [local-registry]"
echo "════════════════════════════════════════════════════════════════"
