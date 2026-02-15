#!/usr/bin/env bash
# =============================================================================
# airgap-verify.sh - Verify image signature + attestations on air-gapped env
#
# Usage: ./scripts/airgap-verify.sh <package-dir> [local-registry]
#
# Performs OFFLINE verification of a signed container image using cosign
# bundles exported by the pipeline (via airgap-export.sh).
#
# FAIL-CLOSED: all three verifications must pass. If ANY fails, exit 1.
#
#   1. Image digest integrity   (docker load + digest comparison)
#   2. Image signature           (cosign verify --bundle --offline)
#   3. SBOM attestation          (cosign verify-attestation --bundle --offline)
#   4. SLSA provenance           (cosign verify-attestation --bundle --offline)
#   5. SBOM file integrity       (SHA256 comparison)
#
# Prerequisites on the air-gapped machine:
#   - Docker (for loading images and running local registry)
#   - Cosign binary (same major version used for signing)
#   - A local container registry reachable at <local-registry>
#     (default: localhost:5000). Start one with:
#     docker run -d -p 5000:5000 --name registry registry:2
#
# Why a local registry? cosign verify resolves the image manifest from
# a registry to compare digests. docker load alone is not sufficient —
# the image must be pushable/pullable from a registry reference.
# =============================================================================
set -euo pipefail

PKG_DIR="${1:?Usage: $0 <package-dir> [local-registry]}"
LOCAL_REGISTRY="${2:-localhost:5000}"

echo "🔍 Air-gap verification"
echo "   Package:  ${PKG_DIR}"
echo "   Registry: ${LOCAL_REGISTRY}"
echo ""

# ── Verify required files ───────────────────────────────────────────────────
echo "── Checking package contents ──"
REQUIRED_FILES=(manifest.json image.tar cosign.pub sbom.json
    image-signature.bundle sbom-attestation.bundle slsa-attestation.bundle)
MISSING=0

for f in "${REQUIRED_FILES[@]}"; do
    if [ -f "${PKG_DIR}/${f}" ]; then
        echo "   ✅ ${f}"
    else
        echo "   ❌ ${f} MISSING" >&2
        MISSING=$((MISSING + 1))
    fi
done

if [ "$MISSING" -gt 0 ]; then
    echo "FATAL: ${MISSING} required file(s) missing in ${PKG_DIR}" >&2
    exit 1
fi
echo ""

# ── Read manifest ───────────────────────────────────────────────────────────
echo "── Reading manifest ──"
EXPECTED_DIGEST=$(cat "${PKG_DIR}/manifest.json" | python3 -c "import sys,json; print(json.load(sys.stdin)['image']['digest'])" 2>/dev/null \
    || cat "${PKG_DIR}/manifest.json" | jq -r '.image.digest')
EXPECTED_SBOM_SHA=$(cat "${PKG_DIR}/manifest.json" | python3 -c "import sys,json; print(json.load(sys.stdin)['sbom']['sha256'])" 2>/dev/null \
    || cat "${PKG_DIR}/manifest.json" | jq -r '.sbom.sha256')
IMAGE_REF=$(cat "${PKG_DIR}/manifest.json" | python3 -c "import sys,json; print(json.load(sys.stdin)['image']['reference'])" 2>/dev/null \
    || cat "${PKG_DIR}/manifest.json" | jq -r '.image.reference')
IMAGE_NAME=$(echo "$IMAGE_REF" | rev | cut -d'/' -f1 | rev)

echo "   Image:          ${IMAGE_REF}"
echo "   Expected digest: ${EXPECTED_DIGEST}"
echo "   Expected SBOM:   ${EXPECTED_SBOM_SHA}"
echo ""

# ── Step 1: Load image and verify digest ────────────────────────────────────
echo "── Step 1/5: Loading image ──"
docker load < "${PKG_DIR}/image.tar"

# Tag for local registry
LOCAL_IMAGE="${LOCAL_REGISTRY}/${IMAGE_NAME}:airgap-verify"
echo "   Tagging as ${LOCAL_IMAGE}"

# Find the loaded image — docker load output or inspect by known tags
LOADED_IMAGES=$(docker load < "${PKG_DIR}/image.tar" 2>/dev/null | grep "Loaded image" | sed 's/Loaded image: //')
if [ -n "$LOADED_IMAGES" ]; then
    LOADED_REF=$(echo "$LOADED_IMAGES" | head -1)
else
    # Fallback: use the original reference
    LOADED_REF="$IMAGE_REF"
fi

docker tag "$LOADED_REF" "$LOCAL_IMAGE"
echo "   Pushing to local registry..."
docker push "$LOCAL_IMAGE" 2>/dev/null

# Resolve digest from local registry
LOCAL_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "$LOCAL_IMAGE" 2>/dev/null || true)

if [ -z "$LOCAL_DIGEST" ]; then
    echo "FATAL: Cannot resolve digest from local registry." >&2
    echo "   Is the registry running at ${LOCAL_REGISTRY}?" >&2
    echo "   Start one with: docker run -d -p 5000:5000 --name registry registry:2" >&2
    exit 1
fi

LOCAL_DIGEST_HASH=$(echo "$LOCAL_DIGEST" | cut -d'@' -f2)

echo "   Local digest: ${LOCAL_DIGEST_HASH}"

if [ "$LOCAL_DIGEST_HASH" != "$EXPECTED_DIGEST" ]; then
    echo "FATAL: Digest mismatch!" >&2
    echo "   Expected: ${EXPECTED_DIGEST}" >&2
    echo "   Got:      ${LOCAL_DIGEST_HASH}" >&2
    echo "   The image may have been tampered with during transfer." >&2
    exit 1
fi

echo "   ✅ Image digest matches expected value"
echo ""

# ── Common verify args ──────────────────────────────────────────────────────
COSIGN_ALLOW_INSECURE_REGISTRY=true
export COSIGN_ALLOW_INSECURE_REGISTRY

KEY_ARGS=(--key "${PKG_DIR}/cosign.pub")
VERIFY_IMAGE="${LOCAL_DIGEST}"

# ── Helper ──────────────────────────────────────────────────────────────────
verify_step() {
    local step="$1"
    local label="$2"
    local logfile="${PKG_DIR}/${3}"
    shift 3

    echo "── Step ${step}: ${label} ──"
    echo "   Digest: ${VERIFY_IMAGE}"

    set +e
    "$@" 2>&1 | tee "${logfile}"
    local rc=${PIPESTATUS[0]}
    set -e

    if [ "$rc" -ne 0 ]; then
        echo "" >&2
        echo "FATAL: ${label} FAILED (exit code ${rc})" >&2
        echo "   Log: ${logfile}" >&2
        exit 1
    fi

    echo "   ✅ ${label} passed"
    echo ""
}

# ── Step 2: Verify image signature ──────────────────────────────────────────
verify_step "2/5" "Image signature" "verify-signature.log" \
    cosign verify "${KEY_ARGS[@]}" \
    --bundle "${PKG_DIR}/image-signature.bundle" \
    --offline \
    "$VERIFY_IMAGE"

# ── Step 3: Verify SBOM attestation ────────────────────────────────────────
verify_step "3/5" "SBOM attestation (cyclonedx)" "verify-attestation-sbom.log" \
    cosign verify-attestation "${KEY_ARGS[@]}" \
    --type cyclonedx \
    --bundle "${PKG_DIR}/sbom-attestation.bundle" \
    --offline \
    "$VERIFY_IMAGE"

# ── Step 4: Verify SLSA provenance ─────────────────────────────────────────
verify_step "4/5" "SLSA provenance (slsaprovenance)" "verify-attestation-slsa.log" \
    cosign verify-attestation "${KEY_ARGS[@]}" \
    --type slsaprovenance \
    --bundle "${PKG_DIR}/slsa-attestation.bundle" \
    --offline \
    "$VERIFY_IMAGE"

# ── Step 5: Verify SBOM integrity ──────────────────────────────────────────
echo "── Step 5/5: SBOM file integrity ──"
ACTUAL_SBOM_SHA=$(sha256sum "${PKG_DIR}/sbom.json" | cut -d' ' -f1)

if [ "$ACTUAL_SBOM_SHA" != "$EXPECTED_SBOM_SHA" ]; then
    echo "FATAL: SBOM file was modified!" >&2
    echo "   Expected SHA256: ${EXPECTED_SBOM_SHA}" >&2
    echo "   Actual SHA256:   ${ACTUAL_SBOM_SHA}" >&2
    exit 1
fi

echo "   ✅ SBOM SHA256 matches (${ACTUAL_SBOM_SHA})"
echo ""

# ── Summary ─────────────────────────────────────────────────────────────────
echo "════════════════════════════════════════════════════════════════"
echo "✅ ALL VERIFICATIONS PASSED (air-gap, offline, fail-closed)"
echo ""
echo "   Image digest:     ${EXPECTED_DIGEST}"
echo "   SBOM SHA256:      ${EXPECTED_SBOM_SHA}"
echo "   Signature:        ✅ verified"
echo "   SBOM attestation: ✅ verified"
echo "   SLSA provenance:  ✅ verified"
echo "   SBOM integrity:   ✅ verified"
echo ""
echo "   Logs saved to ${PKG_DIR}/"
echo "════════════════════════════════════════════════════════════════"
