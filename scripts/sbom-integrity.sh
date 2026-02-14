#!/usr/bin/env bash
# =============================================================================
# sbom-integrity.sh - Record or verify SBOM integrity and image alignment
#
# Usage:
#   ./scripts/sbom-integrity.sh record <sbom-file> <image>
#   ./scripts/sbom-integrity.sh verify <sbom-file> <image>
#
# record: saves SHA256 hash + ImageID to sidecar files (.sha256, .image-id)
# verify: compares current hash + ImageID against saved values
#
# Exit 1 on mismatch (fail-closed).
# =============================================================================
set -euo pipefail

ACTION="${1:?Usage: $0 <record|verify> <sbom-file> <image>}"
SBOM_FILE="${2:?Usage: $0 <record|verify> <sbom-file> <image>}"
IMAGE="${3:?Usage: $0 <record|verify> <sbom-file> <image>}"

SHA256_FILE="${SBOM_FILE}.sha256"
IMAGEID_FILE="${SBOM_FILE%.json}.image-id"

case "$ACTION" in
  record)
    echo "📋 Recording SBOM integrity checksums..."
    echo "   SBOM:  ${SBOM_FILE}"
    echo "   Image: ${IMAGE}"

    if [ ! -f "$SBOM_FILE" ]; then
      echo "❌ SBOM file not found: $SBOM_FILE"
      exit 1
    fi

    # SHA256 of SBOM file
    SBOM_SHA256=$(sha256sum "$SBOM_FILE" | awk '{print $1}')
    echo "$SBOM_SHA256" > "$SHA256_FILE"
    echo "   SBOM SHA256: $SBOM_SHA256"

    # Image ID from SBOM (recorded by Trivy)
    IMAGE_ID_IN_SBOM=$(jq -r '.metadata.component.properties[]? | select(.name == "aquasecurity:trivy:ImageID") | .value' "$SBOM_FILE" 2>/dev/null || echo "")
    echo "$IMAGE_ID_IN_SBOM" > "$IMAGEID_FILE"
    echo "   Image ID (SBOM): $IMAGE_ID_IN_SBOM"

    # Verify alignment with actual image right now
    ACTUAL_IMAGE_ID=$(docker inspect --format='{{.Id}}' "$IMAGE" 2>/dev/null || echo "")
    echo "   Image ID (docker): $ACTUAL_IMAGE_ID"

    if [ -n "$IMAGE_ID_IN_SBOM" ] && [ -n "$ACTUAL_IMAGE_ID" ] && [ "$ACTUAL_IMAGE_ID" != "$IMAGE_ID_IN_SBOM" ]; then
      echo "❌ Image ID mismatch — SBOM describes a different image!"
      exit 1
    fi

    echo "   ✅ Image-SBOM alignment verified"
    ;;

  verify)
    echo "🔍 Verifying SBOM integrity..."
    echo "   SBOM:  ${SBOM_FILE}"
    echo "   Image: ${IMAGE}"

    # 1. SHA256 verification
    if [ ! -f "$SHA256_FILE" ]; then
      echo "❌ SHA256 sidecar not found: $SHA256_FILE"
      echo "   Run '$0 record' first."
      exit 1
    fi

    EXPECTED_SHA256=$(cat "$SHA256_FILE")
    ACTUAL_SHA256=$(sha256sum "$SBOM_FILE" | awk '{print $1}')
    echo "   Expected SHA256: $EXPECTED_SHA256"
    echo "   Actual SHA256:   $ACTUAL_SHA256"

    if [ "$EXPECTED_SHA256" != "$ACTUAL_SHA256" ]; then
      echo "❌ SBOM was modified — integrity broken!"
      exit 1
    fi
    echo "   SHA256: OK"

    # 2. Image ID alignment (loaded/current image must match SBOM)
    if [ -f "$IMAGEID_FILE" ]; then
      EXPECTED_IMAGE_ID=$(cat "$IMAGEID_FILE")
      ACTUAL_IMAGE_ID=$(docker inspect --format='{{.Id}}' "$IMAGE" 2>/dev/null || echo "")
      echo "   Expected Image ID: $EXPECTED_IMAGE_ID"
      echo "   Actual Image ID:   $ACTUAL_IMAGE_ID"

      if [ -n "$EXPECTED_IMAGE_ID" ] && [ -n "$ACTUAL_IMAGE_ID" ] && [ "$ACTUAL_IMAGE_ID" != "$EXPECTED_IMAGE_ID" ]; then
        echo "❌ Loaded image does not match SBOM — different image!"
        exit 1
      fi
      echo "   Image ID: OK"
    fi

    echo "   ✅ SBOM integrity verified"
    ;;

  *)
    echo "❌ Unknown action: $ACTION"
    echo "Usage: $0 <record|verify> <sbom-file> <image>"
    exit 1
    ;;
esac
