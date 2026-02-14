#!/usr/bin/env bash
# =============================================================================
# sbom-generate-source.sh - Generate SBOM from source code (declared deps)
#
# Usage: ./scripts/sbom-generate-source.sh <source-dir> <output-dir>
#
# This scans manifests (requirements.txt, package.json, go.mod, pom.xml, etc.)
# BEFORE the image is built. Answers: "what does my code declare?"
#
# Contrast with image SBOM which answers: "what's actually in the container?"
# =============================================================================
set -euo pipefail

SOURCE_DIR="${1:?Usage: $0 <source-dir> <output-dir>}"
OUTPUT_DIR="${2:?Usage: $0 <source-dir> <output-dir>}"

mkdir -p "$OUTPUT_DIR"

echo "📦 Generating source SBOM (declared dependencies)..."
echo "   Source: ${SOURCE_DIR}"
echo "   Output: ${OUTPUT_DIR}/"
echo ""

GENERATED=0

# --- cdxgen (preferred for source analysis) ---
if command -v cdxgen &>/dev/null; then
    echo "── cdxgen ──"
    cdxgen -o "${OUTPUT_DIR}/sbom-source-cdxgen.json" "$SOURCE_DIR" 2>/dev/null
    COMPONENTS=$(jq '.components | length' "${OUTPUT_DIR}/sbom-source-cdxgen.json" 2>/dev/null || echo "0")
    echo "   ✅ ${COMPONENTS} components → sbom-source-cdxgen.json"
    ((GENERATED++))
else
    echo "   ⚠️  cdxgen not installed, skipping"
fi

# --- Trivy filesystem mode ---
if command -v trivy &>/dev/null; then
    echo "── Trivy (fs mode) ──"
    trivy fs "$SOURCE_DIR" \
        --format cyclonedx \
        --output "${OUTPUT_DIR}/sbom-source-trivy.json" 2>/dev/null
    COMPONENTS=$(jq '.components | length' "${OUTPUT_DIR}/sbom-source-trivy.json" 2>/dev/null || echo "0")
    echo "   ✅ ${COMPONENTS} components → sbom-source-trivy.json"
    ((GENERATED++))
else
    echo "   ⚠️  Trivy not installed, skipping"
fi


echo ""

if [ "$GENERATED" -eq 0 ]; then
    echo "❌ No SBOM tools available. Run: task install"
    exit 1
fi

echo "✅ Source SBOM generation complete (${GENERATED} tool(s))"
