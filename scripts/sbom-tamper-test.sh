#!/usr/bin/env bash
# =============================================================================
# sbom-tamper-test.sh - Simulate SBOM tampering to demonstrate integrity checks
#
# Usage: ./scripts/sbom-tamper-test.sh <sbom-file> <cosign-pub>
#
# This script:
#   1. Takes a signed SBOM
#   2. Creates a tampered copy (removes a component)
#   3. Shows that signature verification fails
#   4. Cleans up
# =============================================================================
set -euo pipefail

SBOM_FILE="${1:?Usage: $0 <sbom-file> <cosign-pub>}"
COSIGN_PUB="${2:-cosign.pub}"

TAMPERED_FILE="${SBOM_FILE}.tampered"

echo "🧪 SBOM Tampering Simulation"
echo "═══════════════════════════════════════════════════════"
echo ""

# --- Original SBOM ---
ORIGINAL_HASH=$(sha256sum "$SBOM_FILE" | cut -d' ' -f1)
ORIGINAL_COMPONENTS=$(jq '.components | length' "$SBOM_FILE")
echo "📄 Original SBOM:"
echo "   Hash:       ${ORIGINAL_HASH}"
echo "   Components: ${ORIGINAL_COMPONENTS}"
echo ""

# --- Verify original signature ---
if [ -f "${SBOM_FILE}.sig" ] && [ -f "$COSIGN_PUB" ]; then
    echo "🔐 Verifying original signature..."
    if cosign verify-blob --key "$COSIGN_PUB" --signature "${SBOM_FILE}.sig" "$SBOM_FILE" 2>/dev/null; then
        echo "   ✅ Original signature: VALID"
    else
        echo "   ❌ Original signature already invalid — cannot proceed"
        exit 1
    fi
    echo ""
else
    echo "⚠️  No signature file found, demonstrating hash-based detection only"
    echo ""
fi

# --- Tamper: remove first component ---
echo "💉 Tampering: removing a component from SBOM..."
jq 'del(.components[0])' "$SBOM_FILE" > "$TAMPERED_FILE"

TAMPERED_HASH=$(sha256sum "$TAMPERED_FILE" | cut -d' ' -f1)
TAMPERED_COMPONENTS=$(jq '.components | length' "$TAMPERED_FILE")
REMOVED_NAME=$(jq -r '.components[0].name' "$SBOM_FILE")

echo "   Removed:    ${REMOVED_NAME}"
echo ""

echo "📄 Tampered SBOM:"
echo "   Hash:       ${TAMPERED_HASH}"
echo "   Components: ${TAMPERED_COMPONENTS}"
echo ""

# --- Detection: hash comparison ---
echo "🔍 Detection Method 1: Hash Comparison"
if [ "$ORIGINAL_HASH" != "$TAMPERED_HASH" ]; then
    echo "   ✅ TAMPERING DETECTED — hashes differ"
    echo "   Original: ${ORIGINAL_HASH:0:16}..."
    echo "   Tampered: ${TAMPERED_HASH:0:16}..."
else
    echo "   ❌ Hashes match (should not happen)"
fi
echo ""

# --- Detection: signature verification ---
if [ -f "${SBOM_FILE}.sig" ] && [ -f "$COSIGN_PUB" ]; then
    echo "🔍 Detection Method 2: Signature Verification"
    if cosign verify-blob --key "$COSIGN_PUB" --signature "${SBOM_FILE}.sig" "$TAMPERED_FILE" 2>/dev/null; then
        echo "   ❌ Signature still valid (PROBLEM!)"
    else
        echo "   ✅ TAMPERING DETECTED — signature invalid for tampered file"
    fi
    echo ""
fi

# --- Detection: component count ---
echo "🔍 Detection Method 3: Component Count Delta"
DELTA=$((ORIGINAL_COMPONENTS - TAMPERED_COMPONENTS))
echo "   Original: ${ORIGINAL_COMPONENTS} components"
echo "   Tampered: ${TAMPERED_COMPONENTS} components"
echo "   Delta:    ${DELTA} component(s) removed"
echo ""

# --- Cleanup ---
rm -f "$TAMPERED_FILE"

echo "═══════════════════════════════════════════════════════"
echo "✅ Tampering simulation complete"
echo ""
echo "Key takeaway: cryptographic signing + hash verification"
echo "makes SBOM tampering detectable and provable."
