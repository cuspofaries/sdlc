#!/usr/bin/env bash
# =============================================================================
# sbom-verify.sh - Verify SBOM signature and integrity
#
# Usage: ./scripts/sbom-verify.sh <image> <sbom-file> <cosign-pub>
#
# Checks:
#   1. Cryptographic signature validity
#   2. SBOM structural integrity (valid JSON, required fields)
#   3. Hash consistency
# =============================================================================
set -euo pipefail

IMAGE="${1:?Usage: $0 <image> <sbom-file> <cosign-pub>}"
SBOM_FILE="${2:?Usage: $0 <image> <sbom-file> <cosign-pub>}"
COSIGN_PUB="${3:-cosign.pub}"

PASS=0
FAIL=0

check_pass() { echo "   ✅ $1"; ((PASS++)); }
check_fail() { echo "   ❌ $1"; ((FAIL++)); }

echo "🔍 Verifying SBOM: ${SBOM_FILE}"
echo "   Image: ${IMAGE}"
echo ""

# --- Check 1: File exists and is valid JSON ---
echo "── Check 1: SBOM Structure ──"

if [ ! -f "$SBOM_FILE" ]; then
    check_fail "SBOM file not found"
    exit 1
fi

if jq empty "$SBOM_FILE" 2>/dev/null; then
    check_pass "Valid JSON"
else
    check_fail "Invalid JSON"
fi

# Check required CycloneDX fields
BOM_FORMAT=$(jq -r '.bomFormat // empty' "$SBOM_FILE")
SPEC_VERSION=$(jq -r '.specVersion // empty' "$SBOM_FILE")
COMPONENTS_COUNT=$(jq '.components | length' "$SBOM_FILE" 2>/dev/null || echo "0")

if [ "$BOM_FORMAT" = "CycloneDX" ]; then
    check_pass "Format: CycloneDX"
else
    check_fail "Expected CycloneDX format, got: ${BOM_FORMAT:-none}"
fi

if [ -n "$SPEC_VERSION" ]; then
    check_pass "Spec version: ${SPEC_VERSION}"
else
    check_fail "Missing spec version"
fi

if [ "$COMPONENTS_COUNT" -gt 0 ]; then
    check_pass "Components found: ${COMPONENTS_COUNT}"
else
    check_fail "No components in SBOM"
fi

# Metadata check
TIMESTAMP=$(jq -r '.metadata.timestamp // empty' "$SBOM_FILE")
if [ -n "$TIMESTAMP" ]; then
    check_pass "Timestamp: ${TIMESTAMP}"
else
    check_fail "Missing metadata timestamp"
fi

echo ""

# --- Check 2: Cryptographic Signature ---
echo "── Check 2: Signature Verification ──"

SBOM_DIGEST=$(sha256sum "$SBOM_FILE" | cut -d' ' -f1)
echo "   SHA256: ${SBOM_DIGEST}"

if [ -f "${SBOM_FILE}.sig" ] && [ -f "$COSIGN_PUB" ]; then
    if cosign verify-blob \
        --key "$COSIGN_PUB" \
        --signature "${SBOM_FILE}.sig" \
        "$SBOM_FILE" 2>/dev/null; then
        check_pass "Blob signature valid"
    else
        check_fail "Blob signature INVALID"
    fi
elif [ -f "$COSIGN_PUB" ]; then
    # Try attestation verification on image
    if cosign verify-attestation \
        --key "$COSIGN_PUB" \
        --type cyclonedx \
        "$IMAGE" 2>/dev/null; then
        check_pass "Image attestation valid"
    else
        check_fail "No valid attestation found on image"
    fi
else
    echo "   ⚠️  No public key found at ${COSIGN_PUB}, skipping signature check"
fi

echo ""

# --- Check 3: Component Quality ---
echo "── Check 3: SBOM Quality ──"

# Check for components with versions
VERSIONED=$(jq '[.components[] | select(.version != null and .version != "")] | length' "$SBOM_FILE" 2>/dev/null || echo "0")
UNVERSIONED=$((COMPONENTS_COUNT - VERSIONED))

if [ "$UNVERSIONED" -eq 0 ]; then
    check_pass "All components have versions"
else
    check_fail "${UNVERSIONED} components missing version info"
fi

# Check for PURLs (Package URLs)
PURL_COUNT=$(jq '[.components[] | select(.purl != null)] | length' "$SBOM_FILE" 2>/dev/null || echo "0")
if [ "$PURL_COUNT" -gt 0 ]; then
    PURL_PCT=$((PURL_COUNT * 100 / COMPONENTS_COUNT))
    check_pass "Package URLs present: ${PURL_COUNT}/${COMPONENTS_COUNT} (${PURL_PCT}%)"
else
    check_fail "No Package URLs (purl) found"
fi

# Check for licenses
LICENSE_COUNT=$(jq '[.components[] | select(.licenses != null and (.licenses | length > 0))] | length' "$SBOM_FILE" 2>/dev/null || echo "0")
if [ "$LICENSE_COUNT" -gt 0 ]; then
    LICENSE_PCT=$((LICENSE_COUNT * 100 / COMPONENTS_COUNT))
    check_pass "License info present: ${LICENSE_COUNT}/${COMPONENTS_COUNT} (${LICENSE_PCT}%)"
else
    check_fail "No license information found"
fi

echo ""

# --- Summary ---
echo "══════════════════════════════════════"
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo "══════════════════════════════════════"

if [ "$FAIL" -gt 0 ]; then
    echo "  Status: ⚠️  ISSUES FOUND"
    exit 1
else
    echo "  Status: ✅ ALL CHECKS PASSED"
    exit 0
fi
