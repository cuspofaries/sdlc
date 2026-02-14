#!/usr/bin/env bash
# =============================================================================
# trivy-exceptions.sh - Generate .trivyignore from security exceptions
# =============================================================================
# Usage: trivy-exceptions.sh <exceptions-yaml> <output-ignorefile>
#
# Reads security-exceptions.yaml and generates a .trivyignore file containing
# only non-expired CVE IDs. Expired exceptions are NOT included, so Trivy
# blocks them again automatically.
#
# All 5 fields are required per exception:
#   id, package, reason, approved_by, expires, ticket
#
# Requires: yq (https://github.com/mikefarah/yq)
# =============================================================================
set -euo pipefail

EXCEPTIONS_FILE="${1:?Usage: $0 <exceptions-yaml> <output-ignorefile>}"
OUTPUT_FILE="${2:?Usage: $0 <exceptions-yaml> <output-ignorefile>}"

if [ ! -f "$EXCEPTIONS_FILE" ]; then
    echo "No exceptions file found at ${EXCEPTIONS_FILE}, skipping"
    : > "$OUTPUT_FILE"
    exit 0
fi

if ! command -v yq &>/dev/null; then
    echo "FATAL: yq is not installed. Run: task install:yq" >&2
    exit 1
fi

TODAY=$(date -u +"%Y-%m-%d")
ACTIVE_COUNT=0
EXPIRED_COUNT=0
INVALID_COUNT=0

echo "📋 Processing security exceptions..."
echo "   File:  ${EXCEPTIONS_FILE}"
echo "   Date:  ${TODAY}"
echo ""

# Required fields
REQUIRED_FIELDS=("id" "package" "reason" "approved_by" "expires" "ticket")

# Start fresh
: > "$OUTPUT_FILE"

# Header in .trivyignore
{
    echo "# Auto-generated from ${EXCEPTIONS_FILE}"
    echo "# Generated: ${TODAY}"
    echo "# DO NOT EDIT — modify ${EXCEPTIONS_FILE} instead"
    echo ""
} >> "$OUTPUT_FILE"

# Count exceptions
TOTAL=$(yq '.exceptions | length' "$EXCEPTIONS_FILE" 2>/dev/null || echo "0")

if [ "$TOTAL" -eq 0 ]; then
    echo "   No exceptions defined"
    exit 0
fi

for i in $(seq 0 $((TOTAL - 1))); do
    CVE_ID=$(yq ".exceptions[$i].id // \"\"" "$EXCEPTIONS_FILE")
    PACKAGE=$(yq ".exceptions[$i].package // \"\"" "$EXCEPTIONS_FILE")
    REASON=$(yq ".exceptions[$i].reason // \"\"" "$EXCEPTIONS_FILE")
    APPROVED=$(yq ".exceptions[$i].approved_by // \"\"" "$EXCEPTIONS_FILE")
    EXPIRES=$(yq ".exceptions[$i].expires // \"\"" "$EXCEPTIONS_FILE")
    TICKET=$(yq ".exceptions[$i].ticket // \"\"" "$EXCEPTIONS_FILE")

    # Check required fields
    MISSING=""
    for field in "${REQUIRED_FIELDS[@]}"; do
        VALUE=$(yq ".exceptions[$i].$field // \"\"" "$EXCEPTIONS_FILE")
        if [ -z "$VALUE" ]; then
            MISSING="${MISSING} ${field}"
        fi
    done

    if [ -n "$MISSING" ]; then
        echo "   ❌ INVALID exception #$((i+1)): missing fields:${MISSING}"
        INVALID_COUNT=$((INVALID_COUNT + 1))
        continue
    fi

    # Check expiry
    if [[ "$EXPIRES" < "$TODAY" ]]; then
        echo "   ⏰ EXPIRED: ${CVE_ID} (${PACKAGE}) — expired ${EXPIRES}, approved by ${APPROVED}"
        EXPIRED_COUNT=$((EXPIRED_COUNT + 1))
        # NOT added to .trivyignore — Trivy will block it
    else
        echo "   ✅ ACTIVE:  ${CVE_ID} (${PACKAGE}) — expires ${EXPIRES}, approved by ${APPROVED}, ticket ${TICKET}"
        echo "${CVE_ID}" >> "$OUTPUT_FILE"
        ACTIVE_COUNT=$((ACTIVE_COUNT + 1))
    fi
done

echo ""
echo "── Summary ──"
echo "   Active:  ${ACTIVE_COUNT} (added to ${OUTPUT_FILE})"
echo "   Expired: ${EXPIRED_COUNT} (NOT in ignorefile — Trivy will block)"
echo "   Invalid: ${INVALID_COUNT}"
echo "   Total:   ${TOTAL}"

if [ "$INVALID_COUNT" -gt 0 ]; then
    echo ""
    echo "FATAL: ${INVALID_COUNT} invalid exception(s) found — fix ${EXCEPTIONS_FILE}" >&2
    exit 1
fi
