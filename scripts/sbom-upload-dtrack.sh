#!/usr/bin/env bash
# =============================================================================
# sbom-upload-dtrack.sh - Upload SBOM to Dependency-Track for continuous monitoring
#
# Usage: ./scripts/sbom-upload-dtrack.sh <sbom-file> <dtrack-url> <api-key> <project-name>
# =============================================================================
set -euo pipefail

SBOM_FILE="${1:?Usage: $0 <sbom-file> <dtrack-url> <api-key> <project-name>}"
DTRACK_URL="${2:?Missing Dependency-Track URL}"
DTRACK_API_KEY="${3:?Missing API key}"
PROJECT_NAME="${4:-supply-chain-poc}"
PROJECT_VERSION="${5:-latest}"

echo "📤 Uploading SBOM to Dependency-Track..."
echo "   Server:  ${DTRACK_URL}"
echo "   Project: ${PROJECT_NAME}:${PROJECT_VERSION}"

# Check DTrack is reachable
if ! curl -sf "${DTRACK_URL}/api/version" > /dev/null 2>&1; then
    echo "❌ Dependency-Track unreachable at ${DTRACK_URL}"
    echo "   Run: task dtrack:up"
    exit 1
fi

# Base64 encode SBOM
SBOM_B64=$(base64 -w0 "$SBOM_FILE")

# Upload via API
RESPONSE=$(curl -s -w "\n%{http_code}" -X PUT \
    "${DTRACK_URL}/api/v1/bom" \
    -H "X-Api-Key: ${DTRACK_API_KEY}" \
    -H "Content-Type: application/json" \
    -d "{
        \"projectName\": \"${PROJECT_NAME}\",
        \"projectVersion\": \"${PROJECT_VERSION}\",
        \"autoCreate\": true,
        \"bom\": \"${SBOM_B64}\"
    }")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -1)

if [ "$HTTP_CODE" = "200" ]; then
    TOKEN=$(echo "$BODY" | jq -r '.token // empty')
    echo "✅ SBOM uploaded successfully"
    if [ -n "$TOKEN" ]; then
        echo "   Processing token: ${TOKEN}"
        echo "   Dashboard: ${DTRACK_URL}/projects"
    fi
else
    echo "❌ Upload failed (HTTP ${HTTP_CODE})"
    echo "   Response: ${BODY}"
    exit 1
fi
