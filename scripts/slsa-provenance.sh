#!/usr/bin/env bash
# =============================================================================
# Generate and attest SLSA provenance predicate
# =============================================================================
# Usage: slsa-provenance.sh <image> <cosign-key>
#
# Generates a SLSA v0.2 provenance predicate (in-toto format) and attests it
# to the image digest using cosign.
#
# Signing priority (same as image-sign.sh):
#   1. Azure Key Vault KMS    (COSIGN_KMS_KEY set)
#   2. GitHub Actions keyless  (ACTIONS_ID_TOKEN_REQUEST_URL detected)
#   3. Azure DevOps keyless    (SYSTEM_OIDCREQUESTURI detected)
#   4. Keypair                 (cosign.key file exists)
#
# Keyless is ONLY attempted when a CI OIDC provider is detected, so it
# never triggers an interactive browser login in local or e2e contexts.
#
# Env: COSIGN_KMS_KEY (optional), BUILD_ID, BUILD_URL, SOURCE_REPO, SOURCE_SHA
# =============================================================================
set -euo pipefail

IMAGE="${1:?Usage: $0 <image> <cosign-key>}"
COSIGN_KEY="${2:-cosign.key}"

# ── Resolve digest ──────────────────────────────────────────────────────────
DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "$IMAGE" 2>/dev/null || true)
if [ -z "$DIGEST" ]; then
  echo "FATAL: Cannot resolve digest for $IMAGE — was it pushed?" >&2
  exit 1
fi
echo "Attesting SLSA provenance to: $DIGEST"

# ── Build provenance predicate ──────────────────────────────────────────────
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
PROVENANCE_FILE=$(mktemp /tmp/slsa-provenance.XXXXXX.json)

cat > "$PROVENANCE_FILE" <<PRED
{
  "builder": {
    "id": "${BUILD_URL:-local-builder}"
  },
  "buildType": "https://slsa.dev/container-based-build/v0.1",
  "invocation": {
    "configSource": {
      "uri": "${SOURCE_REPO:-unknown}",
      "digest": {
        "sha1": "${SOURCE_SHA:-unknown}"
      }
    },
    "parameters": {
      "buildId": "${BUILD_ID:-local}"
    }
  },
  "metadata": {
    "buildInvocationId": "${BUILD_ID:-local}",
    "buildStartedOn": "$TIMESTAMP",
    "completeness": {
      "parameters": true,
      "environment": false,
      "materials": false
    }
  },
  "materials": [
    {
      "uri": "${SOURCE_REPO:-unknown}",
      "digest": {
        "sha1": "${SOURCE_SHA:-unknown}"
      }
    }
  ]
}
PRED

echo "Provenance predicate:"
cat "$PROVENANCE_FILE"

# ── Attest ──────────────────────────────────────────────────────────────────
COSIGN_ARGS=(attest --yes --predicate "$PROVENANCE_FILE" --type slsaprovenance)

if [ -n "${COSIGN_KMS_KEY:-}" ]; then
  echo "── Mode: Azure Key Vault KMS ──"
  cosign "${COSIGN_ARGS[@]}" --key "azurekms://${COSIGN_KMS_KEY}" "$DIGEST"

elif [ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ]; then
  echo "── Mode: GitHub Actions keyless (OIDC) ──"
  cosign "${COSIGN_ARGS[@]}" "$DIGEST"

elif [ -n "${SYSTEM_OIDCREQUESTURI:-}" ]; then
  echo "── Mode: Azure DevOps keyless (Workload Identity) ──"
  cosign "${COSIGN_ARGS[@]}" "$DIGEST"

elif [ -f "$COSIGN_KEY" ]; then
  echo "── Mode: Keypair (${COSIGN_KEY}) ──"
  cosign "${COSIGN_ARGS[@]}" --key "$COSIGN_KEY" "$DIGEST"

else
  echo "FATAL: No signing method available." >&2
  echo "   Options:" >&2
  echo "   - Set COSIGN_KMS_KEY for Azure Key Vault KMS" >&2
  echo "   - Run in GitHub Actions or Azure DevOps (keyless)" >&2
  echo "   - Generate a keypair: task signing:init" >&2
  rm -f "$PROVENANCE_FILE"
  exit 1
fi

rm -f "$PROVENANCE_FILE"
echo "SLSA provenance attested to $DIGEST"
