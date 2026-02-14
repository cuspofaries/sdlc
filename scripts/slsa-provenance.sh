#!/usr/bin/env bash
# =============================================================================
# Generate and attest SLSA provenance predicate
# =============================================================================
# Usage: slsa-provenance.sh <image> <cosign-key>
#
# Generates a SLSA v1.0 provenance predicate (in-toto format) and attests it
# to the image digest using cosign. Falls back to the same KMS > keyless >
# keypair priority as image-sign.sh.
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
  "buildDefinition": {
    "buildType": "https://slsa.dev/container-based-build/v0.1",
    "externalParameters": {
      "source": "${SOURCE_REPO:-unknown}",
      "revision": "${SOURCE_SHA:-unknown}"
    },
    "internalParameters": {
      "buildId": "${BUILD_ID:-local}",
      "buildUrl": "${BUILD_URL:-}"
    }
  },
  "runDetails": {
    "builder": {
      "id": "${BUILD_URL:-local-builder}"
    },
    "metadata": {
      "invocationId": "${BUILD_ID:-local}",
      "startedOn": "$TIMESTAMP"
    }
  }
}
PRED

echo "Provenance predicate:"
cat "$PROVENANCE_FILE"

# ── Attest ──────────────────────────────────────────────────────────────────
COSIGN_ARGS=(attest --yes --predicate "$PROVENANCE_FILE" --type slsaprovenance)

if [ -n "${COSIGN_KMS_KEY:-}" ]; then
  echo "Attesting with KMS key..."
  cosign "${COSIGN_ARGS[@]}" --key "azurekms://${COSIGN_KMS_KEY}" "$DIGEST"
elif cosign attest --yes --predicate "$PROVENANCE_FILE" --type slsaprovenance "$DIGEST" 2>/dev/null; then
  echo "Attested with keyless (OIDC)"
elif [ -f "$COSIGN_KEY" ]; then
  echo "Attesting with keypair..."
  cosign "${COSIGN_ARGS[@]}" --key "$COSIGN_KEY" "$DIGEST"
else
  echo "FATAL: No signing method available (no KMS, no OIDC, no keypair)" >&2
  rm -f "$PROVENANCE_FILE"
  exit 1
fi

rm -f "$PROVENANCE_FILE"
echo "SLSA provenance attested to $DIGEST"
