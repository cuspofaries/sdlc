# Deploiement air-gap — Verification offline des signatures et attestations

> Guide pour exporter des images signees depuis un environnement connecte (Azure DevOps)
> et verifier les signatures, attestations SBOM et provenance SLSA sur des machines isolees sans internet.

---

## Le probleme

`docker save` exporte les layers et le manifest de l'image, mais **pas les signatures ni les attestations cosign**. Ces artefacts sont des referrers OCI stockes dans le registry, pas des layers Docker.

```
docker save myapp@sha256:abc123 > image.tar

Ce qui est exporte :
  ✅ Layers de l'image
  ✅ Manifest de l'image
  ✅ Config de l'image
  ❌ PAS la signature cosign
  ❌ PAS l'attestation SBOM
  ❌ PAS l'attestation SLSA provenance
```

Sur l'environnement isole, `cosign verify` echoue : `no signatures found`.

## La solution : cosign bundles

Les bundles cosign sont des fichiers JSON autonomes contenant la signature (ou attestation) + l'entree du log de transparence Rekor. Ils voyagent avec l'image via le meme media physique (USB, transfert reseau securise).

Le pipeline genere ces bundles automatiquement quand `AIRGAP_DIR` est configure. Sur la machine isolee, `cosign verify --bundle --offline` verifie tout sans internet.

---

## Architecture du flux

```
┌──────────────────────────────────────────────────┐
│  AZURE DEVOPS (internet)                         │
│                                                  │
│  SAST → build → scan → policy → push → sign → attest │
│                           │       │       │      │
│                           │     bundle  bundle   │
│                           │       │       │      │
│                           v       v       v      │
│  docker save ──> image.tar  sig.bundle  att.bundle│
│  public key ──> cosign.pub                       │
│  SBOM ────────> sbom.json                        │
│  metadata ───-> manifest.json                    │
│                           │                      │
│                    tar -czf package.tar.gz        │
└──────────────────┬───────────────────────────────┘
                   │
          transfert physique
          (USB, sneakernet)
                   │
┌──────────────────v───────────────────────────────┐
│  ENVIRONNEMENT ISOLE (pas d'internet)            │
│                                                  │
│  tar -xzf package.tar.gz                         │
│  docker load < image.tar                         │
│  docker push → registry local (localhost:5000)   │
│                                                  │
│  cosign verify --bundle --offline --key cosign.pub│
│  cosign verify-attestation --bundle --offline     │
│                                                  │
│  ✅ Signature verifiee                           │
│  ✅ SBOM attestation verifiee                    │
│  ✅ SLSA provenance verifiee                     │
│  ✅ Integrite SBOM verifiee (SHA256)             │
└──────────────────────────────────────────────────┘
```

---

## Cote pipeline (Azure DevOps / GitHub Actions / local)

### Etape 1 : Executer le pipeline avec generation de bundles

```bash
# Le flag AIRGAP_DIR active la generation de bundles cosign
# pendant les etapes sign/attest du pipeline standard
task pipeline AIRGAP_DIR=output/airgap
```

Ceci execute le pipeline normal (SAST + build → scan → policy → push → sign → attest → verify) et genere en plus :
- `output/airgap/image-signature.bundle`
- `output/airgap/sbom-attestation.bundle`
- `output/airgap/slsa-attestation.bundle`

### Etape 2 : Creer le package d'export

```bash
task airgap:export
```

Ceci cree une archive `output/airgap/airgap-<name>-<digest>.tar.gz` contenant :

| Fichier | Contenu |
|---------|---------|
| `image.tar` | Image Docker (`docker save`) |
| `cosign.pub` | Cle publique pour verification (exportee depuis KMS ou copiee) |
| `sbom.json` | SBOM CycloneDX |
| `image-signature.bundle` | Bundle de signature cosign |
| `sbom-attestation.bundle` | Bundle d'attestation SBOM |
| `slsa-attestation.bundle` | Bundle d'attestation SLSA provenance |
| `manifest.json` | Metadonnees : digest, SHA256 SBOM, mode de verification (keyless/kms/keypair), version cosign |

### Pipeline ADO (`azure-pipelines/pipeline.yml`)

Le pipeline Azure DevOps expose un parametre `airgap` :

```yaml
# Lancer le pipeline avec le parametre air-gap active
# (via l'UI "Run pipeline" ou via az pipelines run --parameters airgap=true)
```

Quand `airgap: true` :
- Les etapes sign/attest ajoutent `--bundle` pour generer les bundles cosign dans `output/airgap/`
- `airgap-export.sh` cree l'archive (avec export automatique de `cosign.pub` depuis Key Vault si `COSIGN_KV_KEY` est defini)
- L'archive est publiee comme artifact `airgap-package`

Le mode de verification dans le package depend de la configuration du pipeline :
- Si `COSIGN_KV_KEY` est dans le variable group → mode **kms** (recommande), `cosign.pub` exportee automatiquement
- Sinon → mode **keyless** (OIDC via Azure AD Workload Identity), certificat dans les bundles

### GitHub Actions (workflow reusable)

Le workflow reusable expose un input `airgap` :

```yaml
# .github/workflows/build.yml (caller)
jobs:
  supply-chain:
    uses: cuspofaries/sdlc/.github/workflows/supply-chain-reusable.yml@v1
    with:
      context: ./app
      image-name: my-app
      airgap: true          # ← active la generation du package air-gap
    secrets:
      REGISTRY_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

Quand `airgap: true` :
- Les etapes sign/attest ajoutent `--bundle` pour generer les bundles cosign dans `output/airgap/`
- `airgap-export.sh` cree l'archive `airgap-*.tar.gz`
- L'archive est uploadee comme artifact `airgap-package` (retention 30 jours)

L'output `airgap-artifact` permet a un job en aval de telecharger l'artifact :

```yaml
  deploy:
    needs: supply-chain
    if: ${{ needs.supply-chain.outputs.airgap-artifact != '' }}
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: ${{ needs.supply-chain.outputs.airgap-artifact }}
```

---

## Cote environnement isole (machine Linux)

### Prerequis

| Outil | Version | Installation |
|-------|---------|-------------|
| Docker | 20.10+ | Pre-installe sur la machine |
| Cosign | Meme version majeure que le pipeline (v3.x) | Transferer le binaire via le meme media |
| Registry local | `registry:2` | `docker run -d -p 5000:5000 --name registry registry:2` |

**Pourquoi un registry local ?** `cosign verify` resout le manifest de l'image depuis un registry pour comparer les digests. `docker load` seul ne suffit pas — l'image doit etre dans un registry accessible.

### Etape 1 : Transferer et extraire

```bash
# Transferer l'archive (USB, partage reseau securise, etc.)
tar -xzf airgap-myapp-sha256-abc123.tar.gz -C /opt/airgap-import/
```

### Etape 2 : Demarrer le registry local (si pas deja en place)

```bash
# Verifier si un registry local tourne
curl -s http://localhost:5000/v2/ && echo "Registry OK" || \
  docker run -d -p 5000:5000 --restart always --name registry registry:2
```

### Etape 3 : Verifier

```bash
./scripts/airgap-verify.sh /opt/airgap-import/ localhost:5000
```

Le script **auto-detecte le mode de verification** depuis `manifest.json` (champ `verification.mode`) et utilise les bons arguments cosign :

- **kms / keypair** : `--key cosign.pub`
- **keyless** : `--certificate-oidc-issuer <issuer> --certificate-identity-regexp <regexp>`

Il execute **5 verifications fail-closed** :

| # | Verification | Commande |
|---|-------------|----------|
| 1 | Integrite du digest image | `docker load` + comparaison avec `manifest.json` |
| 2 | Signature de l'image | `cosign verify --bundle --offline` + args selon le mode |
| 3 | Attestation SBOM | `cosign verify-attestation --type cyclonedx --bundle --offline` |
| 4 | Provenance SLSA | `cosign verify-attestation --type slsaprovenance --bundle --offline` |
| 5 | Integrite du SBOM | Comparaison SHA256 avec la valeur dans `manifest.json` |

**Si l'une des 5 verifications echoue, le script s'arrete immediatement (fail-closed).**

### Verification manuelle (sans le script)

Les etapes communes (charger, pousser, resoudre le digest) sont identiques quel que soit le mode. Seuls les arguments de verification changent.

```bash
# Charger l'image
docker load < image.tar

# Pousser vers le registry local
docker tag <loaded-ref> localhost:5000/myapp:imported
docker push localhost:5000/myapp:imported

# Resoudre le digest
DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' localhost:5000/myapp:imported)

export COSIGN_ALLOW_INSECURE_REGISTRY=true  # necessaire pour registry local sans TLS
```

#### Mode KMS / Keypair (`cosign.pub` dans le package)

```bash
cosign verify \
  --key cosign.pub \
  --bundle image-signature.bundle \
  --offline \
  "$DIGEST"

cosign verify-attestation \
  --key cosign.pub \
  --type cyclonedx \
  --bundle sbom-attestation.bundle \
  --offline \
  "$DIGEST"

cosign verify-attestation \
  --key cosign.pub \
  --type slsaprovenance \
  --bundle slsa-attestation.bundle \
  --offline \
  "$DIGEST"
```

#### Mode Keyless (OIDC — certificat dans les bundles)

```bash
# Les valeurs oidc_issuer et identity_regexp sont dans manifest.json
cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "github.com/cuspofaries/" \
  --bundle image-signature.bundle \
  --offline \
  "$DIGEST"

cosign verify-attestation \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "github.com/cuspofaries/" \
  --type cyclonedx \
  --bundle sbom-attestation.bundle \
  --offline \
  "$DIGEST"

cosign verify-attestation \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "github.com/cuspofaries/" \
  --type slsaprovenance \
  --bundle slsa-attestation.bundle \
  --offline \
  "$DIGEST"
```

> **Note :** En mode keyless, `cosign.pub` n'est pas present dans le package. Le certificat Fulcio est embarque dans chaque bundle.

---

## Contenu de manifest.json

Le fichier `manifest.json` (genere par `airgap-export.sh`) contient les metadonnees necessaires a la verification. Depuis la version 1.1, il inclut le mode de signature pour auto-detection :

```json
{
  "version": "1.1",
  "created": "2025-02-15T14:30:00Z",
  "image": {
    "reference": "myregistry.azurecr.io/myapp",
    "digest": "sha256:abc123def456...",
    "tar_sha256": "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677..."
  },
  "sbom": {
    "file": "sbom.json",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "format": "cyclonedx"
  },
  "bundles": {
    "signature": "image-signature.bundle",
    "sbom_attestation": "sbom-attestation.bundle",
    "slsa_attestation": "slsa-attestation.bundle"
  },
  "verification": {
    "mode": "keyless",
    "public_key": null,
    "oidc_issuer": "https://token.actions.githubusercontent.com",
    "identity_regexp": "github.com/cuspofaries/"
  },
  "tools": {
    "cosign_version": "cosign v3.0.0"
  }
}
```

| Champ | Role |
|-------|------|
| `verification.mode` | `kms`, `keypair` ou `keyless` — determine les arguments cosign a utiliser |
| `verification.public_key` | `"cosign.pub"` (kms/keypair) ou `null` (keyless) |
| `verification.oidc_issuer` | URL de l'emetteur OIDC (keyless uniquement) |
| `verification.identity_regexp` | Regexp pour valider l'identite du signataire (keyless uniquement) |

`airgap-verify.sh` lit automatiquement ces champs pour choisir les bons arguments de verification.

---

## Contenu du bundle cosign

Chaque fichier `.bundle` est un JSON autonome :

```json
{
  "base64Signature": "MEUCIQD...",
  "cert": "-----BEGIN CERTIFICATE-----\n...",
  "rekorBundle": {
    "SignedEntryTimestamp": "MEQCI...",
    "Payload": {
      "body": "eyJ...",
      "integratedTime": 1708000000,
      "logIndex": 12345678,
      "logID": "c0d23..."
    }
  }
}
```

| Champ | Role |
|-------|------|
| `base64Signature` | La signature cryptographique (sur le digest pour sign, sur l'enveloppe DSSE pour attest) |
| `cert` | Le certificat (mode keyless) ou absent (mode KMS/keypair) |
| `rekorBundle` | L'entree Rekor — preuve immutable que la signature a ete enregistree a un moment donne |

Avec `--offline`, cosign verifie le `rekorBundle` localement au lieu de contacter Rekor en ligne. La preuve cryptographique est identique.

---

## Modes de signature supportes

| Mode | Cle pour verification | Remarque air-gap |
|------|----------------------|-----------------|
| **KMS** (Azure Key Vault) | `cosign.pub` (exportee automatiquement par `airgap-export.sh`) | Recommande. La cle publique est exportee via `cosign public-key --key azurekms://...` |
| **Keypair** | `cosign.pub` (copiee depuis le repo) | Simple. Utilise pour dev/e2e/air-gap natif |
| **Keyless** (OIDC) | Certificat embarque dans le bundle | Le bundle contient le certificat Fulcio. Verification avec `--certificate-oidc-issuer` et `--certificate-identity-regexp` au lieu de `--key` |

---

## Troubleshooting

| Probleme | Cause | Solution |
|----------|-------|---------|
| `no signatures found` | `docker save` n'exporte pas les referrers | Utiliser les bundles cosign (ce guide) |
| `FATAL: Cannot resolve digest` | Pas de registry local | `docker run -d -p 5000:5000 registry:2` |
| `FATAL: Digest mismatch` | Image corrompue pendant le transfert | Re-transferer l'archive, verifier le SHA256 de l'archive |
| `error verifying bundle` | Version cosign incompatible | Utiliser la meme version majeure (v3.x) cote pipeline et cote air-gap |
| `TLS handshake error` | Registry local sans TLS | `export COSIGN_ALLOW_INSECURE_REGISTRY=true` |
| `FATAL: bundle missing` | Pipeline execute sans `AIRGAP_DIR` | Re-executer avec `task pipeline AIRGAP_DIR=output/airgap` |
| `invalid signature when validating ASN.1` | Mode de verification different du mode de signature | Verifier `verification.mode` dans `manifest.json` et utiliser les bons flags (`--key` vs `--certificate-*`) |

## Evidence — Comment verifier

| Question d'audit | Reponse |
|-----------------|---------|
| « L'image est-elle la meme que celle signee en CI ? » | Digest compare entre `manifest.json` et `docker inspect` apres load |
| « La signature est-elle valide sans internet ? » | `cosign verify --bundle --offline` utilise le bundle local |
| « Le SBOM correspond-il a l'image ? » | Attestation cosign lie cryptographiquement le SBOM au digest |
| « Qui a construit cette image ? » | Attestation SLSA provenance (builder, source, revision) |
| « Le SBOM a-t-il ete modifie pendant le transfert ? » | SHA256 compare avec la valeur enregistree dans `manifest.json` |
