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
│  build → scan → policy → push → sign → attest    │
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

Ceci execute le pipeline normal (build → scan → policy → push → sign → attest → verify) et genere en plus :
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
| `manifest.json` | Metadonnees : digest attendu, SHA256 du SBOM, version cosign |

### Pipeline ADO complet (exemple)

```yaml
# azure-pipelines.yml — stage supplementaire pour air-gap
- stage: AirgapExport
  dependsOn: Publish
  condition: succeeded()
  jobs:
  - job: Export
    steps:
    - bash: |
        # Re-charger l'image depuis l'artifact du stage precedent
        docker load < output/image/image.tar
        # Generer le package air-gap
        AIRGAP_DIR=output/airgap task image:sign
        AIRGAP_DIR=output/airgap task sbom:attest
        AIRGAP_DIR=output/airgap task slsa:attest
        task airgap:export
      displayName: Create air-gap package
    - task: PublishPipelineArtifact@1
      inputs:
        targetPath: output/airgap/
        artifactName: airgap-package
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

Le script execute **5 verifications fail-closed** :

| # | Verification | Commande |
|---|-------------|----------|
| 1 | Integrite du digest image | `docker load` + comparaison avec `manifest.json` |
| 2 | Signature de l'image | `cosign verify --key cosign.pub --bundle sig.bundle --offline` |
| 3 | Attestation SBOM | `cosign verify-attestation --type cyclonedx --bundle --offline` |
| 4 | Provenance SLSA | `cosign verify-attestation --type slsaprovenance --bundle --offline` |
| 5 | Integrite du SBOM | Comparaison SHA256 avec la valeur dans `manifest.json` |

**Si l'une des 5 verifications echoue, le script s'arrete immediatement (fail-closed).**

### Verification manuelle (sans le script)

```bash
# Charger l'image
docker load < image.tar

# Pousser vers le registry local
docker tag <loaded-ref> localhost:5000/myapp:imported
docker push localhost:5000/myapp:imported

# Resoudre le digest
DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' localhost:5000/myapp:imported)

# Verifier la signature
COSIGN_ALLOW_INSECURE_REGISTRY=true cosign verify \
  --key cosign.pub \
  --bundle image-signature.bundle \
  --offline \
  "$DIGEST"

# Verifier l'attestation SBOM
COSIGN_ALLOW_INSECURE_REGISTRY=true cosign verify-attestation \
  --key cosign.pub \
  --type cyclonedx \
  --bundle sbom-attestation.bundle \
  --offline \
  "$DIGEST"

# Verifier la provenance SLSA
COSIGN_ALLOW_INSECURE_REGISTRY=true cosign verify-attestation \
  --key cosign.pub \
  --type slsaprovenance \
  --bundle slsa-attestation.bundle \
  --offline \
  "$DIGEST"
```

`COSIGN_ALLOW_INSECURE_REGISTRY=true` est necessaire pour un registry local sans TLS.

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

## Evidence — Comment verifier

| Question d'audit | Reponse |
|-----------------|---------|
| « L'image est-elle la meme que celle signee en CI ? » | Digest compare entre `manifest.json` et `docker inspect` apres load |
| « La signature est-elle valide sans internet ? » | `cosign verify --bundle --offline` utilise le bundle local |
| « Le SBOM correspond-il a l'image ? » | Attestation cosign lie cryptographiquement le SBOM au digest |
| « Qui a construit cette image ? » | Attestation SLSA provenance (builder, source, revision) |
| « Le SBOM a-t-il ete modifie pendant le transfert ? » | SHA256 compare avec la valeur enregistree dans `manifest.json` |
