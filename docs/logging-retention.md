# Journalisation et retention

> Evenements journalises, stockage, durees de retention et procedures d'extraction pour audit et reponse a incident.

## Evenements journalises

Chaque run de pipeline produit les evenements suivants, tous lies au **digest immutable** (`image@sha256:...`) — jamais a un tag mutable.

| Evenement | Donnees enregistrees | Etape pipeline |
|-----------|---------------------|----------------|
| Build image | Build ID, image ID locale, contexte Docker | 1-3 |
| Generation SBOM | SHA256 du fichier SBOM, ImageID embarque, timestamp | 4 |
| Verification image-SBOM | ImageID de l'image vs ImageID dans le SBOM — match/mismatch | 5 |
| Scan vulnerabilites (image) | Resultats Trivy JSON, severites, exit code, exceptions appliquees | 6 |
| Scan vulnerabilites (SBOM) | Resultats Trivy JSON sur le SBOM (gouvernance) | 7 |
| Evaluation OPA | Decisions deny/warn, politiques baseline + custom, exceptions evaluees | 8 |
| Push image | Registry, tag, digest resolu (RepoDigest) | 10-11 |
| Verification integrite SBOM | SHA256 recalcule vs SHA256 enregistre a la generation | 12 |
| Signature (cosign sign) | Digest signe, methode (KMS/keyless/keypair), identite OIDC | 13 |
| Attestation SBOM (cosign attest) | Digest atteste, type `cyclonedx`, SHA256 du SBOM | 14 |
| Attestation SLSA (cosign attest) | Digest atteste, type `slsaprovenance`, builder, source, revision | 15 |
| Verification post-signature | Resultats `cosign verify` + `verify-attestation` x2, `cosign tree` | 16 |
| Upload DTrack | Hostname, project, SBOM version, digest lie | 17 |
| Rescan quotidien | SBOM extrait depuis attestation, resultats Trivy frais | DailyRescan |

**Invariant** : chaque operation cosign (`sign`, `attest`, `verify`) est precedee d'un `echo` explicite du digest cible dans les logs CI — piste d'audit non ambigue.

## Stockage

| Emplacement | Type de donnees | Controle d'acces |
|-------------|----------------|------------------|
| **CI artifacts** (`output/`) | Scans JSON, SBOM, logs de verification, politique OPA | Acces au pipeline run (GitHub Actions / ADO) |
| **Registry referrers** (cosign) | Signatures, attestations SBOM, attestations SLSA | ACR RBAC / GHCR permissions |
| **Dependency-Track** | SBOM indexes, vulnerabilites, historique de composants | API key scope `BOM_UPLOAD` + dashboard |
| **Rekor transparency log** | Entrees de signature publiques (append-only, immutable) | Public — verification independante par quiconque |
| **Azure Key Vault audit logs** | Operations de signature KMS (`sign`, `verify`, `get`) | Azure Monitor / Log Analytics |
| **Git history** | `security-exceptions.yaml` (ajouts, modifications, suppressions) | Acces au repo — chaque changement via PR |

## Table de retention

| Type d'artefact | Duree de retention | Justification |
|----------------|--------------------|---------------|
| CI artifacts (`output/`) — scans, SBOM, logs verify | `<RETENTION_DAYS>` (defaut : 30 jours) | Configurable via `retention-days` dans le workflow. Suffisant pour investigation post-incident |
| Registry attestations (cosign) — SBOM + SLSA | **Permanent** (tant que l'image existe) | Attachees au digest — preuve cryptographique de conformite |
| Registry signatures (cosign) | **Permanent** (tant que l'image existe) | Preuve d'authenticite de l'image |
| Rekor transparency log | **Permanent** (public, append-only) | Immutable par design — verification independante |
| Dependency-Track | **Permanent** | Historique de vulnerabilites et monitoring continu |
| Scan JSON (Trivy) | `<RETENTION_DAYS>` (defaut : 30 jours) | Archive comme CI artifact |
| Resultats OPA | `<RETENTION_DAYS>` (defaut : 30 jours) | Archive comme CI artifact |
| Key Vault audit logs | Selon politique Azure Monitor | Configurer la retention dans Diagnostic Settings |
| ACR access logs | Selon politique Azure Monitor | Configurer la retention dans Diagnostic Settings |

**Note** : Les CI artifacts utilisent `if: always()` / `condition: always()` pour etre preserves **meme si le pipeline echoue** — essentiel pour l'analyse post-incident.

## Integrite des logs

| Mecanisme | Garantie |
|-----------|----------|
| **Rekor append-only** | Les entrees ne peuvent pas etre supprimees ni modifiees. Verification independante par quiconque via `rekor-cli` |
| **Cosign attestations immutables** | Attachees au digest de l'image dans le registry. Toute modification est detectable via `cosign verify-attestation` |
| **CI artifacts read-only** | Les artifacts uploades ne sont pas modifiables apres upload |
| **Git history pour les exceptions** | Chaque modification de `security-exceptions.yaml` est tracee dans l'historique git (PR, auteur, date) |
| **SBOM integrity invariant** | SHA256 + ImageID verifies entre generation et attestation — toute modification arrete le pipeline |

## Procedure d'extraction pour audit / incident

### 1. Identifier le digest concerne

```bash
# Depuis le registry
cosign tree <REGISTRY>/<IMAGE>@sha256:<DIGEST>
```

### 2. Extraire les attestations

```bash
# Verification de la signature
cosign verify <IMAGE>@sha256:<DIGEST> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "github.com/<ORG>/"

# Extraire l'attestation SBOM
cosign verify-attestation --type cyclonedx <IMAGE>@sha256:<DIGEST> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "github.com/<ORG>/" | jq -r '.payload' | base64 -d

# Extraire l'attestation SLSA
cosign verify-attestation --type slsaprovenance <IMAGE>@sha256:<DIGEST> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "github.com/<ORG>/" | jq -r '.payload' | base64 -d
```

### 3. Consulter les logs CI

- **GitHub Actions** : onglet Actions → run correspondant → artifacts `output/verify/`
- **Azure DevOps** : pipeline run → artifacts → `output/`

### 4. Consulter Rekor

```bash
# Rechercher les entrees pour un digest
rekor-cli search --sha sha256:<DIGEST>
```

### 5. Consulter Dependency-Track

- Dashboard → projet → version liee au digest → onglet vulnerabilites
- API : `GET /api/v1/bom?project=<UUID>`

## Evidence — Comment verifier

| Question d'audit | Reponse | Preuve |
|-----------------|---------|--------|
| « Quels artefacts sont journalises ? » | Tout : build, scan, politique, signature, attestation, verification | Ce document + logs CI |
| « Quelle est la retention ? » | 30j CI artifacts, permanent pour registry/Rekor/DTrack | Table ci-dessus + configuration workflow |
| « Les logs sont-ils immutables ? » | Oui : Rekor append-only, attestations cosign, CI artifacts read-only | `rekor-cli verify`, `cosign verify-attestation` |
| « Comment extraire les preuves ? » | Procedure documentee ci-dessus | Commandes reproductibles |
| « Les logs sont-ils preserves en cas d'echec ? » | Oui : `if: always()` sur les uploads d'artifacts | Configuration workflow (step 16) |
