# SDLC — Toolchain Unifié de Sécurité Supply Chain

> **Plateforme réutilisable** pour le build d'images conteneur, la génération SBOM, le scan de vulnérabilités, l'application de politiques, la signature et le monitoring.
> Un seul workflow remplace `poc-build-sign` + `poc-sbom` avec une approche **shift-left** : scanner **avant** de publier.

[![Validate Toolchain](https://github.com/cuspofaries/sdlc/actions/workflows/validate-toolchain.yml/badge.svg)](https://github.com/cuspofaries/sdlc/actions/workflows/validate-toolchain.yml)

---

## Pourquoi ce repo existe

Trois repos distincts (`poc-build-sign`, `poc-sbom`, `poc-sbom-build`) formaient un pipeline supply chain mais souffraient de :

| Problème | Impact |
|----------|--------|
| **Décalage SBOM/digest** | Le SBOM généré *après* le push pouvait décrire une image différente |
| **Dérive des versions d'outils** | Trivy, Cosign, OPA se désynchronisaient entre les repos |
| **Maintenance dispersée** | Les corrections nécessitaient des PRs dans plusieurs repos |
| **Surcharge à deux jobs** | Les repos consommateurs devaient chaîner deux `workflow_call` |

**SDLC** fusionne tout dans un seul workflow réutilisable avec un ordre strict : **build → analyse → GATE → publication**.

---

## Flux du pipeline

```
PHASE 1 — BUILD (rien ne sort du runner)
  1. Checkout
  2. Build image (--load, pas de push)

PHASE 2 — ANALYZE (sur l'image locale)
  3. Génération SBOM (trivy image --format cyclonedx)
  4. Scan vulnérabilités (trivy image direct)
  5. Évaluation politiques OPA (baseline + custom)
  ══ GATE : si 4 ou 5 échoue → STOP ══

PHASE 3 — PUBLISH (seulement si la gate passe)
  6. Push de l'image vers le registry
  7. Signature du digest (Cosign keyless)
  8. Attestation du SBOM au digest (Cosign attest)
  9. Upload du SBOM vers Dependency-Track
```

---

## Démarrage rapide — repo consommateur

Tout repo avec un Dockerfile peut consommer ce pipeline avec un seul fichier workflow :

```yaml
# .github/workflows/build.yml
name: Supply Chain Pipeline

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read
  packages: write
  id-token: write

jobs:
  supply-chain:
    uses: cuspofaries/sdlc/.github/workflows/supply-chain-reusable.yml@main
    with:
      context: ./app
      image-name: my-app
      dtrack-hostname: dep-api.example.com  # optionnel
    secrets:
      REGISTRY_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      DTRACK_API_KEY: ${{ secrets.DTRACK_API_KEY }}  # optionnel
```

### Inputs

| Input | Requis | Défaut | Description |
|-------|--------|--------|-------------|
| `context` | Oui | — | Chemin vers le contexte Docker |
| `image-name` | Oui | — | Nom de l'image (sans préfixe registry) |
| `dockerfile` | Non | `Dockerfile` | Chemin du Dockerfile relatif au contexte |
| `registry` | Non | `ghcr.io` | Registry conteneur |
| `dtrack-hostname` | Non | `""` | Hostname Dependency-Track (ignoré si vide) |
| `trivy-severity` | Non | `HIGH,CRITICAL` | Filtre de sévérité pour le scan |
| `trivy-exit-code` | Non | `"1"` | Code de sortie sur findings (`1` = échec, `0` = avertissement) |

### Politiques custom

Placez un répertoire `policies/` dans votre repo avec des fichiers `.rego` utilisant `package sbom`. Ils sont automatiquement fusionnés avec les politiques baseline via OPA :

```rego
# policies/project-policies.rego
package sbom
import rego.v1

project_blocked_packages := {"moment", "request"}

deny contains msg if {
    some component in input.components
    component.name in project_blocked_packages
    msg := sprintf("[project] Package '%s' n'est pas autorisé", [component.name])
}
```

---

## Développement local

### Prérequis

- Docker
- [Task](https://taskfile.dev/) (go-task)

### Installer le toolchain

```bash
sudo task install
task install:verify
```

### Pipeline local

```bash
task pipeline:local \
  IMAGE_NAME=my-app \
  CONTEXT=../my-app-repo/app
```

Exécute **build → generate → scan → policy** sans push ni signature.

### Pipeline complet (avec publication)

```bash
task pipeline \
  REGISTRY=ghcr.io/myorg \
  IMAGE_NAME=my-app \
  CONTEXT=../my-app-repo/app \
  DTRACK_URL=http://localhost:8081 \
  DTRACK_API_KEY=odt_xxx
```

### Référence des tasks

| Task | Description |
|------|-------------|
| `install` | Installer tous les outils (trivy, cosign, cdxgen, opa, oras) |
| `install:verify` | Afficher les versions installées |
| `build` | Build image locale (pas de push) |
| `sbom:generate` | Générer le SBOM image (CycloneDX) |
| `sbom:generate:source` | Générer le SBOM source (dépendances déclarées) |
| `sbom:scan` | Scanner l'image pour les vulnérabilités (trivy image) |
| `sbom:policy` | Évaluer le SBOM contre les politiques OPA |
| `push` | Push de l'image vers le registry |
| `image:sign` | Signer le digest de l'image (cosign) |
| `image:verify` | Vérifier la signature de l'image |
| `sbom:attest` | Attester le SBOM au digest de l'image |
| `sbom:sign:blob` | Signer le SBOM comme fichier standalone |
| `sbom:verify` | Vérifier la signature et l'intégrité du SBOM |
| `sbom:upload` | Uploader le SBOM vers Dependency-Track |
| `sbom:tamper:test` | Démo de détection de falsification SBOM |
| `pipeline` | Pipeline complet (build → analyse → publication) |
| `pipeline:local` | Pipeline local (build → analyse uniquement) |
| `dtrack:up` | Démarrer Dependency-Track local |
| `dtrack:down` | Arrêter Dependency-Track local |
| `clean` | Supprimer les fichiers générés |

---

## Dependency-Track

Voir [docs/dependency-track.fr.md](docs/dependency-track.fr.md) pour la configuration et l'intégration.

```bash
task dtrack:up        # Démarrer l'instance locale
task sbom:upload      # Uploader le SBOM
```

---

## Azure DevOps

Un template Azure Pipelines est disponible dans `azure-pipelines/pipeline.yml` avec :

- Stage **BuildAndAnalyze** : build + SBOM + scan + policy (rien n'est publié)
- Stage **Publish** : push + sign + attest (uniquement si BuildAndAnalyze réussit)
- Stage **DailyRescan** : rescan planifié avec les dernières données CVE

---

## Structure du repo

```
sdlc/
├── .github/workflows/
│   ├── supply-chain-reusable.yml     ← Workflow unifié (consommé par les repos app)
│   └── validate-toolchain.yml        ← CI du toolchain lui-même
├── azure-pipelines/
│   └── pipeline.yml                  ← Template Azure DevOps
├── scripts/                          ← Scripts shell pour chaque étape du pipeline
│   ├── sbom-attest.sh
│   ├── sbom-generate-source.sh
│   ├── sbom-policy.sh
│   ├── sbom-sign.sh
│   ├── sbom-tamper-test.sh
│   ├── sbom-upload-dtrack.sh
│   └── sbom-verify.sh
├── policies/
│   └── sbom-compliance.rego          ← Politiques OPA baseline
├── docs/
│   ├── dependency-track.md
│   └── dependency-track.fr.md
├── docker-compose.dtrack.yml
├── Taskfile.yml
├── renovate.json
├── POSTMORTEM.md
└── README.md
```

---

## Migration depuis poc-build-sign + poc-sbom

**Avant** (le consommateur avait besoin de 2 jobs) :
```yaml
jobs:
  build:
    uses: cuspofaries/poc-build-sign/.github/workflows/build-sign-reusable.yml@main
    # ...
  sbom:
    needs: build
    uses: cuspofaries/poc-sbom/.github/workflows/sbom-reusable.yml@main
    # ...
```

**Après** (un seul job) :
```yaml
jobs:
  supply-chain:
    uses: cuspofaries/sdlc/.github/workflows/supply-chain-reusable.yml@main
    with:
      context: ./app
      image-name: my-app
    secrets:
      REGISTRY_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

Changements clés :
- L'image est scannée **avant** le push (shift-left)
- Le SBOM correspond forcément au digest publié
- Workflow atomique unique — pas de race conditions entre jobs
- Les versions d'outils sont gérées en un seul endroit

---

## Références

- [Spécification CycloneDX](https://cyclonedx.org/specification/overview/)
- [Sigstore / Cosign](https://docs.sigstore.dev/)
- [Open Policy Agent](https://www.openpolicyagent.org/)
- [Dependency-Track](https://dependencytrack.org/)
- [Framework SLSA](https://slsa.dev/)
- [NIST SSDF](https://csrc.nist.gov/Projects/ssdf)
