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

## Pipeline — Checklist des etapes

### PHASE 1 — BUILD (rien ne sort du runner)

| # | Etape | Outil | Explication |
|---|-------|-------|-------------|
| 1 | **Checkout code** | `actions/checkout` | Clone le repo applicatif (Dockerfile, code source, policies custom). |
| 2 | **Checkout toolchain** | `actions/checkout` | Clone le repo `sdlc` dans `.sdlc/` pour acceder aux policies baseline et aux scripts. |
| 3 | **Build image** | `docker/build-push-action` | Construit l'image conteneur **localement** (`load: true`, `push: false`). Rien ne quitte le runner a ce stade. |

### PHASE 2 — ANALYZE (sur l'image locale, avant toute publication)

| # | Etape | Outil | Explication |
|---|-------|-------|-------------|
| 4 | **Generer le SBOM** | `trivy image --format cyclonedx` | Scanne l'image locale et produit un inventaire complet (OS packages, librairies, versions, licences) au format CycloneDX JSON. Le hash SHA256 du fichier SBOM et l'identifiant de l'image (`aquasecurity:trivy:ImageID`) sont enregistres a ce stade pour verification d'integrite avant attestation. |
| 5 | **Verifier alignement image-SBOM** | `docker inspect` + `jq` | Compare l'identifiant reel de l'image Docker avec celui embarque dans le SBOM. S'ils different, le pipeline s'arrete immediatement — le SBOM doit decrire exactement l'image construite. |
| 6 | **Scanner les vulnerabilites** | `trivy image --exit-code` | Scanne l'image **directement** (pas le SBOM) pour les CVE de severite HIGH et CRITICAL. Utilise `--exit-code 1` pour bloquer ou `0` pour avertir sans bloquer. C'est le **gate de securite** : plus fiable que scanner le SBOM car Trivy accede aux metadonnees du systeme de fichiers. |
| 7 | **Scanner le SBOM** | `trivy sbom --exit-code 0` | Scanne le SBOM lui-meme pour les vulnerabilites (consultatif, **non bloquant**). Garantit que le SBOM atteste a ete verifie : ce qu'on signe = ce qu'on a scanne. Tout delta avec l'etape 6 revele des lacunes dans l'inventaire du SBOM. Les resultats sont archives quel que soit le code de sortie. |
| 8 | **Evaluer les politiques OPA** | `opa eval` | Evalue le SBOM contre des regles Rego en deux niveaux : **deny** (bloquant — fait echouer le pipeline) et **warn** (consultatif — affiche un avertissement). Les politiques baseline (`sdlc/policies/`) sont automatiquement fusionnees avec les politiques custom du repo applicatif (`policies/`) si elles existent. Exemples de regles : packages bloques (supply chain attacks connus), composants sans version, licences non approuvees. |

```
══════════════════════════════════════════════════════
  GATE : si l'etape 5, 6 ou 8 echoue → PIPELINE STOP
  Rien n'est publie. L'image reste locale.
══════════════════════════════════════════════════════
```

### PHASE 3 — PUBLISH (seulement si la gate passe)

| # | Etape | Outil | Explication |
|---|-------|-------|-------------|
| 9 | **Login au registry** | `docker/login-action` | S'authentifie au registry conteneur (GHCR, ACR, etc.) avec le token fourni. |
| 10 | **Push de l'image** | `docker push` | Pousse l'image vers le registry. A ce stade, on sait qu'elle a passe le scan et les politiques. |
| 11 | **Resoudre le digest registry** | `docker inspect` | Recupere le **RepoDigest** (`sha256:...`) du registry apres push. Toutes les operations de signature et d'attestation ciblent ce digest immutable, pas le tag mutable. |
| 12 | **Verifier l'integrite du SBOM** | `sha256sum` | Recalcule le SHA256 du fichier SBOM et le compare au hash enregistre a la generation (etape 4). Si le fichier a ete modifie entre la generation et l'attestation, le pipeline s'arrete. |
| 13 | **Signer le digest** | `cosign sign --yes` | Signe le **digest registry** (pas le tag) avec Cosign. GitHub Actions utilise le mode **keyless** (OIDC via Sigstore). Azure DevOps utilise **Azure Key Vault KMS** (`azurekms://`) en methode principale avec keyless en fallback. La signature prouve que l'image a ete produite par cette pipeline CI/CD et n'a pas ete alteree. |
| 14 | **Attester le SBOM** | `cosign attest --type cyclonedx` | Lie cryptographiquement le SBOM au **digest registry** via une attestation In-Toto. Le SBOM atteste est exactement le fichier genere a l'etape 4 — jamais regenere ni modifie (verifie par l'etape 12). C'est la **garantie la plus forte** : elle prouve que CE SBOM decrit exactement CETTE image. |
| 15 | **Verifier dans le registry** | `cosign verify` + `cosign verify-attestation` | Preuve automatisee que la signature et l'attestation sont effectivement recuperables depuis le registry. Detecte les echecs silencieux, un `--no-upload` accidentel, ou des problemes de persistance du registry. **Bloquant** : si la verification echoue, le pipeline s'arrete avant de declarer le succes. |
| 16 | **Upload vers Dependency-Track** | `DependencyTrack/gh-upload-sbom` | Envoie le SBOM atteste a Dependency-Track pour le monitoring continu, lie au **digest registry** (pas le SHA git). **Non bloquant** (`continue-on-error`) : DTrack est de la gouvernance/monitoring, pas un gate CI. Si DTrack est indisponible, l'image signee est quand meme deployable. Etape optionnelle (ignoree si `dtrack-hostname` est vide). |

### Resume visuel

```
  Code + Dockerfile
        |
        v
  [1-3] BUILD ──────────────> Image locale
        |
        v
  [4]   SBOM ──────────────> sbom-image-trivy.json + SHA256 + ImageID
        |
        v
  [5]   IMAGE ↔ SBOM ─────> ImageID identique ?
        |                         |
        | OK                      | ECART → STOP
        v
  [6]   SCAN (trivy image) ─> Vulnerabilites HIGH/CRITICAL ?
        |                         |
        | OK                      | FAIL → STOP
        v
  [7]   SCAN SBOM (trivy sbom) ─> Consultatif (gouvernance, archive)
        |
        v
  [8]   POLICY (OPA) ──────> deny / warn ?
        |                         |
        | OK                      | FAIL → STOP
        v
  ═══ GATE PASSED ═══
        |
        v
  [9-10] PUSH ─────────────> Image dans le registry
        |
        v
  [11]  RESOLVE DIGEST ────> RepoDigest (sha256:...)
        |
        v
  [12]  VERIF SHA256 SBOM ──> Intact depuis etape 4 ?
        |                         |
        | OK                      | MODIFIE → STOP
        v
  [13]  SIGN ──────────────> Signature Cosign sur digest
        |
        v
  [14]  ATTEST ────────────> SBOM lie au digest (In-Toto)
        |
        v
  [15]  VERIFY ────────────> Signature + attestation dans le registry ?
        |                         |
        | OK                      | FAIL → STOP
        v
  [16]  DTRACK ────────────> Monitoring (non bloquant, lie au digest)
```

---

## Decisions de conception

Cette section explique **pourquoi** le pipeline fonctionne ainsi. Chaque mecanisme existe pour une raison precise — comprendre la logique aide a faire des choix eclaires lors de la personnalisation ou de l'extension du pipeline.

### Pourquoi scanner avant le push (shift-left)

L'ancien pipeline (`poc-build-sign` + `poc-sbom`) poussait l'image d'abord, puis generait le SBOM et le scannait. Cela creait une fenetre ou une image vulnerable ou non conforme etait deja dans le registry. Le shift-left signifie que l'image est analysee **localement** avant toute publication — si elle echoue, rien ne quitte le runner.

### Pourquoi le double scan (trivy image + trivy sbom)

Deux scans distincts servent deux objectifs differents :

- **`trivy image`** (etape 6) est le **gate de securite**. Il scanne l'image directement, accedant aux metadonnees du systeme de fichiers, aux bases de donnees des packages OS et a l'analyse binaire. C'est l'evaluation de vulnerabilites la plus complete et fiable car Trivy voit tout ce que le runtime conteneur verrait. Cette etape est **bloquante** (`--exit-code 1`).

- **`trivy sbom`** (etape 7) est le **scan de gouvernance**. Il scanne le fichier SBOM qui sera atteste et publie. Cela prouve que le SBOM qu'on signe a ete verifie — « ce qu'on signe = ce qu'on a scanne ». Tout delta entre les etapes 6 et 7 revele des lacunes dans l'inventaire du SBOM (packages que Trivy voit dans l'image mais absents du SBOM). Cette etape est **non bloquante** (`--exit-code 0`) car le scan base sur SBOM peut produire des faux positifs ou manquer des packages que le scan direct detecte.

### Pourquoi signer le digest, pas le tag

Les tags sont mutables — `myimage:v1.0` peut etre ecrase a tout moment. Les digests (`sha256:abc123...`) sont des references immutables adressees par contenu. Signer un tag ne garantit rien car le tag peut etre redirige vers une autre image apres la signature. Le pipeline resout le **RepoDigest** apres le push et toutes les operations de signature/attestation ciblent ce digest. Sur Azure DevOps, si `docker inspect` ne peut pas resoudre le digest (problemes de timing avec certains registries), on utilise `az acr repository show` en fallback et on **refuse de signer** si aucun digest n'est resolu — on ne retombe jamais sur un tag mutable.

### L'invariant d'integrite du SBOM

> **Invariant** : Le SBOM est genere, scanne, evalue et atteste a partir de **la meme image exacte**. Ne jamais regenerer ni modifier le SBOM entre la generation et l'attestation.

Cet invariant est applique par trois mecanismes :

1. **Verification croisee ImageID** (etape 5) : L'identifiant de l'image embarque dans le SBOM (`aquasecurity:trivy:ImageID`) est compare avec `docker inspect` de l'image reellement construite. S'ils different, le pipeline s'arrete.

2. **Hash SHA256** (etape 12) : Le SHA256 du fichier SBOM est enregistre a la generation (etape 4) et re-verifie juste avant l'attestation. Si le fichier a ete modifie (meme un seul octet), le pipeline s'arrete.

3. **Pas de rebuild entre les stages** (Azure DevOps) : Comme Azure DevOps utilise des stages separes pour BuildAndAnalyze et Publish, l'image est transferee via `docker save` → artifact → `docker load` pour garantir l'identite binaire. L'ImageID de l'image chargee est explicitement verifie contre la valeur attendue.

### Pourquoi KMS plutot que keyless (contexte entreprise)

La strategie de signature suit un ordre de priorite : **KMS > keyless > keypair**.

- **Azure Key Vault KMS** (`azurekms://`) : Recommande pour l'entreprise. La cle privee ne quitte jamais le HSM, la signature est auditee dans Azure, et la cle peut etre rotee sans modifier le pipeline. Necessite une service connection Azure avec les permissions `sign`, `verify`, `get` sur la cle.

- **Keyless** (OIDC via Sigstore) : Approche zero gestion de cle. Le runner CI obtient un certificat ephemere de Fulcio base sur son identite OIDC. Les signatures sont enregistrees dans le log de transparence Rekor. Ideal pour l'open source, mais necessite l'infrastructure publique Sigstore.

- **Keypair** : Fichiers `.pem` locaux. Le plus simple mais le plus difficile a gerer (rotation, stockage securise). Reserve au developpement ou aux environnements air-gap.

### Pourquoi restreindre `--certificate-identity-regexp`

En mode keyless, `cosign verify` utilise `--certificate-identity-regexp` pour filtrer quelles identites OIDC sont acceptees. Une valeur permissive comme `".*"` accepterait les signatures de **n'importe quel** pipeline sur **n'importe quelle** organisation — annulant la garantie de la verification. Le regexp doit etre aussi specifique que possible :

- **GitHub Actions** : `"github.com/cuspofaries/"` — scope a l'organisation. Le subject OIDC de GitHub inclut le nom du repo, donc le scope au niveau org est deja assez restrictif.
- **Azure DevOps** : `"https://dev.azure.com/cuspofaries/sdlc/_build"` — scope org + projet + definitions de pipeline. Scoper uniquement a l'org (`cuspofaries/`) permettrait a **n'importe quel pipeline de n'importe quel projet** de cette org de passer la verification. Ajouter le nom du projet (`sdlc/`) et `_build` garantit que seuls les pipelines de ce projet specifique sont acceptes.

Lors du portage vers votre organisation, c'est la **premiere chose a changer**. Voir [docs/azure-devops-porting.md](docs/azure-devops-porting.md) pour la liste complete.

### Pourquoi la verification post-attestation (etape 15)

La signature et l'attestation peuvent echouer silencieusement — un flag `--no-upload`, un probleme reseau, ou un souci de persistance du registry peuvent aboutir a un pipeline qui declare le succes alors que la signature n'a jamais atteint le registry. L'etape 15 execute `cosign verify` et `cosign verify-attestation` contre le registry pour **prouver** que les artefacts sont recuperables. Cette etape est **bloquante** : si la verification echoue, le pipeline s'arrete avant de declarer le succes. La sortie complete est archivee dans `output/verify/` pour la piste d'audit.

### Pourquoi Dependency-Track est non bloquant

Dependency-Track est un outil de gouvernance et de monitoring, pas un gate CI. Si DTrack est down, injoignable ou mal configure, l'image signee et attestee doit quand meme etre livree — les garanties de securite viennent des gates du pipeline (scan + politique + signature), pas de DTrack. Le SBOM est lie au **digest registry** (pas au SHA git) pour que l'inventaire DTrack corresponde directement a l'artefact publie.

### Pourquoi le DailyRescan utilise l'attestation cosign

Le stage DailyRescan (Azure DevOps) a besoin du SBOM original pour le rescanner avec les dernieres donnees CVE. Plutot que de se fier a un artifact pipeline (qui peut expirer, etre supprime ou devenir obsolete), le rescan extrait le SBOM depuis l'**attestation cosign** attachee au digest de l'image. C'est la source de verite cryptographique — l'attestation prouve que le SBOM n'a pas ete altere depuis le run original du pipeline. Si aucune attestation n'existe encore (premier run), le stage retombe sur l'artifact pipeline.

### Pourquoi chaque operation cosign affiche le digest

Chaque appel `cosign sign`, `cosign attest`, `cosign verify` et `cosign verify-attestation` est precede d'un `echo` explicite du digest cible. C'est une exigence de **piste d'audit** : en cas d'incident, les logs CI fournissent un enregistrement univoque du digest exact qui a ete signe, atteste et verifie. La sortie des verifications est archivee en fichiers `.log` (pas `.json` — cosign produit du texte, pas du JSON) dans `output/verify/` et uploadee comme artifacts avec 30 jours de retention. L'upload utilise `if: always()` / `condition: always()` pour que les resultats de scan et les donnees SBOM soient conserves **meme si le pipeline echoue** — essentiel pour l'analyse post-incident.

### Pourquoi la transparence Rekor par defaut

Toutes les operations de signature et d'attestation uploadent des entrees dans le [log de transparence Rekor](https://docs.sigstore.dev/logging/overview/) par defaut. Nous avons deliberement supprime `--no-upload=true` de tous les chemins de code (present dans les iterations initiales pour le mode keypair). Rekor fournit un log public, immutable et append-only de toutes les signatures — n'importe qui peut verifier independamment qu'une image specifique a ete signee a un moment donne par une identite donnee. Le flag `--no-upload` est documente comme option **uniquement** pour les environnements air-gap ou hors ligne.

### Pourquoi la fusion baseline + politiques custom

L'evaluation OPA charge les politiques depuis deux sources simultanement :

1. **Politiques baseline** (`sdlc/policies/`) : Maintenues dans ce repo, appliquees a tous les repos consommateurs. Elles imposent des regles universelles (packages d'attaques supply chain connues, composants sans version).
2. **Politiques custom** (`policies/` dans le repo consommateur) : Regles specifiques au projet (librairies bloquees, restrictions de licences, exigences specifiques a l'org).

Les deux sont passees a `opa eval` via des flags `-d` et partagent le meme namespace `package sbom`. Les regles des deux sources sont automatiquement fusionnees — aucune configuration necessaire. Un repo consommateur peut ajouter des regles `deny` pour bloquer des packages supplementaires ou des regles `warn` pour des verifications consultatives sans modifier le baseline.

### Pourquoi une installation resiliente des outils

L'etape d'installation de Trivy utilise une **boucle de retry avec backoff** (3 tentatives, 5 secondes de delai entre les echecs). Cela protege contre les echecs reseau transitoires lors des telechargements `curl` dans les environnements CI, ou les runners partages peuvent connaitre des problemes de connectivite intermittents. Un seul echec de telechargement ne fait pas echouer tout le pipeline — seuls 3 echecs consecutifs le font.

### Coherence cross-plateforme

Le pipeline est implemente sur trois plateformes avec le **meme flux logique** :

| Plateforme | Implementation | Notes |
|------------|---------------|-------|
| **GitHub Actions** | `.github/workflows/supply-chain-reusable.yml` | Job unique, workflow reutilisable `workflow_call` |
| **Azure DevOps** | `azure-pipelines/pipeline.yml` | Multi-stage (BuildAndAnalyze → Publish → DailyRescan) |
| **Local / tout CI** | `Taskfile.yml` + `scripts/` | Tasks portables, appelees par GH et ADO |

Les trois partagent le meme ordre (build → analyse → gate → publication), les memes outils (Trivy, Cosign, OPA), la meme priorite de signature (KMS > keyless > keypair), et les memes invariants (integrite SBOM, signature sur digest uniquement, verification post-publication). Quand un mecanisme est ajoute a l'un, il est ajoute aux trois.

### Output du workflow pour la consommation downstream

Le workflow reutilisable GitHub Actions expose un output `image` contenant la **reference complete de l'image avec digest** (`registry/owner/name@sha256:...`). Les jobs en aval peuvent utiliser cet output pour deployer, scanner ou referencer l'image exacte qui a ete construite, signee et attestee — sans avoir besoin de resoudre le digest eux-memes.

---

## Garanties de securite

Ce pipeline fournit les garanties verifiables suivantes :

| Garantie | Mecanisme | Mode d'echec |
|----------|-----------|-------------|
| **Rien n'est publie sans scan** | Shift-left : build → analyse → GATE → publication | Le pipeline s'arrete au gate |
| **Le SBOM decrit l'image exacte** | Verification croisee ImageID (etape 5) | `FATAL: Image ID mismatch` |
| **Le SBOM n'a pas ete modifie apres le scan** | SHA256 enregistre a la generation, verifie avant attestation (etape 12) | `FATAL: SBOM was modified` |
| **Meme binaire entre les stages** (ADO) | `docker save` → artifact → `docker load` + verification ImageID | `Loaded image does not match SBOM` |
| **Les signatures ciblent des digests immutables** | RepoDigest resolu apres push, fallback sur tag refuse | `Cannot resolve registry digest` |
| **Les signatures sont effectivement dans le registry** | Post-publication `cosign verify` + `cosign verify-attestation` (etape 15) | Le pipeline s'arrete avant de declarer le succes |
| **Seul le pipeline de ce projet peut passer la verif** | `--certificate-identity-regexp` scope a l'org/projet | Signatures d'autres pipelines rejetees |
| **Le contenu SBOM est lie cryptographiquement a l'image** | Attestation In-Toto via `cosign attest --type cyclonedx` | Falsification de l'attestation detectable |
| **Toutes les signatures sont publiquement auditables** | Log de transparence Rekor (pas de `--no-upload`) | Verification independante possible |
| **Les packages dangereux connus sont bloques** | Regles OPA `deny` (baseline + custom) | `POLICY CHECK FAILED` |
| **Un echec DTrack ne bloque pas la livraison** | `continue-on-error: true`, lie au digest | L'image signee est livree quoi qu'il arrive |

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
| `sbom:scan` | Scanner l'image pour les vulnérabilités (trivy image — gate sécurité) |
| `sbom:scan:sbom` | Scanner le SBOM pour les vulnérabilités (trivy sbom — gouvernance, consultatif) |
| `sbom:policy` | Évaluer le SBOM contre les politiques OPA |
| `push` | Push de l'image vers le registry |
| `image:sign` | Signer le digest de l'image (cosign) |
| `image:verify` | Vérifier la signature de l'image |
| `sbom:attest` | Attester le SBOM au digest de l'image |
| `sbom:attest:verify` | Verifier que la signature et l'attestation sont publiees dans le registry |
| `sbom:sign:blob` | Signer le SBOM comme fichier standalone |
| `sbom:verify` | Vérifier la signature et l'intégrité du SBOM |
| `sbom:store` | Stocker le SBOM comme artefact OCI dans le registry (ORAS) |
| `sbom:fetch` | Recuperer le SBOM depuis le registry OCI (ORAS) |
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

Un template Azure Pipelines est disponible dans `azure-pipelines/pipeline.yml` implementant le meme pipeline avec des adaptations specifiques a Azure.

### Stages

| Stage | Declencheur | Description |
|-------|-------------|-------------|
| **BuildAndAnalyze** | Chaque run CI | Build + generation SBOM + scan vulnerabilites + evaluation politique. Rien n'est pousse. L'image est sauvee en artifact via `docker save` pour le stage suivant. |
| **Publish** | Seulement si BuildAndAnalyze reussit | `docker load` depuis l'artifact (pas de rebuild), push, sign, attest, verification dans le registry, upload vers DTrack. |
| **DailyRescan** | Planifie (cron) | Extrait le SBOM depuis l'attestation cosign (source de verite), rescanne avec les dernieres donnees CVE, uploade les resultats frais vers DTrack. |

### Mecanismes specifiques a Azure

- **Transfert d'image entre stages** : `docker save` dans BuildAndAnalyze → artifact pipeline → `docker load` dans Publish. Pas de rebuild, identite binaire garantie.
- **Resolution du digest** : `docker inspect` avec `az acr repository show` en fallback. Refuse de signer si aucun digest immutable n'est resolu.
- **Signature** : Azure Key Vault KMS (`azurekms://`) en methode principale, keyless (OIDC via `vstoken.dev.azure.com`) en fallback.
- **Identite keyless** : `--certificate-identity-regexp` scope a `"https://dev.azure.com/cuspofaries/sdlc/_build"` (scope org + projet + pipeline).
- **Integrite du SBOM entre stages** : SHA256 + ImageID enregistres comme fichiers dans l'artifact, verifies apres `docker load` dans le stage Publish.
- **Source SBOM du DailyRescan** : Extrait depuis l'attestation cosign (`cosign verify-attestation | jq`), retombe sur l'artifact pipeline.

### Guide de portage

Voir [docs/azure-devops-porting.md](docs/azure-devops-porting.md) pour une checklist complete des fichiers et lignes a modifier lors du deploiement de ce pipeline dans votre propre organisation Azure DevOps (identity-regexp, service connections, variable group, configuration KMS, etc.).

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
│   ├── azure-devops-porting.md       ← Checklist de portage Azure DevOps
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
