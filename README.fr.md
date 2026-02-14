# SDLC — Toolchain Unifié de Sécurité Supply Chain

> **Plateforme réutilisable** pour le build d'images conteneur, la génération SBOM, le scan de vulnérabilités, l'application de politiques, la signature et le monitoring.
> Approche shift-left : scanner **avant** de publier. Ordre strict : **build → analyse → GATE → publication**.

[![Validate Toolchain](https://github.com/cuspofaries/sdlc/actions/workflows/validate-toolchain.yml/badge.svg)](https://github.com/cuspofaries/sdlc/actions/workflows/validate-toolchain.yml)

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
| 15 | **Attester la provenance SLSA** | `actions/attest-build-provenance` | Genere et atteste un predicat de provenance [SLSA](https://slsa.dev/) au digest de l'image. Enregistre l'identite du builder, le repo source, la revision et les metadonnees de build. Sur GitHub Actions, utilise l'action native d'attestation ; sur Azure DevOps et en local, un predicat cosign est utilise via `scripts/slsa-provenance.sh`. |
| 16 | **Verifier tout dans le registry (fail-closed)** | `cosign verify` + `cosign verify-attestation` x2 | **Fail-closed** : verifie les trois artefacts (signature, attestation SBOM, provenance SLSA) sur le meme digest `image@sha256:...`. Si **l'un** manque ou est invalide, le pipeline s'arrete. Les contraintes d'identite (`--certificate-oidc-issuer` + `--certificate-identity-regexp`) sont appliquees sur chaque verification — y compris la provenance SLSA, qui prouve qui a construit l'image. `cosign tree` est execute en debug pour montrer les referrers. Tous les logs sont archives dans `output/verify/` pour audit. |
| 17 | **Upload vers Dependency-Track** | `DependencyTrack/gh-upload-sbom` | Envoie le SBOM atteste a Dependency-Track pour le monitoring continu, lie au **digest registry** (pas le SHA git). **Non bloquant** (`continue-on-error`) : DTrack est de la gouvernance/monitoring, pas un gate CI. Si DTrack est indisponible, l'image signee est quand meme deployable. Etape optionnelle (ignoree si `dtrack-hostname` est vide). |

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
  [14]  ATTEST SBOM ───────> SBOM lie au digest (In-Toto)
        |
        v
  [15]  ATTEST SLSA ───────> Provenance de build liee au digest
        |
        v
  [16]  VERIFY ────────────> Signature + attestation dans le registry ?
        |                         |
        | OK                      | FAIL → STOP
        v
  [17]  DTRACK ────────────> Monitoring (non bloquant, lie au digest)
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

La strategie de signature suit un ordre de priorite : **KMS > keyless CI > keypair**.

Tous les scripts de signature (`image-sign.sh`, `slsa-provenance.sh`, `sbom-attest.sh`) utilisent la meme logique de detection :

1. **Azure Key Vault KMS** (`azurekms://`) : Si `COSIGN_KMS_KEY` est defini. Recommande pour l'entreprise. La cle privee ne quitte jamais le HSM, la signature est auditee dans Azure, et la cle peut etre rotee sans modifier le pipeline.

2. **Keyless** (OIDC via Sigstore) : Si un fournisseur OIDC CI est detecte — `ACTIONS_ID_TOKEN_REQUEST_URL` (GitHub Actions) ou `SYSTEM_OIDCREQUESTURI` (Azure DevOps). Le runner obtient un certificat ephemere de Fulcio. **Le keyless n'est jamais tente a l'aveugle** : les scripts verifient les variables d'env specifiques au CI d'abord, donc il ne declenche jamais un login interactif dans le browser en contexte local ou e2e.

3. **Keypair** : Si un fichier `cosign.key` existe. Le plus simple mais le plus difficile a gerer (rotation, stockage securise). Reserve au developpement, aux tests e2e ou aux environnements air-gap.

Si aucune methode n'est disponible, le script echoue avec une erreur claire listant les options.

### Pourquoi restreindre `--certificate-identity-regexp`

En mode keyless, `cosign verify` utilise `--certificate-identity-regexp` pour filtrer quelles identites OIDC sont acceptees. Une valeur permissive comme `".*"` accepterait les signatures de **n'importe quel** pipeline sur **n'importe quelle** organisation — annulant la garantie de la verification. Le regexp doit etre aussi specifique que possible :

- **GitHub Actions** : `"github.com/cuspofaries/"` — scope a l'organisation. Le subject OIDC de GitHub inclut le nom du repo, donc le scope au niveau org est deja assez restrictif.
- **Azure DevOps** : `"https://dev.azure.com/cuspofaries/sdlc/_build"` — scope org + projet + definitions de pipeline. Scoper uniquement a l'org (`cuspofaries/`) permettrait a **n'importe quel pipeline de n'importe quel projet** de cette org de passer la verification. Ajouter le nom du projet (`sdlc/`) et `_build` garantit que seuls les pipelines de ce projet specifique sont acceptes.

Lors du portage vers votre organisation, c'est la **premiere chose a changer**. Voir [docs/azure-devops-porting.md](docs/azure-devops-porting.md) pour la liste complete.

### Pourquoi la verification post-attestation est fail-closed (etape 16)

La signature et l'attestation peuvent echouer silencieusement — un flag `--no-upload`, un probleme reseau, ou un souci de persistance du registry peuvent aboutir a un pipeline qui declare le succes alors que la signature n'a jamais atteint le registry. L'etape 16 execute trois verifications separees sur le **meme digest** (`image@sha256:...`, jamais un tag mutable) :

1. `cosign verify` — signature de l'image
2. `cosign verify-attestation --type cyclonedx` — attestation SBOM
3. `cosign verify-attestation --type slsaprovenance` — provenance SLSA

**Les trois doivent passer.** Il n'y a pas de mode « au moins une » — si la provenance SLSA manque, le pipeline echoue meme si l'attestation SBOM est presente. C'est delibere : le SBOM prouve **ce qu'il y a** dans l'image, et la provenance SLSA prouve **qui** l'a construite et **a partir de quoi**. Les deux sont necessaires pour une garantie supply chain complete.

Les contraintes d'identite (`--certificate-oidc-issuer` + `--certificate-identity-regexp`) sont appliquees sur **chaque** verification y compris la provenance SLSA — c'est la preuve que le build vient du pipeline CI attendu, pas d'un attaquant avec acces au registry.

Une commande `cosign tree` s'execute en premier (non bloquante, debug) pour afficher tous les referrers (signature + attestations) attaches au digest — utile pour le troubleshooting quand une verification echoue.

Tous les resultats sont archives dans `output/verify/` :
- `cosign-tree.log` — listing des referrers (debug)
- `verify-signature.log` — verification de signature
- `verify-attestation-sbom.log` — attestation SBOM
- `verify-attestation-slsa.log` — provenance SLSA

### Pourquoi Dependency-Track est non bloquant

Dependency-Track est un outil de gouvernance et de monitoring, pas un gate CI. Si DTrack est down, injoignable ou mal configure, l'image signee et attestee doit quand meme etre livree — les garanties de securite viennent des gates du pipeline (scan + politique + signature), pas de DTrack. Le SBOM est lie au **digest registry** (pas au SHA git) pour que l'inventaire DTrack corresponde directement a l'artefact publie.

### Pourquoi le DailyRescan utilise l'attestation cosign

Le stage DailyRescan (Azure DevOps) a besoin du SBOM original pour le rescanner avec les dernieres donnees CVE. Plutot que de se fier a un artifact pipeline (qui peut expirer, etre supprime ou devenir obsolete), le rescan extrait le SBOM depuis l'**attestation cosign** attachee au digest de l'image. C'est la source de verite cryptographique — l'attestation prouve que le SBOM n'a pas ete altere depuis le run original du pipeline. Si aucune attestation n'existe encore (premier run), le stage retombe sur l'artifact pipeline.

### Pourquoi chaque operation cosign affiche le digest

Chaque appel `cosign sign`, `cosign attest`, `cosign verify` et `cosign verify-attestation` est precede d'un `echo` explicite du digest cible. C'est une exigence de **piste d'audit** : en cas d'incident, les logs CI fournissent un enregistrement univoque du digest exact qui a ete signe, atteste et verifie. Les sorties de verification sont stockees en fichiers `.log` car cosign produit du texte lisible ; le parsing JSON est intentionnellement evite pour garder l'etape de verification agnostique de la plateforme. Ces fichiers sont archives dans `output/verify/` et uploades comme artifacts avec 30 jours de retention. L'upload utilise `if: always()` / `condition: always()` pour que les resultats de scan et les donnees SBOM soient conserves **meme si le pipeline echoue** — essentiel pour l'analyse post-incident.

### Pourquoi la transparence Rekor par defaut

Toutes les operations de signature et d'attestation uploadent des entrees dans le [log de transparence Rekor](https://docs.sigstore.dev/logging/overview/) par defaut. Nous avons deliberement supprime `--no-upload=true` de tous les chemins de code (present dans les iterations initiales pour le mode keypair). Rekor fournit un log public, immutable et append-only de toutes les signatures — n'importe qui peut verifier independamment qu'une image specifique a ete signee a un moment donne par une identite donnee. Le flag `--no-upload` est documente comme option **uniquement** pour les environnements air-gap ou hors ligne.

### Pourquoi la fusion baseline + politiques custom

L'evaluation OPA charge les politiques depuis deux sources simultanement :

1. **Politiques baseline** (`sdlc/policies/`) : Maintenues dans ce repo, appliquees a tous les repos consommateurs. Elles imposent des regles universelles (packages d'attaques supply chain connues, composants sans version).
2. **Politiques custom** (`policies/` dans le repo consommateur) : Regles specifiques au projet (librairies bloquees, restrictions de licences, exigences specifiques a l'org).

Les deux sont passees a `opa eval` via des flags `-d` et partagent le meme namespace `package sbom`. Les regles des deux sources sont automatiquement fusionnees — aucune configuration necessaire. Un repo consommateur peut ajouter des regles `deny` pour bloquer des packages supplementaires ou des regles `warn` pour des verifications consultatives sans modifier le baseline.

Les politiques baseline (`policies/sbom-compliance.rego`) incluent :

| Niveau | Regle | Justification |
|--------|-------|---------------|
| **deny** | Packages bloques (`event-stream`, `colors`, `faker`...) | Attaques supply chain connues ou sabotage |
| **deny** | Composants sans version | Impossible de suivre les vulnerabilites sans version |
| **deny** | Librairies sans Package URL (purl) | Impossible de croiser avec les bases de vulnerabilites |
| **deny** | Licences copyleft (GPL, AGPL, SSPL) dans les librairies applicatives | Incompatibles avec la distribution proprietaire (packages OS exclus — attendus dans les images de base) |
| **deny** | Timestamp SBOM manquant | Impossible de verifier la fraicheur |
| **deny** | Zero composants | La generation SBOM a probablement echoue |
| **deny** | Metadonnees d'outil de generation manquantes | Impossible d'auditer comment le SBOM a ete produit |
| **deny** | Spec CycloneDX < 1.4 | Les specs anciennes manquent de champs requis pour la conformite |
| **warn** | Licences non approuvees | Signalees pour revue legale, non bloquantes |
| **warn** | Information de licence manquante | Lacune de tracabilite |
| **warn** | Nombre eleve de composants (> 500) | Possible surcharge de dependances |
| **warn** | Packages deprecies/abandonnes | Devraient etre remplaces |
| **warn** | Metadonnees fournisseur/editeur manquantes | Tracabilite reduite |

### Versions d'outils pinnees

Tous les outils sont pinnes a des versions specifiques dans `Taskfile.yml` (variables `TRIVY_VERSION`, `COSIGN_VERSION`, `OPA_VERSION`, `CDXGEN_VERSION`, `ORAS_VERSION`). Cela garantit :
- **Reproductibilite** : memes versions en dev, CI, et dans tous les repos consommateurs
- **Pas de rupture surprise** : une nouvelle version trivy/cosign ne peut pas silencieusement changer les resultats de scan ou le comportement de signature
- **Auditabilite** : les versions exactes sont visibles dans la sortie de `task install:verify`

Renovate surveille ces versions et ouvre des PRs quand des mises a jour sont disponibles, donc pinner ne signifie pas stagner.

### Pourquoi une installation resiliente des outils

L'etape d'installation de Trivy utilise une **boucle de retry avec backoff** (3 tentatives, 5 secondes de delai entre les echecs). Cela protege contre les echecs reseau transitoires lors des telechargements `curl` dans les environnements CI, ou les runners partages peuvent connaitre des problemes de connectivite intermittents. Un seul echec de telechargement ne fait pas echouer tout le pipeline — seuls 3 echecs consecutifs le font.

### Taskfile orchestre, scripts font le travail

La logique metier (resolution de digest, detection du mode de signature, attestation, evaluation de politique) vit dans `scripts/*.sh` — jamais inline dans le YAML du Taskfile. Chaque script suit le meme contrat :
- `set -euo pipefail` en haut
- Entrees via arguments positionnels et variables d'environnement (pas de chemins en dur)
- Logging explicite de chaque digest, fichier et mode avant d'agir
- Exit 1 en cas d'echec (fail-closed)

Le Taskfile ne fait qu'orchestrer : il appelle les scripts avec les bonnes variables. Cela empeche la duplication de logique et rend les scripts testables independamment du task runner.

### Coherence cross-plateforme

Le pipeline est implemente sur trois plateformes avec le **meme flux logique** :

| Plateforme | Implementation | Notes |
|------------|---------------|-------|
| **GitHub Actions** | `.github/workflows/supply-chain-reusable.yml` | Job unique, workflow reutilisable `workflow_call` |
| **Azure DevOps** | `azure-pipelines/pipeline.yml` | Multi-stage (BuildAndAnalyze → Publish → DailyRescan) |
| **Local / tout CI** | `Taskfile.yml` + `scripts/` | Tasks portables, appelees par GH et ADO |

Les trois partagent le meme ordre (build → analyse → gate → publication), les memes outils (Trivy, Cosign, OPA), la meme priorite de signature (KMS > keyless CI > keypair), et les memes invariants (integrite SBOM, signature sur digest uniquement, verification post-publication). Quand un mecanisme est ajoute a l'un, il est ajoute aux trois. Le workflow `validate-toolchain.yml` inclut un **test end-to-end** (job `e2e-test`) qui construit une image de test, genere le SBOM, execute tous les scans et verifications de politique, verifie l'invariant d'integrite SBOM, puis signe, atteste et verifie avec un registry local. Cela detecte les regressions d'integration que des verifications unitaires ne detecteraient pas.

**Philosophie e2e : aussi strict que la prod, fail-closed.** Le e2e execute les memes tasks Taskfile avec les memes defaults — pas de `TRIVY_EXIT_CODE=0`, pas de `--ignore-unfixed`, pas de regexp d'identite relachee. Si l'image de test a des CVEs HIGH/CRITICAL, le e2e echoue ; on corrige l'image de base, on ne relaxe pas le test.

Relaxations connues (inherentes au CI, chacune documentee inline dans le workflow) :

| Relaxation | Pourquoi inevitable | Ou le comportement reel est teste |
|------------|---------------------|-----------------------------------|
| Signature par keypair (pas keyless) | Keyless necessite OIDC depuis un fournisseur CI ; les scripts detectent les variables d'env (`ACTIONS_ID_TOKEN_REQUEST_URL`, `SYSTEM_OIDCREQUESTURI`) et ne tentent le keyless que quand disponible | Repos consommateurs utilisant `supply-chain-reusable.yml` avec de vrais registries |
| `registry:2` local + `COSIGN_ALLOW_INSECURE_REGISTRY` | Pas de TLS sans certificats externes en CI ; c'est le seul override d'env | Repos consommateurs poussant vers ghcr.io / ACR |
| Runner unique (pas de save/load) | Le pattern multi-stage ADO est specifique a la plateforme | `azure-pipelines/pipeline.yml` avec docker save/load + re-verification ImageID |

Non relaxe (identique a la prod) : `TRIVY_EXIT_CODE=1`, `TRIVY_SEVERITY=HIGH,CRITICAL`, regles OPA deny, resolution digest via les tasks, memes scripts, memes policies.

**Regle : chaque relaxation doit repondre a POURQUOI elle est inevitable et OU le comportement reel est teste. Sans les deux reponses, on ne relaxe pas.**

### Provenance SLSA de build

[SLSA](https://slsa.dev/) (Supply chain Levels for Software Artifacts) enregistre **qui** a construit une image, a partir de **quelle** source, et **comment**. Le pipeline atteste un predicat de provenance SLSA au digest de l'image en plus de l'attestation SBOM :

- **GitHub Actions** : Utilise `actions/attest-build-provenance@v2` (attestation native GitHub, stockee dans le package registry).
- **Azure DevOps / local** : Utilise `scripts/slsa-provenance.sh` qui genere un predicat SLSA v0.2 (ID du builder, repo source, revision, URL du build) et l'atteste via cosign avec la meme priorite KMS > keyless CI > keypair.

Cela fournit une chaine verifiable depuis l'image publiee jusqu'au commit source exact et au run CI qui l'a produite.

### Versionnage semantique

Le toolchain utilise le [versionnage semantique](https://semver.org/) via des tags git (`v1.0.0`, `v1.2.3`). Pousser un tag de version declenche le workflow `release.yml` qui :

1. Valide le format du tag (`vX.Y.Z`)
2. Genere un changelog depuis l'historique des commits
3. Cree une GitHub Release
4. Met a jour un tag majeur flottant (`v1`) pointant vers le dernier `v1.x.y`

Les repos consommateurs peuvent pinner a :
- `@v1` — mises a jour mineures/patch automatiques (recommande)
- `@v1.2.0` — version exacte (reproductibilite maximale)
- `@main` — derniere version de developpement (non recommande pour la production)

### Exceptions de securite (CRA/NIS2 audit-ready)

Quand une vulnerabilite ne peut pas etre corrigee immediatement mais est evaluee comme temporairement acceptable, le pipeline supporte des **exceptions structurees, limitees dans le temps, et auditables** via `security-exceptions.yaml`. Cela repond a la question de l'auditeur : « Comment gerez-vous une vulnerabilite acceptable temporairement ? »

```yaml
# security-exceptions.yaml (dans le repo consommateur, versionne git)
exceptions:
  - id: CVE-2024-32002
    package: "git"
    reason: "Non exploitable dans notre contexte (pas de clone submodule)"
    approved_by: "security@example.com"
    expires: "2025-06-30"
    ticket: "JIRA-1234"
```

**Les 6 champs sont obligatoires.** Pas d'exception permanente — `expires` est requis.

Le mecanisme opere sur **deux gates independants** :

1. **Gate Trivy** : `scripts/trivy-exceptions.sh` lit le YAML et genere `.trivyignore` contenant **uniquement les CVE non expirees**. Quand une exception expire, elle disparait du `.trivyignore` et Trivy la bloque a nouveau automatiquement.

2. **Gate OPA** (defense en profondeur) : `policies/security-exceptions.rego` lit le meme YAML (converti en JSON) et ajoute des regles :
   - **deny** si une exception a des champs requis manquants ou vides
   - **deny** si une exception a expire (detecte les fichiers obsoletes meme si Trivy n'a pas detecte)
   - **warn** si une exception expire dans moins de 7 jours (rappel de renouvellement)
   - **warn** listant toutes les exceptions actives (visibilite d'audit a chaque run de pipeline)

**Invariant critique** : Le fichier SBOM n'est **jamais modifie**. Les exceptions vivent uniquement au niveau des gates. L'integrite SBOM (SHA256 + ImageID) est intacte.

Le flux de donnees :
```
security-exceptions.yaml (repo consommateur, versionne git)
        |
        +---> trivy-exceptions.sh ---> .trivyignore (CVEs non expirees)
        |                                  |
        |                           trivy image --ignorefile .trivyignore
        |
        +---> sbom-policy.sh ---> yq -o json ---> OPA --data exceptions.json
                                                    |
                                                    +-- deny : expire, champs manquants
                                                    +-- warn : expire < 7 jours
                                                    +-- warn : exceptions actives (audit)
```

Pour utiliser dans un repo consommateur : creer `security-exceptions.yaml` a la racine du repo et passer `exceptions-file: security-exceptions.yaml` au workflow reutilisable. En local : `task sbom:scan EXCEPTIONS_FILE=security-exceptions.yaml`.

### Tests unitaires OPA

Les politiques OPA baseline sont couvertes par des tests unitaires dans `policies/sbom-compliance_test.rego` (executes via `task opa:test` ou `opa test policies/ -v`). Les tests verifient les regles deny et warn en utilisant `json.patch`/`json.remove` sur un SBOM valide minimal. Le CI `validate-toolchain.yml` execute ces tests a chaque push.

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
| **Les 3 artefacts verifies dans le registry (fail-closed)** | `cosign verify` + `verify-attestation --type cyclonedx` + `--type slsaprovenance` sur meme digest (etape 16) | Le pipeline s'arrete si l'un manque |
| **Seul le pipeline de ce projet peut passer la verif** | `--certificate-identity-regexp` scope a l'org/projet | Signatures d'autres pipelines rejetees |
| **Le contenu SBOM est lie cryptographiquement a l'image** | Attestation In-Toto via `cosign attest --type cyclonedx` | Falsification de l'attestation detectable |
| **Toutes les signatures sont publiquement auditables** | Log de transparence Rekor (pas de `--no-upload`) | Verification independante possible |
| **La provenance de build est attestee** | Predicat de provenance SLSA atteste au digest de l'image | Builder, source et revision lies cryptographiquement |
| **Les exceptions de securite expirees sont bloquees** | Gate Trivy (.trivyignore) + OPA deny (defense en profondeur) | `EXPIRED on ...` + Trivy bloque le CVE |
| **Les exceptions actives sont auditables** | OPA warn liste toutes les exceptions actives a chaque run de pipeline | Piste d'audit dans les logs CI |
| **Pas d'exception permanente** | Les 6 champs sont obligatoires, `expires` requis | `missing required field` |
| **Les packages dangereux connus sont bloques** | Regles OPA `deny` (baseline + custom) | `POLICY CHECK FAILED` |
| **Les licences copyleft sont detectees** | OPA `deny` pour GPL/AGPL/SSPL dans les librairies applicatives (warn pour packages OS) | `Copyleft license ... incompatible` |
| **Les specs SBOM obsoletes sont rejetees** | OPA `deny` pour CycloneDX < 1.4 | `spec version too old` |
| **La chaine pipeline est testee end-to-end** | Job `e2e-test` : build → SBOM → scan → policy → sign → attest → verify | La CI echoue sur toute etape cassee |
| **Les nouvelles CVE sont detectees post-deploiement** | DailyRescan extrait le SBOM depuis l'attestation, rescanne avec les donnees fraiches | Consultatif (non bloquant) |
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
    uses: cuspofaries/sdlc/.github/workflows/supply-chain-reusable.yml@v1
    with:
      context: ./app
      image-name: my-app
      dtrack-hostname: dep-api.example.com  # optionnel
    secrets:
      REGISTRY_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      DTRACK_API_KEY: ${{ secrets.DTRACK_API_KEY }}  # optionnel
```

Pinner a `@v1` pour les mises a jour mineures/patch automatiques, ou `@v1.2.0` pour un pinning exact.

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
| `exceptions-file` | Non | `""` | Chemin vers `security-exceptions.yaml` dans le repo appelant (vide = pas d'exceptions) |

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
| `opa:test` | Executer les tests unitaires OPA sur les regles de politique |
| `exceptions:validate` | Valider le format et l'expiration de security-exceptions.yaml |
| `push` | Push de l'image vers le registry |
| `image:sign` | Signer le digest de l'image (cosign) |
| `image:verify` | Vérifier la signature de l'image |
| `sbom:attest` | Attester le SBOM au digest de l'image |
| `slsa:attest` | Attester la provenance SLSA de build au digest de l'image |
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
│   ├── daily-rescan.yml              ← Rescan planifié avec les dernières données CVE
│   ├── validate-toolchain.yml        ← CI + test end-to-end du pipeline
│   └── release.yml                   ← Versionnage sémantique (tag → GitHub Release)
├── azure-pipelines/
│   └── pipeline.yml                  ← Template Azure DevOps
├── scripts/                          ← Scripts shell (Taskfile orchestre, scripts font le travail)
│   ├── image-sign.sh
│   ├── image-verify.sh
│   ├── sbom-attest.sh
│   ├── sbom-integrity.sh
│   ├── sbom-generate-source.sh
│   ├── sbom-policy.sh
│   ├── trivy-exceptions.sh
│   ├── sbom-sign.sh
│   ├── sbom-tamper-test.sh
│   ├── sbom-upload-dtrack.sh
│   ├── sbom-verify.sh
│   └── slsa-provenance.sh
├── policies/
│   ├── sbom-compliance.rego          ← Politiques OPA baseline
│   ├── sbom-compliance_test.rego     ← Tests unitaires OPA
│   ├── security-exceptions.rego      ← Regles de validation des exceptions (CRA/NIS2)
│   └── security-exceptions_test.rego ← Tests des exceptions
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
    uses: cuspofaries/sdlc/.github/workflows/supply-chain-reusable.yml@v1
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
