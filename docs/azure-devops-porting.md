# Guide de portage — Azure DevOps

> Ce document liste **tous les fichiers et lignes a modifier** pour porter le repo `sdlc` sur Azure DevOps. Il est concu pour etre suivi comme une checklist.

---

## 1. Restriction d'identite keyless (CRITIQUE — securite)

En mode keyless (Cosign sans cle KMS), la verification utilise `--certificate-identity-regexp` pour n'accepter que les signatures provenant de votre pipeline specifique. **Si vous ne modifiez pas ces valeurs, le pipeline acceptera les signatures du projet `cuspofaries/sdlc` au lieu du votre.**

Le regexp doit etre le plus specifique possible : **org + projet + pipeline**, pas seulement l'org. Scoper uniquement a l'org permettrait a n'importe quel pipeline de n'importe quel projet de cette org de passer la verification.

### Fichiers concernes

| Fichier | Ligne(s) | Valeur actuelle | A remplacer par |
|---------|----------|-----------------|-----------------|
| `azure-pipelines/templates/verify.yml` | parametre `identityRegexp` (defaut) | `"https://dev.azure.com/cuspofaries/sdlc/_build"` | `"https://dev.azure.com/<VOTRE_ORG>/<VOTRE_PROJET>/_build"` |
| `azure-pipelines/pipeline.yml` | ~352 (DailyRescan extract) | `"https://dev.azure.com/cuspofaries/sdlc/_build"` | `"https://dev.azure.com/<VOTRE_ORG>/<VOTRE_PROJET>/_build"` |
| `.github/workflows/supply-chain-reusable.yml` | ~321, ~329 | `"github.com/cuspofaries/"` | `"github.com/<VOTRE_ORG>/"` |
| `Taskfile.yml` | ~280, ~332, ~338 | `"github.com/cuspofaries/"` | `"github.com/<VOTRE_ORG>/"` |
| `scripts/sbom-attest.sh` | N/A | Pas de regexp hardcodee | Aucune modification |
| `scripts/sbom-sign.sh` | N/A | Pas de regexp hardcodee | Aucune modification |

> **Pourquoi c'est critique** : `--certificate-identity-regexp` est le filtre qui determine quelles signatures sont acceptees lors de la verification. Un `".*"` ou un scope trop large (org seule) accepterait des signatures provenant de pipelines tiers ou d'autres projets de la meme org — ce qui annule la garantie d'integrite de toute la chaine.
>
> **Format de l'identite OIDC Azure DevOps** : `https://dev.azure.com/{org}/{projet}/_build/results?buildId={id}`. Le regexp `https://dev.azure.com/<ORG>/<PROJET>/_build` couvre toutes les definitions de pipeline de ce projet.

---

## 2. OIDC Issuer (verification keyless)

L'issuer OIDC est l'autorite qui emet les tokens d'identite pour le mode keyless. Chaque plateforme CI a le sien.

| Fichier | Valeur actuelle | Contexte |
|---------|-----------------|----------|
| `azure-pipelines/templates/verify.yml` | `https://vstoken.dev.azure.com` (parametre `oidcIssuer`) | Issuer Azure DevOps — **ne pas modifier** |
| `.github/workflows/supply-chain-reusable.yml` | `https://token.actions.githubusercontent.com` | Issuer GitHub Actions — **ne pas modifier** sauf si vous migrez entierement hors de GitHub |
| `Taskfile.yml` | `https://token.actions.githubusercontent.com` | Utilise par defaut pour la verification locale. Si vous ne verifiez jamais depuis GitHub, remplacez par `https://vstoken.dev.azure.com` |

---

## 3. Service connections Azure DevOps

| Fichier | Ligne(s) | Nom actuel | Description |
|---------|----------|------------|-------------|
| `azure-pipelines/templates/azure-login.yml` | parametre `azureServiceConnection` (defaut) | `azure-service-connection` | Service connection Azure Resource Manager (pour Key Vault + ACR) |
| `azure-pipelines/pipeline.yml` | ~157, ~291 | `acr-service-connection` | Service connection Docker Registry (pour login ACR) |

> Ces noms doivent correspondre exactement a ceux crees dans Project Settings > Service connections.

---

## 4. Variable group et variables

Le pipeline Azure DevOps attend un variable group nomme `supply-chain` (ligne ~43 de `azure-pipelines/pipeline.yml`).

| Variable | Obligatoire | Description | Exemple |
|----------|-------------|-------------|---------|
| `ACR_NAME` | Oui | Nom de l'Azure Container Registry (sans `.azurecr.io`) | `myorgacr` |
| `COSIGN_KV_KEY` | Recommande | Reference de la cle dans Azure Key Vault | `myorgvault.vault.azure.net/cosign-key` |
| `DTRACK_URL` | Non | URL de l'API Dependency-Track | `https://dep-api.example.com` |
| `DTRACK_API_KEY` | Non (secret) | Cle API Dependency-Track | `odt_xxx` |

---

## 5. Image et registry

| Fichier | Ligne(s) | Valeur actuelle | A adapter |
|---------|----------|-----------------|-----------|
| `azure-pipelines/pipeline.yml` | ~45 | `IMAGE_NAME: 'supply-chain-poc'` | Nom de votre image |
| `azure-pipelines/pipeline.yml` | ~49 | `REGISTRY: '$(ACR_NAME).azurecr.io'` | Ne pas modifier si ACR |
| `Taskfile.yml` | ~26 | `REGISTRY: 'localhost:5000'` (defaut) | Passer en parametre : `task build REGISTRY=myacr.azurecr.io` |
| `Taskfile.yml` | ~27 | `IMAGE_NAME: 'supply-chain-poc'` (defaut) | Passer en parametre |

---

## 6. Chemin du Dockerfile

| Fichier | Ligne(s) | Valeur actuelle | A adapter |
|---------|----------|-----------------|-----------|
| `Taskfile.yml` | ~154 | `docker build -t {{.IMAGE}} ./app` | Modifier `./app` si votre Dockerfile est ailleurs |

---

## 7. Azure Key Vault KMS (signature)

La strategie de signature est : **KMS > keyless CI > keypair**. Le keyless n'est tente que si un fournisseur OIDC CI est detecte (`SYSTEM_OIDCREQUESTURI` pour Azure DevOps).

Pour utiliser KMS :
1. Creer un Key Vault : `az keyvault create -n <name> -g <rg>`
2. Generer la cle cosign : `cosign generate-key-pair --kms azurekms://<vault>.vault.azure.net/<key-name>`
3. Donner les permissions au Service Principal : `az keyvault set-policy -n <vault> --spn <client-id> --key-permissions sign verify get`
4. Ajouter `COSIGN_KV_KEY` au variable group (valeur : `<vault>.vault.azure.net/<key-name>`)

Si `COSIGN_KV_KEY` n'est pas defini, le pipeline utilise le mode keyless (OIDC/Sigstore) en fallback.

> **Air-gap** : le pipeline expose un parametre `airgap` (boolean, defaut false). Quand active, les etapes sign/attest generent des bundles cosign et `airgap-export.sh` cree un package deployable offline. Si `COSIGN_KV_KEY` est defini, la cle publique est exportee automatiquement dans le package. Voir `docs/airgap-deployment.md` pour le flux complet.

| Fichier | Lignes concernees | Ce qui se passe |
|---------|-------------------|-----------------|
| `azure-pipelines/templates/sign.yml` | sign step | Branche `if COSIGN_KV_KEY` pour KMS, sinon keyless |
| `azure-pipelines/templates/attest.yml` | attest SBOM + SLSA steps | Branche `if COSIGN_KV_KEY` pour KMS, sinon keyless |
| `azure-pipelines/templates/verify.yml` | verify 1/3, 2/3, 3/3 steps | Branche `if COSIGN_KV_KEY` pour KMS, sinon keyless |
| `Taskfile.yml` | ~241-257 (`image:sign`), ~298-302 (`sbom:attest`) | Variable `COSIGN_KMS_KEY` passee aux scripts |
| `scripts/sbom-attest.sh` | ~65-71 | Premier `if` verifie `COSIGN_KMS_KEY` |
| `scripts/sbom-sign.sh` | ~42-49 | Premier `if` verifie `COSIGN_KMS_KEY` |

---

## 8. DailyRescan — resolution du digest ACR

Le stage DailyRescan utilise `az acr repository show` pour resoudre le digest de la derniere image. Si votre tag de reference n'est pas `latest`, modifiez :

| Fichier | Ligne(s) | Valeur actuelle | A adapter |
|---------|----------|-----------------|-----------|
| `azure-pipelines/pipeline.yml` | ~299 | `--image "$(IMAGE_NAME):latest"` | Remplacer `latest` par votre tag de reference si different |

---

## 9. Rescan SBOM depuis attestation

Le DailyRescan extrait la SBOM depuis l'attestation Cosign (source de verite cryptographique) plutot que depuis un artifact pipeline. Si vous n'avez pas encore d'attestation publiee, le fallback vers l'artifact pipeline est automatique.

> Aucune modification necessaire — le mecanisme est conditionnel.

---

## 10. Checklist de verification post-portage

```bash
# 1. Verifier que les outils s'installent
task install:verify

# 2. Pipeline local (build + analyse, sans publish)
task pipeline:local IMAGE_NAME=my-app

# 3. Verifier la signature (apres un premier run complet)
cosign verify --key azurekms://<vault>.vault.azure.net/<key> <image>@sha256:...

# 4. Verifier l'attestation SBOM
cosign verify-attestation --key azurekms://<vault>.vault.azure.net/<key> \
  --type cyclonedx <image>@sha256:...
```

---

## Resume des fichiers a modifier

| Fichier | Modifications | Priorite |
|---------|---------------|----------|
| `azure-pipelines/pipeline.yml` | IMAGE_NAME, ACR tag | **Critique** |
| `azure-pipelines/templates/verify.yml` | Identity regexp (parametre `identityRegexp`) | **Critique** |
| `azure-pipelines/templates/azure-login.yml` | Service connection (parametre `azureServiceConnection`) | **Critique** |
| `Taskfile.yml` | Identity regexp, chemin Dockerfile, IMAGE_NAME (defaut) | **Haute** |
| `.github/workflows/supply-chain-reusable.yml` | Identity regexp (si GitHub est aussi utilise) | Moyenne |
| `scripts/sbom-attest.sh` | Aucune (parametres passes par env) | Aucune |
| `scripts/sbom-sign.sh` | Aucune (parametres passes par env) | Aucune |
| `scripts/sbom-upload-dtrack.sh` | Aucune (parametres passes par args) | Aucune |
