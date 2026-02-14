# Gouvernance des acces

> Modele d'acces least privilege pour la signature, l'attestation et la publication d'images conteneur.

## Principe : least privilege

**Seuls les pipelines CI/CD signent et publient.** Aucun humain ne signe manuellement une image en production. Les cles de signature (KMS) ne sont accessibles qu'aux identites de pipeline.

| Regle | Application |
|-------|-------------|
| Jamais signer un tag mutable | Toutes les operations cosign ciblent le digest (`image@sha256:...`) |
| Priorite de signature : KMS > CI keyless > keypair | Detectee automatiquement par les scripts (`image-sign.sh`, `sbom-attest.sh`, `slsa-provenance.sh`) |
| Fail-closed | Si aucune methode de signature n'est disponible, le script echoue — pas de mode degrade |
| Post-sign & post-attest verify obligatoires | Etape 16 du pipeline verifie les 3 artefacts dans le registry avant cloture |

## Matrice RACI

| Activite | RSSI | Tech Lead | DevOps/SRE | Dev | PO |
|----------|------|-----------|------------|-----|-----|
| Definir la politique d'acces | **R/A** | C | C | I | I |
| Configurer les service connections CI | I | C | **R/A** | I | I |
| Configurer Azure Key Vault KMS | A | C | **R** | I | I |
| Gerer les identites de pipeline (SPN, OIDC) | A | I | **R** | I | I |
| Approuver les exceptions de securite | **R/A** | C | I | C | I |
| Revue d'acces periodique | **R/A** | C | **R** | I | I |
| Rotation des cles / certificats | A | I | **R** | I | I |
| Investiguer une anomalie d'acces | **R/A** | C | **R** | C | I |

**R** = Responsable, **A** = Approbateur, **C** = Consulte, **I** = Informe

## Controles d'acces par composant

### Azure Container Registry (ACR)

| Role | Qui | Permissions |
|------|-----|-------------|
| `AcrPush` | Service principal du pipeline CI | Push images, push referrers (signatures/attestations) |
| `AcrPull` | Pipelines de deploiement, developpeurs | Pull images uniquement |
| `AcrDelete` | Administrateurs (manuel, exceptionnel) | Suppression d'images (jamais automatise) |

Aucun humain n'a `AcrPush` en production — seul le pipeline publie.

### Azure Key Vault (KMS)

La cle de signature cosign est stockee dans Azure Key Vault. Acces configure via :

```bash
az keyvault set-policy \
  --name <VAULT_NAME> \
  --object-id <PIPELINE_SPN_OBJECT_ID> \
  --key-permissions sign verify get
```

| Permission | Qui | Usage |
|------------|-----|-------|
| `sign` | Service principal du pipeline uniquement | `cosign sign`, `cosign attest` |
| `verify` | Pipeline + auditeurs | `cosign verify`, `cosign verify-attestation` |
| `get` | Pipeline | Recuperer les metadonnees de la cle |
| `list`, `create`, `delete`, `rotate` | Administrateurs Key Vault | Gestion du lifecycle de la cle |

**La cle privee ne quitte jamais le HSM.** Le pipeline envoie le hash a signer, Key Vault retourne la signature.

### Service connections CI

| Plateforme | Mecanisme | Scope |
|------------|-----------|-------|
| **GitHub Actions** | OIDC `id-token: write` | Keyless via Sigstore Fulcio — certificat ephemere lie a l'identite du workflow |
| **Azure DevOps** | Service connection (SPN) + OIDC | KMS via `azurekms://` + keyless via `vstoken.dev.azure.com` |

### Contraintes d'identite OIDC

La verification post-signature (`cosign verify`) applique des contraintes strictes :

```
--certificate-oidc-issuer https://token.actions.githubusercontent.com
--certificate-identity-regexp "github.com/<ORG>/"
```

ou pour Azure DevOps :

```
--certificate-identity-regexp "https://dev.azure.com/<ORG>/<PROJECT>/_build"
```

Une regexp trop permissive (`".*"`) permettrait a n'importe quel pipeline de passer la verification — c'est la **premiere chose a adapter** lors du portage.

## Gestion des secrets

| Secret | Stockage | Rotation |
|--------|----------|----------|
| Cle KMS (cosign) | Azure Key Vault HSM | Rotation periodique via `az keyvault key rotate` |
| SPN credentials | Azure AD / Workload Identity Federation | Preferer workload identity (pas de secret stocke) |
| `REGISTRY_TOKEN` (GitHub) | `GITHUB_TOKEN` automatique | Ephemere (expire a la fin du job) |
| `DTRACK_API_KEY` | GitHub Secrets / ADO Variable Group (secret) | Rotation manuelle, scope minimum (`BOM_UPLOAD`) |
| `cosign.key` (dev/e2e) | Genere localement, jamais committe | Usage local uniquement, pas en production |

**Workload Identity Federation** (sans secret) est prefere a un SPN avec secret. Le token est emis par le fournisseur OIDC du CI et echange contre un token Azure AD scope aux seules permissions necessaires.

## Revue d'acces periodique

| Frequence | Action | Responsable |
|-----------|--------|-------------|
| Trimestrielle | Revue des permissions ACR (qui a push/pull/delete) | RSSI + DevOps/SRE |
| Trimestrielle | Revue des policies Key Vault (qui peut sign/verify) | RSSI + DevOps/SRE |
| Trimestrielle | Revue des service connections ADO / GitHub OIDC | RSSI + DevOps/SRE |
| A chaque changement | Revue de la `--certificate-identity-regexp` | Tech Lead |
| Annuelle | Audit complet des acces et rotation des cles | RSSI |

## Evidence — Comment verifier

| Preuve | Source | Commande / acces |
|--------|--------|------------------|
| Permissions ACR courantes | Azure Portal / CLI | `az acr scope-map list` / `az role assignment list` |
| Key Vault access policies | Azure Portal / CLI | `az keyvault show --name <VAULT>` |
| Key Vault audit logs | Azure Monitor / Log Analytics | Diagnostic settings → `AuditEvent` |
| ACR access logs | Azure Monitor | Diagnostic settings → `ContainerRegistryLoginEvents`, `ContainerRegistryRepositoryEvents` |
| Service connections ADO | ADO Project Settings | Service connections → History |
| GitHub OIDC claims | CI logs | Verifier `--certificate-identity-regexp` dans les logs de `cosign verify` |
| Historique de rotation des cles | Key Vault | `az keyvault key list-versions --name <KEY>` |
