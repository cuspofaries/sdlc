# PSIRT — Politique de reponse aux vulnerabilites

> Product Security Incident Response Team — Processus de triage, remediation et suivi des vulnerabilites dans la supply chain conteneur.

## But et perimetre

Cette politique couvre la gestion des vulnerabilites affectant les images conteneur, SBOM (CycloneDX), attestations (cosign), provenance SLSA, politiques OPA et le pipeline CI/CD lui-meme. Elle s'applique a l'equipe en charge du repo `sdlc` et aux repos consommateurs qui utilisent le workflow reutilisable.

### Definitions

| Terme | Definition |
|-------|-----------|
| **CVE** | Common Vulnerabilities and Exposures — identifiant unique d'une vulnerabilite |
| **VEX** | Vulnerability Exploitability eXchange — declaration de l'impact reel d'un CVE sur un produit |
| **SBOM** | Software Bill of Materials — inventaire complet des composants (CycloneDX JSON) |
| **SLSA provenance** | Attestation cryptographique prouvant qui a construit l'image, depuis quel source, comment |
| **Digest** | Reference immutable d'une image (`sha256:...`) — jamais un tag mutable |
| **Fail-closed** | Le pipeline s'arrete si une verification echoue (pas de mode degrade) |

## Canaux d'entree

| Source | Frequence | Description |
|--------|-----------|-------------|
| `SECURITY.md` | Ad hoc | Signalement externe (voir [SECURITY.md](../SECURITY.md)) |
| **Alertes Dependency-Track** | Continue | Monitoring des SBOM attestes, nouvelles CVE sur composants existants |
| **Scans CI (Trivy)** | Chaque build | `trivy image` (gate bloquant) + `trivy sbom` (gouvernance) |
| **DailyRescan** | Quotidien | Rescan du SBOM depuis l'attestation cosign avec donnees CVE fraiches |
| **Decouverte interne** | Ad hoc | Audit de code, revue de dependances, alerte equipe |
| **GitHub Security Advisories** | Continue | Dependabot / Renovate PRs |

## Workflow de triage et remediation

### Etape 1 — Detection et enregistrement

| Action | Responsable |
|--------|-------------|
| Recevoir l'alerte (DTrack, Trivy, signalement externe, rescan) | DevOps/SRE |
| Creer un ticket dans `<ISSUE_TRACKER>` (Azure Boards / Jira / GitHub Issues) | DevOps/SRE |
| Classifier la severite initiale (CVSS + contexte d'exploitation) | RSSI + Tech Lead |

### Etape 2 — Triage

| Action | Responsable |
|--------|-------------|
| Evaluer l'exploitabilite dans le contexte du produit (VEX analysis) | Tech Lead + Dev |
| Determiner si une exception temporaire est justifiee | RSSI |
| Si exception : creer une entree dans `security-exceptions.yaml` (6 champs obligatoires, PR reviewee) | Dev + RSSI |
| Si correction immediate : planifier le fix dans le sprint courant | Tech Lead |

### Etape 3 — Remediation

| Action | Responsable |
|--------|-------------|
| Appliquer le correctif (mise a jour de dependance, patch, changement de base image) | Dev |
| Verifier que le pipeline passe (scan Trivy + politique OPA + verification cosign) | DevOps/SRE |
| Confirmer que l'image signee et attestee est publiee avec le digest corrige | DevOps/SRE |
| Retirer l'exception de `security-exceptions.yaml` si applicable | Dev |
| Mettre a jour le ticket avec les preuves (digest, logs de verification) | Dev |

### Etape 4 — Cloture

| Action | Responsable |
|--------|-------------|
| Verifier dans DTrack que le CVE n'apparait plus sur le digest courant | DevOps/SRE |
| Fermer le ticket avec lien vers le commit, la PR et le digest signe | Tech Lead |
| Notifier le rapporteur si signalement externe | RSSI |

## SLA par severite

| Severite | Delai de remediation | Escalade si depasse |
|----------|---------------------|---------------------|
| **Critical** (CVSS 9.0-10.0) | `<SLA_CRITICAL>` (defaut : 24h) | RSSI → Direction |
| **High** (CVSS 7.0-8.9) | 72h | RSSI |
| **Medium** (CVSS 4.0-6.9) | 30 jours | Tech Lead |
| **Low** (CVSS 0.1-3.9) | 90 jours | — |

Les SLA demarrent a la **confirmation du triage** (etape 2), pas a la detection brute.

## Gestion des exceptions

Les exceptions temporaires sont gerees via `security-exceptions.yaml` dans le repo consommateur. Double gate : Trivy (`.trivyignore` genere) + OPA (`security-exceptions.rego`).

**Champs requis** (les 6 sont obligatoires) :

```yaml
- id: CVE-2024-XXXXX
  package: "nom-du-package"
  reason: "Justification contextuelle de l'acceptation temporaire"
  approved_by: "security@<ORG>.com"
  expires: "YYYY-MM-DD"
  ticket: "JIRA-1234"
```

**Invariants** :
- Pas d'exception permanente — `expires` est requis
- Le SBOM n'est **jamais modifie** par les exceptions (integrite SHA256 + ImageID preservee)
- Une exception expiree est automatiquement bloquee par les deux gates (defense en profondeur)
- Chaque ajout/modification passe par une PR (piste d'audit git)

## Evidence — Comment verifier

| Preuve | Emplacement | Commande de verification |
|--------|-------------|--------------------------|
| Logs de verification (signature + attestations) | `output/verify/` (CI artifacts) | Consulter les artifacts du pipeline run |
| Attestation SBOM | Registry (cosign referrers) | `cosign verify-attestation --type cyclonedx <image>@sha256:...` |
| Attestation SLSA provenance | Registry (cosign referrers) | `cosign verify-attestation --type slsaprovenance <image>@sha256:...` |
| Signature de l'image | Registry (cosign referrers) | `cosign verify <image>@sha256:...` |
| Referrers complets | Registry | `cosign tree <image>@sha256:...` |
| Historique des exceptions | Git log du repo consommateur | `git log -- security-exceptions.yaml` |
| Tickets de remediation | `<ISSUE_TRACKER>` | Lien dans le champ `ticket` de chaque exception |
| Monitoring continu | Dependency-Track | Dashboard DTrack, lie au digest registry |
