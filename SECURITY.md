# Security Policy

## Signaler une vulnerabilite

Si vous decouvrez une vulnerabilite de securite dans ce projet, merci de la signaler de maniere responsable.

### Contact

- **Email** : `<SECURITY_EMAIL>` (ex : `security@<ORG>.com`)
- **PGP** : Cle publique disponible sur `<URL_PGP_KEY>` (optionnel)
- **Ne pas** ouvrir de GitHub Issue publique pour les vulnerabilites de securite

### Informations a fournir

Pour accelerer le triage, incluez dans votre rapport :

| Champ | Exemple |
|-------|---------|
| Image digest | `ghcr.io/<ORG>/app@sha256:abc123...` |
| Version / tag | `v1.2.3` (pour reference, le digest fait foi) |
| SBOM concerne | Hash SHA256 du fichier SBOM si applicable |
| Composant affecte | Nom du package, version, purl |
| Etapes de reproduction | Commandes exactes, Dockerfile, configuration |
| Impact estime | RCE, fuite de donnees, escalade de privileges, etc. |
| CVE existant | Si un identifiant CVE est deja attribue |

### Perimetre

Ce qui est couvert par cette politique :

- **Images conteneur** produites par le pipeline (build, scan, signature)
- **SBOM** (CycloneDX) — generation, integrite, attestation
- **Pipeline CI/CD** — workflows GitHub Actions, templates Azure DevOps, Taskfile
- **Politiques OPA** — regles Rego baseline et mecanisme d'exceptions
- **Scripts de signature/attestation** — cosign sign, attest, verify
- **Infrastructure de monitoring** — integration Dependency-Track

Ce qui n'est **pas** couvert :

- Vulnerabilites dans les outils upstream (Trivy, Cosign, OPA) — reporter directement aux mainteneurs
- Repos consommateurs — chaque projet gere ses propres vulnerabilites applicatives

## Delais de reponse

| Etape | Delai |
|-------|-------|
| Accuse de reception | 48 heures |
| Reponse initiale (triage + severite) | 5 jours ouvres |
| Remediation Critical | `<SLA_CRITICAL>` (defaut : 24h) |
| Remediation High | 72h |
| Remediation Medium | 30 jours |
| Remediation Low | 90 jours |

Les SLA de remediation sont documentes en detail dans [docs/psirt-policy.md](docs/psirt-policy.md).

## Disclosure coordonnee

- **Delai de disclosure** : 90 jours apres le signalement initial
- Nous travaillons avec le rapporteur pour coordonner la publication
- Si un correctif est disponible avant les 90 jours, la disclosure peut etre avancee d'un commun accord
- Les CVE sont demandes via le processus standard (MITRE / GitHub Security Advisories)

## Safe harbor

Toute personne signalant de bonne foi une vulnerabilite selon cette politique :

- Ne fera pas l'objet de poursuites legales liees a cette recherche
- Recevra une reponse dans les delais indiques
- Sera creditee dans l'advisory (sauf demande contraire)

Conditions : pas d'exfiltration de donnees, pas de degradation de service, pas d'acces a des comptes tiers.

## Gouvernance associee

| Document | Contenu |
|----------|---------|
| [docs/psirt-policy.md](docs/psirt-policy.md) | Workflow complet de triage et remediation |
| [docs/access-governance.md](docs/access-governance.md) | Controles d'acces, gestion des cles, RACI |
| [docs/logging-retention.md](docs/logging-retention.md) | Retention des logs, integrite, extraction audit |
