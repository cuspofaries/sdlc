# Supply Chain Security Toolchain — Resume executif

> **Version** : 1.0 | **Mise a jour** : Fevrier 2026
> **Public cible** : RSSI, equipes conformite, decideurs techniques

---

## Ce que c'est

Une pipeline automatisee, prete pour la production, qui securise la supply chain logicielle conteneurisee du build au deploiement. Le toolchain applique des gates de securite, genere des preuves cryptographiques de conformite et fournit des pistes d'audit completes — concu pour les organisations soumises au **Cyber Resilience Act (CRA)** et a la **directive NIS2**.

> **Principe fondamental** : Rien n'atteint la production sans avoir ete scanne, valide contre des politiques, et signe cryptographiquement avec provenance verifiable.

---

## Valeur metier

| Benefice | Impact |
|----------|--------|
| **Conformite reglementaire** | CRA Article 10 (SBOM), NIS2 Article 21 (securite supply chain), NIST SSDF |
| **Reduction du temps de reponse** | Alertes de vulnerabilites liees directement aux images deployees via digest registry |
| **Pret pour l'audit** | Chaine de preuves complete : scans, decisions de politique, signatures, logs de transparence |
| **Reduction du risque** | Bloque les artefacts vulnerables ou non conformes avant le deploiement en production |
| **Velocite developpeur** | Les gates automatiques eliminent les revues manuelles de securite pour les builds conformes |
| **Multi-plateforme** | Garanties de securite identiques sur GitHub Actions, Azure DevOps et local/air-gap |

---

## Garanties de securite

| Garantie | Mecanisme technique | Preuve d'audit |
|----------|--------------------|--------------------|
| **Aucun logiciel vulnerable deploye** | SAST (code source) + SCA (dependances) bloquent le pipeline avant publication | `scan-sast.json` + `trivy-scan-results.json` dans les CI artifacts |
| **Inventaire logiciel complet** | SBOM (CycloneDX) genere et lie cryptographiquement a l'image | Attestation cosign dans le registry (`cosign verify-attestation`) |
| **Integrite du SBOM** | Verification SHA256 + ImageID empeche toute modification | `sbom-sha256.txt` enregistre a la generation, re-verifie avant attestation |
| **Packages dangereux bloques** | Regles OPA (attaques supply chain, licences copyleft, versions manquantes) | `opa-results.json` montrant les regles deny/warn appliquees |
| **Provenance de build** | Attestation SLSA prouve qui a construit, depuis quelle source, quand | `cosign verify-attestation --type slsaprovenance` |
| **Seuls les builders autorises** | Contraintes d'identite OIDC (`--certificate-identity-regexp`) | Entrees Rekor scopees a l'organisation/projet |
| **References immutables** | Toutes les signatures ciblent des digests (`sha256:...`), jamais des tags mutables | Digest resolu via `docker inspect`, journalise dans chaque operation |
| **Auditabilite publique** | Toutes les signatures uploadees dans le log de transparence Rekor | `rekor-cli search --sha sha256:...` |
| **Responsabilite des exceptions** | Exceptions limitees dans le temps, versionnees git, avec approbation et expiration obligatoires | Historique git de `security-exceptions.yaml`, logs OPA |
| **Monitoring post-deploiement** | Rescans quotidiens avec les dernieres donnees CVE, SBOM extrait depuis l'attestation | Dashboard Dependency-Track lie au digest registry |

---

## Mapping de conformite

### Cyber Resilience Act (CRA)

| Article | Exigence | Couverture |
|---------|----------|------------|
| **Article 10(2)** | Le fabricant doit generer un SBOM | SBOM CycloneDX auto-genere via Trivy a chaque build |
| **Article 10(3)** | Le SBOM doit etre verifiable | SBOM atteste cryptographiquement au digest de l'image via Cosign |
| **Article 13** | Gestion des vulnerabilites | Scan automatise + processus structure d'exceptions ([PSIRT policy](psirt-policy.md)) |
| **Article 14** | Mises a jour de securite | Rescans quotidiens detectent les nouvelles CVE ; DTrack alerte sur les composants vulnerables |

### Directive NIS2

| Article | Exigence | Couverture |
|---------|----------|------------|
| **Article 21(2)(a)** | Mesures de securite supply chain | Pipeline multi-gate : scan → politique → signature avant publication |
| **Article 21(2)(d)** | Securite du developpement et de l'exploitation | Provenance de build (SLSA), gouvernance des acces (KMS/OIDC) |
| **Article 23(1)** | Signalement d'incidents | Politique de journalisation et retention avec stockage a integrite protegee |

### NIST Secure Software Development Framework (SSDF)

| Pratique | Implementation |
|----------|---------------|
| **PO.3** (Exigences de securite) | Politiques OPA appliquent les exigences sur les composants (versions, licences, blocklists) |
| **PS.1** (Proteger l'integrite du code) | Signatures sur digests immutables, provenance SLSA |
| **PS.2** (Build verifiable) | Attestations SBOM + provenance, log de transparence |
| **PW.4** (Scanner les vulnerabilites) | Scan Trivy pre-publication (bloquant) + rescans quotidiens post-publication (monitoring) |
| **RV.1** (Identifier les vulnerabilites) | Monitoring continu Dependency-Track, alertes CVE |

---

## Preuves pour les auditeurs

Chaque run de pipeline produit des **artefacts cryptographiquement verifiables**. Les auditeurs peuvent verifier la conformite independamment, sans acces au systeme CI.

| # | Preuve | Emplacement | Ce que ca prouve |
|---|--------|-------------|------------------|
| 1 | **Signature de l'image** | Registry referrers + Rekor | L'image a ete produite par le pipeline CI autorise |
| 2 | **Attestation SBOM** | Registry referrers | Ce SBOM decrit exactement cette image (invariant d'integrite) |
| 3 | **Provenance SLSA** | Registry referrers | Chaine tracable de l'image deployee au commit source et au run CI |
| 4 | **Resultats de scan** | CI artifacts (`output/`) | Toutes les CVE trouvees, severite, version corrigee |
| 5 | **Decisions de politique** | CI artifacts (`output/`) | Regles declenchees (deny/warn), packages bloques, violations de licence |
| 6 | **Logs de verification** | CI artifacts (`output/verify/`) | Preuve que signature + attestations ont ete verifiees dans le registry apres publication |
| 7 | **Piste d'audit des exceptions** | Historique git | Qui a ajoute l'exception, quand, approuvee par qui, date d'expiration |
| 8 | **Log de transparence** | Rekor (registre public) | Enregistrement immutable de quand la signature a ete creee, par quelle identite |

**Verification independante par l'auditeur** (aucun acces a nos systemes requis) :

```bash
# Verifier la signature de l'image
cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "github.com/<ORG>/" \
  <REGISTRY>/<IMAGE>@sha256:...

# Verifier l'attestation SBOM
cosign verify-attestation --type cyclonedx \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "github.com/<ORG>/" \
  <REGISTRY>/<IMAGE>@sha256:...

# Verifier la provenance SLSA
cosign verify-attestation --type slsaprovenance \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "github.com/<ORG>/" \
  <REGISTRY>/<IMAGE>@sha256:...

# Consulter le log de transparence public
rekor-cli search --sha sha256:...
```

Detail complet : [docs/logging-retention.md](logging-retention.md)

---

## Scenarios de risque couverts

| Scenario d'attaque | Mecanisme de prevention | Point de detection |
|--------------------|------------------------|-------------------|
| **Dependance vulnerable deployee** | Scan Trivy bloque les CVEs HIGH/CRITICAL | Etape 6 (pipeline s'arrete avant le push) |
| **Injection de package malveillant** | Regles OPA blocklist (`event-stream`, `colors`, `faker`...) | Etape 8 (pipeline s'arrete avant le push) |
| **Falsification du SBOM** | Verification SHA256 + ImageID | Etape 5 + Etape 12 (pipeline s'arrete si ecart) |
| **Image non signee deployee** | Verification post-publication fail-closed | Etape 16 (pipeline s'arrete si verification echoue) |
| **Attaquant avec acces en ecriture au registry** | Verification de signature exige l'identite OIDC du CI | Admission controller rejette les images non signees |
| **Violation de licence copyleft** | Politique OPA bloque GPL/AGPL/SSPL dans le code applicatif | Etape 8 (risque legal signale avant publication) |
| **Vulnerabilite zero-day** | Rescans quotidiens avec la derniere base CVE | Stage DailyRescan (alertes, non bloquant) |
| **Exception de securite permanente** | Toutes les exceptions exigent une date d'expiration | Regle OPA deny + YAML versionne git |

---

## Modele operationnel

**Pour les equipes de developpement**
- **Transparent pour les builds conformes** : si le code passe scan + politique, aucune intervention manuelle
- **Feedback clair** : violations CVE/politique affichees dans les checks de PR
- **Politiques custom** : les equipes peuvent ajouter des regles specifiques au projet (packages bloques, restrictions de licence)

**Pour les equipes securite**
- **Gouvernance centralisee** : politiques baseline appliquees automatiquement sur tous les repos
- **Gestion des exceptions** : processus structure, limite dans le temps, auditable ([PSIRT policy](psirt-policy.md))
- **Monitoring continu** : dashboard Dependency-Track agregant les donnees de vulnerabilites sur toutes les images

**Pour les equipes conformite / audit**
- **Packages de preuves pre-generes** : chaque run de pipeline produit une piste d'audit complete dans les CI artifacts
- **Verification independante** : les auditeurs peuvent verifier signatures/attestations sans acceder aux systemes CI
- **Policy-as-code** : toutes les regles de securite sont versionnees git, reviewees et testables

---

## Cout de mise en oeuvre

| Phase | Effort | Livrable |
|-------|--------|----------|
| **Setup initial** (une fois) | 1-2 jours | Toolchain installe, politiques baseline configurees, KMS/OIDC en place |
| **Integration par application** | 2-4 heures | Fichier workflow ajoute, premier build signe reussi |
| **Developpement de politiques custom** | Variable | Regles OPA specifiques au projet (optionnel) |
| **Setup Dependency-Track** | 1 jour | Instance DTrack operationnelle, projets crees, ingestion SBOM configuree |
| **Formation** | 4 heures | Workshop developpeur sur le workflow pipeline et le processus d'exceptions |

**Maintenance continue** : mises a jour d'outils via Renovate (automatise), affinage des politiques (selon besoin).

---

## Objectifs mesurables

| Indicateur | Objectif | Mecanisme |
|------------|----------|-----------|
| Couverture SBOM | 100% des deployements conteneur | SBOM genere automatiquement a chaque build (CRA Article 10) |
| Images vulnerables en production | Zero (HIGH/CRITICAL) | CVEs bloquees au gate avant publication |
| Temps de preparation d'audit | Reduction significative | Preuves pre-generees dans le pipeline |
| Delai de detection (MTTD) nouvelles CVE | < 24 heures | Rescans quotidiens via DailyRescan |
| SLA d'approbation d'exception | < 2 jours ouvres | Processus structure ([PSIRT policy](psirt-policy.md)) |

---

## Prochaines etapes

1. **Revue technique** : [README.md](../README.md) pour les details d'implementation
2. **Politiques de gouvernance** : [access-governance.md](access-governance.md), [psirt-policy.md](psirt-policy.md)
3. **Piste d'audit** : [logging-retention.md](logging-retention.md) pour la retention et l'integrite
4. **Proof-of-concept** : deployer sur un environnement de test avec une application exemple (2-4 heures)
5. **Verification externe** : utiliser `cosign verify` sur le log public Rekor pour confirmer les garanties cryptographiques

---

## Contact technique

- **Technical Lead** : Anthony (Pre-Sales Technical Architect, Axians)
- **Repository** : [github.com/cuspofaries/sdlc](https://github.com/cuspofaries/sdlc)
- **Signalement securite** : voir [SECURITY.md](../SECURITY.md) pour la disclosure responsable

---

| Version | Date | Changements |
|---------|------|-------------|
| 1.0 | Fevrier 2026 | Resume executif initial |
