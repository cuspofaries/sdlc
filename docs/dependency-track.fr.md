# Integration Dependency-Track

Dependency-Track assure le monitoring continu des vulnerabilites dans vos SBOMs. A chaque execution du pipeline, le SBOM image est uploade vers Dependency-Track, qui suit ensuite les nouvelles CVE au fur et a mesure de leur publication.

---

## 1. Prerequis

- Une instance Dependency-Track accessible (auto-hebergee ou managee)
- Une cle API avec les permissions suivantes :
  - **BOM_UPLOAD**
  - **PROJECT_CREATION_UPLOAD** (requis si `autoCreate` est active)

### Obtenir une cle API

1. Se connecter a Dependency-Track
2. Aller dans **Administration > Access Management > Teams**
3. Selectionner ou creer une equipe (ex : "Automation")
4. Verifier que l'equipe a les permissions **BOM_UPLOAD** et **PROJECT_CREATION_UPLOAD**
5. Copier la cle API depuis la page de l'equipe

---

## 2. Configuration GitHub Actions

Le pipeline utilise l'action officielle [`DependencyTrack/gh-upload-sbom`](https://github.com/DependencyTrack/gh-upload-sbom).

### Ajouter le secret

Aller dans les **Settings > Secrets and variables > Actions** du repo GitHub et creer un secret :

| Nom | Valeur |
|-----|--------|
| `DTRACK_API_KEY` | Votre cle API Dependency-Track |

### Etape du workflow

L'etape dans `.github/workflows/supply-chain.yml` :

```yaml
- name: Push SBOM to Dependency-Track
  uses: DependencyTrack/gh-upload-sbom@v3
  with:
    serverHostname: dep-api.example.com
    apiKey: ${{ secrets.DTRACK_API_KEY }}
    projectName: ${{ env.IMAGE_NAME }}
    projectVersion: ${{ env.IMAGE_TAG }}
    bomFilename: output/sbom/image/sbom-image-trivy.json
    autoCreate: true
```

---

## 3. Reference des parametres de l'action GitHub

| Parametre | Requis | Default | Description |
|-----------|--------|---------|-------------|
| `serverHostname` | Oui | - | Adresse du serveur Dependency-Track (sans protocole) |
| `apiKey` | Oui | - | Cle API pour l'authentification |
| `projectName` | Oui* | - | Nom du projet dans Dependency-Track |
| `projectVersion` | Oui* | - | Version du projet (typiquement le SHA git) |
| `bomFilename` | Non | `bom.xml` | Chemin vers le fichier SBOM |
| `autoCreate` | Non | `false` | Creation automatique du projet s'il n'existe pas |
| `protocol` | Non | `https` | `https` ou `http` |
| `port` | Non | `443` | Port du serveur |

\* Soit `projectName` + `projectVersion`, soit un UUID `project` est requis.

---

## 4. Configuration locale (Taskfile)

Le Taskfile expose trois variables pour Dependency-Track, configurables via des variables d'environnement ou en surcharge CLI :

| Variable | Default | Description |
|----------|---------|-------------|
| `DTRACK_URL` | `http://localhost:8081` | URL de l'API Dependency-Track |
| `DTRACK_API_KEY` | _(vide)_ | Cle API pour l'authentification |
| `DTRACK_PROJECT` | `supply-chain-poc` | Nom du projet |

### Taches disponibles

| Tache | Description |
|-------|-------------|
| `task dtrack:up` | Demarrer une instance locale Dependency-Track via Docker Compose |
| `task dtrack:down` | Arreter l'instance locale |
| `task sbom:upload` | Uploader le SBOM image vers Dependency-Track |

### Uploader un SBOM manuellement

```bash
task sbom:upload \
  DTRACK_URL=http://localhost:8081 \
  DTRACK_API_KEY=votre-cle-api \
  DTRACK_PROJECT=supply-chain-poc
```

Cela execute `scripts/sbom-upload-dtrack.sh` qui :
1. Verifie que Dependency-Track est accessible
2. Encode le SBOM en base64
3. Upload via `PUT /api/v1/bom`
4. Retourne un token de traitement

Pour pointer vers une instance distante :

```bash
task sbom:upload \
  DTRACK_URL=https://dep-api.example.com \
  DTRACK_API_KEY=odt_xxxxxxxxxxxx \
  DTRACK_PROJECT=mon-app
```

---

## 5. Instance locale avec Docker Compose

Le fichier `docker-compose.dtrack.yml` fournit un stack local pret a l'emploi.

### Demarrer

```bash
task dtrack:up
```

### Architecture

| Service | Image | Port | Description |
|---------|-------|------|-------------|
| `dtrack-apiserver` | `dependencytrack/apiserver:latest` | `8081` | API REST + moteur de vulnerabilites |
| `dtrack-frontend` | `dependencytrack/frontend:latest` | `8082` | Interface web |

- Identifiants par defaut : **admin / admin** (a changer a la premiere connexion)
- Le serveur API est configure avec **2 Go de RAM** (`-Xmx2g`) pour garder le POC leger (par defaut il necessite 8 Go+)
- Les donnees sont persistees dans un volume Docker `dtrack-data`
- Le premier demarrage prend **2-3 minutes** pendant la synchronisation de la base NVD
- Un health check garantit que le frontend ne demarre qu'apres que l'API est prete

### Arreter

```bash
task dtrack:down
```

---

## 6. Depannage

| Erreur | Cause | Solution |
|--------|-------|----------|
| **HTTP 401** | Cle API invalide ou expiree | Verifier la cle dans Dependency-Track > Administration > Teams |
| **HTTP 403** | Permissions manquantes | Verifier que l'equipe a BOM_UPLOAD et PROJECT_CREATION_UPLOAD |
| **HTTP 415** | Mauvais content type | Utiliser l'action GitHub officielle ou encoder le BOM en base64 dans un body JSON |
| **Connection refused** | Serveur inaccessible | Verifier le hostname et que l'instance est bien demarree |
| **Argument list too long** | BOM trop volumineux pour curl `-d` en inline | Ecrire le payload dans un fichier et utiliser `curl -d @file.json` |
