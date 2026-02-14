# Dependency-Track Integration

Dependency-Track provides continuous monitoring of vulnerabilities in your SBOMs. Each time the pipeline runs, the image SBOM is uploaded to Dependency-Track, which then tracks new CVEs as they are published.

---

## 1. Prerequisites

- A running Dependency-Track instance (self-hosted or managed)
- An API key with the following permissions:
  - **BOM_UPLOAD**
  - **PROJECT_CREATION_UPLOAD** (required when `autoCreate` is enabled)

### Getting an API key

1. Log into Dependency-Track
2. Go to **Administration > Access Management > Teams**
3. Select or create a team (e.g. "Automation")
4. Ensure the team has **BOM_UPLOAD** and **PROJECT_CREATION_UPLOAD** permissions
5. Copy the API key from the team page

---

## 2. GitHub Actions Configuration

The pipeline uses the official [`DependencyTrack/gh-upload-sbom`](https://github.com/DependencyTrack/gh-upload-sbom) action.

### Add the secret

Go to your GitHub repository **Settings > Secrets and variables > Actions** and create a secret:

| Name | Value |
|------|-------|
| `DTRACK_API_KEY` | Your Dependency-Track API key |

### Workflow step

The step in `.github/workflows/supply-chain.yml`:

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

## 3. GitHub Action Parameters Reference

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `serverHostname` | Yes | - | Dependency-Track server address (without protocol) |
| `apiKey` | Yes | - | API key for authentication |
| `projectName` | Yes* | - | Project name in Dependency-Track |
| `projectVersion` | Yes* | - | Project version (typically the git SHA) |
| `bomFilename` | No | `bom.xml` | Path to the SBOM file |
| `autoCreate` | No | `false` | Auto-create project if it doesn't exist |
| `protocol` | No | `https` | `https` or `http` |
| `port` | No | `443` | Server port |

\* Either `projectName` + `projectVersion` or a `project` UUID is required.

---

## 4. Local Configuration (Taskfile)

The Taskfile exposes three variables for Dependency-Track, configurable via environment variables or CLI overrides:

| Variable | Default | Description |
|----------|---------|-------------|
| `DTRACK_URL` | `http://localhost:8081` | Dependency-Track API URL |
| `DTRACK_API_KEY` | _(empty)_ | API key for authentication |
| `DTRACK_PROJECT` | `supply-chain-poc` | Project name |

### Available tasks

| Task | Description |
|------|-------------|
| `task dtrack:up` | Start a local Dependency-Track instance via Docker Compose |
| `task dtrack:down` | Stop the local instance |
| `task sbom:upload` | Upload the image SBOM to Dependency-Track |

### Upload SBOM manually

```bash
task sbom:upload \
  DTRACK_URL=http://localhost:8081 \
  DTRACK_API_KEY=your-api-key \
  DTRACK_PROJECT=supply-chain-poc
```

This runs `scripts/sbom-upload-dtrack.sh` which:
1. Checks Dependency-Track is reachable
2. Base64-encodes the SBOM
3. Uploads via `PUT /api/v1/bom`
4. Returns a processing token

To point at a remote instance:

```bash
task sbom:upload \
  DTRACK_URL=https://dep-api.example.com \
  DTRACK_API_KEY=odt_xxxxxxxxxxxx \
  DTRACK_PROJECT=my-app
```

---

## 5. Local Instance with Docker Compose

The file `docker-compose.dtrack.yml` provides a ready-to-use local stack.

### Start

```bash
task dtrack:up
```

### Architecture

| Service | Image | Port | Description |
|---------|-------|------|-------------|
| `dtrack-apiserver` | `dependencytrack/apiserver:latest` | `8081` | REST API + vulnerability engine |
| `dtrack-frontend` | `dependencytrack/frontend:latest` | `8082` | Web UI |

- Default credentials: **admin / admin** (change on first login)
- The API server is configured with **2 GB RAM** (`-Xmx2g`) to keep the POC lightweight (default requires 8 GB+)
- Data is persisted in a Docker volume `dtrack-data`
- The first startup takes **2-3 minutes** while the NVD database syncs
- A health check ensures the frontend only starts after the API is ready

### Stop

```bash
task dtrack:down
```

---

## 6. Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| **HTTP 401** | Invalid or expired API key | Verify the key in Dependency-Track > Administration > Teams |
| **HTTP 403** | Missing permissions | Ensure the team has BOM_UPLOAD and PROJECT_CREATION_UPLOAD |
| **HTTP 415** | Wrong content type | Use the official GitHub Action or base64-encode the BOM in JSON body |
| **Connection refused** | Server unreachable | Check the hostname and that the instance is running |
| **Argument list too long** | BOM too large for inline curl `-d` | Write payload to a file and use `curl -d @file.json` |
