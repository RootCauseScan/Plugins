# Infralyzer Plugin

Unified plugin for **containers and orchestration**: Dockerfile, Containerfile (Podman), docker-compose, Kubernetes/OpenShift. Detects **misconfigurations** and optionally **image vulnerabilities** via Trivy.

## Capabilities

| Phase | Description |
|-------|-------------|
| **discover** | Finds Dockerfile, Containerfile, docker-compose*.yml, compose*.yml, and YAML under k8s/, openshift/, manifests/, deploy/. |
| **analyze** | Parses files, extracts images, runs misconfig rules (unpinned image, USER root, no HEALTHCHECK, privileged, etc.) and optionally scans images with Trivy (CVEs). |
| **report** | Writes JSON and/or HTML reports (images found and infra findings). |

## Usage

```bash
# Without image scanning (misconfig only)
rootcause scan . --plugin ./plugins/general/infra

# With image scanning (requires Trivy installed)
rootcause scan . --plugin ./plugins/general/infra --plugin-opt infralyzer.scan_images=true

# JSON only, custom output directory
rootcause scan . --plugin ./plugins/general/infra \
  --plugin-opt infralyzer.output_formats=json \
  --plugin-opt infralyzer.output_dir=out/infra
```

## Options

Pass with `--plugin-opt infralyzer.<key>=<value>` or via config:

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `output_dir` | string | `reports` | Directory under workspace for report files. |
| `output_formats` | list | `json,html` | Formats: `json`, `html` (and `pdf` if reportlab is added). |
| `scan_images` | bool | `false` | Scan images with Trivy for CVEs. |
| `trivy_path` | string | `trivy` | Path to Trivy binary. |
| `trivy_timeout_sec` | int | 300 | Timeout per image (seconds); large images may take 2–5 min. |
| `report_title` | string | RootCause Infra Report | Report title. |
| `check_healthcheck` | bool | `true` | Emit finding when Dockerfile has no HEALTHCHECK. |

## Misconfig rules (rule_id)

- `infra.image-unpinned` — Image has no tag or uses `latest`.
- `infra.runs-as-root` — Root user in Dockerfile or securityContext in K8s.
- `infra.no-healthcheck` — Dockerfile has no HEALTHCHECK.
- `infra.dockerfile-use-add` — Use of ADD instead of COPY.
- `infra.privileged-container` — Privileged container in K8s.
- `infra.image-vulnerability` — CVE in image (when `scan_images=true` and Trivy finds vulnerabilities).

## Requirements

- Python 3.10+
- PyYAML (see `requirements.txt`)
- **Image CVE scanning:** set `--plugin-opt infralyzer.scan_images=true` and have [Trivy](https://github.com/aquasecurity/trivy) installed and on PATH. If Trivy is missing, the plugin logs a warning and skips image scanning. Images must be pullable (network and, in many environments, Docker).

## Structure

```
infra/   # plugin name: infralyzer
  plugin.py
  plugin.toml
  install.sh
  plugin_wrapper.sh  # created by install.sh
  schema.json
  options.py
  discover/files.py
  analyze/dockerfile.py, compose.py, kubernetes.py, misconfig.py, images.py, run.py
  report/json.py, html.py
  requirements.txt
  README.md
```
