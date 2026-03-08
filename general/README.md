# General Plugins

General-purpose RootCause plugins for infrastructure, dependencies, and reporting.

| Plugin | Description | Capabilities |
|--------|-------------|--------------|
| [infra](./infra/) | Container and orchestration: Dockerfile, Compose, Kubernetes/OpenShift. Misconfig detection and optional image CVE scanning (Trivy). | discover, analyze, report |
| [panorama](./panorama/) | SBOM and dependency analysis with optional OSV vulnerability lookup; PDF/HTML/JSON/CSV reports. | discover, analyze, report |

## Usage

Point RootCause at a plugin directory when scanning:

```bash
# Infra: containers and orchestration (misconfig + optional image CVEs)
rootcause scan . --plugin ./plugins/general/infra

# With image CVE scanning (requires Trivy)
rootcause scan . --plugin ./plugins/general/infra --plugin-opt infra.scan_images=true
```

Each plugin has its own options and README. See the plugin subdirectory for details.

## Requirements

- Python 3.10+
- Dependencies per plugin (see each plugin's `requirements.txt`)
