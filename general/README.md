# General Plugins

General-purpose RootCause plugins for the full software lifecycle: dependencies, infra, and reporting.

| Plugin | Description | Capabilities |
|--------|-------------|--------------|
| [panorama](./panorama/) | SBOM and dependency analysis (OSV), **plus infra**: Dockerfile, Compose, Kubernetes/OpenShift (misconfig + optional Trivy image CVEs). PDF/HTML/JSON/CSV reports. | discover, analyze, report |

## Usage

Point RootCause at the plugin directory when scanning:

```bash
# Dependencies + infra (Dockerfile, compose, K8s) in one run
rootcause scan . --plugin ./plugins/general/panorama

# With Trivy image CVE scanning (requires Trivy in PATH)
rootcause scan . --plugin ./plugins/general/panorama --plugin-opt panorama.scan_images=true
```

See [panorama](./panorama/) for all options and README.

## Requirements

- Python 3.10+
- Dependencies: see panorama's `requirements.txt` and `install.sh`
