# Panorama

Unified view plugin for the software lifecycle: **dependencies (Syft SBOM + Grype vulns)** and **infra (Dockerfile, Compose, Kubernetes/OpenShift)**. Discover → analyze → report in one run. Supports JSON, CSV, HTML, PDF, Excel; infra reports (images + misconfig + optional Trivy image CVEs) are written to the same `reports/` directory.

## Installation

**Before using the plugin** run the installation script once:

```bash
cd Plugins/general/panorama
chmod +x install.sh
./install.sh
```

This will:

- Create a Python venv and install reportlab, openpyxl, PyYAML (for PDF, Excel, and infra).
- Download **Syft** and **Grype** into `./bin/` (Anchore tools, Go binaries; no Node.js). Syft generates the SBOM, Grype scans it for vulns.

RootCause uses `plugin_wrapper.sh` to start the plugin with the venv. If Syft or Grype are missing, the plugin will log a warning and skip dependency SBOM/vuln analysis (infra analysis is independent).

## Capabilities

| Phase     | What it does |
|----------|---------------|
| **discover** | Manifest/lock files (package.json, go.mod, Cargo.toml, etc.) **and** infra files (Dockerfile, Containerfile, docker-compose, K8s/OpenShift manifests). |
| **analyze**  | **Dependencies**: Syft generates SBOM (CycloneDX), Grype scans it for vulns. **Infra**: parses Dockerfile/compose/K8s, misconfig checks, optional Trivy image CVE scan. |
| **report**   | Deps: JSON, CSV, HTML, PDF, Excel. Infra: `infra-report.json` and `infra-report.html` in the same output dir when infra data exists. |

## Options (plugin arguments)

Passed via CLI as `--plugin-opt panorama.<key>=<value>` or from config file. All are optional.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `output_dir` | string | `reports` | Directory under workspace for report output. |
| `output_formats` | list | all | Formats to generate: `json`, `csv`, `html`, `pdf`, `xlsx` (default: all). |
| `include_sbom` | bool | true | Include SBOM in reports. |
| `include_vulns` | bool | true | Include vulnerabilities in reports. |
| `min_severity` | string | `INFO` | Minimum severity: INFO, LOW, MEDIUM, HIGH, CRITICAL. |
| `ecosystems` | list | [] | Only these ecosystems (e.g. npm, PyPI). Empty = all. |
| `exclude_ecosystems` | list | [] | Exclude these ecosystems. |
| `denied_licenses` | list | [] | License identifiers to treat as policy violations (future use). |
| `report_title` | string | RootCause Panorama Report | Title for HTML/PDF reports. |
| `pdf_template` | string | (plugin) | Path to Markdown template for PDF (default: plugin `templates/panorama-report.md`). |
| `pdf_template_css` | string | (plugin) | Path to CSS for PDF template (default: plugin `templates/panorama-report.css`). |
| `xlsx_template` | string | (plugin) | Path to Markdown template for XLSX (default: plugin `templates/panorama-xlsx-template.md` if present). |
| `csv_separator` | string | `,` | CSV field separator. |
| `syft_path` | string | (plugin) | Path to Syft binary. Empty = plugin-local `bin/syft`. |
| `grype_path` | string | (plugin) | Path to Grype binary. Empty = plugin-local `bin/grype`. |
| `grype_timeout_sec` | int | 300 | Timeout for Grype SBOM scan (seconds). |
| `scan_images` | bool | true | Scan container images for CVEs via Trivy (infra). |
| `trivy_path` | string | `trivy` | Path to Trivy binary. |
| `trivy_timeout_sec` | int | 300 | Timeout per image (seconds). |
| `check_healthcheck` | bool | true | Emit finding when Dockerfile has no HEALTHCHECK. |

### Usage examples

```bash
# Default: all formats (json, csv, html, pdf, xlsx). Run ./install.sh in the plugin folder first.
rootcause scan . --plugin ./Plugins/general/panorama

# Only PDF and Excel
rootcause scan . --plugin ./Plugins/general/panorama \
  --plugin-opt panorama.output_formats=pdf,xlsx

# npm only, output under reports/deps
rootcause scan . --plugin ./Plugins/general/panorama \
  --plugin-opt panorama.ecosystems=npm \
  --plugin-opt panorama.output_dir=reports/deps

# Minimum severity HIGH and custom title
rootcause scan . --plugin ./Plugins/general/panorama \
  --plugin-opt panorama.min_severity=HIGH \
  --plugin-opt panorama.report_title="My Security Report"
```

## Output formats

- **json**: `sbom.json` (CycloneDX 1.4) and `deps-vulns.json` (vuln list).
- **csv**: `sbom.csv` and `deps-vulns.csv` (configurable separator).
- **html**: `deps-report.html` (SBOM and vulnerabilities tables).
- **pdf**: `deps-report.pdf` (requires `./install.sh`). Order: introduction, **1. Code vulnerabilities** (SAST), **2. Vulnerabilities in dependencies** (Grype, with Description column), **3. Dependencies and licenses** (SBOM). Numbered pages; logo on cover (same as pdf_report). File names kept for compatibility.
- **xlsx**: `panorama-report.xlsx` (requires openpyxl, installed via `./install.sh`). Sheets: **FRONTPAGE** (title, date, workspace, summary counts, SAST/SCA severity breakdown), **SAST** (Finding ID, Rule ID, Severity, File, Line, Column, Message, Excerpt, Remediation, Context), **SCA** (Vuln ID, Package, Version, Ecosystem, File, Line, Severity, Description, Fixed In, References, Published, Modified), optional **INFRA** when infra data exists, and **LICENSES** (PURL, Component Name, Version, Ecosystem, Line, Type, License).

### XLSX templates

Panorama puede generar las hojas de Excel a partir de una plantilla Markdown sencilla:

- **Fichero de plantilla**: por defecto `templates/panorama-xlsx-template.md` (se usa automáticamente si existe), o un fichero personalizado configurando `panorama.xlsx_template`.
- **Fuente de datos**: todas las rutas (`source`, `Value path`) se evalúan contra el informe canónico (`sast.findings`, `dependency_vulnerabilities.vulnerabilities`, `infrastructure.images`, `infrastructure.findings`, `sbom.components`, etc.).
- Con plantilla, **todas las hojas/tablas** (SAST, SCA, INFRA, LICENSES, ...) se generan desde la plantilla. Solo `FRONTPAGE` sigue siendo programática.

Hoja con una sola tabla (formato clásico):

```md
## Sheet SAST (source: sast.findings)

| Header      | Value path   | Width | Wrap |
|------------ |------------- |-------|------|
| Finding ID  | id           | 12    | true |
| Rule ID     | rule_id      | 22    | true |
| File        | file         | 38    | true |
| Line        | line         | 8     | true |
| Column      | column       | 8     | true |
| Severity    | severity     | 10    | true |
| Message     | message      | 42    | true |
| Excerpt     | excerpt      | 32    | true |
| Remediation | remediation  | 32    | true |
| Context     | context      | 28    | true |
```

- **Header**: texto de cabecera de la columna.
- **Value path**: ruta al campo dentro de cada elemento de la lista (`id`, `rule_id`, `file`, `line`, `severity`, etc.).
- **Width**: ancho aproximado de la columna (número, en unidades de Excel).
- **Wrap**: `true`/`false` para indicar si se activa el ajuste de texto (por defecto `true` si se omite).

#### Varias tablas en la misma hoja (INFRA)

Para INFRA puedes definir una única hoja con varias tablas apiladas verticalmente, usando bloques con `Source:` (y opcionalmente `Expand:`) justo encima de cada tabla:

```md
## Sheet INFRA

Source: infrastructure.images
| Header | Value path | Width | Wrap |
|--------|----------- |-------|------|
| File   | file       | 32    | true |
| Line   | line       | 10    | true |
| Image  | image_ref  | 24    | true |
| Source | source     | 38    | true |

Source: infrastructure.findings
| Header   | Value path | Width | Wrap |
|----------|----------- |-------|------|
| Rule ID  | rule_id    | 24    | true |
| Severity | severity   | 10    | true |
| File     | file       | 32    | true |
| Line     | line       | 10    | true |
| Message  | message    | 48    | true |

Source: infrastructure.findings
Expand: vulnerabilities
| Header            | Value path           | Width | Wrap |
|-------------------|----------------------|-------|------|
| Image             | image_ref            | 32    | true |
| File              | file                 | 32    | true |
| Line              | line                 | 10    | true |
| Vuln ID           | vulnerability_id     | 22    | true |
| Package           | pkg_name             | 24    | true |
| Severity          | severity             | 10    | true |
| Title/Description | title_or_description | 60    | true |
```

- Cada bloque `Source: ...` + tabla genera una tabla en la misma hoja, una debajo de otra.
- `Expand: vulnerabilities` indica que, para `infrastructure.findings`, se debe aplanar la lista `vulnerabilities` de cada finding, generando una fila por CVE con campos combinados de la imagen y de la vulnerabilidad.
- La columna opcional `Style` permite aplicar estilos básicos; por ejemplo, `style: severity` colorea la celda según el nivel de severidad (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).

La plantilla por defecto `templates/panorama-xlsx-template.md` reproduce las columnas actuales de `SAST`, `SCA`, `LICENSES` y añade una hoja `INFRA` con tres tablas (imágenes, misconfiguraciones, CVEs) como punto de partida editable.

## Requirements

- Python 3.10+
- **Installation**: run `./install.sh` in the plugin folder. It creates a venv (reportlab, openpyxl, PyYAML) and downloads Syft and Grype to `bin/`. If Syft or Grype are missing, dependency analysis is skipped and a warning is logged.

## Supported ecosystems (via Syft + Grype)

Syft detects and generates SBOM for many ecosystems (npm, PyPI, Go, Cargo, Maven, etc.). Grype then scans the SBOM for known vulnerabilities.

**npm:** Syft needs a lock file and/or installed dependencies. Run `npm install` in the project before scanning so Syft can read `package-lock.json` and `node_modules`. Without them you may see "0 components".

## Plugin structure

```
panorama/
  plugin.py              # JSON-RPC loop and dispatch
  options.py             # Options and parsing (CLI → dict)
  discover/               # Discover phase
    manifests.py         # discover_manifests(), is_manifest()
    infra_files.py       # discover_infra_files(), is_infra_file()
  analyze/               # Analyze phase
    cyclonedx_grype.py   # run_syft(), run_grype(), sbom_from_cyclonedx(), vulns_from_grype()
    run.py               # analyze_files() → deps via Syft+Grype
    infra/               # Dockerfile, compose, K8s (Trivy optional)
    filters.py           # filter_sbom(), filter_vulns()
  report/                # Report phase (json, csv, html, pdf, excel; infra_json, infra_html)
  schema.json, plugin.toml, requirements.txt, install.sh
```
