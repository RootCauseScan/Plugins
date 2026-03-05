# Panorama

Unified view plugin: **code (SAST)**, **dependencies and vulnerabilities (OSV)**, **SBOM and licenses**. A single process runs discover → analyze → report with in-memory state. Supports multiple output formats and filtering options.

## Installation

**Before using the plugin** run the installation script once (it creates the venv with reportlab and the wrapper):

```bash
cd Plugins/general/panorama
chmod +x install.sh
./install.sh
```

After that, RootCause will use `plugin_wrapper.sh`, which starts the plugin with the venv Python and all dependencies. Without this step the plugin would fail when generating PDF.

## Capabilities

| Phase     | What it does |
|----------|---------------|
| **discover** | Walks the workspace and returns manifest/lock files (package.json, go.mod, Cargo.toml, requirements.txt, etc.). |
| **analyze**  | Parses manifests, builds SBOM, queries OSV and emits findings per vulnerability. |
| **report**   | Generates reports in JSON, CSV, HTML and/or PDF according to options. |

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
| `csv_separator` | string | `,` | CSV field separator. |

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
- **pdf**: `deps-report.pdf` (requires `./install.sh`). Order: introduction, **1. Code vulnerabilities** (SAST), **2. Vulnerabilities in dependencies** (OSV, with Description column), **3. Dependencies and licenses** (SBOM). Numbered pages; logo on cover (same as pdf_report). File names kept for compatibility.
- **xlsx**: `panorama-report.xlsx` (requires openpyxl, installed via `./install.sh`). Four sheets: **FRONTPAGE** (title, date, workspace, summary counts, SAST/SCA severity breakdown), **SAST** (Rule ID, Severity, File, Line, Column, Message, Excerpt, Remediation, Context, Finding ID), **SCA** (Vuln ID, Package, Version, Ecosystem, File, Line, Severity, Description, Fixed In, References, Published, Modified), **LICENSES** (Component Name, Version, Ecosystem, File, Line, License, PURL, Type, Notes).

## Requirements

- Python 3.10+
- **Installation required**: run `./install.sh` in the plugin folder. It creates a venv with reportlab and openpyxl; `plugin.toml` uses `plugin_wrapper.sh` to start with that venv so PDF and Excel generation do not fail for missing libraries.

## Supported manifests

- npm: package.json  
- Python: requirements.txt  
- Go: go.mod, go.sum  
- Rust: Cargo.toml, Cargo.lock  

Other names are discovered; parsing can be extended in the plugin.

## Plugin structure

Single entry file (`plugin.py`) and folders per phase for clear, maintainable code:

```
panorama/
  plugin.py              # Single entry: JSON-RPC loop and dispatch to each phase
  options.py             # Options and parsing (CLI → dict)
  discover/              # Discover phase
    manifests.py         # MANIFEST_NAMES, discover_manifests(), is_manifest()
  analyze/               # Analyze phase
    parsers.py           # Parse package.json, requirements.txt, go.mod, Cargo.*
    osv.py               # OSV API: querybatch and description per vuln
    filters.py           # filter_sbom(), filter_vulns(), severity
    run.py               # analyze_files(files, state) → findings
  report/                # Report phase
    json.py, csv.py, html.py   # One file per format
    pdf/                 # PDF in multiple modules
      styles.py          # Styles and helpers (para, truncate, group_findings, etc.)
      sections.py        # Cover, intro, code vulns, dependency vulns, SBOM
      builder.py         # create_pdf(), write_pdf()
  assets/                # Logo for PDF (optional)
  schema.json, plugin.toml, requirements.txt, install.sh
```
