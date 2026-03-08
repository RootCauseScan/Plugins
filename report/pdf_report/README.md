# PDF Report Plugin

This plugin generates professional PDF reports from SAST (Static Application Security Testing) findings.

## Features

- **Editable Markdown template**: Customise the report via `templates/report.md` and `templates/report.css`
- **Variables and loops**: Use `{variable}`, `{for finding in findings}` ... `{end}`, `{if x}` ... `{endif}`
- **Optional commands**: Insert output of shell commands with `{cmd:...}` (e.g. date, hashes) when `allow_commands` is enabled
- **Full Markdown + CSS**: Tables, images, headings, lists; style everything with CSS (WeasyPrint)
- **Fallback**: If the template engine is unavailable or fails, the built-in ReportLab report is used
- **Professional Layout**: Clean, modern PDF design; executive summary, severity breakdown, detailed findings
- **Smart Path Display**: Relative paths from workspace root; code excerpts, remediation, context

## Installation

1. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Make the plugin executable:
   ```bash
   chmod +x plugin.py
   ```

## Usage

The plugin implements the `report` capability and can be used with RootCause to generate PDF reports from SAST analysis results.

### Input Format

The plugin expects findings in the following JSON format:

```json
{
  "findings": [
    {
      "id": "unique-finding-id",
      "rule_id": "security.sql-injection",
      "severity": "high",
      "file": "/workspace/src/api/users.py",
      "line": 42,
      "column": 15,
      "excerpt": "SELECT * FROM users WHERE id = " + user_input",
      "message": "Potential SQL injection vulnerability",
      "remediation": "Use parameterised queries to prevent SQL injection"
    }
  ],
  "metrics": {
    "issues": 15,
    "files": 8,
    "ms": 1250
  }
}
```

### Output

The plugin generates:
- A PDF file saved to the workspace root with timestamp
- Base64-encoded PDF content for programmatic access
- Report metadata including file size and processing metrics

## Configuration

Options (e.g. in rootcause config under `[plugins.pdf-report]` or via CLI):

- **output**: Output path for the PDF (default: `reports/report.pdf`; `reports/` is created if missing)
- **template**: Path to your Markdown template (default: plugin `templates/report.md`)
- **template_css**: Path to CSS file (default: plugin `templates/report.css`)
- **allow_commands**: If `true`, allows `{cmd:shell command}` in the template (e.g. `{cmd:python -c "import datetime; print(datetime.date.today())"}`). Use with care.

## Template syntax

- **Variables**: `{report_date}`, `{workspace_root}`, `{total_unique}`, `{total_occurrences}`, `{metrics.ms}`, `{finding.rule_id}`, `{finding.message}`, etc.
- **Loop**: `{for finding in findings}` ... `{end}` — each finding has: `title`, `rule_id`, `severity`, `file_display`, `occ_count`, `locations_txt`, `message`, `excerpt_md`, `remediation_md`, `context_md`
- **Conditional**: `{if no_findings}` ... `{endif}`; inside loops you can use `{if finding.remediation_md}` etc. (by value)
- **Severity table**: `{for row in severity_breakdown}` with `row.severity`, `row.unique`, `row.occurrences`, `row.percent`
- **Page break**: `<div class="page-break"></div>` in the template (styled in CSS with `page-break-after: always`)
- **Images**: Standard Markdown `![alt](path)`; paths are relative to the plugin directory (e.g. `assets/logo.png`)
- **Commands** (only if `allow_commands` is true): `{cmd:python -c "import hashlib; print(hashlib.sha256(b'x').hexdigest())"}` — output is inserted as text

## Report Structure

1. **Title Page**: Report title, generation date, and workspace information
2. **Executive Summary**: Total findings count and severity distribution with professional tables
3. **Analysis Metrics**: Processing statistics and performance data
4. **Detailed Findings**: Individual security issues with:
   - Rule ID and severity level
   - File path (relative to workspace root)
   - Line and column numbers
   - Code excerpt showing the problematic code
   - Detailed message explaining the issue
   - Remediation steps (when available)
5. **Footer**: Report generation information

## Recent Improvements

- **Fixed Path Display**: Corrected field mapping from `path` to `file` to properly display file paths
- **Enhanced Information**: Added support for column numbers, code excerpts, and remediation steps
- **Smart Path Handling**: Automatically converts absolute paths to relative paths from workspace root
- **Brand Integration**: Updated to use official RootCause brand colors and logo
- **Professional Cover Page**: Added logo and improved title page design
- **Better Error Handling**: Added comprehensive logging and improved error reporting
- **Professional Tables**: Enhanced table styling with brand colors and better formatting

## Dependencies

- `reportlab`: Built-in PDF generation (fallback)
- `markdown`, `weasyprint`: For template-based PDF (MD + CSS → PDF). If missing, the plugin uses the built-in report.
- Standard Python libraries: `json`, `sys`, `os`, `base64`, `datetime`

## Example Output

The generated PDF includes:
- Professional header with RootCause branding
- Color-coded severity indicators
- Tabular data presentation
- Code context highlighting
- Proper page breaks and formatting
- Executive summary with key metrics

## Error Handling

The plugin includes comprehensive error handling for:
- PDF generation failures
- File system access issues
- Invalid input data
- Memory and timeout constraints

## License

This plugin is part of the RootCause SAST toolkit and follows the same licensing terms.
