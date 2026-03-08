<div class="cover-page">
  <img src="assets/logo.png" alt="RootCause" class="cover-logo" />
  <h1>{title}</h1>
  <p class="cover-subtitle">Security and dependency analysis</p>
  <p class="cover-meta">
    <strong>Generated on:</strong> {report_date}<br/>
    <strong>Workspace:</strong> {workspace_root}<br/>
    <strong>Code findings (SAST):</strong> {metadata.summary.sast_findings_count}<br/>
{if dependency_vulnerabilities.vulnerabilities}
    <strong>Vulnerabilities in dependencies:</strong> {metadata.summary.dependency_vulnerabilities_count}<br/>
{endif}
{if sbom.components}
    <strong>Components (SBOM):</strong> {metadata.summary.sbom_components_count}<br/>
{endif}
{if infrastructure.images}
    <strong>Infrastructure:</strong> {metadata.summary.infrastructure_images_count} images, {metadata.summary.infrastructure_findings_count} findings<br/>
{endif}
{if sbom.components}
    <strong>Licenses:</strong> from SBOM<br/>
{endif}
  </p>
</div>

<div class="page-break"></div>

## Executive Summary

This document is the security and dependency report for **{workspace_name}**, generated on {report_date}. It summarises findings from static application security testing (SAST), dependency and container image scanning, and the software bill of materials (SBOM).

The report is organised into four sections: code vulnerabilities (issues in your source code), dependency vulnerabilities (known CVEs in third-party packages), infrastructure (container images and configuration), and licenses. Use the summary counts on the cover and the severity breakdowns in each section to prioritise remediation. For a full machine-readable dataset, use the accompanying JSON report.

### Overview by severity

{if dependency_vulnerabilities.severity_breakdown}
<div class="chart-pie-wrapper">
<h4>Dependency vulnerabilities by severity</h4>
{chart type="pie" from="dependency_vulnerabilities.severity_breakdown" title="Dependency vulnerabilities by severity"}
</div>
{endif}

{if sast_severity_breakdown}
<div class="chart-pie-wrapper">
<h4>Code findings by severity</h4>
{chart type="pie" from="sast_severity_breakdown" title="Code findings by severity"}
</div>
{endif}

<div class="page-break"></div>

## Introduction

This report presents the results of a combined security and dependency analysis of the target workspace. The analysis covers application source code (via static analysis rules), third-party dependencies (SBOM and vulnerability matching), container and infrastructure definitions (Dockerfile, Docker Compose, Kubernetes), and license information derived from the SBOM.

The content is intended for development and security teams to identify risks, plan fixes, and maintain compliance. Findings are presented with severity, location, and remediation guidance where available. Use this document alongside your issue tracker and the canonical JSON output for traceability and automation.

<div class="page-break"></div>

## 1. Code Vulnerabilities

This section lists issues found in the application source code by static analysis (SAST). Each finding includes the rule that triggered it, severity, file and line, and remediation guidance.

Findings are grouped when the same issue appears in multiple locations within the same file. Address high and critical items first; low and informational findings can be scheduled according to your policy.

{if sast_severity_breakdown}
<div class="chart-pie-wrapper">
<h4>Code findings by severity</h4>
{chart type="pie" from="sast_severity_breakdown" title="Code findings by severity"}
</div>
{endif}

{if no_sast_findings}
No code vulnerabilities were reported.
{endif}

{for finding in sast.findings}

### {finding.title}

| Property | Value |
|----------|-------|
| Rule ID | {finding.rule_id} |
| Severity | {finding.severity} |
| File Path | {finding.file_display} |
| Occurrences | {finding.occ_count} |
| Locations (line:col) | {finding.locations_txt} |
| Message | {finding.message} |

{finding.excerpt_md}

{finding.remediation_md}

{finding.context_md}

<div class="page-break"></div>

{end}

{if dependency_vulnerabilities.vulnerabilities}
## 2. Dependencies

This section covers known vulnerabilities in third-party packages identified by dependency scanning (e.g. Grype). The tables below show a breakdown by severity and the full list of affected packages.

Each row includes the vulnerability identifier, affected package and version, ecosystem, and severity. Use this section to prioritise upgrades or patches and to align with your software supply chain policy.

<div class="chart-pie-wrapper">
<h4>Vulnerabilities by severity</h4>
{chart type="pie" from="dependency_vulnerabilities.severity_breakdown" title="Vulnerabilities by severity"}
</div>

### Vulnerabilities by severity (table)

| Severity | Count | % |
|----------|-------|---|
{for row in dependency_vulnerabilities.severity_breakdown}
| {row.severity} | {row.count} | {row.percent}% |
{end}

### Vulnerability list

| Vuln ID | Package | Version | Ecosystem | Severity | Description |
|---------|---------|---------|-----------|----------|-------------|
{for v in dependency_vulnerabilities.vulnerabilities}
| {v.vuln_id} | {v.name} | {v.version} | {v.ecosystem} | {v.severity} | {v.description_short} |
{end}

<div class="page-break"></div>
{endif}

{if has_infra}
## 3. Infrastructure

This section describes infrastructure-related findings: container images referenced in Dockerfile, Docker Compose, or Kubernetes manifests, and configuration issues (e.g. missing HEALTHCHECK, base image choices).

For each image, vulnerability scan results (e.g. from Trivy) are summarised. Only the first 30 vulnerabilities per image are listed in this report; the total count and full details are available in the canonical JSON. Use this section to decide which images to rebuild or replace.

### Images

| File | Line | Image | Source |
|------|------|-------|--------|
{for im in infrastructure.images}
| {im.file} | {im.line} | {im.image_ref} | {im.source} |
{end}

### Configuration findings

| Severity | Rule ID | File | Line |
|----------|---------|------|------|
{for f in infrastructure.config_findings}
| {f.severity} | {f.rule_id} | {f.file} | {f.line} |
{end}

{if infrastructure.image_vulnerability_findings}
### Image vulnerabilities

{for f in infrastructure.image_vulnerability_findings}

**Image: {f.image_ref}**

| Vuln ID | Package | Severity |
|---------|---------|----------|
{for v in f.vulnerabilities}
| {v.vulnerability_id} | {v.pkg_name} | {v.severity} |
{end}
{if f.remaining_vulns_count}
*… and {f.remaining_vulns_count} more vulnerabilities not listed. Address the image or run a full scan for the complete list.*
{endif}

{end}
{endif}

<div class="page-break"></div>
{endif}

{if sbom.components}
## 4. Licenses

This section lists the license inventory derived from the software bill of materials (SBOM). It is intended for compliance and policy review.

Components marked as denied are those whose license is in your configured denied-licenses list and may require legal or architectural review before use or distribution.

| Component | Version | Ecosystem | License | Denied |
|-----------|---------|------------|---------|--------|
{for c in sbom.components}
| {c.name} | {c.version} | {c.ecosystem} | {c.license} | {c.denied} |
{end}
{endif}
