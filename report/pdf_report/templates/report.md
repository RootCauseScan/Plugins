<div class="cover-page">
  <img src="assets/logo.png" alt="RootCause" class="cover-logo" />
  <h1>RootCause SAST Report</h1>
  <p class="cover-subtitle">Security analysis of {workspace_name}</p>
</div>

<div class="page-break"></div>

## Executive Summary

**Report metadata**  
Generated on {report_date}
Workspace: {workspace_root}  
Unique issues: **{total_unique}**
Total occurrences: **{total_occurrences}**

This report presents the results of a Static Application Security Testing (SAST) analysis performed on the codebase. The analysis identifies potential security vulnerabilities, misconfigurations, and compliance issues based on a defined rule set. Findings are grouped by rule and location to support prioritisation and remediation.

This security analysis identified **{total_unique}** unique security issue(s), representing **{total_occurrences}** total occurrence(s) across the codebase.

### Severity Breakdown

| Severity | Unique Issues | Occurrences | % of Occurrences |
|----------|---------------|-------------|------------------|
{for row in severity_breakdown}
| {row.severity} | {row.unique} | {row.occurrences} | {row.percent}% |
{end}

### Analysis Metrics

- **Analysis Time:** {metrics.ms}ms
- **Files Analyzed:** {metrics.files}

<div class="page-break"></div>

## Detailed Findings

Findings are grouped when the same file contains the same vulnerability across multiple line locations.

{for finding in findings}

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

{if no_findings}
No security issues were found during the analysis.
{endif}
