# Panorama XLSX Template

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

## Sheet SCA (source: dependency_vulnerabilities.vulnerabilities)

| Header    | Value path  | Width | Wrap |
|---------- |------------ |-------|------|
| Vuln ID   | vuln_id     | 22    | true |
| Package   | name        | 24    | true |
| Version   | version     | 14    | true |
| Ecosystem | ecosystem   | 12    | true |
| File      | file        | 32    | true |
| Line      | line        | 8     | true |
| Severity  | severity    | 8     | true |
| Desc      | description | 48    | true |
| Fixed In  | fixed_in    | 14    | true |
| Published | published   | 12    | true |
| Modified  | modified    | 12    | true |
| Ref       | references  | 28    | true |

## Sheet LICENSES (source: sbom.components)

| Header    | Value path | Width | Wrap |
|---------- |----------- |-------|------|
| PURL      | purl       | 48    | true |
| Component | name       | 28    | true |
| Version   | version    | 14    | true |
| Ecosystem | ecosystem  | 12    | true |
| Line      | line       | 8     | true |
| Type      | type       | 10    | true |
| License   | license    | 14    | true |

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

