# Test cases: AdvisoryRegistry

Status values: RUN (executed, the result below was observed) or DEFINED (not executed on chain). Results come from the final Studio test report dated 2026-10-21. ACC1 is the registrar and policy owner 1. ACC2 is the challenger and policy owner 2. A row marked v1 ran on the first deployment of that contract, which has the same function as the final file.

Test data: VID = CVE-2021-44228. OSV = https://api.osv.dev/v1/vulns/GHSA-jfh8-c2jp-5v3q. CVEORG = https://cveawg.mitre.org/api/cve/CVE-2021-44228. G_LOW and G_HIGH are two public gists whose text mentions the vulnerability id: G_LOW states a low rating with a CVSS vector, G_HIGH states Severity: High with no vector.

| ID | Deployment | Steps | Expected result | Actual result | Status | Evidence |
|----|------------|-------|-----------------|---------------|--------|----------|
| R1 | v2 | register_advisory(CVE-2021-44228, OSV, CVEORG, empty), then advisory_count() | advisory 1 created | Advisory 1 registered | RUN | view, or transaction hash not recorded in the report |
| R2 | v2 | Repeat R1 | ALREADY_REGISTERED | Reverted with ALREADY_REGISTERED | RUN | view, or transaction hash not recorded in the report |
| R3 | v2 | register_advisory with vuln id ab | INVALID_VULN_ID | Reverted with INVALID_VULN_ID | RUN | view, or transaction hash not recorded in the report |
| R4 | v2 | register_advisory with an http:// first URL | INVALID_URL_1 | Reverted with INVALID_URL_1 | RUN | view, or transaction hash not recorded in the report |
| R5 | v2 | register_advisory with two gist URLs (same base domain) | SOURCES_NOT_INDEPENDENT | Reverted with SOURCES_NOT_INDEPENDENT | RUN | view, or transaction hash not recorded in the report |
| R6 | v2 | View preview_sources(G_LOW, G_HIGH, empty) and preview_sources(OSV, CVEORG, empty) | SOURCES_NOT_INDEPENDENT, then OK | SOURCES_NOT_INDEPENDENT, then OK | RUN | view, or transaction hash not recorded in the report |
| R7 | v2 | Register advisories 2 (G_LOW, OSV, CVEORG), 3 (G_HIGH, OSV), 4 (G_HIGH, CVEORG), 5 (two example hosts) | Advisories 2 to 5 created, three source advisory accepted | All four registered, advisory 2 has three sources | RUN | view, or transaction hash not recorded in the report |
| R8 | v2 | register_advisory(CVE-2021-44228, CVEORG, OSV, empty) (reversed order) | ALREADY_REGISTERED | Reverted with ALREADY_REGISTERED | RUN | view, or transaction hash not recorded in the report |
