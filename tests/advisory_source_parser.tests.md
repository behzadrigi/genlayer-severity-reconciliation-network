# Test cases: AdvisorySourceParser

Status values: RUN (executed, the result below was observed) or DEFINED (not executed on chain). Results come from the final Studio test report dated 2026-10-21. ACC1 is the registrar and policy owner 1. ACC2 is the challenger and policy owner 2. A row marked v1 ran on the first deployment of that contract, which has the same function as the final file.

Test data: VID = CVE-2021-44228. OSV = https://api.osv.dev/v1/vulns/GHSA-jfh8-c2jp-5v3q. CVEORG = https://cveawg.mitre.org/api/cve/CVE-2021-44228. G_LOW and G_HIGH are two public gists whose text mentions the vulnerability id: G_LOW states a low rating with a CVSS vector, G_HIGH states Severity: High with no vector.

| ID | Deployment | Steps | Expected result | Actual result | Status | Evidence |
|----|------------|-------|-----------------|---------------|--------|----------|
| P1 | v2 | View score_of_vector for six vectors | 100, 98, 75, 78, 61, INVALID | 100, 98, 75, 78, 61, INVALID. These match the official CVSS 3.1 base scores 10.0, 9.8, 7.5, 7.8, 6.1 | RUN | view, or transaction hash not recorded in the report |
| P2 | v2 | View bucket_of with 0, 39, 40, 69, 70, 89, 90 | NONE, LOW, MEDIUM, MEDIUM, HIGH, HIGH, CRITICAL | NONE, LOW, MEDIUM, MEDIUM, HIGH, HIGH, CRITICAL | RUN | view, or transaction hash not recorded in the report |
| P3 | v2 | View vectors_in_text with the same vector twice | One vector, score 100 | One vector with score 100 | RUN | view, or transaction hash not recorded in the report |
| P4 | v2 | parse_source for OSV, CVEORG, G_LOW, G_HIGH, then parsed_count() | Four accepted, count 4 | OSV digest fb2fa225...15c4 (1 vector, score 100). CVEORG digest 3fe605a6...227c (1 vector, score 100). G_LOW digest 3eb3fb8f...22c6 (1 vector, score 16, LOW). G_HIGH digest dd4a66eb...7ad8 (0 vectors). parsed_count 4 | RUN | view, or transaction hash not recorded in the report |
| P5 | v2 | get_source(OSV) | n_vectors 1, CRITICAL | n_vectors 1, buckets CRITICAL | RUN | view, or transaction hash not recorded in the report |
| P6 | v2 | get_source(G_LOW) and get_source(G_HIGH) | LOW with 1 vector, no vectors | n_vectors 1 and LOW, then n_vectors 0 and empty buckets | RUN | view, or transaction hash not recorded in the report |
| P7 | v2 | parse_source of a URL on a host that does not exist | SOURCE_UNREADABLE | Reverted with SOURCE_UNREADABLE | RUN | view, or transaction hash not recorded in the report |
| P8 | v2 | get_source(OSV + ?v=1) | exists false | exists false, a query string is a distinct resource | RUN | view, or transaction hash not recorded in the report |
| P9 | v2 | parse_source(OSV) again, then get_source(OSV) | version 2 | version 2 | RUN | view, or transaction hash not recorded in the report |
