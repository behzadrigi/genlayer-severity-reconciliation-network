# Test cases: SeverityPolicyGate

Status values: RUN (executed, the result below was observed) or DEFINED (not executed on chain). Results come from the final Studio test report dated 2026-10-21. ACC1 is the registrar and policy owner 1. ACC2 is the challenger and policy owner 2. A row marked v1 ran on the first deployment of that contract, which has the same function as the final file.

Test data: VID = CVE-2021-44228. OSV = https://api.osv.dev/v1/vulns/GHSA-jfh8-c2jp-5v3q. CVEORG = https://cveawg.mitre.org/api/cve/CVE-2021-44228. G_LOW and G_HIGH are two public gists whose text mentions the vulnerability id: G_LOW states a low rating with a CVSS vector, G_HIGH states Severity: High with no vector.

| ID | Deployment | Steps | Expected result | Actual result | Status | Evidence |
|----|------------|-------|-----------------|---------------|--------|----------|
| V0g | v2 | time_probe() then get_last_probe() | A unix time above 1700000000 | 1792450118 | RUN | 0x1a344370e70409d692520ebf8054ffdc0252bcdedef08970846aa33efe04aa67 (https://explorer-studio.genlayer.com/tx/0x1a344370e70409d692520ebf8054ffdc0252bcdedef08970846aa33efe04aa67) |
| G1 | v1 | set_policy(NONE, HOLD) | INVALID_BLOCK_AT | Reverted with INVALID_BLOCK_AT | RUN | view, or transaction hash not recorded in the report |
| G2 | v1 | set_policy(HIGH, ALLOW) | INVALID_ON_SPLIT | Reverted with INVALID_ON_SPLIT | RUN | view, or transaction hash not recorded in the report |
| G3.1 | v2 | ACC1 set_policy(HIGH, HOLD) | Accepted | Accepted | RUN | 0xd7a9dcf5794382e5fe9ee2eaa46c0f688fbbcd2c24ef1f9905e6580e536c0245 (https://explorer-studio.genlayer.com/tx/0xd7a9dcf5794382e5fe9ee2eaa46c0f688fbbcd2c24ef1f9905e6580e536c0245) |
| G3.2 | v2 | ACC2 set_policy(CRITICAL, BLOCK) | Accepted | Accepted | RUN | 0x8631649c5701bf0cf7ae5d94cf8c09072c4d2240fe2256f7d9f6fc07db545f07 (https://explorer-studio.genlayer.com/tx/0x8631649c5701bf0cf7ae5d94cf8c09072c4d2240fe2256f7d9f6fc07db545f07) |
| G10 | v1 | View preview_decision with six policy and result combinations | As listed in the guide | All six as expected. Run on the first deployment of the gate, which has the same function | RUN | view, or transaction hash not recorded in the report |
| G4 | v2 | evaluate(2, ACC1) inside the challenge window | CHALLENGE_WINDOW_OPEN | Reverted with CHALLENGE_WINDOW_OPEN | RUN | 0x50c13952249ffe688cb910800db59d97771ed7c8c3b514db5862c7b332b61985 (https://explorer-studio.genlayer.com/tx/0x50c13952249ffe688cb910800db59d97771ed7c8c3b514db5862c7b332b61985) |
| G5 | v2 | evaluate(1, ACC1) while the challenge is PENDING | CHALLENGE_UNRESOLVED | Reverted with CHALLENGE_UNRESOLVED | RUN | 0x384c0a8aad0c02663d06c1282c449bb92b42ad0000fc9ba00e41f7abcab1c15c (https://explorer-studio.genlayer.com/tx/0x384c0a8aad0c02663d06c1282c449bb92b42ad0000fc9ba00e41f7abcab1c15c) |
| G6 | v2 | evaluate(1, an address with no policy) | POLICY_NOT_SET | Reverted with POLICY_NOT_SET | RUN | 0xa88fcc4d4096805ad2252cd4c375bcafef6d00cb6d409860ae839cb32685a558 (https://explorer-studio.genlayer.com/tx/0xa88fcc4d4096805ad2252cd4c375bcafef6d00cb6d409860ae839cb32685a558) |
| G8 | v2 | evaluate(1, ACC1) after the challenge was resolved | BLOCK, path UPHELD | Succeeded: BLOCK, path UPHELD, reason AT_OR_ABOVE_THRESHOLD | RUN | 0x79fbc3c9419ed2c03d7f055dd206723929d722e062b1fc5e8c2d78278ae0192d (https://explorer-studio.genlayer.com/tx/0x79fbc3c9419ed2c03d7f055dd206723929d722e062b1fc5e8c2d78278ae0192d) |
| G11a | v2 | View lifecycle(1) after resolution | CHALLENGE_RESOLVED, result_final true | CHALLENGE_RESOLVED, result_final true | RUN | view, or transaction hash not recorded in the report |
| G11b | v2 | View lifecycle(2) (reconciled, not challenged) | RECONCILED, result_final false | RECONCILED, result_final false | RUN | view, or transaction hash not recorded in the report |
| G7 | v2 | evaluate(2, ACC1) and evaluate(2, ACC2) after the window closed | HOLD for ACC1, BLOCK for ACC2, path UNCHALLENGED | Not run on chain | DEFINED | none |
| G9 | v2 | evaluate(3, ACC1) after the challenge expired | path EXPIRED | Not run on chain | DEFINED | none |
| G11c | v2 | View lifecycle(3) after expiry | CHALLENGE_EXPIRED | Not run on chain | DEFINED | none |
| G12 | v2 | Change policy, evaluate(1, ACC1) again | evaluations 2 | Not run on chain | DEFINED | none |
| G13 | v2 | evaluate(4, ACC1) unchallenged after the window | path UNCHALLENGED | Not run on chain | DEFINED | none |
