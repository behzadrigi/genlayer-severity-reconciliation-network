# Test cases: ReconciliationChallenge

Status values: RUN (executed, the result below was observed) or DEFINED (not executed on chain). Results come from the final Studio test report dated 2026-10-21. ACC1 is the registrar and policy owner 1. ACC2 is the challenger and policy owner 2. A row marked v1 ran on the first deployment of that contract, which has the same function as the final file.

Test data: VID = CVE-2021-44228. OSV = https://api.osv.dev/v1/vulns/GHSA-jfh8-c2jp-5v3q. CVEORG = https://cveawg.mitre.org/api/cve/CVE-2021-44228. G_LOW and G_HIGH are two public gists whose text mentions the vulnerability id: G_LOW states a low rating with a CVSS vector, G_HIGH states Severity: High with no vector.

| ID | Deployment | Steps | Expected result | Actual result | Status | Evidence |
|----|------------|-------|-----------------|---------------|--------|----------|
| V0c | v2 | time_probe() then get_last_probe() | A unix time above 1700000000 | 1792450434 | RUN | 0x2fd2c9c6d6732ca1e4fd2ffd15460dd443a21fbf6850b1c1ebfb730c4a36e3df (https://explorer-studio.genlayer.com/tx/0x2fd2c9c6d6732ca1e4fd2ffd15460dd443a21fbf6850b1c1ebfb730c4a36e3df) |
| C1 | v2 | raise_challenge(1) as ACC2 inside the window | Accepted, status PENDING | Accepted | RUN | 0xbe128bbde0fee4e3da068b676d80c413eaf975ddaf59680318a3d6f2d7232a49 (https://explorer-studio.genlayer.com/tx/0xbe128bbde0fee4e3da068b676d80c413eaf975ddaf59680318a3d6f2d7232a49) |
| C2 | v2 | raise_challenge(1) again | ALREADY_CHALLENGED | Reverted with ALREADY_CHALLENGED | RUN | 0xef2c30a3a9cd0ee44db0c90a51e0a7fb50f4e49ddfca3d4784bcfa0aa53996c3 (https://explorer-studio.genlayer.com/tx/0xef2c30a3a9cd0ee44db0c90a51e0a7fb50f4e49ddfca3d4784bcfa0aa53996c3) |
| C5 | v2 | raise_challenge(99) | RECONCILIATION_NOT_FOUND | Reverted with RECONCILIATION_NOT_FOUND | RUN | 0x54bcd80224e4c0a01118995c685fb855552eb8ad4d271896f355153081317e3e (https://explorer-studio.genlayer.com/tx/0x54bcd80224e4c0a01118995c685fb855552eb8ad4d271896f355153081317e3e) |
| C6 | v2 | resolve_challenge(1), then get_challenge(1) | RESOLVED, outcome UPHELD or OVERTURNED | Succeeded: RESOLVED, outcome UPHELD, reason INDEPENDENT_JUDGMENT, source match true | RUN | 0x423826373e01ce3cd2ed1ed5446e424d36d2f94efe81f6851e36e9e655c0e270 (https://explorer-studio.genlayer.com/tx/0x423826373e01ce3cd2ed1ed5446e424d36d2f94efe81f6851e36e9e655c0e270) |
| C3 | v2 | raise_challenge(3) for the expiry path | Accepted | Not run on chain | DEFINED | none |
| C4 | v2 | expire_challenge(1) right after it was raised | RESOLUTION_WINDOW_OPEN | Not run on chain | DEFINED | none |
| C7 | v2 | resolve_challenge(1) again, then expire_challenge(1) | NOT_PENDING both | Not run on chain | DEFINED | none |
| C8 | v2 | raise_challenge(2) after its window closed | CHALLENGE_WINDOW_CLOSED | Not run on chain | DEFINED | none |
| C9 | v2 | expire_challenge(3) after the resolution deadline | EXPIRED, EXPIRED_ORIGINAL_STANDS | Not run on chain | DEFINED | none |
| C10 | v2 | challenge_count() | 2 | Not run on chain | DEFINED | none |
