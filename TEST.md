# Test report

Date: 2026-10-21. Network: GenLayer Studio. Bradbury was not completed, see section G. Accounts: ACC1 0x6E74BCbC7153892E8602E72182e64D525A0e3Ac7 (registrar, policy owner 1) and ACC2 0xaB46b4ae332818735fcc1b6C3E37Ec0b33D92757 (challenger, policy owner 2). Vulnerability id used everywhere: CVE-2021-44228.

Status legend: RUN means executed and the result was observed. DEFINED means not executed on chain. Nothing is marked RUN without a recorded result.

## A. Deployed contracts (Studio)

| Contract | Address | Constructor |
|----------|---------|-------------|
| AdvisoryRegistry | https://explorer-studio.genlayer.com/address/0xE1B81A97fb45470d20942AA21D0191e39bB2b860 | none |
| AdvisorySourceParser | https://explorer-studio.genlayer.com/address/0xa73E0127b569dCFD411f0856640e90ed75b28e26 | none |
| SeverityReconciler | https://explorer-studio.genlayer.com/address/0x4f8293a34B4F4477B275EC73a8ADeDcE7e0843F3 | registry, parser, 600 |
| ReconciliationChallenge | https://explorer-studio.genlayer.com/address/0x5D3234f13a4ECeA29dd91617462f2e58b22eFD9D | reconciler, 300 |
| SeverityPolicyGate | https://explorer-studio.genlayer.com/address/0xC0a4F68884b61e071E7c6BB45D0cF4dEe28f4Ccd | reconciler, challenge |

The registry and the parser were deployed once and kept. The reconciler, challenge and gate were redeployed after the change described in section D. The first deployments of those three are superseded: SeverityReconciler 0x289Db46D074A8b119Cd336d194AA2420339E0800, ReconciliationChallenge 0xdd83F26996615124Ed599A0F21145102D2a32dC6, SeverityPolicyGate 0xEBb8c37e423FBfE8e79B07C3795d9296f71C6E69. Rows in the results tables marked v1 ran on those first deployments.

Deployment transaction hashes listed in the report (the report does not say which contract each belongs to, check each on the explorer):

- 0x578c09f14aa0cc82ee3cd8fd3bc2f28d4cd48680fa5186a2b7b733fbdd880d38
- 0x15fd9f9a58ba8a996f2b027e6b4b55b4e78c7a2e94c7e545a4a7e01dddfc98e1
- 0xb9aa100d7a73799502b80050498cbd144b096f2f7b416a4baee91a74c0b9bc6e
- 0x2af7d31126a7e64806d89a49085afff0e2401604e0a7f6eab8e01c7f432b175a
- 0x42ae20e515e0ed14014ef479354f90000b79f3113002d2c826da9f56c04f484b

## B. Source digests seen at parse time (shortened in the report)

```
OSV      fb2fa225...15c4  (1 vector, score 100)
CVEORG   3fe605a6...227c  (1 vector, score 100)
G_LOW    3eb3fb8f...22c6  (1 vector, score 16, LOW)
G_HIGH   dd4a66eb...7ad8  (0 vectors)
```

## C. Results

| ID | Contract | Deployment | Result | Status | Transaction |
|----|----------|------------|--------|--------|-------------|
| R1 | AdvisoryRegistry | v2 | Advisory 1 registered | RUN | view, or transaction hash not recorded in the report |
| R2 | AdvisoryRegistry | v2 | Reverted with ALREADY_REGISTERED | RUN | view, or transaction hash not recorded in the report |
| R3 | AdvisoryRegistry | v2 | Reverted with INVALID_VULN_ID | RUN | view, or transaction hash not recorded in the report |
| R4 | AdvisoryRegistry | v2 | Reverted with INVALID_URL_1 | RUN | view, or transaction hash not recorded in the report |
| R5 | AdvisoryRegistry | v2 | Reverted with SOURCES_NOT_INDEPENDENT | RUN | view, or transaction hash not recorded in the report |
| R6 | AdvisoryRegistry | v2 | SOURCES_NOT_INDEPENDENT, then OK | RUN | view, or transaction hash not recorded in the report |
| R7 | AdvisoryRegistry | v2 | All four registered, advisory 2 has three sources | RUN | view, or transaction hash not recorded in the report |
| R8 | AdvisoryRegistry | v2 | Reverted with ALREADY_REGISTERED | RUN | view, or transaction hash not recorded in the report |
| P1 | AdvisorySourceParser | v2 | 100, 98, 75, 78, 61, INVALID. These match the official CVSS 3.1 base scores 10.0, 9.8, 7.5, 7.8, 6.1 | RUN | view, or transaction hash not recorded in the report |
| P2 | AdvisorySourceParser | v2 | NONE, LOW, MEDIUM, MEDIUM, HIGH, HIGH, CRITICAL | RUN | view, or transaction hash not recorded in the report |
| P3 | AdvisorySourceParser | v2 | One vector with score 100 | RUN | view, or transaction hash not recorded in the report |
| P4 | AdvisorySourceParser | v2 | OSV digest fb2fa225...15c4 (1 vector, score 100). CVEORG digest 3fe605a6...227c (1 vector, score 100). G_LOW digest 3eb3fb8f...22c6 (1 vector, score 16, LOW). G_HIGH digest dd4a66eb...7ad8 (0 vectors). parsed_count 4 | RUN | view, or transaction hash not recorded in the report |
| P5 | AdvisorySourceParser | v2 | n_vectors 1, buckets CRITICAL | RUN | view, or transaction hash not recorded in the report |
| P6 | AdvisorySourceParser | v2 | n_vectors 1 and LOW, then n_vectors 0 and empty buckets | RUN | view, or transaction hash not recorded in the report |
| P7 | AdvisorySourceParser | v2 | Reverted with SOURCE_UNREADABLE | RUN | view, or transaction hash not recorded in the report |
| P8 | AdvisorySourceParser | v2 | exists false, a query string is a distinct resource | RUN | view, or transaction hash not recorded in the report |
| P9 | AdvisorySourceParser | v2 | version 2 | RUN | view, or transaction hash not recorded in the report |
| V0 | SeverityReconciler | v2 | 1792450318 | RUN | 0x0d7c40633e3a3b8060549e940f30655f098e85163d351451d9618b1fcd3673c5 (https://explorer-studio.genlayer.com/tx/0x0d7c40633e3a3b8060549e940f30655f098e85163d351451d9618b1fcd3673c5) |
| V9 | SeverityReconciler | v1 | All four as expected. Run on the first deployment of the reconciler, which has the same function | RUN | view, or transaction hash not recorded in the report |
| V1 | SeverityReconciler | v2 | Reverted with PARSE_REQUIRED_1 | RUN | 0xbd6c6c1c8a171e1e2c476277d5193e86cd4efbf71e4cc39af74b52a04f2b442d (https://explorer-studio.genlayer.com/tx/0xbd6c6c1c8a171e1e2c476277d5193e86cd4efbf71e4cc39af74b52a04f2b442d) |
| V8 | SeverityReconciler | v2 | Reverted with ADVISORY_NOT_FOUND | RUN | 0x1f0790b0ebf7d29fd1016b33d3fc35115c8039af64e55920668189bba162b037 (https://explorer-studio.genlayer.com/tx/0x1f0790b0ebf7d29fd1016b33d3fc35115c8039af64e55920668189bba162b037) |
| V2 | SeverityReconciler | v2 | Succeeded: CRITICAL, UNANIMOUS, anchor [MATCH, MATCH]. The report calls this the second attempt | RUN | 0x3e301e44f759d7a73ac25d31c973127bc4cf2dfe961abe1250d0448f2893e10f (https://explorer-studio.genlayer.com/tx/0x3e301e44f759d7a73ac25d31c973127bc4cf2dfe961abe1250d0448f2893e10f) |
| V3 | SeverityReconciler | v2 | Succeeded: CRITICAL, ADJACENT | RUN | 0xa9e7fe39736105d1912551048433bdb8eda8c4c48c49b411bd61ae7e9ed108f4 (https://explorer-studio.genlayer.com/tx/0xa9e7fe39736105d1912551048433bdb8eda8c4c48c49b411bd61ae7e9ed108f4) |
| V4 | SeverityReconciler | v2 | Succeeded: CRITICAL, ADJACENT | RUN | 0xafe8682578c3af8e94d21d90b3af473c17074d3b173d75817a720ab151b94525 (https://explorer-studio.genlayer.com/tx/0xafe8682578c3af8e94d21d90b3af473c17074d3b173d75817a720ab151b94525) |
| V5 | SeverityReconciler | v2 | Succeeded: CRITICAL, SPLIT | RUN | 0xa6bdcbb02b45220e38629f5036f5f0524adfbdea8103afc7056c9feefd681ca1 (https://explorer-studio.genlayer.com/tx/0xa6bdcbb02b45220e38629f5036f5f0524adfbdea8103afc7056c9feefd681ca1) |
| V6 | SeverityReconciler | v2 | Reverted with ALREADY_RECONCILED | RUN | 0x85c1bd4946161c3a4b9715225ce9646f2a493758727f75482ac25d9ae4b74a1c (https://explorer-studio.genlayer.com/tx/0x85c1bd4946161c3a4b9715225ce9646f2a493758727f75482ac25d9ae4b74a1c) |
| V7 | SeverityReconciler | v2 | Not run on chain. Covered only by the local mock run | DEFINED | none |
| V0c | ReconciliationChallenge | v2 | 1792450434 | RUN | 0x2fd2c9c6d6732ca1e4fd2ffd15460dd443a21fbf6850b1c1ebfb730c4a36e3df (https://explorer-studio.genlayer.com/tx/0x2fd2c9c6d6732ca1e4fd2ffd15460dd443a21fbf6850b1c1ebfb730c4a36e3df) |
| C1 | ReconciliationChallenge | v2 | Accepted | RUN | 0xbe128bbde0fee4e3da068b676d80c413eaf975ddaf59680318a3d6f2d7232a49 (https://explorer-studio.genlayer.com/tx/0xbe128bbde0fee4e3da068b676d80c413eaf975ddaf59680318a3d6f2d7232a49) |
| C2 | ReconciliationChallenge | v2 | Reverted with ALREADY_CHALLENGED | RUN | 0xef2c30a3a9cd0ee44db0c90a51e0a7fb50f4e49ddfca3d4784bcfa0aa53996c3 (https://explorer-studio.genlayer.com/tx/0xef2c30a3a9cd0ee44db0c90a51e0a7fb50f4e49ddfca3d4784bcfa0aa53996c3) |
| C5 | ReconciliationChallenge | v2 | Reverted with RECONCILIATION_NOT_FOUND | RUN | 0x54bcd80224e4c0a01118995c685fb855552eb8ad4d271896f355153081317e3e (https://explorer-studio.genlayer.com/tx/0x54bcd80224e4c0a01118995c685fb855552eb8ad4d271896f355153081317e3e) |
| C6 | ReconciliationChallenge | v2 | Succeeded: RESOLVED, outcome UPHELD, reason INDEPENDENT_JUDGMENT, source match true | RUN | 0x423826373e01ce3cd2ed1ed5446e424d36d2f94efe81f6851e36e9e655c0e270 (https://explorer-studio.genlayer.com/tx/0x423826373e01ce3cd2ed1ed5446e424d36d2f94efe81f6851e36e9e655c0e270) |
| C3 | ReconciliationChallenge | v2 | Not run on chain | DEFINED | none |
| C4 | ReconciliationChallenge | v2 | Not run on chain | DEFINED | none |
| C7 | ReconciliationChallenge | v2 | Not run on chain | DEFINED | none |
| C8 | ReconciliationChallenge | v2 | Not run on chain | DEFINED | none |
| C9 | ReconciliationChallenge | v2 | Not run on chain | DEFINED | none |
| C10 | ReconciliationChallenge | v2 | Not run on chain | DEFINED | none |
| V0g | SeverityPolicyGate | v2 | 1792450118 | RUN | 0x1a344370e70409d692520ebf8054ffdc0252bcdedef08970846aa33efe04aa67 (https://explorer-studio.genlayer.com/tx/0x1a344370e70409d692520ebf8054ffdc0252bcdedef08970846aa33efe04aa67) |
| G1 | SeverityPolicyGate | v1 | Reverted with INVALID_BLOCK_AT | RUN | view, or transaction hash not recorded in the report |
| G2 | SeverityPolicyGate | v1 | Reverted with INVALID_ON_SPLIT | RUN | view, or transaction hash not recorded in the report |
| G3.1 | SeverityPolicyGate | v2 | Accepted | RUN | 0xd7a9dcf5794382e5fe9ee2eaa46c0f688fbbcd2c24ef1f9905e6580e536c0245 (https://explorer-studio.genlayer.com/tx/0xd7a9dcf5794382e5fe9ee2eaa46c0f688fbbcd2c24ef1f9905e6580e536c0245) |
| G3.2 | SeverityPolicyGate | v2 | Accepted | RUN | 0x8631649c5701bf0cf7ae5d94cf8c09072c4d2240fe2256f7d9f6fc07db545f07 (https://explorer-studio.genlayer.com/tx/0x8631649c5701bf0cf7ae5d94cf8c09072c4d2240fe2256f7d9f6fc07db545f07) |
| G10 | SeverityPolicyGate | v1 | All six as expected. Run on the first deployment of the gate, which has the same function | RUN | view, or transaction hash not recorded in the report |
| G4 | SeverityPolicyGate | v2 | Reverted with CHALLENGE_WINDOW_OPEN | RUN | 0x50c13952249ffe688cb910800db59d97771ed7c8c3b514db5862c7b332b61985 (https://explorer-studio.genlayer.com/tx/0x50c13952249ffe688cb910800db59d97771ed7c8c3b514db5862c7b332b61985) |
| G5 | SeverityPolicyGate | v2 | Reverted with CHALLENGE_UNRESOLVED | RUN | 0x384c0a8aad0c02663d06c1282c449bb92b42ad0000fc9ba00e41f7abcab1c15c (https://explorer-studio.genlayer.com/tx/0x384c0a8aad0c02663d06c1282c449bb92b42ad0000fc9ba00e41f7abcab1c15c) |
| G6 | SeverityPolicyGate | v2 | Reverted with POLICY_NOT_SET | RUN | 0xa88fcc4d4096805ad2252cd4c375bcafef6d00cb6d409860ae839cb32685a558 (https://explorer-studio.genlayer.com/tx/0xa88fcc4d4096805ad2252cd4c375bcafef6d00cb6d409860ae839cb32685a558) |
| G8 | SeverityPolicyGate | v2 | Succeeded: BLOCK, path UPHELD, reason AT_OR_ABOVE_THRESHOLD | RUN | 0x79fbc3c9419ed2c03d7f055dd206723929d722e062b1fc5e8c2d78278ae0192d (https://explorer-studio.genlayer.com/tx/0x79fbc3c9419ed2c03d7f055dd206723929d722e062b1fc5e8c2d78278ae0192d) |
| G11a | SeverityPolicyGate | v2 | CHALLENGE_RESOLVED, result_final true | RUN | view, or transaction hash not recorded in the report |
| G11b | SeverityPolicyGate | v2 | RECONCILED, result_final false | RUN | view, or transaction hash not recorded in the report |
| G7 | SeverityPolicyGate | v2 | Not run on chain | DEFINED | none |
| G9 | SeverityPolicyGate | v2 | Not run on chain | DEFINED | none |
| G11c | SeverityPolicyGate | v2 | Not run on chain | DEFINED | none |
| G12 | SeverityPolicyGate | v2 | Not run on chain | DEFINED | none |
| G13 | SeverityPolicyGate | v2 | Not run on chain | DEFINED | none |

Counts from the tables above: 55 test rows, 43 RUN, 12 DEFINED. 20 of the RUN rows have a transaction hash in the report. The other RUN rows are views, or Registry and Parser transactions whose hashes were not recorded in the report.

## D. What happened with the first reconcile

On the first deployment, reconcile reverted with SOURCE_CHANGED_SINCE_PARSE for advisories 1, 2 and 3 right after the sources had been parsed. That version compared the digest it fetched during reconcile with the digest stored by parse_source in an earlier transaction and reverted on any difference. The get_source records showed the parse-time digests unchanged afterwards.

The cause of that revert was not established. The report suggests that the page text changes between calls. The evidence does not settle this: parse_source reached strict equality consensus on the same pages many times, and after the change below the reconcile of advisory 1 recorded anchor MATCH for both sources, which means the fresh digests equalled the parse-time digests.

The change: reconcile no longer reverts on a digest difference. It fetches the sources itself, validators agree on those fetches, and the record stores the fresh digests, the parse-time digests (anchor_digests) and a MATCH or DRIFT flag per source. The challenge contract stores the digests it saw (judged_digests). After the change reconcile(1) succeeded with CRITICAL and UNANIMOUS (the report calls it the second attempt, the outcome of the first attempt on the new deployment is not described).

## E. Honest gaps

- No OVERTURNED outcome was observed on chain. The only resolved challenge (advisory 1) was UPHELD. Overturn in several directions, the expiry path and the source-changed rule are covered only by the local mock run in section F.
- Not run on chain: C3, C4, C7, C8, C9, C10, G7, G9, G11c, G12, G13, V7. They need waits of 5 to 10 minutes for the challenge windows to pass.
- The model path (a source without a CVSS vector) ran on chain in V3 and V4, but no single run proves the tolerance band on strength scores.
- Transaction hashes for the Registry and Parser tests were not recorded in the report.

## F. Local mock run (not chain evidence)

The final contract files were loaded in a local harness that replaces the GenLayer runtime with a stub (fake web pages, a scripted language model, a settable block clock). Result: 108 checks, 108 passed. It covers the registry guards, the CVSS calculator against official scores, vector extraction, parser versioning, reconcile outcomes (unanimous, adjacent, split, unresolved, bounded model path), drift recording, the strength tolerance band, challenge guards, the blind and untrusted-data judge prompts, overturn in several directions, source changed after reconcile (original stands), infrastructure failure leaving a challenge PENDING, expiry, the gate decision table for every combination, finalization blocked inside the window and while pending, and validator checks against a lying leader. It is a logic check of the same files, not a replacement for the chain results.

## G. Bradbury

Bradbury was not completed and no Bradbury result is claimed. The report states that after deployment the first four checks (V0, P1, V9, R1) passed, then parse_source returned UNDETERMINED and later transactions stayed in Sending for a long period. Deployment addresses and transaction hashes for Bradbury were not recorded, so they are not listed here. A future run should use windows of at least 3600 seconds.

## H. How the steward lessons map to evidence

1. Finalization cannot bypass the challenge process. Chain evidence: G4 (evaluate inside the window reverts with CHALLENGE_WINDOW_OPEN), G5 (evaluate while the challenge is pending reverts with CHALLENGE_UNRESOLVED), G8 (evaluate after resolution succeeds with path UPHELD), G11a and G11b (lifecycle stages).
2. The independent judge. Chain evidence: C6 (resolve_challenge with reason INDEPENDENT_JUDGMENT, outcome UPHELD). The judge sees only the documents. Overturn in either direction is covered only locally, see section E.
3. Safe threshold comparison. The gate compares bucket ranks as small integers and has no subtraction. Chain evidence: G10 (six policy combinations, run on the first deployment of the gate).
4. Content binding. The reconcile consensus binds the digests of the fresh fetches, and the record exposes anchor flags. Chain evidence: V2 (anchor MATCH, MATCH).

