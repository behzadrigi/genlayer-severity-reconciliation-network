# GenLayer Vulnerability Severity Reconciliation Network

Five standalone GenLayer Intelligent Contracts that answer one question with consensus instead of trust: "how severe is this vulnerability, when different advisory sources say different things?"

No contract in this suite handles funds. Every judgment is made from material the contracts fetch themselves, never from free text typed by the caller.

## Why it matters beyond a demo

The same vulnerability is often published by several databases with different severity. A team that blocks releases on "high or above" needs one defensible answer, and needs to know when the sources disagree. This suite registers a vulnerability with two or three sources on different domains, reads each source (a built-in CVSS 3.x calculator scores any source that publishes a vector, a language model reads only the sources without one), reconciles the result conservatively, lets any third party challenge it inside a window, produces an independently judged correction when challenged, and only then lets a policy gate act on it.

## Architecture

```
 anyone                          anyone                          any third party
   |                               |                                   |
   v                               v                                   v
+------------------+  urls   +-----------------------+      +--------------------------+
| 1 Advisory       |<--------| 2 AdvisorySource      |      | 4 Reconciliation         |
|   Registry       |         |   Parser              |      |   Challenge              |
| deterministic    |         | strict equality       |      | non-comparative          |
+---------+--------+         +-----------+-----------+      +------------+-------------+
          | advisory (view)              | parse anchor (view)           | reconciliation (view)
          v                              v                               |
+------------------------------------------------------+                 |
| 3 SeverityReconciler (tolerance band)                |<----------------+
| fetches every source, scores, reconciles, deadline   |
+---------------------------+--------------------------+
                            | reconciliation (view)      challenge (view)
                            v                                  v
                  +---------------------------------------------+
                  | 5 SeverityPolicyGate (deterministic)        |
                  | acts only on final results                  |
                  +---------------------------------------------+
```

All cross-contract access is view reads. No contract relies on a cross-contract write.

## Contracts and consensus patterns

| # | Contract | Role | Consensus logic |
|---|----------|------|-----------------|
| 1 | AdvisoryRegistry | Records a vulnerability id with two or three sources on different base domains | Deterministic |
| 2 | AdvisorySourceParser | Fetches a source, stores its SHA-256 digest and the CVSS vectors it contains, each scored by the built-in calculator | Strict equality across validators (digest, vectors, length) |
| 3 | SeverityReconciler | Fetches every source, derives a severity bucket per source, reconciles them | Custom tolerance band: digests, buckets, methods, scores and the reconciled result must match exactly, strength scores of model-read sources must agree within 15 points |
| 4 | ReconciliationChallenge | Independent corrected outcome after a challenge, blind to the first result and to the challenger | Comparative on the corrected bucket (every validator determines the bucket itself and the leader's bucket must equal it) plus evidence verification (the quote is found in the validator's copy and supports exactly one bucket) |
| 5 | SeverityPolicyGate | Per-owner policy (block threshold and split action) applied to final results | Deterministic |

## How a source is read

1. A source that does not mention the vulnerability id is UNRELATED and makes the result UNRESOLVED.
2. If the source contains CVSS 3.0 or 3.1 vectors that all fall into one bucket, the bucket is computed by the contract. No language model is used.
3. If the vectors fall into several buckets, the model must choose a bucket inside that range (MODEL_BOUNDED), otherwise UNCLEAR.
4. If there is no vector, the model reads the text (MODEL). The text is wrapped in BEGIN_DATA and END_DATA markers and the prompt says it is data.

Reconciliation takes the worst (highest) bucket across sources. Agreement is UNANIMOUS (same bucket), ADJACENT (one bucket apart) or SPLIT (two or more apart). Any source with an unclear bucket or a strength below 50 makes the result UNRESOLVED.

## Lifecycle of one advisory

```
REGISTERED -> (sources parsed) -> RECONCILED
RECONCILED: challengeable while block time < challengeable_until
            (challengeable_until = reconciled_at + window_seconds)
 no challenge -> final once block time >= challengeable_until      (path UNCHALLENGED)
 challenge raised -> CHALLENGE_PENDING, the gate refuses to evaluate
     resolve_challenge -> RESOLVED (path UPHELD or OVERTURNED, the judged result replaces the first one)
     expire_challenge  -> EXPIRED  (only after resolution_deadline, the first result stands)
 RESOLVED or EXPIRED -> final
Gate: evaluate(advisory, policy_owner) -> BLOCK, ALLOW or HOLD, recorded with the path taken
```

The view `SeverityPolicyGate.lifecycle(advisory_id)` returns the stage, `challengeable_until`, `resolution_deadline` and `result_final`, so a client can see exactly when a result is challengeable and when it is final.

## Deployed addresses

Studio, tested on 2026-10-21 and again on 2026-10-23 after a review rejection (only ReconciliationChallenge and SeverityPolicyGate were redeployed). Full evidence is in TEST.md.

| Contract | Studio |
|----------|--------|
| AdvisoryRegistry | [0xE1B81A97fb45470d20942AA21D0191e39bB2b860](https://explorer-studio.genlayer.com/address/0xE1B81A97fb45470d20942AA21D0191e39bB2b860) |
| AdvisorySourceParser | [0xa73E0127b569dCFD411f0856640e90ed75b28e26](https://explorer-studio.genlayer.com/address/0xa73E0127b569dCFD411f0856640e90ed75b28e26) |
| SeverityReconciler | [0x4f8293a34B4F4477B275EC73a8ADeDcE7e0843F3](https://explorer-studio.genlayer.com/address/0x4f8293a34B4F4477B275EC73a8ADeDcE7e0843F3) |
| ReconciliationChallenge | [0xa11cA73018f99052a8Faa7b0Fb1eb7092a685B68](https://explorer-studio.genlayer.com/address/0xa11cA73018f99052a8Faa7b0Fb1eb7092a685B68) |
| SeverityPolicyGate | [0xA04146a186a447b721A57DEa5a10d5e80086DF06](https://explorer-studio.genlayer.com/address/0xA04146a186a447b721A57DEa5a10d5e80086DF06) |

Bradbury: not completed, no Bradbury result is claimed. See TEST.md section G.

## Test results at a glance

- Studio: 53 test rows with a recorded result and 14 rows defined but not executed on chain (TEST.md section C). The core pipeline ran end to end twice: reconcile (unanimous, adjacent and split results), challenge raise, independent resolve (UPHELD), and gate evaluation, plus the refusals that protect it (evaluate inside the window and evaluate while a challenge is pending).
- The second run (advisory 6) used a model-read source (no CVSS vector) together with two vector sources, and resolve_challenge finalized with validators binding the corrected bucket independently.
- Not run on chain: the expiry path, a late challenge, an OVERTURNED outcome and the drift test. They are listed in TEST.md section F and are covered by a local mock run (115 checks).

## Quick start

Deploy in this order. Constructor arguments are strings for addresses and integers for seconds.

1. `AdvisoryRegistry()`
2. `AdvisorySourceParser()`
3. `SeverityReconciler(registry_addr, parser_addr, window_seconds)` use 600 for testing, 86400 for real use
4. `ReconciliationChallenge(reconciler_addr, resolution_seconds)` use 300 for testing
5. `SeverityPolicyGate(reconciler_addr, challenge_addr)`

Then: `time_probe()` on the reconciler first (proves block time), `register_advisory(vuln_id, url_1, url_2, url_3)` (use an empty string for url_3 to register two sources), `parse_source(url)` for every source, `reconcile(advisory_id)`, optionally `raise_challenge` and `resolve_challenge`, then `set_policy(block_at, on_split)` and `evaluate(advisory_id, policy_owner)`. The executed test cases are in tests/ and the full report is in TEST.md.

## Source integrity

The files in contracts/ are the files deployed on Studio (the registry, parser and reconciler were deployed in the first round, the challenge and the gate in the second round). SHA-256 checksums:

```
2cd3562b22301de4c04a46cdb0e06c4a98dc28ce258b544d74728df285f85733  advisory_registry.py
25f07b3e09a2438251005effe3bd68b6a5c598a7ebd320a8fd15c78d5eb6fceb  advisory_source_parser.py
a8a24e276c0852fff1b72372c0e6c44605e4443cedd979a72cb68d4fc33760f8  severity_reconciler.py
dbc2837aa7411ac70422ae441e7fd529ca63e52962c4d160f8ef34e1eef74888  reconciliation_challenge.py
7a0a6642403bca39ed8ac87e183d88e2265e879862189b494837b3d258131a79  severity_policy_gate.py
```

Verify with `sha256sum contracts/*.py`.

## Limits

- The suite reads what advisory sources say. It does not decide whether a vulnerability is exploitable in a given deployment.
- Only CVSS 3.0 and 3.1 base scores are calculated. Vectors of other versions are ignored and such sources fall back to the model path.
- A source must mention the vulnerability id (compared in lowercase) or it is UNRELATED.
- The independence check compares the last two labels of the host names. It is a practical guard, not a proof of independent ownership.
- Pages that change their text can produce different fresh digests over time. Reconcile does not revert on that. It records MATCH or DRIFT against the parse-time digest, and the challenge judge keeps the first result when the digests it sees differ from the reconciliation digests.
- A resolved challenge keeps the first result when the sources changed, and an expired challenge keeps the first result.
- A model-read source on an ambiguous page can fail validator agreement in a challenge and must be retried. A challenge that never reaches agreement ends by expiry with the first result standing.
- Anyone may call parse, reconcile, resolve, expire and evaluate. Timing is block time of the transaction.
