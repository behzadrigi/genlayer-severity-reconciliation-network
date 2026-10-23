# Design decisions

Each entry gives the decision, the reason and the cost.

1. No funds anywhere.
   Reason: removes the whole class of stuck money findings. Cost: no economic stake behind a result, the gate only informs a decision.

2. The contracts fetch the evidence themselves.
   Reason: a language model never judges a statement typed by the caller. Parser, reconciler and challenge all use `gl.nondet.web.render`. Cost: sources must be fetchable.

3. A deterministic CVSS calculator inside the contract.
   Reason: when a source publishes a vector, the severity is arithmetic, not opinion. The contract computes it, so a language model cannot be talked into a different answer for those sources. The calculator was checked on chain against official scores (P1). Cost: only versions 3.0 and 3.1 are supported.

4. The model is used only where arithmetic is not available.
   Reason: sources without a vector are read by the model, and sources whose vectors disagree are read by the model inside the vector range (MODEL_BOUNDED), so the model can never leave what the vectors allow. Cost: model-read sources need a strength score and can fail consensus near a boundary.

5. Two or three sources on different base domains, and the source must mention the vulnerability id.
   Reason: a single caller-chosen URL is easy to control and an unrelated page cannot influence the result (it becomes UNRELATED and the result UNRESOLVED). Cost: the base domain check is approximate.

6. Fetched text is untrusted data.
   Reason: both prompts wrap the text in BEGIN_DATA and END_DATA and say it is data. A model cannot override a vector-based source. Cost: none.

7. Conservative reconciliation.
   Reason: the reconciled bucket is the highest across sources, and the agreement level (UNANIMOUS, ADJACENT, SPLIT) is a first-class output, so a consumer can choose how to treat disagreement. Any unclear or weak source makes the result UNRESOLVED instead of guessing. Cost: one weak source holds up the whole advisory.

8. Four different consensus patterns.
   Reason: deterministic registry, strict equality for the parser (a pure fetch and compute step, so it must match exactly), a tolerance band for the reconciler (model strength scores are fuzzy, every outcome field is exact), comparative determination for the challenge judge (every validator determines the corrected bucket on its own and the leader must match it, with evidence checks on top). Cost: more validator code.

9. Every outcome-bearing field is compared by validators.
   Reason: in the reconciler the digests, buckets, methods, scores, reconciled bucket and agreement must be equal. Only the strength scores of model-read sources have a tolerance of 15, and the minimum strength of 50 affects the outcome through the reconciled result, which is compared exactly. Cost: a rare retry when a score sits at the boundary.

10. Reconcile binds to its own fetch, and the parse-time digest is an anchor, not a gate.
    Reason: the first version reverted when the digest seen by reconcile differed from the digest stored by parse_source in an earlier transaction. On Studio that revert blocked the whole pipeline right after parsing and its cause was not established. The judgment and the check now use the same fetch, validators agree on the digests of that fetch, and the record stores the parse-time digests with a MATCH or DRIFT flag per source, so any difference stays visible. Cost: the parse step is no longer a hard precondition on content, only on existence, and a DRIFT does not stop a reconciliation.

11. Infrastructure failures revert.
    Reason: an unreadable source raises an error before any state is written, so the transaction can be retried and no permanent bad record exists. Cost: a permanently dead source leaves an advisory unreconciled, a new advisory with other sources can be registered.

12. One clock rule for challenge and evaluation.
    Reason: the reconciliation stores `deadline = reconciled_at + window_seconds`. A challenge needs block time before the deadline, an evaluation without a challenge needs block time at or after it. The two ranges never overlap. Cost: depends on block time, proven by `time_probe` as the first test.

13. A pending challenge blocks evaluation and always has an exit.
    Reason: `evaluate` reverts with CHALLENGE_UNRESOLVED while PENDING. The exits are `resolve_challenge` (open to anyone) and `expire_challenge` (open to anyone after the resolution deadline). Cost: an expired challenge keeps the first result.

14. A correction is an independently validated result, never a fixed penalty.
    Reason: the judge sees only the documents. The corrected result is computed by code from the judged buckets and replaces the first one in either direction (including to UNRESOLVED). Cost: the judge reads the same sources as the reconciliation, so it corrects reading errors, not a bad choice of sources.

15. If the sources changed since the reconciliation, the first result stands.
    Reason: the judge compares the digests it fetches with the digests stored in the reconciliation. A difference means the documents are no longer the ones that were reconciled, so no correction is made. Cost: a genuinely wrong first result cannot be fixed after the pages changed, and a page whose text changes often can make every challenge end this way.

16. Anyone can challenge, nobody is scored.
    Reason: the reconciliation is a public, permissionless step, so there is no attester to protect and no reputation to move. The challenge carries no free text. Cost: no incentive layer.

17. The gate acts only on final results and compares ranks.
    Reason: policy thresholds are small integer ranks compared with at-or-above checks, there is no subtraction that could go wrong. Cost: none.

18. Query strings are never stripped and exact URLs are the keys.
    Reason: distinct resources must not share a record.

19. Time parsing is self-contained.
    Reason: the block time string is parsed with integer arithmetic only, with the `gl.message_raw["datetime"]` fallback and `TIME_UNAVAILABLE` on failure. Block time was proven on Studio by `time_probe` on the reconciler, the challenge and the gate.

20. One `from dataclasses import dataclass` line after the genlayer import.
    Reason: makes the dataclass name explicit. It is a plain import line directly under the dependency header.

21. Test windows.
    Reason: 600 seconds for the reconciliation window and 300 seconds for the resolution window on Studio, so a manual tester has time for consecutive transactions. Cost: real use needs much longer windows.

22. Validators determine and bind the corrected bucket independently.
    Reason: the first design only checked that the leader's quote occurs in the page and matches the leader's bucket, so a page that mentions two severities could validate two different buckets, and the corrected bucket decides the final policy action. Each validator now determines the bucket of every source on its own, blind to the leader, and the leader's bucket is accepted only if it equals the validator's. A quote must also support exactly one bucket. Cost: an ambiguous model-read page can fail agreement and need a retry, and a challenge that cannot reach agreement ends by expiry with the first result standing.

## Known limitations

- The cause of the first reconcile revert (decision 10) was not established. After the change, advisory 1 recorded anchor MATCH on both sources, so the pages did not differ at that time.
- No OVERTURNED outcome has been observed on chain. The expiry path, a late challenge, the drift flag and a second policy owner were not run on chain. They are covered by the local mock run described in TEST.md.
- The model path (sources without a vector) ran on chain in reconciliations and once in a challenge (advisory 6), but its tolerance band has no dedicated on-chain test and no on-chain case where validators reject a conflicting bucket was run.
- In the second test round, resolve_challenge on an advisory whose two sources both carry vectors returned UNDETERMINED twice before a later resolve on another advisory finalized. The cause was not established.
- Only CVSS 3.0 and 3.1 are calculated.
- The independence check on sources compares the last two labels of host names.
- Bradbury was not completed, see TEST.md section G.
