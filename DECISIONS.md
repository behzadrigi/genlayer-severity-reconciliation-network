# Contracts

Common rules for all files: first line is the py-genlayer dependency comment, pure ASCII, no undecorated instance methods, helpers at module level, views return strings, constructor addresses are strings, cross-contract calls are view reads only.

Shared definitions: buckets NONE, LOW, MEDIUM, HIGH, CRITICAL (ranks 0 to 4, plus UNCLEAR for a source that cannot be read). Score ranges: 0 is NONE, 0.1 to 3.9 LOW, 4.0 to 6.9 MEDIUM, 7.0 to 8.9 HIGH, 9.0 to 10.0 CRITICAL. Scores are handled as integers times ten. Reconciled result: the highest bucket across sources. Agreement: UNANIMOUS (spread 0), ADJACENT (1), SPLIT (2 or more), UNRESOLVED when any source is UNCLEAR or has strength below 50.

Fetched text is normalized (lowercase, whitespace collapsed) before hashing. Digest means SHA-256 of that normalized text. Query strings in URLs are never stripped.

## 1. AdvisoryRegistry (deterministic)

Storage: `advisories` (id to Advisory: vuln_id, sources_json, registrant), `seen` (dedupe key to id), `advisory_total`.

Methods: `register_advisory(vuln_id, url_1, url_2, url_3)` write (url_3 may be an empty string); `get_advisory`, `advisory_count`, `preview_sources` views.

Guards and exact errors: `INVALID_VULN_ID` (4 to 64 ASCII characters: letters, digits, dash, underscore, dot, colon), `INVALID_URL_1`, `INVALID_URL_2`, `INVALID_URL_3` (https only, ASCII, no whitespace, no user info, 300 characters max), `SOURCES_NOT_INDEPENDENT` (identical URLs or any two sources on the same base domain), `ALREADY_REGISTERED` (same vulnerability id and the same set of URLs in any order).

Safety properties: URLs are stored exactly as given. State only grows. The same advisory cannot be registered twice, whatever the order of its sources.

## 2. AdvisorySourceParser (strict equality)

Storage: `parsed` (sha256 of exact URL to ParsedSource: url, content_hash, vectors_json, n_vectors, version, parser), `parsed_total`.

Methods: `parse_source(url)` write; `get_source`, `parsed_count`, `score_of_vector`, `bucket_of`, `vectors_in_text`, `url_key` views.

Consensus: the leader fetches the page with `gl.nondet.web.render(url, mode='text')` and returns the digest, the sorted list of distinct valid CVSS 3.0 and 3.1 vectors with their scores, and the text length. A validator fetches again and requires the whole result to be equal. If the leader fails, a validator accepts only if its own fetch fails too.

Guards: `INVALID_URL`, `SOURCE_UNREADABLE` (fetch failed or fewer than 40 characters, fail closed), `BAD_DIGEST`, `BAD_VECTOR` (a returned score differs from the contract's own calculation).

CVSS calculator: implements the CVSS 3.1 base score equations (scope changed and unchanged, the specified round-up rule) with integer-safe rounding and no use of the power operator. A vector must contain each of AV, AC, PR, UI, S, C, I and A exactly once with valid values. Temporal and environmental metrics are ignored.

Safety properties: re-parsing a URL raises its version and replaces its digest. Unreadable pages never create a record.

## 3. SeverityReconciler (custom tolerance band)

Constructor: `(registry_addr, parser_addr, window_seconds)`. Error `INVALID_WINDOW` unless 1 to 31536000.

Storage: `recons` (advisory id to Recon: vuln_id, reconciler, sources, digests, anchor_digests, anchor, buckets, methods, strengths, scores, reconciled, agreement, reconciled_at, deadline), `window_seconds`, counters, `last_probe`.

Methods: `time_probe()` and `reconcile(advisory_id)` write; `get_reconciliation`, `reconciliation_count`, `preview_combine`, `get_last_probe`, `get_config` views.

Flow of `reconcile`: read the advisory from the registry, require a parse record for every source, then inside the nondeterministic block fetch every source and classify each one. A source that does not contain the vulnerability id is UNRELATED. A source whose vectors all fall into one bucket is classified by the contract (method VECTOR, strength 100). A source with vectors in several buckets is classified by the model inside that range (MODEL_BOUNDED). A source without vectors is classified by the model (MODEL). The prompt wraps the text in BEGIN_DATA and END_DATA and states it is data.

Consensus: validators repeat the work and require equal fresh digests, buckets, methods, scores, reconciled bucket and agreement. Strength scores of model-read sources must agree within 15 points. The contract recomputes the combination of buckets before storing.

Digest anchor: after consensus the record stores the fresh digests (agreed by the validators), the parse-time digests (`anchor_digests`) and a flag per source, MATCH or DRIFT. A difference does not revert the transaction.

Guards: `ALREADY_RECONCILED`, `ADVISORY_NOT_FOUND`, `PARSE_REQUIRED_1`, `PARSE_REQUIRED_2`, `PARSE_REQUIRED_3` (the source with that position has no parse record), `SOURCE_UNREADABLE`, `BAD_RESULT`, `BAD_BUCKET`, `BAD_STRENGTH`, `TIME_UNAVAILABLE`.

Safety properties: an unreadable source reverts and stores nothing, so it can never produce a bad record. Any doubt (unrelated source, unclear bucket, weak statement) gives UNRESOLVED, which the gate treats as HOLD. The record carries `deadline = reconciled_at + window_seconds`, the single source of truth for the challenge window.

## 4. ReconciliationChallenge (comparative on the corrected bucket, with evidence verification)

Constructor: `(reconciler_addr, resolution_seconds)`. Error `INVALID_RESOLUTION_WINDOW`.

Storage: `challenges` (advisory id to ChallengeRec: challenger, original reconciled and agreement, status PENDING or RESOLVED or EXPIRED, raised_at, resolution_deadline, resolved_at, corrected and final reconciled and agreement, outcome UPHELD or OVERTURNED, reason, judged buckets, judged digests).

Methods: `time_probe()`, `raise_challenge(advisory_id)`, `resolve_challenge(advisory_id)`, `expire_challenge(advisory_id)` write; `get_challenge`, `challenge_status`, `challenge_count`, `get_last_probe`, `get_config` views.

`raise_challenge` guards: `ALREADY_CHALLENGED`, `RECONCILIATION_NOT_FOUND`, `CHALLENGE_WINDOW_CLOSED` (block time at or after the deadline of the reconciliation). A challenge carries no free text.

`resolve_challenge` is the independent judge. It is only available while block time is before the `resolution_deadline` of the pending challenge. At or after the deadline it reverts with `RESOLUTION_WINDOW_CLOSED` before reading any source and stores nothing, and the only exit is `expire_challenge`. It reads only the source URLs, the digests stored in the reconciliation and the vulnerability id. Inside the nondeterministic block it fetches every source. If the fresh digests differ from the stored ones, it returns without judging and the first result stands (reason `SOURCE_CHANGED_ORIGINAL_STANDS`). Otherwise each source is judged: vector sources by the contract, other sources by the model, which must return a bucket and a short verbatim quote. The judge prompt contains only the document text. It never contains the first result, the challenge, or anything from the challenger. After consensus the contract combines the judged buckets, compares the corrected result with the first one (same reconciled bucket and agreement means UPHELD, otherwise OVERTURNED) and stores the corrected result as final, so a correction can move in either direction, including to UNRESOLVED.

Consensus: validators do not trust the leader's bucket. Each validator fetches every source itself and determines the bucket on its own. Vector sources are classified by the contract's calculator. Model-read sources are classified by the validator's own blind model run (the same judge prompt, never shown the leader's answer), restricted to the vector range when vectors disagree. The leader's bucket for a source is accepted only if it equals the validator's own bucket, so the corrected bucket is bound by independent determination. A leader abstention (UNCLEAR) is accepted only if the validator's own run also gives UNCLEAR. On top of that, the quote must occur in the validator's own copy of the text, must be 8 to 200 characters long, and must support exactly one bucket (the claimed one): a quote containing a severity word or score of a second bucket is rejected. The digests must be equal as well.

`expire_challenge` guards: `CHALLENGE_NOT_FOUND`, `NOT_PENDING`, `RESOLUTION_WINDOW_OPEN`. After the resolution deadline anyone may expire a pending challenge and the first result stands.

Other guards: `CHALLENGE_NOT_FOUND`, `NOT_PENDING`, `RESOLUTION_WINDOW_CLOSED`, `RECONCILIATION_NOT_FOUND`, `SOURCE_UNREADABLE` (reverts, the challenge stays PENDING and can be retried), `BAD_RESULT`, `BAD_BUCKET`, `TIME_UNAVAILABLE`.

Safety properties: every PENDING challenge has exactly one exit at any moment: resolve while block time is before the resolution deadline, expire from the deadline on. The two never overlap. An infrastructure failure never changes status.

## 5. SeverityPolicyGate (deterministic)

Storage: `policies` (owner to Policy: block_at, on_split), `decisions` (advisory id and owner to Decision: decision, reason, final reconciled and agreement, path, evaluated_at, evaluations), counters.

Methods: `time_probe()`, `set_policy(block_at, on_split)`, `evaluate(advisory_id, policy_owner)` write; `get_policy`, `get_decision`, `lifecycle`, `preview_decision`, `decision_count`, `get_last_probe`, `get_config` views.

`set_policy` guards: `INVALID_BLOCK_AT` (must be LOW, MEDIUM, HIGH or CRITICAL), `INVALID_ON_SPLIT` (must be BLOCK or HOLD).

`evaluate` rules in order: `POLICY_NOT_SET`, `RECONCILIATION_NOT_FOUND`. If a challenge exists: `CHALLENGE_RECONCILIATION_MISMATCH` when its recorded original result differs from the reconciliation, `CHALLENGE_UNRESOLVED` while PENDING, the final result taken from the resolved challenge (path UPHELD or OVERTURNED) or the expired one (path EXPIRED), else `CHALLENGE_STATE_INVALID`. If no challenge exists: `CHALLENGE_WINDOW_OPEN` until block time reaches the reconciliation deadline, then path UNCHALLENGED. `FINAL_RESULT_INVALID` guards the final value.

Decision: UNRESOLVED gives HOLD. A SPLIT result gives the owner's split action. Otherwise BLOCK when the rank of the reconciled bucket is at or above the rank of `block_at`, else ALLOW. A re-evaluation overwrites the decision and raises `evaluations`.

Safety properties: no decision can be made inside the challenge window or while a challenge is unresolved. A challenge cannot be raised once the window has closed, so a late challenge cannot appear after an evaluation. Threshold checks are comparisons of small integer ranks, there is no subtraction.
