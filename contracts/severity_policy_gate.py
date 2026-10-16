# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

from genlayer import *
from dataclasses import dataclass
import json
import hashlib


BUCKETS = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def sha_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def sender_hex() -> str:
    s = gl.message.sender_address
    try:
        return str(s.as_hex).lower()
    except Exception:
        return str(s).lower()


def civil_to_epoch(y: int, m: int, d: int, hh: int, mm: int, ss: int) -> int:
    y2 = y - 1 if m <= 2 else y
    era = y2 // 400
    yoe = y2 - era * 400
    mp = (m + 9) % 12
    doy = (153 * mp + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    days = era * 146097 + doe - 719468
    return days * 86400 + hh * 3600 + mm * 60 + ss


def to_epoch(raw) -> int:
    if isinstance(raw, bool):
        raise Exception("TIME_UNAVAILABLE")
    if isinstance(raw, int) or isinstance(raw, float):
        return int(raw)
    if hasattr(raw, "year") and hasattr(raw, "month") and hasattr(raw, "day"):
        return civil_to_epoch(int(raw.year), int(raw.month), int(raw.day), int(getattr(raw, "hour", 0)), int(getattr(raw, "minute", 0)), int(getattr(raw, "second", 0)))
    s = str(raw).strip()
    if s.isdigit():
        return int(s)
    if len(s) < 19:
        raise Exception("TIME_UNAVAILABLE")
    try:
        y = int(s[0:4])
        m = int(s[5:7])
        d = int(s[8:10])
        hh = int(s[11:13])
        mm = int(s[14:16])
        ss = int(s[17:19])
    except Exception:
        raise Exception("TIME_UNAVAILABLE")
    if m < 1 or m > 12 or d < 1 or d > 31:
        raise Exception("TIME_UNAVAILABLE")
    return civil_to_epoch(y, m, d, hh, mm, ss)


def now_seconds() -> int:
    raw = None
    try:
        raw = gl.message.datetime
    except Exception:
        raw = None
    if raw is None:
        try:
            raw = gl.message_raw["datetime"]
        except Exception:
            raw = None
    if raw is None:
        raise Exception("TIME_UNAVAILABLE")
    return to_epoch(raw)


def parse_obj(raw) -> dict:
    s = str(raw)
    a = s.find("{")
    b = s.rfind("}")
    if a < 0 or b <= a:
        return {}
    try:
        v = json.loads(s[a:b + 1])
    except Exception:
        return {}
    if isinstance(v, dict):
        return v
    return {}


def leader_failed_ok(fn) -> bool:
    try:
        fn()
    except Exception:
        return True
    return False


BLOCK_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
SPLIT_ACTIONS = ["BLOCK", "HOLD"]


def decide(reconciled: str, agreement: str, block_at: str, on_split: str):
    if reconciled not in BUCKETS or agreement == "UNRESOLVED":
        return "HOLD", "UNRESOLVED"
    if agreement == "SPLIT":
        return on_split, "SPLIT"
    if BUCKETS.index(reconciled) >= BUCKETS.index(block_at):
        return "BLOCK", "AT_OR_ABOVE_THRESHOLD"
    return "ALLOW", "BELOW_THRESHOLD"


@allow_storage
@dataclass
class Policy:
    owner: str
    block_at: str
    on_split: str


@allow_storage
@dataclass
class Decision:
    advisory_id: str
    owner: str
    decision: str
    reason: str
    final_reconciled: str
    final_agreement: str
    path: str
    evaluated_at: u256
    evaluations: u256


class SeverityPolicyGate(gl.Contract):
    policies: TreeMap[str, Policy]
    decisions: TreeMap[str, Decision]
    reconciler_addr: str
    challenge_addr: str
    decision_total: u256
    last_probe: u256

    def __init__(self, reconciler_addr: str, challenge_addr: str):
        self.reconciler_addr = reconciler_addr.strip()
        self.challenge_addr = challenge_addr.strip()
        self.decision_total = u256(0)
        self.last_probe = u256(0)

    @gl.public.write
    def time_probe(self):
        self.last_probe = u256(now_seconds())

    @gl.public.write
    def set_policy(self, block_at: str, on_split: str):
        if block_at not in BLOCK_LEVELS:
            raise Exception("INVALID_BLOCK_AT")
        if on_split not in SPLIT_ACTIONS:
            raise Exception("INVALID_ON_SPLIT")
        who = sender_hex()
        if who in self.policies:
            p = self.policies[who]
            p.block_at = block_at
            p.on_split = on_split
        else:
            self.policies[who] = Policy(owner=who, block_at=block_at, on_split=on_split)

    @gl.public.write
    def evaluate(self, advisory_id: str, policy_owner: str):
        owner = policy_owner.strip().lower()
        if owner not in self.policies:
            raise Exception("POLICY_NOT_SET")
        rv = parse_obj(gl.get_contract_at(Address(self.reconciler_addr)).view().get_reconciliation(advisory_id))
        if rv.get("exists") is not True:
            raise Exception("RECONCILIATION_NOT_FOUND")
        ch = parse_obj(gl.get_contract_at(Address(self.challenge_addr)).view().get_challenge(advisory_id))
        now = now_seconds()
        if ch.get("exists") is True:
            if str(ch["original_reconciled"]) != str(rv["reconciled"]) or str(ch["original_agreement"]) != str(rv["agreement"]):
                raise Exception("CHALLENGE_RECONCILIATION_MISMATCH")
            st = str(ch["status"])
            if st == "PENDING":
                raise Exception("CHALLENGE_UNRESOLVED")
            if st == "RESOLVED":
                path = str(ch["outcome"])
            elif st == "EXPIRED":
                path = "EXPIRED"
            else:
                raise Exception("CHALLENGE_STATE_INVALID")
            final_r = str(ch["final_reconciled"])
            final_a = str(ch["final_agreement"])
        else:
            if now < int(rv["deadline"]):
                raise Exception("CHALLENGE_WINDOW_OPEN")
            path = "UNCHALLENGED"
            final_r = str(rv["reconciled"])
            final_a = str(rv["agreement"])
        if final_r != "UNRESOLVED" and final_r not in BUCKETS:
            raise Exception("FINAL_RESULT_INVALID")
        pol = self.policies[owner]
        decision, reason = decide(final_r, final_a, str(pol.block_at), str(pol.on_split))
        key = advisory_id + ":" + owner
        if key in self.decisions:
            d = self.decisions[key]
            d.decision = decision
            d.reason = reason
            d.final_reconciled = final_r
            d.final_agreement = final_a
            d.path = path
            d.evaluated_at = u256(now)
            d.evaluations = u256(int(d.evaluations) + 1)
        else:
            self.decisions[key] = Decision(
                advisory_id=advisory_id,
                owner=owner,
                decision=decision,
                reason=reason,
                final_reconciled=final_r,
                final_agreement=final_a,
                path=path,
                evaluated_at=u256(now),
                evaluations=u256(1),
            )
            self.decision_total = u256(int(self.decision_total) + 1)

    @gl.public.view
    def get_policy(self, owner: str) -> str:
        o = owner.strip().lower()
        if o not in self.policies:
            return json.dumps({"exists": False})
        p = self.policies[o]
        return json.dumps({"exists": True, "owner": p.owner, "block_at": p.block_at, "on_split": p.on_split}, sort_keys=True)

    @gl.public.view
    def get_decision(self, advisory_id: str, owner: str) -> str:
        key = advisory_id + ":" + owner.strip().lower()
        if key not in self.decisions:
            return json.dumps({"exists": False})
        d = self.decisions[key]
        return json.dumps({
            "exists": True,
            "advisory_id": d.advisory_id,
            "owner": d.owner,
            "decision": d.decision,
            "reason": d.reason,
            "final_reconciled": d.final_reconciled,
            "final_agreement": d.final_agreement,
            "path": d.path,
            "evaluated_at": int(d.evaluated_at),
            "evaluations": int(d.evaluations),
        }, sort_keys=True)

    @gl.public.view
    def lifecycle(self, advisory_id: str) -> str:
        rv = parse_obj(gl.get_contract_at(Address(self.reconciler_addr)).view().get_reconciliation(advisory_id))
        if rv.get("exists") is not True:
            return json.dumps({"advisory_id": advisory_id, "stage": "NOT_RECONCILED", "result_final": False}, sort_keys=True)
        ch = parse_obj(gl.get_contract_at(Address(self.challenge_addr)).view().get_challenge(advisory_id))
        out = {
            "advisory_id": advisory_id,
            "original_reconciled": str(rv["reconciled"]),
            "original_agreement": str(rv["agreement"]),
            "challengeable_until": int(rv["deadline"]),
        }
        if ch.get("exists") is not True:
            out["stage"] = "RECONCILED"
            out["result_final"] = False
            out["rule"] = "challengeable while block time < challengeable_until; final without a challenge once block time >= challengeable_until"
        else:
            st = str(ch["status"])
            out["challenge_status"] = st
            out["resolution_deadline"] = int(ch["resolution_deadline"])
            if st == "PENDING":
                out["stage"] = "CHALLENGE_PENDING"
                out["result_final"] = False
                out["rule"] = "not final until the challenge is resolved, or expired after resolution_deadline"
            else:
                out["stage"] = "CHALLENGE_RESOLVED" if st == "RESOLVED" else "CHALLENGE_EXPIRED"
                out["result_final"] = True
                out["final_reconciled"] = str(ch["final_reconciled"])
                out["final_agreement"] = str(ch["final_agreement"])
                out["rule"] = "final, the gate may evaluate it"
        return json.dumps(out, sort_keys=True)

    @gl.public.view
    def preview_decision(self, reconciled: str, agreement: str, block_at: str, on_split: str) -> str:
        if block_at not in BLOCK_LEVELS or on_split not in SPLIT_ACTIONS:
            return "INVALID_POLICY"
        d, r = decide(reconciled, agreement, block_at, on_split)
        return json.dumps({"decision": d, "reason": r}, sort_keys=True)

    @gl.public.view
    def decision_count(self) -> str:
        return str(int(self.decision_total))

    @gl.public.view
    def get_last_probe(self) -> str:
        return str(int(self.last_probe))

    @gl.public.view
    def get_config(self) -> str:
        return json.dumps({"reconciler": self.reconciler_addr, "challenge": self.challenge_addr}, sort_keys=True)
