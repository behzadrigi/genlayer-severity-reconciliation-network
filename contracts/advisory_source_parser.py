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


def url_host(u: str) -> str:
    rest = u[8:]
    for sep in ["/", "?", "#"]:
        i = rest.find(sep)
        if i >= 0:
            rest = rest[:i]
    return rest.lower()


def base_domain(host: str) -> str:
    parts = host.split(":")[0].split(".")
    return ".".join(parts[-2:])


def check_url(u: str, err: str):
    if not isinstance(u, str) or len(u) < 12 or len(u) > 300 or not u.startswith("https://"):
        raise Exception(err)
    for ch in u:
        if ord(ch) <= 32 or ord(ch) >= 127:
            raise Exception(err)
    host = url_host(u)
    if host == "" or "@" in host or "." not in host:
        raise Exception(err)


def normalize_text(t) -> str:
    return " ".join(str(t).lower().split())


def fetch_norm(url: str) -> str:
    try:
        raw = gl.nondet.web.render(url, mode='text')
    except Exception:
        raise Exception("SOURCE_UNREADABLE")
    norm = normalize_text(raw if raw is not None else "")
    if len(norm) < 40:
        raise Exception("SOURCE_UNREADABLE")
    return norm


CVSS_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
CVSS_AC = {"L": 0.77, "H": 0.44}
CVSS_UI = {"N": 0.85, "R": 0.62}
CVSS_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def pow15(x: float) -> float:
    r = 1.0
    for _ in range(15):
        r = r * x
    return r


def roundup10(x: float) -> int:
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i // 10000
    return i // 10000 + 1


def cvss_score10(vector: str) -> int:
    v = str(vector).strip().upper()
    if not (v.startswith("CVSS:3.1/") or v.startswith("CVSS:3.0/")):
        return -1
    m = {}
    for p in v[9:].split("/"):
        kv = p.split(":")
        if len(kv) != 2 or kv[0] == "" or kv[1] == "":
            return -1
        if kv[0] in m:
            return -1
        m[kv[0]] = kv[1]
    for k in ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]:
        if k not in m:
            return -1
    if m["AV"] not in CVSS_AV or m["AC"] not in CVSS_AC or m["UI"] not in CVSS_UI:
        return -1
    if m["C"] not in CVSS_CIA or m["I"] not in CVSS_CIA or m["A"] not in CVSS_CIA:
        return -1
    if m["S"] not in ["U", "C"] or m["PR"] not in ["N", "L", "H"]:
        return -1
    changed = m["S"] == "C"
    if m["PR"] == "N":
        pr = 0.85
    elif m["PR"] == "L":
        pr = 0.68 if changed else 0.62
    else:
        pr = 0.5 if changed else 0.27
    iss = 1.0 - (1.0 - CVSS_CIA[m["C"]]) * (1.0 - CVSS_CIA[m["I"]]) * (1.0 - CVSS_CIA[m["A"]])
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * pow15(iss - 0.02)
    else:
        impact = 6.42 * iss
    expl = 8.22 * CVSS_AV[m["AV"]] * CVSS_AC[m["AC"]] * pr * CVSS_UI[m["UI"]]
    if impact <= 0:
        return 0
    if changed:
        total = 1.08 * (impact + expl)
    else:
        total = impact + expl
    if total > 10.0:
        total = 10.0
    return roundup10(total)


def bucket_of_score10(s: int) -> str:
    if s <= 0:
        return "NONE"
    if s < 40:
        return "LOW"
    if s < 70:
        return "MEDIUM"
    if s < 90:
        return "HIGH"
    return "CRITICAL"


def extract_vectors(norm: str) -> list:
    out = []
    seen = []
    for prefix in ["cvss:3.1/", "cvss:3.0/"]:
        start = 0
        while True:
            i = norm.find(prefix, start)
            if i < 0:
                break
            start = i + 1
            j = i
            while j < len(norm) and (norm[j].isalnum() or norm[j] in ":/."):
                j += 1
            tok = norm[i:j].upper().rstrip("./:")
            if tok in seen:
                continue
            s = cvss_score10(tok)
            if s >= 0:
                seen.append(tok)
                out.append([tok, s])
    out.sort()
    return out


def bucket_set(vecs: list) -> list:
    ranks = []
    for pair in vecs:
        r = BUCKETS.index(bucket_of_score10(int(pair[1])))
        if r not in ranks:
            ranks.append(r)
    ranks.sort()
    return ranks


def combine_buckets(buckets: list, strengths: list):
    n = len(buckets)
    if n < 2:
        return "UNRESOLVED", "UNRESOLVED"
    ranks = []
    for i in range(n):
        if buckets[i] not in BUCKETS or int(strengths[i]) < 50:
            return "UNRESOLVED", "UNRESOLVED"
        ranks.append(BUCKETS.index(buckets[i]))
    spread = max(ranks) - min(ranks)
    if spread == 0:
        agreement = "UNANIMOUS"
    elif spread == 1:
        agreement = "ADJACENT"
    else:
        agreement = "SPLIT"
    return BUCKETS[max(ranks)], agreement


@allow_storage
@dataclass
class ParsedSource:
    url: str
    content_hash: str
    vectors_json: str
    n_vectors: u256
    version: u256
    parser: str


class AdvisorySourceParser(gl.Contract):
    parsed: TreeMap[str, ParsedSource]
    parsed_total: u256

    def __init__(self):
        self.parsed_total = u256(0)

    @gl.public.write
    def parse_source(self, url: str):
        check_url(url, "INVALID_URL")

        def leader_fn():
            norm = fetch_norm(url)
            return {"digest": sha_hex(norm), "vectors": extract_vectors(norm), "len": len(norm)}

        def validator_fn(leader_result) -> bool:
            if not isinstance(leader_result, gl.vm.Return):
                return leader_failed_ok(leader_fn)
            try:
                mine = leader_fn()
            except Exception:
                return False
            return mine == leader_result.calldata

        res = gl.vm.run_nondet_unsafe(leader_fn, validator_fn)
        digest = str(res["digest"])
        vectors = res["vectors"]
        if len(digest) != 64:
            raise Exception("BAD_DIGEST")
        clean = []
        for pair in vectors:
            if cvss_score10(str(pair[0])) != int(pair[1]):
                raise Exception("BAD_VECTOR")
            clean.append([str(pair[0]), int(pair[1])])
        key = sha_hex(url)
        who = sender_hex()
        if key in self.parsed:
            rec = self.parsed[key]
            rec.content_hash = digest
            rec.vectors_json = json.dumps(clean)
            rec.n_vectors = u256(len(clean))
            rec.version = u256(int(rec.version) + 1)
            rec.parser = who
        else:
            self.parsed[key] = ParsedSource(
                url=url,
                content_hash=digest,
                vectors_json=json.dumps(clean),
                n_vectors=u256(len(clean)),
                version=u256(1),
                parser=who,
            )
            self.parsed_total = u256(int(self.parsed_total) + 1)

    @gl.public.view
    def get_source(self, url: str) -> str:
        key = sha_hex(url)
        if key not in self.parsed:
            return json.dumps({"exists": False})
        r = self.parsed[key]
        vecs = json.loads(r.vectors_json)
        return json.dumps({
            "exists": True,
            "url": r.url,
            "content_hash": r.content_hash,
            "vectors": vecs,
            "n_vectors": int(r.n_vectors),
            "buckets": [bucket_of_score10(int(p[1])) for p in vecs],
            "version": int(r.version),
            "parser": r.parser,
        }, sort_keys=True)

    @gl.public.view
    def parsed_count(self) -> str:
        return str(int(self.parsed_total))

    @gl.public.view
    def score_of_vector(self, vector: str) -> str:
        s = cvss_score10(vector)
        if s < 0:
            return "INVALID"
        return str(s)

    @gl.public.view
    def bucket_of(self, score10: int) -> str:
        return bucket_of_score10(score10)

    @gl.public.view
    def vectors_in_text(self, text: str) -> str:
        return json.dumps(extract_vectors(normalize_text(text)))

    @gl.public.view
    def url_key(self, url: str) -> str:
        return sha_hex(url)
