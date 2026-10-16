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


@allow_storage
@dataclass
class Advisory:
    advisory_id: str
    vuln_id: str
    sources_json: str
    registrant: str


def check_vuln_id(v: str):
    if not isinstance(v, str) or len(v) < 4 or len(v) > 64:
        raise Exception("INVALID_VULN_ID")
    for ch in v:
        if not (ch.isalnum() or ch in "-_.:"):
            raise Exception("INVALID_VULN_ID")
        if ord(ch) >= 127:
            raise Exception("INVALID_VULN_ID")


def check_sources(urls: list):
    # urls holds two or three non empty strings
    for i in range(len(urls)):
        check_url(urls[i], "INVALID_URL_" + str(i + 1))
    for i in range(len(urls)):
        for j in range(i + 1, len(urls)):
            if urls[i] == urls[j]:
                raise Exception("SOURCES_NOT_INDEPENDENT")
            if base_domain(url_host(urls[i])) == base_domain(url_host(urls[j])):
                raise Exception("SOURCES_NOT_INDEPENDENT")


def collect_urls(url_1: str, url_2: str, url_3: str) -> list:
    urls = [url_1, url_2]
    if url_3 != "":
        urls.append(url_3)
    return urls


class AdvisoryRegistry(gl.Contract):
    advisories: TreeMap[str, Advisory]
    seen: TreeMap[str, str]
    advisory_total: u256

    def __init__(self):
        self.advisory_total = u256(0)

    @gl.public.write
    def register_advisory(self, vuln_id: str, url_1: str, url_2: str, url_3: str):
        check_vuln_id(vuln_id)
        urls = collect_urls(url_1, url_2, url_3)
        check_sources(urls)
        key = sha_hex(json.dumps([vuln_id.lower(), sorted(urls)]))
        if key in self.seen:
            raise Exception("ALREADY_REGISTERED")
        n = int(self.advisory_total) + 1
        aid = str(n)
        self.advisories[aid] = Advisory(
            advisory_id=aid,
            vuln_id=vuln_id,
            sources_json=json.dumps(urls),
            registrant=sender_hex(),
        )
        self.seen[key] = aid
        self.advisory_total = u256(n)

    @gl.public.view
    def get_advisory(self, advisory_id: str) -> str:
        if advisory_id not in self.advisories:
            return json.dumps({"exists": False})
        a = self.advisories[advisory_id]
        return json.dumps({
            "exists": True,
            "advisory_id": a.advisory_id,
            "vuln_id": a.vuln_id,
            "sources": json.loads(a.sources_json),
            "registrant": a.registrant,
        }, sort_keys=True)

    @gl.public.view
    def advisory_count(self) -> str:
        return str(int(self.advisory_total))

    @gl.public.view
    def preview_sources(self, url_1: str, url_2: str, url_3: str) -> str:
        try:
            check_sources(collect_urls(url_1, url_2, url_3))
        except Exception as e:
            return str(e)
        return "OK"
