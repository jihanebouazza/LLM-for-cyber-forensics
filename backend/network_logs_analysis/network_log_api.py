from __future__ import annotations

from fastapi import APIRouter, UploadFile, File, HTTPException, Query
from datetime import datetime
from typing import Any, Dict, List, Optional
import json
import re
import requests
from concurrent.futures import ThreadPoolExecutor
import uuid
from backend.network_logs_analysis.database import get_connection, get_cursor

from backend.network_logs_analysis.models import NetworkFlowInput,LogInput

IOC_REGEX = re.compile(
    r"(?P<url>https?://\S+)"
    r"|(?P<ip>\b(?:\d{1,3}\.){3}\d{1,3}\b)"
    r"|(?P<domain>\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b)"
    r"|(?P<sha256>\b[a-fA-F0-9]{64}\b)"
    r"|(?P<md5>\b[a-fA-F0-9]{32}\b)"
    r"|(?P<path>\b[A-Za-z]:\\[^\n\r\t\"']+\b)"
    r"|(?P<linux_path>\b/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+\b)"
)


PLACEHOLDER_VALUES = {
    "1.2.3.4", "8.8.8.8", "example.com", "localhost", "...", "null", "none",
    "[ip_address]", "[domain]", "[url]", "[hash]", "[redacted]", "[confidential]",
    "unknown", "n/a", "na"
}


ALLOWED_IOC_TYPES = {
    "ip", "domain", "url", "hash", "file_path", "registry_key",
    "user", "process", "email", "unknown"
}


BLOCKLIST_SUBSTRINGS = [
    "any.run/report/",
    "app.any.run/tasks/",
    "any.run/tasks/",
]


PRIVATE_IP_RE = re.compile(
    r"^(10\.)|^(192\.168\.)|^(172\.(1[6-9]|2\d|3[0-1])\.)"
)

SUSPICIOUS_PORTS = {22, 23, 3389, 445, 139, 135, 5985, 5986}


def _now_iso() -> str:
    return datetime.utcnow().isoformat()


def _safe_json_parse(text: str) -> dict:
    """
    Tries to parse JSON even if the model adds extra text.
    """
    text = (text or "").strip()
    if not text:
        return {}

    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return {}

    candidate = text[start:end + 1]
    try:
        obj = json.loads(candidate)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def _jsonable(obj: Any) -> Any:
    """
    Make DB/response-safe (handles datetimes, tuples, etc).
    """
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, (list, tuple)):
        return [_jsonable(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _jsonable(v) for k, v in obj.items()}
    return obj


def _is_placeholder(v: str) -> bool:
    vv = (v or "").strip().lower()
    return (not vv) or (vv in PLACEHOLDER_VALUES)


def _is_meta_reference(value: str) -> bool:
    v = (value or "").lower()
    return any(s in v for s in BLOCKLIST_SUBSTRINGS)


def _normalize_ip(v: str) -> Optional[str]:
    """
    - strips :port
    - validates 0..255 octets
    - removes leading zeros: 10.00.0.5 -> 10.0.0.5
    """
    v = (v or "").strip()
    if ":" in v:
        v = v.split(":")[0].strip()

    if not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", v):
        return None

    parts = v.split(".")
    nums: List[str] = []
    for p in parts:
        try:
            n = int(p, 10)
        except ValueError:
            return None
        if n < 0 or n > 255:
            return None
        nums.append(str(n))  
    return ".".join(nums)


def _valid_domain(v: str) -> bool:
    vv = (v or "").strip().lower()
    if _is_placeholder(vv):
        return False
    if vv.startswith("http://") or vv.startswith("https://"):
        return False
    return bool(re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", vv))


def _valid_hash(v: str) -> bool:
    vv = (v or "").strip().lower()
    if _is_placeholder(vv):
        return False
    
    if re.fullmatch(r"[a-f0-9]{32}", vv):
        return True
    if re.fullmatch(r"[a-f0-9]{64}", vv):
        return True
    return False


def _valid_email(v: str) -> bool:
    vv = (v or "").strip().lower()
    if _is_placeholder(vv):
        return False
    return bool(re.fullmatch(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", vv))


def _valid_user(v: str) -> bool:
    vv = (v or "").strip()
    if not vv:
        return False
    low = vv.lower()
    if _is_placeholder(low):
        return False
    
    if low in {"user", "username", "unknown", "adminuser"}:
        return False
    return bool(re.fullmatch(r"[a-zA-Z0-9._-]{1,64}", vv))


def _valid_process(v: str) -> bool:
    vv = (v or "").strip()
    if not vv:
        return False
    low = vv.lower()
    if _is_placeholder(low):
        return False
    
    return bool(re.fullmatch(r"[a-zA-Z0-9._-]{1,64}(\.exe)?", vv))


def _valid_file_path(v: str) -> bool:
    vv = (v or "").strip()
    if _is_placeholder(vv.lower()):
        return False
    
    if re.fullmatch(r"[A-Za-z]:\\[^\n\r\t\"']+", vv):
        return True
    if vv.startswith("/") and len(vv) >= 2:
        return True
    return False


def _normalize_and_filter_ioc(ioc_type: str, value: str) -> Optional[Dict[str, str]]:
    t = (ioc_type or "").strip().lower()
    v = (value or "").strip()

    if not t or not v:
        return None

    if t not in ALLOWED_IOC_TYPES:
        return None

    if _is_placeholder(v):
        return None

    if _is_meta_reference(v):
        return None

    
    if t == "ip":
        canon = _normalize_ip(v)
        if not canon:
            return None
        v = canon

    elif t == "domain":
        if not _valid_domain(v):
            return None
        v = v.lower()

    elif t == "url":
        if not v.lower().startswith(("http://", "https://")):
            return None

    elif t == "hash":
        
        vv = v.lower()
        if vv.startswith("sha256:"):
            vv = vv.split("sha256:", 1)[1]
        if vv.startswith("md5:"):
            vv = vv.split("md5:", 1)[1]
        if not _valid_hash(vv):
            return None
        v = vv

    elif t == "email":
        if not _valid_email(v):
            return None
        v = v.lower()

    elif t == "user":
        if not _valid_user(v):
            return None

    elif t == "process":
        if not _valid_process(v):
            return None
        v = v.lower()

    elif t == "file_path":
        if not _valid_file_path(v):
            return None

    
    elif t == "unknown":
        if len(v) > 120:
            return None

    return {"type": t, "value": v}


def _normalize_iocs(value: Any) -> List[Dict[str, Any]]:
    """
    Enforce: iocs is ALWAYS list[{"type": "...", "value": "..."}]
    + filter/normalize with _normalize_and_filter_ioc
    """
    out: List[Dict[str, Any]] = []

    if value is None:
        return out

    
    if isinstance(value, str):
        v = value.strip()
        norm = _normalize_and_filter_ioc("unknown", v)
        return [norm] if norm else []

    if isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                norm = _normalize_and_filter_ioc("unknown", item.strip())
                if norm:
                    out.append(norm)
            elif isinstance(item, dict):
                t = (item.get("type") or item.get("ioc_type") or "unknown").strip()
                v = (item.get("value") or "").strip()
                norm = _normalize_and_filter_ioc(t, v)
                if norm:
                    out.append(norm)
        return out

    
    if isinstance(value, dict):
        t = (value.get("type") or value.get("ioc_type") or "unknown").strip()
        v = (value.get("value") or "").strip()
        norm = _normalize_and_filter_ioc(t, v)
        return [norm] if norm else []

    return out


def _extract_iocs_regex(text: str) -> List[Dict[str, str]]:
    """
    Cheap, fast IOC extraction to avoid placeholder outputs.
    Now also normalizes and filters (incl. IP canonicalization).
    """
    text = (text or "")
    found: List[Dict[str, str]] = []
    seen = set()

    for m in IOC_REGEX.finditer(text):
        kind = m.lastgroup
        val = m.group(0)

        if not kind or not val:
            continue

        t = kind
        if kind in ("sha256", "md5"):
            t = "hash"
        elif kind in ("path", "linux_path"):
            t = "file_path"

        norm = _normalize_and_filter_ioc(t, val)
        if not norm:
            continue

        key = (norm["type"], norm["value"].lower())
        if key in seen:
            continue

        seen.add(key)
        found.append(norm)

    return found


def _dedupe_iocs(iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen = set()
    for i in iocs or []:
        if not isinstance(i, dict):
            continue
        t = (i.get("type") or "").strip().lower()
        v = (i.get("value") or "").strip()
        if not t or not v:
            continue
        key = (t, v.lower())
        if key in seen:
            continue
        seen.add(key)
        out.append({"type": t, "value": v})
    return out


def _is_private_ip(ip: str) -> bool:
    return bool(PRIVATE_IP_RE.match(ip or ""))


def _severity_rank(s: str) -> int:
    s = (s or "").strip().lower()
    order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    return order.get(s, 1)


def _max_severity(a: str, b: str) -> str:
    return a if _severity_rank(a) >= _severity_rank(b) else b


def _apply_network_severity_heuristics(flow: NetworkFlowInput, analysis: dict) -> dict:
    """
    Rule-based safety net to prevent obviously wrong severity
    (e.g. DENY suspicious port marked as low).
    """
    hints = analysis.get("hint") or []
    if not isinstance(hints, list):
        hints = []

    
    current = "low"
    for h in hints:
        if isinstance(h, dict) and h.get("severity"):
            current = (h.get("severity") or "low").strip().lower()
            break

   
    sev = current
    action = (flow.action or "").strip().upper()
    proto = (flow.protocol or "").strip().upper()
    dst_port = int(flow.dst_port)
    src_ip = (flow.src_ip or "").strip()
    dst_ip = (flow.dst_ip or "").strip()

    
    if action == "DENY":
        sev = _max_severity(sev, "medium")

    
    if dst_port in SUSPICIOUS_PORTS and action in {"ALLOW", "DENY"}:
        sev = _max_severity(sev, "high")

    
    if (not _is_private_ip(dst_ip)) and dst_port in {22, 3389, 445}:
        sev = _max_severity(sev, "high")

    
    if (not _is_private_ip(dst_ip)) and flow.bytes_out and flow.bytes_out > 5_000_000:
        sev = _max_severity(sev, "high")

    
    if _severity_rank(sev) > _severity_rank(current):
        hints.insert(0, {
            "type": "info",
            "description": f"Severity adjusted by heuristics (action={action}, proto={proto}, dst_port={dst_port}).",
            "severity": sev,
        })
        analysis["hint"] = hints

    return analysis



class NetworkAPI:
    def __init__(self):
        self.router = APIRouter(prefix="/api/network", tags=["network"])
        self.ollama_url = "http://localhost:11434/api/generate"
        self.model = "phi3:mini" 
        self.executor = ThreadPoolExecutor(max_workers=4)

        self.router.add_api_route("/upload", self.upload_file, methods=["POST"])
        self.router.add_api_route("",get_logs_and_flows, methods=["GET"])

    
    def analyze_with_ollama(self, text: str, extracted_iocs: Optional[List[Dict[str, str]]] = None) -> dict:
        """
        Returns a stable schema:
        {
          "iocs": [{"type": "...", "value": "..."}],
          "event": {"type": "...", "summary": "..."},
          "hint": [{"type": "...", "description": "...", "severity": "..."}],
          "status": "success",
          "analyzed_at": "..."
        }
        """
        extracted_iocs = extracted_iocs or []
        
        iocs_json = json.dumps(extracted_iocs, ensure_ascii=False)

        prompt = f"""
You are a security analyst.
Return ONLY valid JSON (no markdown, no extra text).

Schema (EXACT keys):
{{
  "iocs": [{{"type":"ip|domain|url|hash|file_path|registry_key|user|process|email|unknown","value":"..."}}],
  "event": {{"type":"string","summary":"string"}},
  "hint": [{{"type":"info|action","description":"string","severity":"low|medium|high|critical"}}]
}}

Rules:
- iocs.type MUST be ONE of: ip, domain, url, hash, file_path, registry_key, user, process, email, unknown
- iocs.value must be the indicator ONLY (no "whitelisted", no extra words, no placeholders)
- If nothing found: "iocs": []
- Prefer and reuse iocs from extracted_iocs when valid.

extracted_iocs: {iocs_json}

data:
{text}
""".strip()

        try:
            r = requests.post(
                self.ollama_url,
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.0, "num_predict": 220},
                    "format": "json",
                },
                timeout=(10, 40),
            )
            r.raise_for_status()
            raw = (r.json().get("response") or "").strip()
            parsed = _safe_json_parse(raw)

            
            iocs = _normalize_iocs(parsed.get("iocs"))

            
            merged = iocs + extracted_iocs
            iocs = _dedupe_iocs(merged)

            event = parsed.get("event")
            if not isinstance(event, dict):
                event = {"type": "unknown", "summary": "Automatic analysis"}
            else:
                event_type = (event.get("type") or "unknown").strip()
                summary = (event.get("summary") or "Automatic analysis").strip()
                event = {"type": event_type, "summary": summary}

            hint = parsed.get("hint")
            if not isinstance(hint, list):
                hint = []
            norm_hint = []
            for h in hint:
                if not isinstance(h, dict):
                    continue
                sev = (h.get("severity") or "low").strip().lower()
                if sev not in {"low", "medium", "high", "critical"}:
                    sev = "low"
                norm_hint.append({
                    "type": (h.get("type") or "info").strip(),
                    "description": (h.get("description") or "").strip(),
                    "severity": sev,
                })

            return {
                "iocs": iocs,
                "event": event,
                "hint": norm_hint,
                "status": "success",
                "analyzed_at": _now_iso(),
            }

        except Exception:
            
            return {
                "iocs": _dedupe_iocs(extracted_iocs),
                "event": {"type": "unknown", "summary": "Automatic analysis"},
                "hint": [{
                    "type": "info",
                    "description": "Fallback analysis applied",
                    "severity": "low",
                }],
                "status": "success",
                "analyzed_at": _now_iso(),
            }

   
    async def upload_file(self, file: UploadFile = File(...)):
        if not file:
            raise HTTPException(status_code=400, detail="File is required")

        conn = None
        cur = None

        try:
            content = await file.read()
            if not content:
                raise HTTPException(status_code=400, detail="Uploaded file is empty")

            try:
                data = json.loads(content.decode("utf-8"))
            except json.JSONDecodeError as e:
                raise HTTPException(status_code=400, detail=f"Invalid JSON file: {str(e)}")

            logs = data.get("logs", [])
            network = data.get("network", [])

            if not isinstance(logs, list) or not isinstance(network, list):
                raise HTTPException(status_code=400, detail="'logs' and 'network' must be arrays")

            results = {"logs": [], "network": []}

            conn = get_connection()
            cur = get_cursor(conn)

           

            for log in logs:
                log_obj = LogInput(**log)
                
                source_id = uuid.uuid4()
                cur.execute(
        "INSERT INTO log_sources (id) VALUES (%s)",
        (str(source_id),)
    )
                extracted = _extract_iocs_regex(log_obj.raw_text)
                analysis = self.analyze_with_ollama(log_obj.raw_text, extracted_iocs=extracted)
                log_id = uuid.uuid4()
                cur.execute(
                    """
                    INSERT INTO logs
                    (id, source_id, timestamp, log_level, raw_text, category, parsed_json)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (
                        str(log_id),       
                        str(source_id),
                        log_obj.timestamp,
                        log_obj.log_level,
                        log_obj.raw_text,
                        log_obj.category,
                        json.dumps(analysis, ensure_ascii=False),
                    ),
                )
                

            
            for ioc in analysis.get("iocs", []):
                cur.execute(
                    """
                    INSERT INTO log_iocs (log_id, ioc_type, value,description,source)
                    VALUES (%s,%s,%s,%s,%s)
                    """,
                    (str(log_id), ioc.get("type", "unknown"),
            ioc.get("value", ""),
            ioc.get("description", ""),  
            ioc.get("source", "analysis"))
                )

            
            event = analysis.get("event", {})
            cur.execute(
                """
                INSERT INTO log_events (log_id, event_type,event_description,severity )
                VALUES (%s,%s,%s,%s)
                """,
                (str(log_id), event.get("type", "unknown"),
        event.get("summary", ""),  
        event.get("severity", "low")
    ),
)
            
            for h in analysis.get("hint", []):
                cur.execute(
                    """
                    INSERT INTO log_detection_hints (log_id, hint_type, hint_text)
                    VALUES (%s,%s,%s)
                    """,
                    (str(log_id), h.get("type"), h.get("description")),
                )
                results["logs"].append(analysis)

            
            for flow in network:
                flow_obj = NetworkFlowInput(**flow)
                flow_id = uuid.uuid4()
                cur.execute(
                    """
                    INSERT INTO network_flows (
                        id,
                        timestamp_start, timestamp_end,
                        src_ip, src_port,
                        dst_ip, dst_port,
                        protocol, action,
                        bytes_in, bytes_out,
                        sensor
                    )
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (
                        str(flow_id),
                        flow_obj.timestamp_start,
                        flow_obj.timestamp_end,
                        flow_obj.src_ip,
                        flow_obj.src_port,
                        flow_obj.dst_ip,
                        flow_obj.dst_port,
                        flow_obj.protocol,
                        flow_obj.action,
                        flow_obj.bytes_in,
                        flow_obj.bytes_out,
                        flow_obj.sensor,
                    ),
                )

                

                flow_text = json.dumps(flow_obj.model_dump(mode="json"), ensure_ascii=False)

                extracted = _extract_iocs_regex(flow_text)
                analysis = self.analyze_with_ollama(flow_text, extracted_iocs=extracted)
                analysis = _apply_network_severity_heuristics(flow_obj, analysis)
                for ioc in analysis.get("iocs", []):
                  cur.execute(
                    """
                    INSERT INTO network_iocs (flow_id, ioc_type, value, category, source)
                    VALUES (%s,%s,%s,%s,%s)
                    """,
                    (str(flow_id), 
                ioc.get("type", "unknown"),
            ioc.get("value", ""),
            ioc.get("category", ""),  
            ioc.get("source", "analysis")  
        ),
                  )
                for h in analysis.get("hint", []):
                  cur.execute(
                    """
                    INSERT INTO network_detection_hints (flow_id, hint_type, hint_text)
                    VALUES (%s,%s,%s)
                    """,
                    (str(flow_id), h.get("type"),
            h.get("description")  
        ),
    )
                
                results["network"].append(analysis)

                geoip_country = analysis.get("geoip_country")  
                geoip_city = analysis.get("geoip_city")
                asn = analysis.get("asn")
                reputation_score = analysis.get("reputation_score")
                threat_actor_guess = analysis.get("threat_actor_guess")
                cur.execute(
    """
    INSERT INTO network_enrichment (
        flow_id, geoip_country, geoip_city, asn, reputation_score, threat_actor_guess
    )
    VALUES (%s,%s,%s,%s,%s,%s)
    """,
    (
        str(flow_id),
        geoip_country,
        geoip_city,
        asn,
        reputation_score,
        threat_actor_guess,
    ),
)
                conn.commit()

            return {
                "status": "success",
                "inserted": {
                    "logs": len(results["logs"]),
                    "network": len(results["network"]),
                },
                "results": results,
                "timestamp": _now_iso(),
            }

        except HTTPException:
            if conn:
                conn.rollback()
            raise
        except Exception as e:
            if conn:
                conn.rollback()
            raise HTTPException(status_code=500, detail=str(e))
        finally:
            try:
                if cur:
                    cur.close()
            finally:
                if conn:
                    conn.close()

   
   


async def get_logs_and_flows(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    conn = None
    cur = None
    try:
        conn = get_connection()
        cur = get_cursor(conn)

        
        cur.execute(
            """
            SELECT l.id, l.timestamp, l.log_level, l.raw_text, l.category,
                   l.parsed_json, s.id AS source_id
            FROM logs l
            LEFT JOIN log_sources s ON l.source_id = s.id
            ORDER BY l.timestamp DESC
            LIMIT %s OFFSET %s
            """,
            (limit, offset),
        )
        logs = cur.fetchall()

        
        cur.execute(
            """
            SELECT * FROM network_flows
            ORDER BY timestamp_start DESC
            LIMIT %s OFFSET %s
            """,
            (limit, offset),
        )
        flows = cur.fetchall()

        return {
            "logs_count": len(logs),
            "logs": _jsonable(logs),
            "flows_count": len(flows),
            "flows": _jsonable(flows),
        }

    finally:
        try:
            if cur:
                cur.close()
        finally:
            if conn:
                conn.close()



api = NetworkAPI()
router = api.router   