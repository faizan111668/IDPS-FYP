"""
routers/incidents.py
====================
All /api/incidents/* endpoints for the Incidents & Detections page.

Sections:
  1. Stat Cards        — total detections, anomaly, signature, ransomware, critical
  2. Incidents         — CRUD: list, update status, assign analyst
  3. Detections        — list raw detections, block/whitelist IP
  4. Charts            — donut + severity bar data
  5. Snapshot          — single call to hydrate full page
"""

from fastapi import APIRouter
from typing import Optional
from datetime import datetime

router = APIRouter(prefix="/api/incidents", tags=["Incidents"])

# ══════════════════════════════════════════════════════════════
# IN-MEMORY STATE
# ══════════════════════════════════════════════════════════════

incidents = [
    {"id":"INC-001","desc":"SYN flood targeting web server port 443",           "type":"DDoS",        "severity":"Critical","status":"Open",       "analyst":"analyst1", "updated":"2026-02-24 09:10","srcIp":"185.220.101.47","dstIp":"10.0.0.15", "protocol":"TCP", "port":443,  "timestamp":"2026-02-24 08:55"},
    {"id":"INC-002","desc":"Repeated SSH login failures from external IP",      "type":"Brute Force", "severity":"High",    "status":"In Progress","analyst":"soc_lead", "updated":"2026-02-24 08:44","srcIp":"91.108.4.200",  "dstIp":"10.0.0.22", "protocol":"TCP", "port":22,   "timestamp":"2026-02-24 07:30"},
    {"id":"INC-003","desc":"SQL injection attempt on login endpoint",           "type":"Signature",   "severity":"Critical","status":"Open",       "analyst":"analyst2", "updated":"2026-02-24 09:01","srcIp":"103.75.190.12", "dstIp":"10.0.0.5",  "protocol":"HTTP","port":80,   "timestamp":"2026-02-24 08:40"},
    {"id":"INC-004","desc":"LockBit C2 beacon detected on port 8443",          "type":"Ransomware",  "severity":"Critical","status":"Open",       "analyst":"admin",    "updated":"2026-02-24 09:05","srcIp":"77.83.246.90",  "dstIp":"10.0.0.8",  "protocol":"TCP", "port":8443, "timestamp":"2026-02-24 09:00"},
    {"id":"INC-005","desc":"Anomalous outbound traffic spike — 3x baseline",   "type":"Anomaly",     "severity":"High",    "status":"In Progress","analyst":"analyst1", "updated":"2026-02-24 08:20","srcIp":"10.0.0.44",     "dstIp":"8.8.8.8",   "protocol":"UDP", "port":53,   "timestamp":"2026-02-24 07:55"},
    {"id":"INC-006","desc":"Port scan detected across /24 subnet",             "type":"Signature",   "severity":"Medium",  "status":"Resolved",   "analyst":"analyst2", "updated":"2026-02-24 07:00","srcIp":"45.142.212.100","dstIp":"10.0.0.0",  "protocol":"TCP", "port":0,    "timestamp":"2026-02-23 22:10"},
    {"id":"INC-007","desc":"Shadow copy deletion via vssadmin command",        "type":"Ransomware",  "severity":"Critical","status":"Open",       "analyst":"soc_lead", "updated":"2026-02-24 08:58","srcIp":"10.0.0.31",     "dstIp":"10.0.0.100","protocol":"SMB", "port":445,  "timestamp":"2026-02-24 08:50"},
    {"id":"INC-008","desc":"XSS payload in user-agent header",                 "type":"Signature",   "severity":"Medium",  "status":"Resolved",   "analyst":"analyst1", "updated":"2026-02-24 06:30","srcIp":"162.247.74.200","dstIp":"10.0.0.5",  "protocol":"HTTP","port":80,   "timestamp":"2026-02-23 20:00"},
    {"id":"INC-009","desc":"UDP amplification attack — 921K packets/sec",      "type":"DDoS",        "severity":"Critical","status":"In Progress","analyst":"admin",    "updated":"2026-02-24 09:08","srcIp":"194.165.16.78", "dstIp":"10.0.0.1",  "protocol":"UDP", "port":123,  "timestamp":"2026-02-24 08:45"},
    {"id":"INC-010","desc":"Emotet malware C2 communication pattern",          "type":"Signature",   "severity":"High",    "status":"Open",       "analyst":"analyst2", "updated":"2026-02-24 08:35","srcIp":"5.188.206.14",  "dstIp":"10.0.0.19", "protocol":"HTTP","port":8080, "timestamp":"2026-02-24 08:10"},
    {"id":"INC-011","desc":"Mass read of /home directories — possible exfil",  "type":"Ransomware",  "severity":"High",    "status":"In Progress","analyst":"soc_lead", "updated":"2026-02-24 08:00","srcIp":"10.0.0.55",     "dstIp":"10.0.0.200","protocol":"NFS", "port":2049, "timestamp":"2026-02-24 07:40"},
    {"id":"INC-012","desc":"Baseline traffic anomaly — packet size >3x avg",   "type":"Anomaly",     "severity":"Low",     "status":"Closed",     "analyst":"analyst1", "updated":"2026-02-23 18:00","srcIp":"10.0.0.77",     "dstIp":"10.0.0.1",  "protocol":"TCP", "port":443,  "timestamp":"2026-02-23 16:00"},
    {"id":"INC-013","desc":"Ryuk-style registry key modification detected",    "type":"Ransomware",  "severity":"Critical","status":"Open",       "analyst":"admin",    "updated":"2026-02-24 09:02","srcIp":"10.0.0.31",     "dstIp":"10.0.0.100","protocol":"RPC", "port":135,  "timestamp":"2026-02-24 08:52"},
    {"id":"INC-014","desc":"FTP brute force — 2,400 attempts in 10 minutes",   "type":"Brute Force", "severity":"Medium",  "status":"Resolved",   "analyst":"analyst2", "updated":"2026-02-23 14:00","srcIp":"91.108.4.200",  "dstIp":"10.0.0.22", "protocol":"FTP", "port":21,   "timestamp":"2026-02-23 12:00"},
    {"id":"INC-015","desc":"DNS tunneling pattern — covert data exfiltration", "type":"Anomaly",     "severity":"High",    "status":"Open",       "analyst":"soc_lead", "updated":"2026-02-24 08:50","srcIp":"10.0.0.44",     "dstIp":"185.1.1.1", "protocol":"DNS", "port":53,   "timestamp":"2026-02-24 08:30"},
]

detections = [
    {"id":1,  "timestamp":"2026-02-24 09:12","srcIp":"185.220.101.47","dstIp":"10.0.0.15", "protocol":"TCP", "port":443,  "detType":"Anomaly",   "severity":"Critical","classification":"Malicious",  "explanation":"Traffic volume 50x baseline — DDoS pattern confirmed"},
    {"id":2,  "timestamp":"2026-02-24 09:10","srcIp":"103.75.190.12", "dstIp":"10.0.0.5",  "protocol":"HTTP","port":80,   "detType":"Signature", "severity":"Critical","classification":"Malicious",  "explanation":"SQL UNION SELECT payload matched SIG-001"},
    {"id":3,  "timestamp":"2026-02-24 09:08","srcIp":"77.83.246.90",  "dstIp":"10.0.0.8",  "protocol":"TCP", "port":8443, "detType":"Ransomware","severity":"Critical","classification":"Malicious",  "explanation":"LockBit C2 beacon pattern on non-standard port"},
    {"id":4,  "timestamp":"2026-02-24 09:05","srcIp":"91.108.4.200",  "dstIp":"10.0.0.22", "protocol":"TCP", "port":22,   "detType":"Signature", "severity":"High",    "classification":"Suspicious", "explanation":"SSH brute force — 847 failed attempts in 5 minutes"},
    {"id":5,  "timestamp":"2026-02-24 09:01","srcIp":"10.0.0.31",     "dstIp":"10.0.0.100","protocol":"SMB", "port":445,  "detType":"Ransomware","severity":"Critical","classification":"Malicious",  "explanation":"vssadmin shadow copy deletion — Ryuk indicator"},
    {"id":6,  "timestamp":"2026-02-24 08:58","srcIp":"194.165.16.78", "dstIp":"10.0.0.1",  "protocol":"UDP", "port":123,  "detType":"Anomaly",   "severity":"Critical","classification":"Malicious",  "explanation":"UDP amplification — 921K pps from known bad actor"},
    {"id":7,  "timestamp":"2026-02-24 08:55","srcIp":"10.0.0.44",     "dstIp":"8.8.8.8",   "protocol":"DNS", "port":53,   "detType":"Anomaly",   "severity":"High",    "classification":"Suspicious", "explanation":"Unusually high DNS query rate — possible tunneling"},
    {"id":8,  "timestamp":"2026-02-24 08:50","srcIp":"45.142.212.100","dstIp":"10.0.0.0",  "protocol":"TCP", "port":0,    "detType":"Signature", "severity":"Medium",  "classification":"Suspicious", "explanation":"NMAP SYN scan across /24 — 254 hosts probed"},
    {"id":9,  "timestamp":"2026-02-24 08:44","srcIp":"5.188.206.14",  "dstIp":"10.0.0.19", "protocol":"HTTP","port":8080, "detType":"Signature", "severity":"High",    "classification":"Malicious",  "explanation":"Emotet dropper URL pattern in HTTP payload"},
    {"id":10, "timestamp":"2026-02-24 08:40","srcIp":"162.247.74.200","dstIp":"10.0.0.5",  "protocol":"HTTP","port":80,   "detType":"Signature", "severity":"Medium",  "classification":"Suspicious", "explanation":"XSS payload detected in User-Agent header"},
    {"id":11, "timestamp":"2026-02-24 08:35","srcIp":"10.0.0.55",     "dstIp":"10.0.0.200","protocol":"NFS", "port":2049, "detType":"Ransomware","severity":"High",    "classification":"Suspicious", "explanation":"Mass file read across /home — 1,200 reads/sec"},
    {"id":12, "timestamp":"2026-02-24 08:30","srcIp":"10.0.0.77",     "dstIp":"10.0.0.1",  "protocol":"TCP", "port":443,  "detType":"Anomaly",   "severity":"Low",     "classification":"Suspicious", "explanation":"Packet size 3x above moving average baseline"},
    {"id":13, "timestamp":"2026-02-24 08:20","srcIp":"91.108.4.200",  "dstIp":"10.0.0.22", "protocol":"FTP", "port":21,   "detType":"Signature", "severity":"Medium",  "classification":"Suspicious", "explanation":"FTP login failures — 2,400 attempts over 10 minutes"},
    {"id":14, "timestamp":"2026-02-24 08:10","srcIp":"10.0.0.31",     "dstIp":"10.0.0.100","protocol":"RPC", "port":135,  "detType":"Ransomware","severity":"Critical","classification":"Malicious",  "explanation":"Ryuk registry key write to HKLM\\SOFTWARE\\Microsoft\\Windows"},
    {"id":15, "timestamp":"2026-02-24 07:55","srcIp":"203.0.113.9",   "dstIp":"10.0.0.5",  "protocol":"HTTP","port":80,   "detType":"Signature", "severity":"High",    "classification":"Malicious",  "explanation":"Blind SQL injection time-delay pattern detected"},
    {"id":16, "timestamp":"2026-02-24 07:40","srcIp":"10.0.0.44",     "dstIp":"185.1.1.1", "protocol":"DNS", "port":53,   "detType":"Anomaly",   "severity":"High",    "classification":"Suspicious", "explanation":"Long DNS subdomain queries — covert channel indicator"},
    {"id":17, "timestamp":"2026-02-24 07:30","srcIp":"185.220.101.47","dstIp":"10.0.0.15", "protocol":"TCP", "port":80,   "detType":"Anomaly",   "severity":"Medium",  "classification":"Suspicious", "explanation":"Connection rate 8x baseline from single source"},
    {"id":18, "timestamp":"2026-02-24 07:15","srcIp":"10.0.0.12",     "dstIp":"10.0.0.50", "protocol":"TCP", "port":3389, "detType":"Signature", "severity":"Low",     "classification":"Normal",     "explanation":"RDP connection within policy — informational log"},
    {"id":19, "timestamp":"2026-02-24 07:00","srcIp":"198.51.100.7",  "dstIp":"10.0.0.22", "protocol":"TCP", "port":22,   "detType":"Signature", "severity":"Info",    "classification":"Normal",     "explanation":"SSH login from known admin IP — policy compliant"},
    {"id":20, "timestamp":"2026-02-24 06:45","srcIp":"10.0.0.100",    "dstIp":"10.0.0.200","protocol":"TCP", "port":443,  "detType":"Anomaly",   "severity":"Low",     "classification":"Normal",     "explanation":"Minor traffic deviation — within acceptable threshold"},
]

blocked_ips: list[str]     = []
whitelisted_ips: list[str] = []

TIMELINE = [
    {"time":"08:55","event":"Incident created — automated detection triggered"},
    {"time":"09:00","event":"Alert escalated to SOC analyst"},
    {"time":"09:05","event":"Initial triage completed — confirmed threat"},
    {"time":"09:10","event":"Containment action initiated — IP flagged for blocking"},
]


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M")


# ══════════════════════════════════════════════════════════════
# 1. STAT CARDS
# ══════════════════════════════════════════════════════════════
@router.get("/stats")
def get_stats():
    return {
        "stats": [
            {"label":"Total Detections", "value":108844, "sub":"Last 24 hours",             "color":"#00d4ff", "pulse":False},
            {"label":"Anomaly",          "value":17832,  "sub":"Anomaly-based detections",  "color":"#ffbe0b", "pulse":False},
            {"label":"Signature",        "value":84721,  "sub":"Signature-based detections","color":"#00ff9f", "pulse":False},
            {"label":"Ransomware",       "value":6291,   "sub":"Ransomware patterns",       "color":"#f97316", "pulse":False},
            {"label":"Critical Severity","value":3847,   "sub":"Require immediate action",  "color":"#ff006e", "pulse":True },
        ]
    }


# ══════════════════════════════════════════════════════════════
# 2. INCIDENTS
# ══════════════════════════════════════════════════════════════
@router.get("/list")
def get_incidents(
    status:   Optional[str] = None,
    severity: Optional[str] = None,
    analyst:  Optional[str] = None,
    search:   Optional[str] = None,
):
    result = list(incidents)
    if status   and status   != "All": result = [i for i in result if i["status"]   == status]
    if severity and severity != "All": result = [i for i in result if i["severity"] == severity]
    if analyst  and analyst  != "All": result = [i for i in result if i["analyst"]  == analyst]
    if search:
        q = search.lower()
        result = [i for i in result if q in i["id"].lower() or q in i["desc"].lower()]
    return {"total": len(result), "incidents": result}


@router.post("/resolve/{inc_id}")
def resolve_incident(inc_id: str):
    for inc in incidents:
        if inc["id"] == inc_id:
            if inc["status"] in ("Resolved","Closed"):
                return {"success": False, "message": f"{inc_id} is already {inc['status']}"}
            inc["status"]  = "Resolved"
            inc["updated"] = _now()
            return {"success": True, "incident": inc}
    return {"success": False, "message": f"{inc_id} not found"}


@router.post("/close/{inc_id}")
def close_incident(inc_id: str):
    for inc in incidents:
        if inc["id"] == inc_id:
            inc["status"]  = "Closed"
            inc["updated"] = _now()
            return {"success": True, "incident": inc}
    return {"success": False, "message": f"{inc_id} not found"}


@router.post("/assign/{inc_id}")
def assign_incident(inc_id: str, body: dict):
    analyst = body.get("analyst","analyst1")
    for inc in incidents:
        if inc["id"] == inc_id:
            inc["analyst"] = analyst
            inc["updated"] = _now()
            if inc["status"] == "Open":
                inc["status"] = "In Progress"
            return {"success": True, "incident": inc}
    return {"success": False, "message": f"{inc_id} not found"}


@router.post("/resolve-all")
def resolve_all(body: dict):
    """Resolve a list of incident IDs in one call."""
    ids = body.get("ids", [])
    updated = []
    for inc in incidents:
        if inc["id"] in ids and inc["status"] not in ("Resolved","Closed"):
            inc["status"]  = "Resolved"
            inc["updated"] = _now()
            updated.append(inc["id"])
    return {"success": True, "resolved": updated, "count": len(updated)}


@router.get("/timeline/{inc_id}")
def get_timeline(inc_id: str):
    """Return the event timeline for a given incident."""
    return {"inc_id": inc_id, "timeline": TIMELINE}


# ══════════════════════════════════════════════════════════════
# 3. DETECTIONS
# ══════════════════════════════════════════════════════════════
@router.get("/detections")
def get_detections(
    detType:  Optional[str] = None,
    severity: Optional[str] = None,
    search:   Optional[str] = None,
):
    result = list(detections)
    if detType  and detType  != "All": result = [d for d in result if d["detType"]  == detType]
    if severity and severity != "All": result = [d for d in result if d["severity"] == severity]
    if search:
        q = search.lower()
        result = [d for d in result if q in d["srcIp"] or q in d["dstIp"] or q in d["protocol"].lower()]
    return {"total": len(result), "detections": result}


@router.post("/detections/block")
def block_ip(body: dict):
    ip = body.get("ip","")
    if ip and ip not in blocked_ips:
        blocked_ips.append(ip)
    return {"success": True, "message": f"IP {ip} blocked", "blocked_ips": blocked_ips}


@router.post("/detections/whitelist")
def whitelist_ip(body: dict):
    ip = body.get("ip","")
    if ip and ip not in whitelisted_ips:
        whitelisted_ips.append(ip)
    return {"success": True, "message": f"IP {ip} whitelisted", "whitelisted_ips": whitelisted_ips}


# ══════════════════════════════════════════════════════════════
# 4. CHARTS DATA
# ══════════════════════════════════════════════════════════════
@router.get("/charts")
def get_charts():
    return {
        "donut": [
            {"label":"Signature", "value":84721, "color":"#00ff9f"},
            {"label":"Anomaly",   "value":17832, "color":"#ffbe0b"},
            {"label":"Ransomware","value":6291,  "color":"#f97316"},
        ],
        "severity_bars": [
            {"label":"Info",     "value":12450, "color":"#94a3b8"},
            {"label":"Low",      "value":31200, "color":"#00ff9f"},
            {"label":"Medium",   "value":28900, "color":"#ffbe0b"},
            {"label":"High",     "value":22047, "color":"#f97316"},
            {"label":"Critical", "value":3847,  "color":"#ff006e"},
        ],
    }


# ══════════════════════════════════════════════════════════════
# 5. SNAPSHOT — hydrates full page in one call
# ══════════════════════════════════════════════════════════════
@router.get("/snapshot")
def get_snapshot():
    return {
        "stats":      get_stats(),
        "incidents":  get_incidents(),
        "detections": get_detections(),
        "charts":     get_charts(),
    }