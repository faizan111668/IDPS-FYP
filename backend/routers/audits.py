"""
routers/audits.py
=================
All /api/audits/* endpoints for the Audits & Analytics page.

Sections:
  1. Summary Metrics      — total alerts, incidents, malicious/suspicious traffic
  2. Trend Analysis       — pie chart data + line chart by period (24h/7d/30d)
  3. Detection Distribution — bar breakdown by detection engine
  4. Traffic by Protocol  — per-protocol packet/percentage stats
  5. Severity Outcomes    — resolution rates by severity
  6. Malicious IPs        — top threat source IPs
  7. Audit Log            — immutable audit trail with rollback support
"""

from fastapi import APIRouter, Query
from typing import Optional
from datetime import datetime, timedelta
import random

router = APIRouter(prefix="/api/audits", tags=["Audits"])

# ══════════════════════════════════════════════════════════════
# IN-MEMORY STATE
# ══════════════════════════════════════════════════════════════

malicious_ips = [
    {"ip":"185.220.101.47","events":4821,"type":"Anomaly",   "avgSev":"Critical","protocol":"TCP", "country":"Russia",     "lastSeen":"2026-02-24 09:10"},
    {"ip":"194.165.16.78", "events":3912,"type":"Anomaly",   "avgSev":"Critical","protocol":"UDP", "country":"Iran",       "lastSeen":"2026-02-24 09:08"},
    {"ip":"103.75.190.12", "events":2244,"type":"Signature", "avgSev":"High",    "protocol":"HTTP","country":"China",      "lastSeen":"2026-02-24 09:01"},
    {"ip":"77.83.246.90",  "events":1987,"type":"Signature", "avgSev":"High",    "protocol":"HTTP","country":"Germany",    "lastSeen":"2026-02-24 09:05"},
    {"ip":"91.108.4.200",  "events":1543,"type":"Signature", "avgSev":"High",    "protocol":"TCP", "country":"Ukraine",    "lastSeen":"2026-02-24 08:44"},
    {"ip":"5.188.206.14",  "events":1102,"type":"Ransomware","avgSev":"Critical","protocol":"TCP", "country":"Luxembourg", "lastSeen":"2026-02-24 08:59"},
    {"ip":"45.142.212.100","events":891, "type":"Signature", "avgSev":"Medium",  "protocol":"TCP", "country":"Netherlands","lastSeen":"2026-02-24 08:44"},
    {"ip":"162.247.74.200","events":612, "type":"Anomaly",   "avgSev":"Medium",  "protocol":"HTTP","country":"USA",        "lastSeen":"2026-02-23 23:00"},
    {"ip":"203.0.113.9",   "events":488, "type":"Signature", "avgSev":"High",    "protocol":"HTTP","country":"Brazil",     "lastSeen":"2026-02-24 07:55"},
    {"ip":"198.51.100.7",  "events":204, "type":"Anomaly",   "avgSev":"Low",     "protocol":"TCP", "country":"Unknown",    "lastSeen":"2026-02-24 07:00"},
]

audit_logs = [
    {"id":"AUD-015","timestamp":"2026-02-24 09:10","actor":"admin",   "changeType":"Modified", "target":"SIG-003 SYN Flood",       "action":"Action changed",       "details":"Alert to Drop",              "rolled_back":False},
    {"id":"AUD-014","timestamp":"2026-02-24 08:58","actor":"admin",   "changeType":"Enabled",  "target":"LockBit Network Pattern", "action":"Rule enabled",         "details":"Disabled to Active",         "rolled_back":False},
    {"id":"AUD-013","timestamp":"2026-02-24 08:30","actor":"soc_lead","changeType":"Modified", "target":"Anomaly Sensitivity",     "action":"Setting updated",      "details":"Medium to High",             "rolled_back":False},
    {"id":"AUD-012","timestamp":"2026-02-24 08:10","actor":"admin",   "changeType":"Created",  "target":"Custom-SSH-Geo-Block",    "action":"New rule created",     "details":"Severity High, Action Block","rolled_back":False},
    {"id":"AUD-011","timestamp":"2026-02-24 07:45","actor":"analyst1","changeType":"Disabled", "target":"SIG-008 HTTP Slowloris",  "action":"Rule disabled",        "details":"Active to Inactive",         "rolled_back":False},
    {"id":"AUD-010","timestamp":"2026-02-24 07:00","actor":"admin",   "changeType":"Modified", "target":"AES Pattern Detection",   "action":"Risk level updated",   "details":"High to Critical",           "rolled_back":False},
    {"id":"AUD-009","timestamp":"2026-02-23 22:15","actor":"soc_lead","changeType":"Modified", "target":"Packet Size Threshold",   "action":"Threshold updated",    "details":"1200 to 1500 bytes",         "rolled_back":False},
    {"id":"AUD-008","timestamp":"2026-02-23 18:00","actor":"admin",   "changeType":"Created",  "target":"SIG-015 Stored XSS",      "action":"New signature created","details":"Severity High HTTP",         "rolled_back":False},
    {"id":"AUD-007","timestamp":"2026-02-23 14:30","actor":"analyst2","changeType":"Disabled", "target":"Legacy Ransomware Rule",  "action":"Rule disabled",        "details":"Marked as deprecated",       "rolled_back":False},
    {"id":"AUD-006","timestamp":"2026-02-23 10:00","actor":"admin",   "changeType":"Deleted",  "target":"SIG-OLD-001 Obsolete",    "action":"Rule deleted",         "details":"Rule ID retired permanently","rolled_back":False},
    {"id":"AUD-005","timestamp":"2026-02-22 16:45","actor":"soc_lead","changeType":"Modified", "target":"Traffic Rate Threshold",  "action":"Threshold updated",    "details":"5000 to 10000 pps",          "rolled_back":False},
    {"id":"AUD-004","timestamp":"2026-02-22 12:00","actor":"admin",   "changeType":"Created",  "target":"Custom-DDoS-Rate-Limit",  "action":"Custom rule created",  "details":"Severity Critical Drop",     "rolled_back":False},
    {"id":"AUD-003","timestamp":"2026-02-22 09:30","actor":"analyst1","changeType":"Modified", "target":"Auto IP Blocking",        "action":"Toggle updated",       "details":"OFF to ON",                  "rolled_back":False},
    {"id":"AUD-002","timestamp":"2026-02-21 18:00","actor":"admin",   "changeType":"Enabled",  "target":"Firewall Integration",    "action":"Module enabled",       "details":"Integration activated",      "rolled_back":False},
    {"id":"AUD-001","timestamp":"2026-02-21 10:00","actor":"soc_lead","changeType":"Modified", "target":"Baseline Learning Period","action":"Setting updated",      "details":"6 hours to 24 hours",        "rolled_back":False},
]

# trend data — keyed by period
TREND_DATA = {
    "24h": [4200,3800,5100,4600,5800,6200,5500,6800,7200,6100,5900,7400],
    "7d":  [31000,28000,35000,42000,38000,45000,51000],
    "30d": [120000,135000,128000,142000,158000,149000,165000,172000,160000,178000,182000,195000,188000,202000,210000],
}

# sparkline data (7-point each)
SPARKLINES = [
    [40,55,48,62,58,71,65],   # total alerts
    [88,72,80,75,82,78,85],   # incidents resolved
    [12,18,15,22,28,24,31],   # malicious traffic
    [33,41,38,45,42,50,47],   # suspicious traffic
]


# ══════════════════════════════════════════════════════════════
# 1. SUMMARY METRICS
# ══════════════════════════════════════════════════════════════
@router.get("/summary")
def get_summary():
    """4 top stat cards with sparkline data."""
    return {
        "metrics": [
            {"label":"Total Alerts",       "value":108844,"change":"+12.4%","up":True, "color":"#00d4ff","sub":"All detections today",   "spark":SPARKLINES[0]},
            {"label":"Incidents Resolved", "value":6291,  "change":"+8.1%", "up":True, "color":"#00ff9f","sub":"Closed in last 24h",     "spark":SPARKLINES[1]},
            {"label":"Malicious Traffic",  "value":31204, "change":"+22.7%","up":True, "color":"#ff006e","sub":"Confirmed threats",       "spark":SPARKLINES[2]},
            {"label":"Suspicious Traffic", "value":17832, "change":"-4.3%", "up":False,"color":"#ffbe0b","sub":"Flagged for review",      "spark":SPARKLINES[3]},
        ]
    }


# ══════════════════════════════════════════════════════════════
# 2. TREND ANALYSIS
# ══════════════════════════════════════════════════════════════
@router.get("/trend")
def get_trend(period: str = Query("7d", description="24h | 7d | 30d")):
    """Line chart data + pie chart breakdown."""
    if period not in TREND_DATA:
        period = "7d"
    return {
        "period":    period,
        "trend":     TREND_DATA[period],
        "pie": [
            {"label":"Signature", "value":84721,"color":"#00ff9f","pct":77.8},
            {"label":"Anomaly",   "value":17832,"color":"#ffbe0b","pct":16.4},
            {"label":"Ransomware","value":6291, "color":"#f97316","pct":5.8 },
        ],
        "total": 108844,
    }


# ══════════════════════════════════════════════════════════════
# 3. DETECTION DISTRIBUTION
# ══════════════════════════════════════════════════════════════
@router.get("/detection-distribution")
def get_detection_distribution():
    """Horizontal bar chart by detection engine."""
    return {
        "distributions": [
            {"label":"Anomaly Detection",    "pct":16,"color":"#ffbe0b","desc":"Behavioral baseline deviation — traffic anomalies and unusual patterns flagged"},
            {"label":"Signature Detection",  "pct":78,"color":"#00ff9f","desc":"Pattern-matched against 15 active signature rules covering SQL, XSS, DDoS and malware"},
            {"label":"Ransomware Detection", "pct":6, "color":"#f97316","desc":"Encryption pattern analysis, file system monitoring and registry change detection"},
        ]
    }


# ══════════════════════════════════════════════════════════════
# 4. TRAFFIC BY PROTOCOL
# ══════════════════════════════════════════════════════════════
@router.get("/traffic-protocol")
def get_traffic_protocol():
    """Protocol breakdown cards."""
    return {
        "protocols": [
            {"proto":"TCP",   "pct":45,"packets":1842301,"color":"#00d4ff","status":"HIGH"    },
            {"proto":"UDP",   "pct":22,"packets":901220, "color":"#00ff9f","status":"NORMAL"  },
            {"proto":"HTTP",  "pct":18,"packets":738540, "color":"#ffbe0b","status":"ELEVATED"},
            {"proto":"HTTPS", "pct":12,"packets":491820, "color":"#a78bfa","status":"NORMAL"  },
            {"proto":"Other", "pct":3, "packets":122960, "color":"#64748b","status":"LOW"     },
        ]
    }


# ══════════════════════════════════════════════════════════════
# 5. SEVERITY OUTCOMES
# ══════════════════════════════════════════════════════════════
@router.get("/severity-outcomes")
def get_severity_outcomes():
    """Incident count + resolution rate per severity."""
    return {
        "outcomes": [
            {"label":"Critical","count":3847, "resolved":72,"color":"#ff006e"},
            {"label":"High",    "count":22047,"resolved":85,"color":"#f97316"},
            {"label":"Medium",  "count":28900,"resolved":91,"color":"#ffbe0b"},
        ]
    }


# ══════════════════════════════════════════════════════════════
# 6. MALICIOUS IPs
# ══════════════════════════════════════════════════════════════
@router.get("/malicious-ips")
def get_malicious_ips(search: Optional[str] = None):
    """Top threat source IPs, filterable."""
    result = malicious_ips
    if search:
        result = [ip for ip in result
                  if search in ip["ip"] or search.lower() in ip["type"].lower()]
    return {"total": len(result), "ips": result}


# ══════════════════════════════════════════════════════════════
# 7. AUDIT LOG
# ══════════════════════════════════════════════════════════════
@router.get("/logs")
def get_audit_logs(
    actor:      Optional[str] = None,
    changeType: Optional[str] = None,
    search:     Optional[str] = None,
    sort_asc:   bool          = False,
    limit:      int           = 100,
):
    """Full immutable audit trail, filterable."""
    result = list(audit_logs)
    if actor and actor != "All":
        result = [l for l in result if l["actor"] == actor]
    if changeType and changeType != "All":
        result = [l for l in result if l["changeType"] == changeType]
    if search:
        result = [l for l in result
                  if search.lower() in l["target"].lower()
                  or search.lower() in l["actor"].lower()]
    result.sort(key=lambda x: x["timestamp"], reverse=not sort_asc)
    return {"total": len(result), "logs": result[:limit]}


@router.post("/logs/{log_id}/rollback")
def rollback_log(log_id: str):
    """Mark a log entry as rolled back and record a new audit entry."""
    for log in audit_logs:
        if log["id"] == log_id:
            if log["rolled_back"]:
                return {"success": False, "message": f"{log_id} already rolled back"}
            log["rolled_back"] = True
            # Add a new audit entry for the rollback itself
            nums = [int(l["id"].split("-")[1]) for l in audit_logs]
            new_id = f"AUD-{(max(nums)+1):03d}"
            rollback_entry = {
                "id":          new_id,
                "timestamp":   datetime.now().strftime("%Y-%m-%d %H:%M"),
                "actor":       "admin",
                "changeType":  "Modified",
                "target":      log["target"],
                "action":      f"Rollback of {log_id}",
                "details":     f"Reverted: {log['details']}",
                "rolled_back": False,
            }
            audit_logs.insert(0, rollback_entry)
            return {"success": True, "message": f"Rollback triggered for {log_id}", "new_entry": rollback_entry}
    return {"success": False, "message": f"{log_id} not found"}


# ══════════════════════════════════════════════════════════════
# 8. ALL-IN-ONE SNAPSHOT (page load)
# ══════════════════════════════════════════════════════════════
@router.get("/snapshot")
def get_snapshot():
    """Single call to hydrate the entire Audits page at once."""
    return {
        "summary":               get_summary(),
        "trend":                 get_trend("7d"),
        "detection_distribution":get_detection_distribution(),
        "traffic_protocol":      get_traffic_protocol(),
        "severity_outcomes":     get_severity_outcomes(),
        "malicious_ips":         get_malicious_ips(),
        "audit_logs":            get_audit_logs(),
    }