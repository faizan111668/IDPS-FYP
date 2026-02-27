"""
routers/configuration.py
=========================
All /api/configuration/* endpoints for the Configuration page.

Covers:
  1. Signature-Based Detection  — global toggle + stats
  2. Anomaly Detection Settings — thresholds, sensitivity, save
  3. Active Attackers           — list, block, monitor, whitelist
  4. Signature Database         — CRUD on sig rules
  5. Ransomware Rules           — list, enable/disable
  6. Change Log                 — full audit trail of config changes
  7. Create Custom Rule         — POST new rule
"""

from fastapi import APIRouter, HTTPException
from typing import Optional, List
from datetime import datetime
import random

router = APIRouter(prefix="/api/configuration", tags=["Configuration"])

# ══════════════════════════════════════════════════════════════
# IN-MEMORY STATE  (persists while server is running)
# In production replace with a database
# ══════════════════════════════════════════════════════════════

# ── Signature detection global toggle ────────────────────────
sig_detection_enabled = True

# ── Anomaly settings ─────────────────────────────────────────
anomaly_settings = {
    "enabled":       True,
    "sensitivity":   "High",
    "packet_size":   1500,
    "traffic_rate":  10000,
    "baseline":      "24 hours",
    "auto_block":    False,
}

# ── Signature rules ───────────────────────────────────────────
sig_rules = [
    {"id":"SIG-001","name":"SQL Union Attack",       "category":"SQL Injection","severity":"Critical","protocol":"HTTP", "action":"Block","status":"Active",  "lastTriggered":"2026-02-24 08:12","hits":1482},
    {"id":"SIG-002","name":"XSS Script Injection",   "category":"XSS",         "severity":"High",    "protocol":"HTTP", "action":"Alert","status":"Active",  "lastTriggered":"2026-02-24 07:45","hits":834 },
    {"id":"SIG-003","name":"SYN Flood Detection",    "category":"DDoS",        "severity":"Critical","protocol":"TCP",  "action":"Drop", "status":"Active",  "lastTriggered":"2026-02-24 09:01","hits":5621},
    {"id":"SIG-004","name":"NMAP Port Scan",         "category":"Port Scan",   "severity":"Medium",  "protocol":"TCP",  "action":"Log",  "status":"Active",  "lastTriggered":"2026-02-23 22:10","hits":291 },
    {"id":"SIG-005","name":"SSH Brute Force",        "category":"Brute Force", "severity":"High",    "protocol":"TCP",  "action":"Block","status":"Active",  "lastTriggered":"2026-02-24 06:33","hits":2103},
    {"id":"SIG-006","name":"Mirai Botnet Signature", "category":"Malware",     "severity":"Critical","protocol":"TCP",  "action":"Block","status":"Active",  "lastTriggered":"2026-02-24 05:58","hits":447 },
    {"id":"SIG-007","name":"ICMP Ping Sweep",        "category":"Port Scan",   "severity":"Low",     "protocol":"ICMP", "action":"Log",  "status":"Active",  "lastTriggered":"2026-02-23 18:20","hits":88  },
    {"id":"SIG-008","name":"HTTP Slowloris",         "category":"DDoS",        "severity":"High",    "protocol":"HTTP", "action":"Drop", "status":"Inactive","lastTriggered":"2026-02-22 14:11","hits":129 },
    {"id":"SIG-009","name":"Blind SQL Injection",    "category":"SQL Injection","severity":"High",   "protocol":"HTTPS","action":"Block","status":"Active",  "lastTriggered":"2026-02-24 07:02","hits":678 },
    {"id":"SIG-010","name":"DOM-based XSS",          "category":"XSS",         "severity":"Medium",  "protocol":"HTTPS","action":"Alert","status":"Active",  "lastTriggered":"2026-02-23 20:44","hits":312 },
    {"id":"SIG-011","name":"UDP Amplification",      "category":"DDoS",        "severity":"Critical","protocol":"UDP",  "action":"Drop", "status":"Active",  "lastTriggered":"2026-02-24 09:15","hits":3892},
    {"id":"SIG-012","name":"FTP Brute Force",        "category":"Brute Force", "severity":"Medium",  "protocol":"TCP",  "action":"Alert","status":"Inactive","lastTriggered":"2026-02-21 11:30","hits":54  },
    {"id":"SIG-013","name":"Emotet Malware Pattern", "category":"Malware",     "severity":"Critical","protocol":"HTTP", "action":"Block","status":"Active",  "lastTriggered":"2026-02-24 04:22","hits":198 },
    {"id":"SIG-014","name":"RDP Scan Detection",     "category":"Port Scan",   "severity":"Medium",  "protocol":"TCP",  "action":"Log",  "status":"Active",  "lastTriggered":"2026-02-23 16:05","hits":441 },
    {"id":"SIG-015","name":"Stored XSS Attack",      "category":"XSS",         "severity":"High",    "protocol":"HTTP", "action":"Block","status":"Active",  "lastTriggered":"2026-02-24 08:55","hits":267 },
]

# ── Active attackers ──────────────────────────────────────────
attackers = [
    {"ip":"185.220.101.47","country":"Russia",     "type":"DDoS",       "firstSeen":"2026-02-20 14:22","lastSeen":"2026-02-24 09:01","packets":482910,"status":"Active"    },
    {"ip":"45.142.212.100","country":"China",      "type":"Port Scan",  "firstSeen":"2026-02-22 08:11","lastSeen":"2026-02-24 08:44","packets":12840, "status":"Monitoring"},
    {"ip":"91.108.4.200",  "country":"Ukraine",    "type":"Brute Force","firstSeen":"2026-02-19 22:30","lastSeen":"2026-02-24 07:55","packets":28401, "status":"Blocked"   },
    {"ip":"103.75.190.12", "country":"Netherlands","type":"SQL Inject", "firstSeen":"2026-02-23 10:00","lastSeen":"2026-02-24 09:10","packets":7823,  "status":"Active"    },
    {"ip":"194.165.16.78", "country":"Iran",       "type":"DDoS",       "firstSeen":"2026-02-21 03:15","lastSeen":"2026-02-24 08:30","packets":921034,"status":"Blocked"   },
    {"ip":"77.83.246.90",  "country":"Germany",    "type":"Malware",    "firstSeen":"2026-02-24 01:44","lastSeen":"2026-02-24 09:05","packets":4211,  "status":"Active"    },
    {"ip":"5.188.206.14",  "country":"Luxembourg", "type":"Ransomware", "firstSeen":"2026-02-23 18:20","lastSeen":"2026-02-24 08:59","packets":33120, "status":"Monitoring"},
    {"ip":"162.247.74.200","country":"USA",        "type":"Tor Exit",   "firstSeen":"2026-02-22 12:00","lastSeen":"2026-02-23 23:00","packets":5612,  "status":"Blocked"   },
]

# ── Ransomware rules ──────────────────────────────────────────
ransom_rules = [
    {"id":1, "name":"AES Pattern Detection",          "type":"Encryption",  "risk":"Critical","status":"Active",  "lastTriggered":"2026-02-24 08:45","pattern":"AES-256 entropy >7.9 in outbound stream"        },
    {"id":2, "name":"Burst of Encrypted Temp Files",  "type":"File System", "risk":"Critical","status":"Active",  "lastTriggered":"2026-02-24 07:12","pattern":">500 .tmp files encrypted/min in %TEMP%"         },
    {"id":3, "name":"ChaCha20 Anomaly on NAS",        "type":"Network",     "risk":"High",    "status":"Active",  "lastTriggered":"2026-02-23 22:30","pattern":"ChaCha20 stream cipher on NAS port 445"          },
    {"id":4, "name":"Experimental Disabled Indicator","type":"Experimental","risk":"Medium",  "status":"Disabled","lastTriggered":"2026-02-20 14:00","pattern":"EXPERIMENTAL: unknown cipher header"             },
    {"id":5, "name":"Legacy Disabled Ransomware Rule","type":"Experimental","risk":"Medium",  "status":"Disabled","lastTriggered":"2026-02-15 09:00","pattern":"Legacy WannaCry SMB exploit pattern"            },
    {"id":6, "name":"LockBit Network Pattern",        "type":"Network",     "risk":"Critical","status":"Active",  "lastTriggered":"2026-02-24 09:00","pattern":"LockBit C2 beacon on port 1234/8443"             },
    {"id":7, "name":"Mass Read of Home Directories",  "type":"File System", "risk":"High",    "status":"Active",  "lastTriggered":"2026-02-24 06:55","pattern":">1000 reads/sec on /home/* or C:\\Users\\"      },
    {"id":8, "name":"Ryuk Style Registry Changes",    "type":"Registry",    "risk":"Critical","status":"Active",  "lastTriggered":"2026-02-24 08:01","pattern":"HKLM\\SOFTWARE\\Microsoft\\Windows NT deletion"  },
    {"id":9, "name":"Shadow Copy Deletion Spike",     "type":"File System", "risk":"Critical","status":"Active",  "lastTriggered":"2026-02-24 07:30","pattern":"vssadmin delete shadows /all /quiet"             },
    {"id":10,"name":"Wide Access to Project Archives","type":"File System", "risk":"High",    "status":"Active",  "lastTriggered":"2026-02-23 19:45","pattern":">200 .zip/.tar reads across project dirs"        },
]

# ── Change log ────────────────────────────────────────────────
change_log = [
    {"id":"LOG-012","timestamp":"2026-02-24 09:10","by":"admin",   "section":"Signature",  "action":"Modified","rule":"SIG-003 SYN Flood",        "prev":"Alert",  "next":"Drop",    "status":"Applied"    },
    {"id":"LOG-011","timestamp":"2026-02-24 08:55","by":"admin",   "section":"Ransomware", "action":"Enabled", "rule":"LockBit Network Pattern",  "prev":"Disabled","next":"Active", "status":"Applied"    },
    {"id":"LOG-010","timestamp":"2026-02-24 08:30","by":"soc_lead","section":"Anomaly",    "action":"Modified","rule":"Sensitivity Level",         "prev":"Medium", "next":"High",    "status":"Applied"    },
    {"id":"LOG-009","timestamp":"2026-02-24 07:45","by":"admin",   "section":"Custom Rule","action":"Created", "rule":"Custom-SSH-Geo-Block",     "prev":"—",      "next":"Active",  "status":"Applied"    },
    {"id":"LOG-008","timestamp":"2026-02-24 07:12","by":"analyst1","section":"Signature",  "action":"Disabled","rule":"SIG-008 HTTP Slowloris",   "prev":"Active", "next":"Inactive","status":"Applied"    },
    {"id":"LOG-007","timestamp":"2026-02-24 06:00","by":"admin",   "section":"Ransomware", "action":"Modified","rule":"AES Pattern Detection",    "prev":"High",   "next":"Critical","status":"Applied"    },
    {"id":"LOG-006","timestamp":"2026-02-23 22:15","by":"soc_lead","section":"Anomaly",    "action":"Modified","rule":"Packet Size Threshold",    "prev":"1200",   "next":"1500",    "status":"Applied"    },
    {"id":"LOG-005","timestamp":"2026-02-23 18:00","by":"admin",   "section":"Signature",  "action":"Created", "rule":"SIG-015 Stored XSS",      "prev":"—",      "next":"Active",  "status":"Applied"    },
    {"id":"LOG-004","timestamp":"2026-02-23 14:30","by":"analyst2","section":"Ransomware", "action":"Disabled","rule":"Legacy Disabled Rule",     "prev":"Active", "next":"Disabled","status":"Applied"    },
    {"id":"LOG-003","timestamp":"2026-02-23 10:00","by":"admin",   "section":"Signature",  "action":"Deleted", "rule":"SIG-OLD-001 Obsolete Rule","prev":"Inactive","next":"—",      "status":"Applied"    },
    {"id":"LOG-002","timestamp":"2026-02-22 16:45","by":"soc_lead","section":"Anomaly",    "action":"Modified","rule":"Traffic Rate Threshold",   "prev":"5000",   "next":"10000",   "status":"Rolled Back"},
    {"id":"LOG-001","timestamp":"2026-02-22 09:00","by":"admin",   "section":"Custom Rule","action":"Created", "rule":"Custom-DDoS-Rate-Limit",  "prev":"—",      "next":"Active",  "status":"Pending"    },
]

# ── Helpers ───────────────────────────────────────────────────
def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M")

def _next_log_id():
    nums = [int(l["id"].split("-")[1]) for l in change_log if l["id"].startswith("LOG-")]
    return f"LOG-{(max(nums)+1):03d}" if nums else "LOG-001"

def _add_log(by: str, section: str, action: str, rule: str, prev: str, nxt: str):
    entry = {
        "id":        _next_log_id(),
        "timestamp": _now(),
        "by":        by,
        "section":   section,
        "action":    action,
        "rule":      rule,
        "prev":      prev,
        "next":      nxt,
        "status":    "Applied",
    }
    change_log.insert(0, entry)
    return entry


# ══════════════════════════════════════════════════════════════
# SECTION 1 — SIGNATURE DETECTION GLOBAL
# ══════════════════════════════════════════════════════════════

@router.get("/signature/status")
def get_signature_status():
    active = sum(1 for r in sig_rules if r["status"] == "Active")
    return {
        "enabled":    sig_detection_enabled,
        "total":      len(sig_rules),
        "active":     active,
        "inactive":   len(sig_rules) - active,
        "last_updated": _now(),
        "hit_rate":   "94.2%",
    }

@router.post("/signature/toggle")
def toggle_signature(payload: dict):
    global sig_detection_enabled
    sig_detection_enabled = payload.get("enabled", not sig_detection_enabled)
    _add_log("admin","Signature","Modified","Global Signature Detection",
             "Inactive" if sig_detection_enabled else "Active",
             "Active" if sig_detection_enabled else "Inactive")
    return {"success": True, "enabled": sig_detection_enabled}


# ══════════════════════════════════════════════════════════════
# SECTION 2 — ANOMALY DETECTION SETTINGS
# ══════════════════════════════════════════════════════════════

@router.get("/anomaly/settings")
def get_anomaly_settings():
    return anomaly_settings

@router.post("/anomaly/settings")
def save_anomaly_settings(payload: dict):
    old = dict(anomaly_settings)
    anomaly_settings.update({
        k: v for k, v in payload.items() if k in anomaly_settings
    })
    # Log each changed field
    for key in ["sensitivity","packet_size","traffic_rate","baseline","auto_block","enabled"]:
        if key in payload and str(payload[key]) != str(old.get(key)):
            _add_log("admin","Anomaly","Modified", key.replace("_"," ").title(),
                     str(old.get(key,"")), str(payload[key]))
    return {"success": True, "settings": anomaly_settings}


# ══════════════════════════════════════════════════════════════
# SECTION 3 — ACTIVE ATTACKERS
# ══════════════════════════════════════════════════════════════

@router.get("/attackers")
def get_attackers(search: Optional[str] = None):
    result = attackers
    if search:
        result = [a for a in attackers
                  if search in a["ip"] or search.lower() in a["type"].lower()]
    return {"total": len(result), "attackers": result}

@router.post("/attackers/action")
def attacker_action(payload: dict):
    ip     = payload.get("ip","")
    action = payload.get("action","")   # "Block" | "Monitor" | "Whitelist"
    if not ip or action not in ("Block","Monitor","Whitelist"):
        raise HTTPException(400, "Invalid ip or action")
    status_map = {"Block":"Blocked","Monitor":"Monitoring","Whitelist":"Active"}
    for a in attackers:
        if a["ip"] == ip:
            old_status = a["status"]
            a["status"] = status_map[action]
            a["lastSeen"] = _now()
            _add_log("admin","Attacker",action,f"IP {ip}",old_status,a["status"])
            return {"success":True,"message":f"{action} applied to {ip}","attacker":a}
    raise HTTPException(404, f"IP {ip} not found")


# ══════════════════════════════════════════════════════════════
# SECTION 4 — SIGNATURE DATABASE
# ══════════════════════════════════════════════════════════════

@router.get("/signatures")
def get_signatures(
    search:   Optional[str] = None,
    severity: Optional[str] = None,
    action:   Optional[str] = None,
    status:   Optional[str] = None,
    category: Optional[str] = None,
):
    result = sig_rules
    if search:   result = [r for r in result if search.lower() in r["name"].lower() or search in r["id"]]
    if severity and severity != "All": result = [r for r in result if r["severity"] == severity]
    if action   and action   != "All": result = [r for r in result if r["action"]   == action  ]
    if status   and status   != "All": result = [r for r in result if r["status"]   == status  ]
    if category and category != "All": result = [r for r in result if r["category"] == category]
    return {"total": len(result), "rules": result}

@router.post("/signatures/{rule_id}/toggle")
def toggle_signature_rule(rule_id: str):
    for r in sig_rules:
        if r["id"] == rule_id:
            old = r["status"]
            r["status"] = "Inactive" if r["status"] == "Active" else "Active"
            _add_log("admin","Signature",
                     "Enabled" if r["status"]=="Active" else "Disabled",
                     f"{r['id']} {r['name']}", old, r["status"])
            return {"success":True,"rule":r}
    raise HTTPException(404, f"Rule {rule_id} not found")

@router.delete("/signatures/{rule_id}")
def delete_signature_rule(rule_id: str):
    global sig_rules
    rule = next((r for r in sig_rules if r["id"]==rule_id), None)
    if not rule:
        raise HTTPException(404, f"Rule {rule_id} not found")
    sig_rules = [r for r in sig_rules if r["id"] != rule_id]
    _add_log("admin","Signature","Deleted",
             f"{rule['id']} {rule['name']}","Active","—")
    return {"success":True,"deleted":rule_id}


# ══════════════════════════════════════════════════════════════
# SECTION 5 — CREATE CUSTOM RULE
# ══════════════════════════════════════════════════════════════

@router.post("/signatures/create")
def create_rule(payload: dict):
    required = ["name","category","severity","protocol","action"]
    for f in required:
        if not payload.get(f):
            raise HTTPException(400, f"Missing field: {f}")
    # Generate next SIG id
    existing_ids = [int(r["id"].split("-")[1]) for r in sig_rules if r["id"].startswith("SIG-")]
    next_id = f"SIG-{(max(existing_ids)+1):03d}" if existing_ids else "SIG-001"
    new_rule = {
        "id":            next_id,
        "name":          payload["name"],
        "category":      payload["category"],
        "severity":      payload["severity"],
        "protocol":      payload["protocol"],
        "action":        payload["action"],
        "status":        "Active",
        "lastTriggered": "Never",
        "hits":          0,
    }
    sig_rules.insert(0, new_rule)
    _add_log("admin","Custom Rule","Created",
             f"{next_id} {payload['name']}","—","Active")
    return {"success":True,"rule":new_rule}


# ══════════════════════════════════════════════════════════════
# SECTION 6 — RANSOMWARE RULES
# ══════════════════════════════════════════════════════════════

@router.get("/ransomware/rules")
def get_ransom_rules():
    active   = sum(1 for r in ransom_rules if r["status"]=="Active")
    disabled = len(ransom_rules) - active
    return {
        "total":    len(ransom_rules),
        "active":   active,
        "disabled": disabled,
        "rules":    ransom_rules,
    }

@router.post("/ransomware/rules/{rule_id}/toggle")
def toggle_ransom_rule(rule_id: int):
    for r in ransom_rules:
        if r["id"] == rule_id:
            old = r["status"]
            r["status"] = "Disabled" if r["status"]=="Active" else "Active"
            _add_log("admin","Ransomware",
                     "Enabled" if r["status"]=="Active" else "Disabled",
                     r["name"], old, r["status"])
            return {"success":True,"rule":r}
    raise HTTPException(404, f"Ransomware rule {rule_id} not found")


# ══════════════════════════════════════════════════════════════
# SECTION 7 — CHANGE LOG
# ══════════════════════════════════════════════════════════════

@router.get("/changelog")
def get_changelog(
    search: Optional[str] = None,
    action: Optional[str] = None,
    limit:  int           = 50,
):
    result = change_log
    if search and search != "All":
        result = [l for l in result
                  if search.lower() in l["rule"].lower()
                  or search.lower() in l["by"].lower()]
    if action and action != "All":
        result = [l for l in result if l["action"] == action]
    return {"total": len(result), "logs": result[:limit]}