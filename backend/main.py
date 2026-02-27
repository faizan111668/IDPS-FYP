"""
main.py — CyGuardian-X IDPS Backend v2.0
=========================================

ROOT CAUSE OF 403 ON WEBSOCKET:
  Starlette's CORSMiddleware intercepts WebSocket upgrade requests and
  rejects them with 403 if the Origin header doesn't exactly match
  allow_origins. Even with allow_origins=["http://localhost:3000"],
  the browser may send origin as "http://localhost:3000" but Starlette's
  internal check fails for WebSocket upgrades specifically.

FIX:
  Replace CORSMiddleware with a hand-written middleware that:
  1. Adds CORS headers to every HTTP response
  2. Lets WebSocket upgrade requests pass through unconditionally
"""

from fastapi import FastAPI, Request
from fastapi.responses import Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from datetime import datetime, timedelta
import random

from routers.network        import router as network_router
from routers.configuration  import router as config_router
from routers.audits         import router as audits_router
from routers.incidents      import router as incidents_router
from network_monitor        import start_monitor

app = FastAPI(title="CyGuardian-X IDPS Backend", version="2.0.0")

# ══════════════════════════════════════════════════════════════
# CUSTOM CORS + WEBSOCKET MIDDLEWARE
# Replaces CORSMiddleware entirely — handles both HTTP and WS
# ══════════════════════════════════════════════════════════════
class CORSAndWSMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # WebSocket upgrade — let it pass straight through, no CORS check
        if request.headers.get("upgrade", "").lower() == "websocket":
            return await call_next(request)

        # Handle preflight OPTIONS request
        if request.method == "OPTIONS":
            return Response(
                status_code=200,
                headers={
                    "Access-Control-Allow-Origin":      "*",
                    "Access-Control-Allow-Methods":     "GET, POST, PUT, DELETE, OPTIONS",
                    "Access-Control-Allow-Headers":     "*",
                    "Access-Control-Allow-Credentials": "true",
                },
            )

        # Normal HTTP request — add CORS headers to response
        response = await call_next(request)
        response.headers["Access-Control-Allow-Origin"]      = "*"
        response.headers["Access-Control-Allow-Methods"]     = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"]     = "*"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        return response

app.add_middleware(CORSAndWSMiddleware)

# ── Register routers ────────────────────────────────────────────
app.include_router(network_router)
app.include_router(config_router)
app.include_router(audits_router)
app.include_router(incidents_router)

# ── Start monitor engine on startup ────────────────────────────
@app.on_event("startup")
async def on_startup():
    start_monitor()
    print("[STARTUP] CyGuardian-X backend ready ✓")


# ════════════════════════════════════════════════════════════════
# ROOT / HEALTH
# ════════════════════════════════════════════════════════════════
@app.get("/")
def root():
    return {"status": "CyGuardian-X backend is running", "version": "2.0.0"}

@app.get("/api/health")
def health():
    return {"status": "online", "timestamp": datetime.now().isoformat()}


# ════════════════════════════════════════════════════════════════
# DASHBOARD ENDPOINTS
# ════════════════════════════════════════════════════════════════
@app.get("/api/dashboard/stats")
def dashboard_stats():
    return {
        "total_users":    {"value": 40,                          "trend": "up",   "change": "+12%", "sub": "Across all roles"    },
        "active_attacks": {"value": random.randint(1, 6),        "trend": "down", "change": "-3%",  "sub": "Requires attention"  },
        "network_flows":  {"value": random.randint(40000,55000), "trend": "up",   "change": "+12%", "sub": "Packets/sec live"    },
        "detections":     {"value": 108844,                      "trend": "up",   "change": "+12%", "sub": "Last 24 hours total" },
    }

@app.get("/api/dashboard/detections")
def detection_summary():
    normal = 84721; suspicious = 17832; malicious = 6291
    total  = normal + suspicious + malicious
    return {
        "total": total,
        "categories": [
            {"label": "Normal",     "value": normal,     "pct": round((normal/total)*100),     "color": "#00ff9f"},
            {"label": "Suspicious", "value": suspicious, "pct": round((suspicious/total)*100), "color": "#ffbe0b"},
            {"label": "Malicious",  "value": malicious,  "pct": round((malicious/total)*100),  "color": "#ff006e"},
        ]
    }

@app.get("/api/dashboard/alert-trends")
def alert_trends():
    today = datetime.now()
    days  = []
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        days.append({
            "date":       day.strftime("%a"),
            "full_date":  day.strftime("%Y-%m-%d"),
            "anomaly":    random.randint(80,  300),
            "signature":  random.randint(400, 900),
            "ransomware": random.randint(10,  80),
        })
    return {"days": days}

@app.get("/api/dashboard/users-by-role")
def users_by_role():
    return {
        "total": 40,
        "roles": [
            {"role": "SOC Analyst",        "count": 18, "color": "#00d4ff", "pct": 45},
            {"role": "Network Engineer",   "count": 10, "color": "#00ff9f", "pct": 25},
            {"role": "Security Manager",   "count": 6,  "color": "#ffbe0b", "pct": 15},
            {"role": "Incident Responder", "count": 4,  "color": "#f97316", "pct": 10},
            {"role": "Admin",              "count": 2,  "color": "#a78bfa", "pct": 5  },
        ]
    }

@app.get("/api/dashboard/recent-users")
def recent_users():
    return {
        "recent": [
            {"name": "Ahmad Raza",  "email": "ahmad.raza@soc.local",  "role": "SOC Analyst",      "status": "online",  "avatar": "AR", "last_active": "Just now"},
            {"name": "Sara Malik",  "email": "sara.malik@soc.local",  "role": "Network Engineer", "status": "online",  "avatar": "SM", "last_active": "2m ago"  },
            {"name": "Omar Sheikh", "email": "omar.sheikh@soc.local", "role": "Sec Manager",      "status": "away",    "avatar": "OS", "last_active": "15m ago" },
            {"name": "Zara Khan",   "email": "zara.khan@soc.local",   "role": "IR Specialist",    "status": "online",  "avatar": "ZK", "last_active": "32m ago" },
            {"name": "Bilal Ahmed", "email": "bilal.ahmed@soc.local", "role": "SOC Analyst",      "status": "offline", "avatar": "BA", "last_active": "1h ago"  },
        ],
        "last_created":     {"name": "Faiz Bugti", "email": "faiz.bugti@soc.local", "role": "Admin", "avatar": "FB", "time": "Today, 09:00"     },
        "last_deactivated": {"name": "John Doe",   "email": "john.doe@soc.local",   "role": "Guest", "avatar": "JD", "time": "Yesterday, 17:30" },
    }

@app.get("/api/dashboard/quick-access")
def quick_access():
    c = random.randint(1, 5)
    return {
        "manage_users":           {"badge": "40 users",      "count": 40  },
        "security_configuration": {"badge": "1,247 rules",   "count": 1247},
        "network_monitoring":     {"badge": "32 sensors",    "count": 32  },
        "alerts_incidents":       {"badge": f"{c} critical", "count": c   },
        "audit_reports":          {"badge": "Updated today", "count": None},
    }