"""
routers/network.py
==================
All /api/network/* REST endpoints + WebSocket live stream.

FIXES vs previous version:
  1. Removed _sim_connection and _sim_alert from import (they are internal
     to network_monitor.py and should not be imported here — this was
     causing an ImportError on startup in some cases)
  2. ws.accept() called with no arguments — no origin validation
  3. disconnect() has safety check before remove() to prevent ValueError
"""

import asyncio
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from typing import Optional
from network_monitor import state, MY_IP   # ← only import what exists

router = APIRouter(prefix="/api/network", tags=["Network Monitoring"])


# ══════════════════════════════════════════════════════════════
# REST ENDPOINTS
# ══════════════════════════════════════════════════════════════

@router.get("/snapshot")
def get_snapshot():
    return state.snapshot()


@router.get("/stats")
def get_stats():
    with state.lock:
        return {
            "total_packets":      state.total_packets,
            "pps":                state.pps,
            "bandwidth":          state.bandwidth,
            "upload":             state.upload,
            "download":           state.download,
            "active_connections": state.active_connections,
            "threats_detected":   state.threats_detected,
            "threats_blocked":    state.threats_blocked,
        }


@router.get("/connections")
def get_connections(
    status:   Optional[str] = Query(None),
    protocol: Optional[str] = Query(None),
    search:   Optional[str] = Query(None),
    limit:    int           = Query(40),
):
    with state.lock:
        conns = list(state.connections)
    if status:   conns = [c for c in conns if c["status"].lower()   == status.lower()]
    if protocol: conns = [c for c in conns if c["protocol"].lower() == protocol.lower()]
    if search:   conns = [c for c in conns if search in c["srcIp"]  or search in c["dstIp"]]
    return {"total": len(conns), "connections": conns[:limit]}


@router.get("/alerts")
def get_alerts(
    severity: Optional[str] = Query(None),
    limit:    int           = Query(20),
):
    with state.lock:
        alerts = list(state.alerts)
    if severity:
        alerts = [a for a in alerts if a["severity"].lower() == severity.lower()]
    return {"total": len(alerts), "alerts": alerts[:limit]}


@router.get("/logs")
def get_logs(
    status: Optional[str] = Query(None),
    event:  Optional[str] = Query(None),
    limit:  int           = Query(100),
):
    with state.lock:
        logs = list(state.logs)
    if status: logs = [l for l in logs if l["status"] == status.upper()]
    if event:  logs = [l for l in logs if l["event"]  == event.upper()]
    return {"total": len(logs), "logs": logs[:limit]}


@router.get("/health")
def get_health():
    with state.lock:
        return {
            "cpu":       state.cpu,
            "mem":       state.mem,
            "pkt_loss":  state.pkt_loss,
            "latency":   state.latency,
            "interface": "wlp0s20f3",
            "my_ip":     MY_IP,
            "services": [
                {"name": "Network Adapter",  "status": "ONLINE",  "ok": True},
                {"name": "IDS Engine",       "status": "ACTIVE",  "ok": True},
                {"name": "Firewall",         "status": "ACTIVE",  "ok": True},
                {"name": "Packet Inspector", "status": "RUNNING", "ok": True},
            ]
        }


@router.get("/proto-dist")
def get_proto_dist():
    with state.lock:
        return {"protocols": [{"proto": k, "pct": v} for k, v in state.proto_dist.items()]}


@router.get("/traffic-history")
def get_traffic_history():
    with state.lock:
        return {
            "pps_history": list(state.pps_history),
            "bw_history":  list(state.bw_history),
        }


@router.get("/traffic-type")
def get_traffic_type():
    colors = ["#00d4ff", "#00ff9f", "#ffbe0b", "#ff006e"]
    with state.lock:
        return {
            "breakdown": [
                {"label": k, "value": v, "color": colors[i]}
                for i, (k, v) in enumerate(state.traffic_type.items())
            ]
        }


# ── Action endpoints ──────────────────────────────────────────

@router.post("/block-ip")
def block_ip(payload: dict):
    ip = payload.get("ip", "unknown")
    entry = state.add_log("BLOCKED", ip, "BLOCKED", "SUCCESS", "Manually blocked via dashboard")
    with state.lock:
        state.threats_blocked += 1
        for c in state.connections:
            if c["srcIp"] == ip:
                c["status"]  = "Blocked"
                c["flagged"] = True
    return {"success": True, "message": f"IP {ip} blocked", "log": entry}


@router.post("/whitelist-ip")
def whitelist_ip(payload: dict):
    ip = payload.get("ip", "unknown")
    entry = state.add_log("ALLOWED", ip, "ALLOWED", "INFO", "Whitelisted via dashboard")
    return {"success": True, "message": f"IP {ip} whitelisted", "log": entry}


@router.post("/clear-alerts")
def clear_alerts():
    with state.lock:
        count = len(state.alerts)
        state.alerts.clear()
    return {"success": True, "cleared": count}


@router.post("/clear-logs")
def clear_logs():
    with state.lock:
        count = len(state.logs)
        state.logs.clear()
    return {"success": True, "cleared": count}


# ══════════════════════════════════════════════════════════════
# WEBSOCKET — pushes full snapshot every 2.5 seconds
# ══════════════════════════════════════════════════════════════
class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        # ✅ No origin check — just accept unconditionally
        await ws.accept()
        self.active.append(ws)
        print(f"[WS] Client connected  — active: {len(self.active)}")

    def disconnect(self, ws: WebSocket):
        # ✅ Safety check prevents ValueError if already removed
        if ws in self.active:
            self.active.remove(ws)
        print(f"[WS] Client disconnected — active: {len(self.active)}")


manager = ConnectionManager()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Push snapshot immediately on connect so UI fills instantly
        await websocket.send_json(state.snapshot())

        while True:
            await asyncio.sleep(2.5)
            await websocket.send_json(state.snapshot())

    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        print(f"[WS] Error: {e}")
        manager.disconnect(websocket)