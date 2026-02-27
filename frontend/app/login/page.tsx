"use client";

import { useState, useEffect, useRef } from "react";
import { Eye, EyeOff, Shield, Activity, AlertTriangle, Lock, User, Wifi, Server } from "lucide-react";

// --- Animated Threat Counter ---
function ThreatCounter({ label, value, color }: { label: string; value: number; color: string }) {
  const [count, setCount] = useState(0);
  useEffect(() => {
    const step = Math.ceil(value / 40);
    let current = 0;
    const timer = setInterval(() => {
      current = Math.min(current + step, value);
      setCount(current);
      if (current >= value) clearInterval(timer);
    }, 30);
    return () => clearInterval(timer);
  }, [value]);

  return (
    <div className="flex flex-col items-center gap-1">
      <span className={`font-display text-xl font-bold ${color}`} style={{ fontFamily: "'Orbitron', monospace" }}>
        {count.toLocaleString()}
      </span>
      <span className="text-[10px] text-slate-500 tracking-widest uppercase">{label}</span>
    </div>
  );
}

// --- Animated Network Node Grid ---
function NetworkGrid() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    canvas.width = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;

    const nodes: { x: number; y: number; vx: number; vy: number; threat: boolean }[] = [];
    const NUM_NODES = 35;

    for (let i = 0; i < NUM_NODES; i++) {
      nodes.push({
        x: Math.random() * canvas.width,
        y: Math.random() * canvas.height,
        vx: (Math.random() - 0.5) * 0.4,
        vy: (Math.random() - 0.5) * 0.4,
        threat: Math.random() < 0.15,
      });
    }

    let frame: number;
    const animate = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      nodes.forEach((node) => {
        node.x += node.vx;
        node.y += node.vy;
        if (node.x < 0 || node.x > canvas.width) node.vx *= -1;
        if (node.y < 0 || node.y > canvas.height) node.vy *= -1;
      });

      // Draw edges
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[i].x - nodes[j].x;
          const dy = nodes[i].y - nodes[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 100) {
            const alpha = (1 - dist / 100) * 0.3;
            const isThreat = nodes[i].threat || nodes[j].threat;
            ctx.beginPath();
            ctx.moveTo(nodes[i].x, nodes[i].y);
            ctx.lineTo(nodes[j].x, nodes[j].y);
            ctx.strokeStyle = isThreat
              ? `rgba(255, 0, 110, ${alpha})`
              : `rgba(0, 212, 255, ${alpha})`;
            ctx.lineWidth = 0.8;
            ctx.stroke();
          }
        }
      }

      // Draw nodes
      nodes.forEach((node) => {
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.threat ? 3 : 2, 0, Math.PI * 2);
        ctx.fillStyle = node.threat ? "#ff006e" : "#00d4ff";
        ctx.shadowBlur = node.threat ? 10 : 6;
        ctx.shadowColor = node.threat ? "#ff006e" : "#00d4ff";
        ctx.fill();
        ctx.shadowBlur = 0;
      });

      frame = requestAnimationFrame(animate);
    };

    animate();
    return () => cancelAnimationFrame(frame);
  }, []);

  return <canvas ref={canvasRef} className="w-full h-full opacity-70" />;
}

// --- Scrolling Log Feed ---
const LOG_ENTRIES = [
  { time: "23:41:07", type: "BLOCK", msg: "Port scan detected — 192.168.1.105", color: "text-red-400" },
  { time: "23:41:05", type: "WARN", msg: "Unusual DNS query volume — 10.0.0.44", color: "text-yellow-400" },
  { time: "23:41:02", type: "INFO", msg: "TLS handshake anomaly — 172.16.0.8", color: "text-cyan-400" },
  { time: "23:40:58", type: "BLOCK", msg: "SQL injection attempt — 203.0.113.9", color: "text-red-400" },
  { time: "23:40:55", type: "INFO", msg: "Policy rule #47 matched — 10.0.0.12", color: "text-cyan-400" },
  { time: "23:40:51", type: "WARN", msg: "Brute-force SSH — 198.51.100.7", color: "text-yellow-400" },
  { time: "23:40:49", type: "BLOCK", msg: "DDoS pattern — 203.0.113.22", color: "text-red-400" },
  { time: "23:40:45", type: "INFO", msg: "Geo-IP flagged — 185.220.101.5", color: "text-cyan-400" },
];

function LogFeed() {
  const [logs, setLogs] = useState(LOG_ENTRIES);

  useEffect(() => {
    const interval = setInterval(() => {
      const types = ["BLOCK", "WARN", "INFO"];
      const msgs = [
        "SYN flood detected",
        "ARP spoofing attempt",
        "ICMP sweep scan",
        "HTTP request anomaly",
        "Malformed packet dropped",
      ];
      const colors: Record<string, string> = {
        BLOCK: "text-red-400",
        WARN: "text-yellow-400",
        INFO: "text-cyan-400",
      };
      const type = types[Math.floor(Math.random() * types.length)];
      const now = new Date();
      const time = now.toTimeString().slice(0, 8);
      const ip = `${Math.floor(Math.random() * 254 + 1)}.${Math.floor(Math.random() * 254)}.${Math.floor(Math.random() * 254)}.${Math.floor(Math.random() * 254)}`;
      const newLog = {
        time,
        type,
        msg: `${msgs[Math.floor(Math.random() * msgs.length)]} — ${ip}`,
        color: colors[type],
      };
      setLogs((prev) => [newLog, ...prev.slice(0, 10)]);
    }, 2500);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="space-y-1 overflow-hidden">
      {logs.slice(0, 6).map((log, i) => (
        <div
          key={`${log.time}-${i}`}
          className="flex items-center gap-2 text-[11px] font-mono opacity-0 animate-slide-up"
          style={{ animationDelay: `${i * 50}ms`, animationFillMode: "forwards" }}
        >
          <span className="text-slate-600">{log.time}</span>
          <span className={`${log.color} w-10 text-right shrink-0 font-bold`}>{log.type}</span>
          <span className="text-slate-400 truncate">{log.msg}</span>
        </div>
      ))}
    </div>
  );
}

// --- Main Login Page ---
export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPass, setShowPass] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [initProgress, setInitProgress] = useState(0);
  const [initDone, setInitDone] = useState(false);
  const [currentTime, setCurrentTime] = useState("");

  // Boot sequence
  useEffect(() => {
    let progress = 0;
    const interval = setInterval(() => {
      progress += Math.random() * 15;
      if (progress >= 100) {
        progress = 100;
        setInitProgress(100);
        setTimeout(() => setInitDone(true), 400);
        clearInterval(interval);
      } else {
        setInitProgress(Math.floor(progress));
      }
    }, 80);
    return () => clearInterval(interval);
  }, []);

  // Clock
  useEffect(() => {
    const tick = () => setCurrentTime(new Date().toUTCString().slice(17, 25) + " UTC");
    tick();
    const interval = setInterval(tick, 1000);
    return () => clearInterval(interval);
  }, []);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) {
      setError("All fields are required.");
      return;
    }
    setError("");
    setLoading(true);
    // Simulate API call — replace with real auth
    setTimeout(() => {
      setLoading(false);
      if (email === "admin@idps.local" && password === "admin123") {
        window.location.href = "/dashboard";
      } else {
        setError("ACCESS DENIED — Invalid credentials.");
      }
    }, 1800);
  };

  return (
    <div className="min-h-screen grid-bg flex items-center justify-center p-4 relative overflow-hidden">
      {/* Scan line overlay */}
      <div className="scan-overlay" />

      {/* Background glow blobs */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 rounded-full opacity-5"
        style={{ background: "radial-gradient(circle, #00d4ff, transparent)" }} />
      <div className="absolute bottom-1/4 right-1/4 w-64 h-64 rounded-full opacity-5"
        style={{ background: "radial-gradient(circle, #ff006e, transparent)" }} />

      {/* Boot screen */}
      {!initDone && (
        <div className="fixed inset-0 z-50 bg-[#030712] flex flex-col items-center justify-center gap-6">
          <Shield size={48} className="text-cyan-400 animate-pulse" />
          <div style={{ fontFamily: "'Orbitron', monospace" }} className="text-cyan-400 text-lg tracking-widest">
            CyGuardian-X v2.4
          </div>
          <div className="w-72 space-y-2">
            <div className="flex justify-between text-[11px] text-slate-500 font-mono">
              <span>INITIALIZING SYSTEM...</span>
              <span>{initProgress}%</span>
            </div>
            <div className="h-1 bg-slate-800 rounded-full overflow-hidden">
              <div
                className="h-full rounded-full transition-all duration-100"
                style={{
                  width: `${initProgress}%`,
                  background: "linear-gradient(90deg, #00d4ff, #00ff9f)",
                  boxShadow: "0 0 10px #00d4ff",
                }}
              />
            </div>
          </div>
          <div className="text-[11px] text-slate-600 font-mono tracking-wider">
            {initProgress < 30 && "Loading detection signatures..."}
            {initProgress >= 30 && initProgress < 60 && "Connecting to sensor network..."}
            {initProgress >= 60 && initProgress < 90 && "Starting prevention engine..."}
            {initProgress >= 90 && "System ready."}
          </div>
        </div>
      )}

      {/* Main layout */}
      <div className="w-full max-w-6xl grid grid-cols-1 lg:grid-cols-5 gap-0 animate-fade-in" style={{ opacity: initDone ? 1 : 0 }}>

        {/* LEFT PANEL — Live telemetry */}
        <div className="hidden lg:flex lg:col-span-3 flex-col"
          style={{
            background: "rgba(10, 15, 30, 0.95)",
            border: "1px solid rgba(0, 212, 255, 0.15)",
            borderRight: "none",
          }}>

          {/* Header */}
          <div className="flex items-center justify-between px-6 py-4"
            style={{ borderBottom: "1px solid rgba(0, 212, 255, 0.1)" }}>
            <div className="flex items-center gap-3">
              <div className="relative">
                <Shield size={22} className="text-cyan-400" />
                <div className="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-green-400 status-dot" />
              </div>
              <div>
                <div style={{ fontFamily: "'Orbitron', monospace" }} className="text-cyan-400 text-sm font-bold tracking-wider">
                  CyGuardian-X
                </div>
                <div className="text-[10px] text-slate-600 font-mono">NETWORK OPERATIONS CENTER</div>
              </div>
            </div>
            <div className="flex items-center gap-2 text-[11px] font-mono text-slate-500">
              <Wifi size={12} className="text-green-400" />
              <span className="text-green-400">LIVE</span>
              <span>{currentTime}</span>
            </div>
          </div>

          {/* Network graph */}
          <div className="flex-1 relative" style={{ minHeight: "220px" }}>
            <NetworkGrid />
            <div className="absolute bottom-3 left-4 text-[10px] font-mono text-slate-600 tracking-wider">
              NETWORK TOPOLOGY — LIVE TRAFFIC
            </div>
          </div>

          {/* Stats row */}
          <div className="grid grid-cols-4 gap-0" style={{ borderTop: "1px solid rgba(0, 212, 255, 0.1)" }}>
            {[
              { label: "Threats Blocked", value: 14823, color: "text-red-400" },
              { label: "Packets/sec", value: 48291, color: "text-cyan-400" },
              { label: "Active Rules", value: 1247, color: "text-green-400" },
              { label: "Sensors Online", value: 32, color: "text-yellow-400" },
            ].map((stat, i) => (
              <div
                key={stat.label}
                className="py-4 flex flex-col items-center"
                style={{
                  borderRight: i < 3 ? "1px solid rgba(0, 212, 255, 0.1)" : "none",
                }}>
                <ThreatCounter {...stat} />
              </div>
            ))}
          </div>

          {/* Log feed */}
          <div className="px-6 py-4" style={{ borderTop: "1px solid rgba(0, 212, 255, 0.1)" }}>
            <div className="flex items-center gap-2 mb-3">
              <Activity size={12} className="text-cyan-400" />
              <span className="text-[10px] font-mono text-slate-500 tracking-widest uppercase">
                Live Event Feed
              </span>
              <div className="flex-1 h-px" style={{ background: "rgba(0, 212, 255, 0.1)" }} />
            </div>
            <LogFeed />
          </div>

          {/* Footer */}
          <div className="px-6 py-3 flex items-center gap-4"
            style={{ borderTop: "1px solid rgba(0, 212, 255, 0.1)" }}>
            {[
              { icon: Server, label: "API Connected", color: "text-green-400" },
              { icon: Shield, label: "IDS Active", color: "text-cyan-400" },
              { icon: AlertTriangle, label: "3 Critical Alerts", color: "text-red-400" },
            ].map(({ icon: Icon, label, color }) => (
              <div key={label} className="flex items-center gap-1.5 text-[10px] font-mono">
                <Icon size={10} className={color} />
                <span className={color}>{label}</span>
              </div>
            ))}
          </div>
        </div>

        {/* RIGHT PANEL — Login form */}
        <div className="lg:col-span-2 flex flex-col justify-center px-8 py-10 relative"
          style={{
            background: "rgba(6, 10, 20, 0.97)",
            border: "1px solid rgba(0, 212, 255, 0.2)",
            boxShadow: "0 0 60px rgba(0, 212, 255, 0.08), inset 0 0 40px rgba(0, 212, 255, 0.02)",
          }}>

          {/* Corner decorators */}
          {["top-0 left-0", "top-0 right-0", "bottom-0 left-0", "bottom-0 right-0"].map((pos, i) => (
            <div key={i} className={`absolute ${pos} w-4 h-4`}>
              <div className="absolute top-0 left-0 right-0 h-px"
                style={{ background: "linear-gradient(90deg, #00d4ff, transparent)" }} />
              <div className="absolute top-0 left-0 bottom-0 w-px"
                style={{ background: "linear-gradient(180deg, #00d4ff, transparent)" }} />
            </div>
          ))}

          {/* Logo */}
          <div className="mb-8 text-center animate-slide-up" style={{ animationDelay: "100ms", animationFillMode: "forwards", opacity: 0 }}>
            <div className="inline-flex items-center justify-center w-16 h-16 mb-4 relative">
              <div className="absolute inset-0 rounded-full"
                style={{
                  background: "radial-gradient(circle, rgba(0,212,255,0.15), transparent)",
                  border: "1px solid rgba(0, 212, 255, 0.3)",
                }} />
              <Shield size={28} className="text-cyan-400 relative z-10 text-glow-primary" />
            </div>
            <h1
              className="text-2xl font-bold text-cyan-400 tracking-widest text-glow-primary animate-flicker"
              style={{ fontFamily: "'Orbitron', monospace" }}>
              CyGuardian-X
            </h1>
            <p className="text-[11px] text-slate-500 font-mono tracking-widest mt-1 uppercase">
              Secure Operations Portal
            </p>
          </div>

          {/* System status */}
          <div className="mb-6 px-3 py-2 rounded animate-slide-up"
            style={{
              animationDelay: "200ms", animationFillMode: "forwards", opacity: 0,
              background: "rgba(0, 255, 159, 0.04)",
              border: "1px solid rgba(0, 255, 159, 0.15)",
            }}>
            <div className="flex items-center gap-2 text-[11px] font-mono">
              <div className="w-1.5 h-1.5 rounded-full bg-green-400 status-dot" />
              <span className="text-green-400">ALL SYSTEMS OPERATIONAL</span>
              <span className="ml-auto text-slate-600">v2.4.1</span>
            </div>
          </div>

          {/* Form */}
          <form onSubmit={handleLogin} className="space-y-4">
            {/* Email */}
            <div className="animate-slide-up" style={{ animationDelay: "300ms", animationFillMode: "forwards", opacity: 0 }}>
              <label className="block text-[10px] font-mono text-slate-500 tracking-widest uppercase mb-1.5">
                Operator ID / Email
              </label>
              <div className="relative">
                <User size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-cyan-400 opacity-60" />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="admin@idps.local"
                  className="cyber-input w-full pl-9 pr-4 py-3 rounded text-sm"
                  autoComplete="email"
                />
              </div>
            </div>

            {/* Password */}
            <div className="animate-slide-up" style={{ animationDelay: "380ms", animationFillMode: "forwards", opacity: 0 }}>
              <label className="block text-[10px] font-mono text-slate-500 tracking-widest uppercase mb-1.5">
                Access Key
              </label>
              <div className="relative">
                <Lock size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-cyan-400 opacity-60" />
                <input
                  type={showPass ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="cyber-input w-full pl-9 pr-10 py-3 rounded text-sm"
                  autoComplete="current-password"
                />
                <button
                  type="button"
                  onClick={() => setShowPass(!showPass)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-600 hover:text-cyan-400 transition-colors">
                  {showPass ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              </div>
            </div>

            {/* Error */}
            {error && (
              <div className="flex items-center gap-2 px-3 py-2 rounded text-[11px] font-mono text-red-400"
                style={{ background: "rgba(255,0,110,0.08)", border: "1px solid rgba(255,0,110,0.25)" }}>
                <AlertTriangle size={12} />
                {error}
              </div>
            )}

            {/* Submit */}
            <button
              type="submit"
              disabled={loading}
              className="cyber-btn w-full py-3.5 rounded text-sm font-bold tracking-widest animate-slide-up disabled:opacity-50 disabled:cursor-not-allowed"
              style={{ animationDelay: "460ms", animationFillMode: "forwards", opacity: 0 }}>
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <div className="w-4 h-4 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
                  AUTHENTICATING...
                </span>
              ) : (
                <span className="relative z-10">INITIATE SECURE SESSION</span>
              )}
            </button>

            {/* Demo hint */}
            <div className="text-center animate-slide-up"
              style={{ animationDelay: "520ms", animationFillMode: "forwards", opacity: 0 }}>
              <p className="text-[10px] font-mono text-slate-600">
                Demo: <span className="text-slate-500">admin@idps.local</span> / <span className="text-slate-500">admin123</span>
              </p>
            </div>
          </form>

          {/* Footer links */}
          <div className="mt-8 pt-6 border-t border-slate-800 flex justify-between text-[10px] font-mono text-slate-600 animate-slide-up"
            style={{ animationDelay: "580ms", animationFillMode: "forwards", opacity: 0 }}>
            <span className="hover:text-cyan-400 cursor-pointer transition-colors">Forgot credentials?</span>
            <span className="hover:text-cyan-400 cursor-pointer transition-colors">Contact SOC Admin</span>
          </div>

          <div className="mt-4 text-center text-[9px] font-mono text-slate-700 tracking-widest animate-slide-up"
            style={{ animationDelay: "620ms", animationFillMode: "forwards", opacity: 0 }}>
            UNAUTHORIZED ACCESS IS STRICTLY PROHIBITED — ALL SESSIONS MONITORED
          </div>
        </div>
      </div>
    </div>
  );
}
