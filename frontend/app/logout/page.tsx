"use client";
import { useEffect } from "react";

export default function LogoutPage() {
  useEffect(() => {
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    document.cookie = "token=; path=/; max-age=0";
    window.location.href = "/login";
  }, []);

  return (
    <div className="min-h-screen flex items-center justify-center" style={{ background: "#030712" }}>
      <div className="text-cyan-400 font-mono text-sm animate-pulse">
        TERMINATING SESSION...
      </div>
    </div>
  );
}
