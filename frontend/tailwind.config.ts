import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        mono: ["'JetBrains Mono'", "'Fira Code'", "monospace"],
        display: ["'Orbitron'", "monospace"],
        body: ["'Share Tech Mono'", "monospace"],
      },
      colors: {
        cyber: {
          bg: "#030712",
          card: "#0a0f1e",
          border: "#0f2a4a",
          primary: "#00d4ff",
          secondary: "#00ff9f",
          accent: "#ff006e",
          warn: "#ffbe0b",
          text: "#94a3b8",
          muted: "#334155",
        },
      },
      animation: {
        "scan-line": "scanLine 3s linear infinite",
        "pulse-slow": "pulse 3s ease-in-out infinite",
        "flicker": "flicker 4s ease-in-out infinite",
        "grid-flow": "gridFlow 20s linear infinite",
        "border-flow": "borderFlow 2s linear infinite",
      },
      keyframes: {
        scanLine: {
          "0%": { top: "0%" },
          "100%": { top: "100%" },
        },
        flicker: {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.85" },
          "75%": { opacity: "0.95" },
        },
        gridFlow: {
          "0%": { backgroundPosition: "0 0" },
          "100%": { backgroundPosition: "0 80px" },
        },
        borderFlow: {
          "0%": { backgroundPosition: "0% 50%" },
          "100%": { backgroundPosition: "100% 50%" },
        },
      },
    },
  },
  plugins: [],
};

export default config;
