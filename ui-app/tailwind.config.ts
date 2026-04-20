import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ember: "#f97316",
        graphite: "#0f172a",
        oxide: "#111827",
        ink: "#dbe4f0",
        mist: "#94a3b8",
      },
      fontFamily: {
        sans: ["IBM Plex Sans", "Avenir Next", "Segoe UI", "sans-serif"],
        mono: ["IBM Plex Mono", "ui-monospace", "monospace"],
      },
      boxShadow: {
        panel: "0 24px 80px rgba(15, 23, 42, 0.32)",
      },
    },
  },
  plugins: [],
} satisfies Config;
