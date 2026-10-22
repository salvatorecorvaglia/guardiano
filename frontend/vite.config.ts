/// <reference types="vitest/config" />
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const apiTarget = process.env.VITE_API_PROXY ?? "http://localhost:8000";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": { target: apiTarget, changeOrigin: true },
    },
  },
  test: {
    maxWorkers: 4,
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
  },
  build: {
    // Keep hashed bundles out of "/assets/", which is an SPA route (see nginx/default.conf.template).
    assetsDir: "static",
    sourcemap: false,
    chunkSizeWarningLimit: 900,
    rollupOptions: {
      output: {
        // Listed by package path rather than as `charts: ["recharts"]`: the object form also pulls
        // recharts' dependencies into the chunk, and one of them (clsx) is used by the layout too, so
        // every page -- the sign-in page included -- preloaded all 100 KB of charting to get it.
        manualChunks(id) {
          // clsx is named here because recharts imports it too: left unassigned, Rollup puts it in
          // the charts chunk, and the layout's import of it preloads charting on every page.
          if (/node_modules\/(react|react-dom|react-router|react-router-dom|scheduler|clsx)\//.test(id)) return "react";
          if (/node_modules\/(recharts|recharts-scale|react-smooth|victory-vendor|d3-[a-z-]+|decimal\.js-light)\//.test(id))
            return "charts";
        },
      },
    },
  },
});
