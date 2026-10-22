import { defineConfig } from "@playwright/test";

const externalUrl = process.env.BROWSER_BASE_URL;
if (externalUrl && !["localhost", "127.0.0.1", "[::1]"].includes(new URL(externalUrl).hostname)) {
  throw new Error("Browser writes are restricted to a local staging endpoint");
}

export default defineConfig({
  testDir: "./e2e",
  workers: 1,
  retries: 0,
  use: { baseURL: externalUrl ?? "http://127.0.0.1:5178", trace: "retain-on-failure",
    ignoreHTTPSErrors: !!externalUrl && process.env.BROWSER_ALLOW_LOCAL_CERT === "true" },
  webServer: externalUrl ? undefined : [
    {
      command: ".venv/bin/python browser_server.py",
      cwd: "../backend",
      url: "http://127.0.0.1:8009/healthz",
      reuseExistingServer: false,
    },
    {
      command: "node_modules/.bin/vite --host 127.0.0.1 --port 5178 --strictPort",
      env: { VITE_API_PROXY: "http://127.0.0.1:8009" },
      url: "http://127.0.0.1:5178",
      reuseExistingServer: false,
    },
  ],
});
