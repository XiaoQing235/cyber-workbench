import { defineConfig, devices } from "@playwright/test";

const baseURL = "http://127.0.0.1:4176";

export default defineConfig({
  testDir: "./e2e",
  timeout: 60_000,
  workers: 2,
  retries: 0,
  use: { baseURL, serviceWorkers: "block" },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"], ...(process.env.PLAYWRIGHT_USE_CHROME === "1" ? { channel: "chrome" } : {}) } },
    { name: "firefox", use: devices["Desktop Firefox"] },
    { name: "webkit", use: devices["Desktop Safari"] },
  ],
  webServer: {
    command: "npm run preview -- --host 127.0.0.1 --port 4176 --strictPort",
    url: baseURL,
    reuseExistingServer: false,
    timeout: 30_000,
  },
});