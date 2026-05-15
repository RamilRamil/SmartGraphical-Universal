/* eslint-disable @typescript-eslint/no-require-imports */
const { defineConfig, devices } = require("@playwright/test");

const FRONTEND = "http://127.0.0.1:5173";

module.exports = defineConfig({
  testDir: "./e2e",
  testMatch: "**/*.spec.mjs",
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 2 : 0,
  reporter: "list",
  use: {
    baseURL: FRONTEND,
    trace: "on-first-retry",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: "npm run dev",
    url: FRONTEND,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
