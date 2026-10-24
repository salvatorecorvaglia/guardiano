import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

for (const theme of ["light", "dark"]) {
  test(`sign in, search and navigate in ${theme} mode`, async ({ page }) => {
    await page.addInitScript((value) => localStorage.setItem("guardiano-theme", value), theme);
    await page.goto("/");
    await page.getByLabel("Email", { exact: true }).fill("browser@example.test");
    await page.getByLabel("Password", { exact: true }).fill("Browser-Smoke-Password-2026!");
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Security posture", exact: true })).toBeVisible();
    await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
    await page.keyboard.press("Control+k");
    const dialog = page.getByRole("dialog");
    await expect(dialog).toBeVisible();
    await page.keyboard.press("Tab");
    await expect(dialog).toContainText("Search");
    expect(await dialog.evaluate((element) => element.contains(document.activeElement))).toBeTruthy();
    await page.keyboard.press("Escape");
    await expect(dialog).not.toBeVisible();
    const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa"]).analyze();
    expect(results.violations).toEqual([]);
    await page.setViewportSize({ width: 390, height: 844 });
    await expect(page.getByRole("heading", { name: "Security posture", exact: true })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
    await page.getByRole("button", { name: "Open menu", exact: true }).click();
    await expect(page.getByRole("dialog", { name: "Navigation" })).toBeVisible();
    await page.setViewportSize({ width: 1280, height: 900 });
    await expect(page.getByRole("dialog", { name: "Navigation" })).not.toBeVisible();
    await expect.poll(() => page.locator("main").evaluate((el) => el.closest("[inert]") === null)).toBe(true);
  });
}

test("forced MFA preserves recovery codes and permits a scan upload", async ({ page, request }) => {
  const login = await request.post("/api/v1/auth/login", {
    data: { email: "browser@example.test", password: "Browser-Smoke-Password-2026!" },
  });
  expect(login.ok()).toBeTruthy();
  const admin = await login.json();
  const email = `manager-${Date.now()}@example.test`;
  const password = "Browser-Manager-Password-2026!";
  const created = await request.post("/api/v1/users", {
    headers: { Authorization: `Bearer ${admin.access_token}` },
    data: { email, password, role: "manager", full_name: "Browser manager" },
  });
  expect(created.ok()).toBeTruthy();
  await page.context().clearCookies();
  await page.goto("/");
  await page.getByLabel("Email", { exact: true }).fill(email);
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Set up two-factor authentication", exact: true })).toBeVisible();
  const setupResponse = page.waitForResponse((response) => response.url().endsWith("/auth/mfa/setup"));
  await page.getByRole("button", { name: "Set up two-factor authentication", exact: true }).click();
  const setup = await (await setupResponse).json();
  const { createHmac } = await import("node:crypto");
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bits = [...setup.secret].map((letter) => alphabet.indexOf(letter).toString(2).padStart(5, "0")).join("");
  const bytes = bits.match(/.{8}/g)!.map((byte) => Number.parseInt(byte, 2));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const digest = createHmac("sha1", Buffer.from(bytes)).update(counter).digest();
  const offset = digest[digest.length - 1] & 15;
  const code = ((digest.readUInt32BE(offset) & 0x7fffffff) % 1000000).toString().padStart(6, "0");
  await page.getByLabel("Code from your app").fill(code);
  await page.getByRole("button", { name: "Turn on", exact: true }).click();
  const recovery = page.getByRole("dialog", { name: "Save your recovery codes" });
  await expect(recovery).toBeVisible();
  await expect(recovery.locator("pre")).not.toBeEmpty();
  await recovery.getByRole("button", { name: "I have saved them" }).click();
  await page.getByRole("button", { name: "Continue after setup" }).click();
  await expect(page.getByRole("heading", { name: "Security posture", exact: true })).toBeVisible();
  await page.getByRole("banner").getByRole("button", { name: "Upload scan", exact: true }).click();
  const upload = page.getByRole("dialog", { name: "Upload scan results" });
  await upload.getByLabel("New asset", { exact: true }).check();
  await upload.getByLabel("New asset name").fill(`browser-upload-${Date.now()}`);
  await upload.locator('input[type="file"]').setInputFiles({
    name: "smoke.json", mimeType: "application/json",
    buffer: Buffer.from(JSON.stringify({ schema: "guardiano/v1", tool: { name: "browser" },
      scan_type: "sast", findings: [{ title: "Browser upload regression", type: "sast", severity: "high",
        file_path: "src/app.py", line_start: 1, rule_id: "browser-rule" }] })),
  });
  await upload.getByRole("button", { name: "Import", exact: true }).click();
  await expect(page.getByRole("dialog", { name: "Scan imported" })).toBeVisible();
  await page.getByRole("link", { name: "View findings", exact: true }).click();
  await expect(page.getByRole("link", { name: "Browser upload regression" })).toBeVisible();
});

test("reports and settings remain usable on mobile", async ({ page }) => {
  await page.goto("/");
  await page.getByLabel("Email", { exact: true }).fill("browser@example.test");
  await page.getByLabel("Password", { exact: true }).fill("Browser-Smoke-Password-2026!");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Security posture", exact: true })).toBeVisible();
  let release!: () => void;
  const held = new Promise<void>((resolve) => { release = resolve; });
  await page.route("**/api/v1/analytics/compliance?**", async (route) => {
    await held;
    await route.continue();
  });
  await page.getByRole("link", { name: "Reports", exact: true }).first().click();
  await expect(page.getByRole("button", { name: "Print", exact: true })).toBeDisabled();
  await expect(page.getByRole("combobox", { name: "Report asset" })).toBeVisible();
  await expect(page.getByRole("combobox", { name: "Report time window" })).toBeVisible();
  release();
  await expect(page.getByRole("button", { name: "Print", exact: true })).toBeEnabled();
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa"]).analyze();
  expect(results.violations).toEqual([]);
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.getByRole("link", { name: "Settings & API tokens", exact: true }).first().click();
  await page.getByRole("tab", { name: "Policies", exact: true }).click();
  await expect(page).toHaveURL(/section=policies/);
  await expect(page.getByRole("heading", { name: "API tokens", exact: true })).not.toBeVisible();
  await page.getByRole("tab", { name: "Account & API tokens", exact: true }).click();
  await expect(page.getByRole("heading", { name: "API tokens", exact: true })).toBeVisible();
});

test("filter changes disable stale selections and prevent bulk updates", async ({ page }) => {
  await page.goto("/");
  await page.getByLabel("Email", { exact: true }).fill("browser@example.test");
  await page.getByLabel("Password", { exact: true }).fill("Browser-Smoke-Password-2026!");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Security posture", exact: true })).toBeVisible();
  await page.getByRole("link", { name: "Findings", exact: true }).first().click();
  const selectAll = page.getByRole("checkbox", { name: "Select all on page" });
  await expect(selectAll).toBeEnabled();
  await selectAll.check();
  await expect(page.getByRole("textbox", { name: "Add tag to selected" })).toBeVisible();
  let release!: () => void;
  const held = new Promise<void>((resolve) => { release = resolve; });
  let mutations = 0;
  await page.route("**/api/v1/findings**", async (route) => {
    if (route.request().method() !== "GET") mutations++;
    if (new URL(route.request().url()).searchParams.get("type") === "sca") await held;
    await route.continue();
  });
  await page.getByRole("combobox", { name: "Type", exact: true }).selectOption("sca");
  await expect(selectAll).toBeDisabled();
  await expect(page.getByRole("textbox", { name: "Add tag to selected" })).not.toBeVisible();
  release();
  await expect(selectAll).toBeEnabled();
  await expect(selectAll).not.toBeChecked();
  expect(mutations).toBe(0);
});
