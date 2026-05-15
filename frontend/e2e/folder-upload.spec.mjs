import path from "node:path";
import { fileURLToPath } from "node:url";

import { expect, test } from "@playwright/test";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE_TREE = path.join(__dirname, "fixtures", "solidity-src-tree");

test.describe("folder-shaped Solidity bundle (UI)", () => {
  test("folder pick with src/*.sol yields tree paths and no client extension error", async ({ page }) => {
    await page.goto("/upload");

    await page.getByRole("radio", { name: /Combined graph/i }).click();

    await page.getByLabel("Source folder").setInputFiles(FIXTURE_TREE);

    await expect(page.locator(".sg-banner.sg-banner--error")).toHaveCount(0);

    await expect(page.getByText("2 selected", { exact: true })).toBeVisible();
    await expect(page.getByText("tree (manifest v2 paths)", { exact: true })).toBeVisible();

    const items = page.locator(".sg-preview ul.sg-form__hint li");
    await expect(items).toHaveCount(2);
    await expect(items.filter({ hasText: /src\/Lib\.sol/ })).toHaveCount(1);
    await expect(items.filter({ hasText: /src\/User\.sol/ })).toHaveCount(1);

    await expect(page.locator(".sg-preview").getByText("solidity", { exact: true })).toBeVisible();
  });
});
