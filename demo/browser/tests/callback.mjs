// Start the demo locally, then run with DEMO_URL set to its origin.
import assert from "node:assert/strict";
const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || "playwright");
const origin = new URL(process.env.DEMO_URL).origin;
const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH });
try {
  for (const [query, matched] of [
    ["state=known&error=access_denied", true],
    ["state=known&code=unused", true],
    ["state=unknown&error=access_denied", false],
  ]) {
    const page = await browser.newPage();
    await page.addInitScript(() => sessionStorage.setItem("surge-demo-oauth",
      JSON.stringify({ state: "known", verifier: "test", accountId: "original" })));
    await page.route("**/oauth2/token", route => route.fulfill({ status: 400 }));
    await page.goto(origin + "/oauth/callback?" + query);
    await page.getByText("Authorization failed.").waitFor();
    const link = page.getByRole("link", { name: "Return to account" });
    assert.equal(await link.count(), Number(matched));
    if (matched) assert.equal(await link.getAttribute("href"), "/u/original/");
    assert.equal(await page.evaluate(() => !!sessionStorage.getItem("surge-demo-oauth")), !matched);
    await page.close();
  }
} finally {
  await browser.close();
}
