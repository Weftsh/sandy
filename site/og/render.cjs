// Renders og/card.html to the social images in public/. Needs Playwright
// with Chromium (npx playwright install chromium).
const path = require("node:path");
let playwright;
try { playwright = require("playwright"); } catch {
  playwright = require(path.join(require("node:child_process").execSync("npm root -g").toString().trim(), "playwright"));
}
(async () => {
  const browser = await playwright.chromium.launch();
  for (const [file, width, height] of [["og.png", 1200, 630], ["social-preview.png", 1280, 640]]) {
    const page = await browser.newPage({ viewport: { width, height } });
    await page.goto("file://" + path.join(__dirname, "card.html"));
    await page.screenshot({ path: path.join(__dirname, "..", "public", file) });
    console.log("wrote public/" + file);
  }
  await browser.close();
})();
