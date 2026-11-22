// Run against a disposable, open-registration deployment. The test client must
// be public and require consent. The callback is fulfilled locally by Chromium.
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";

const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || "playwright");
const api = new URL(process.env.SURGE_URL).origin;
const hosted = new URL(process.env.SURGE_AUTH_UI_ORIGIN).origin;
const callback = new URL(process.env.OAUTH_REDIRECT_URI);
assert.notEqual(callback.hostname, new URL(api).hostname, "Use an independent callback host");
const clientId = process.env.OAUTH_CLIENT_ID;
const resource = process.env.OAUTH_RESOURCE;
assert(clientId && resource);
const password = randomBytes(24).toString("hex");
const start = new URL("/v1/login", api);
start.searchParams.set("return_to", hosted + "/services#surge_account");

async function register(prefix) {
  const username = prefix + randomBytes(6).toString("hex");
  const redirect = await fetch(start, { redirect: "manual" });
  assert.equal(redirect.status, 303);
  const id = new URL(redirect.headers.get("location")).searchParams.get("flow");
  const flowUrl = new URL("/v1/flows/" + id, api);
  const { csrf_token } = await (await fetch(flowUrl)).json();
  const response = await fetch(flowUrl + "/register", {
    method: "POST", headers: { "Content-Type": "application/json", Origin: hosted },
    body: JSON.stringify({ csrf_token, username, password, display_name: username }),
  });
  assert.equal(response.status, 201);
  return username;
}

const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH });
try {
  const page = await browser.newPage();
  const members = [];
  for (const prefix of ["work", "home"]) {
    const username = await register(prefix);
    if (members.length) await page.getByRole("button", { name: "Add account" }).click();
    else await page.goto(start.href);
    await page.locator("#login-username").fill(username);
    await page.getByRole("button", { name: "Continue" }).click();
    await page.locator(".auth-stage--active #login-password").fill(password);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await page.waitForURL("**/u/*/services");
    const accountId = new URL(page.url()).pathname.split("/")[2];
    const identityId = await page.evaluate(async ({ api, accountId }) => {
      const response = await fetch(api + "/v1/whoami", {
        credentials: "include", headers: { "X-Surge-Account": accountId },
      });
      return (await response.json()).identity.id;
    }, { api, accountId });
    members.push({ username, accountId, identityId });
  }

  const verifier = randomBytes(32).toString("base64url");
  const state = randomBytes(16).toString("hex");
  const authorize = new URL("/oauth2/authorize", api);
  authorize.search = new URLSearchParams({
    client_id: clientId, resource, redirect_uri: callback.href, response_type: "code",
    prompt: "select_account", state, code_challenge_method: "S256",
    code_challenge: createHash("sha256").update(verifier).digest("base64url"),
  }).toString();
  let callbackHeaders;
  await page.route(callback.href + "?*", async route => {
    callbackHeaders = await route.request().allHeaders();
    await route.fulfill({ body: "Authorization complete." });
  });
  await page.goto(authorize.href);
  await page.getByRole("button", { name: members[0].username }).waitFor();
  await page.getByRole("button", { name: members[1].username }).click();
  await page.getByRole("button", { name: "Allow access" }).click();
  await page.waitForURL(callback.href + "?*");
  const params = new URL(page.url()).searchParams;
  assert.deepEqual([...params.keys()].sort(), ["code", "state"]);
  assert.equal(params.get("state"), state);

  const response = await fetch(new URL("/oauth2/token", api), {
    method: "POST", body: new URLSearchParams({
      client_id: clientId, resource, grant_type: "authorization_code", code: params.get("code"),
      code_verifier: verifier, redirect_uri: callback.href,
    }),
  });
  assert.equal(response.status, 200);
  const tokens = await response.json();
  const claims = JSON.parse(Buffer.from(tokens.access_token.split(".")[1], "base64url"));
  assert.equal(claims.sub, members[1].identityId);
  const disclosed = JSON.stringify([page.url(), callbackHeaders, tokens, claims]);
  for (const value of [...Object.values(members[0]), members[1].accountId]) {
    assert(!disclosed.includes(value), "Callback or token disclosed a browser membership");
  }
  console.log("Selected second identity, granted consent, and verified third-party callback and token.");
} finally {
  await browser.close();
}
