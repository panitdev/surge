// Run against a disposable open-registration deployment. APP_API_URL is
// either an embedded browser API or a remote proxy. SURGE_URL is the issuer.
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
const { chromium } = await import(process.env.PLAYWRIGHT_MODULE || "playwright");
const app = new URL(process.env.APP_API_URL).origin;
const issuer = new URL(process.env.SURGE_URL).origin;
const hosted = new URL(process.env.SURGE_AUTH_UI_ORIGIN).origin;
const callback = process.env.OAUTH_REDIRECT_URI;
const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH });
const context = await browser.newContext();
const work = await context.newPage();
const personal = await context.newPage();
const password = randomBytes(24).toString("hex");
async function request(page, base, path, method = "GET", body, pin) {
  return page.evaluate(async ({ base, path, method, body, pin }) => {
    const headers = { Accept: "application/json" };
    if (method !== "GET") headers["X-Surge-CSRF"] = "1";
    if (pin) headers["X-Surge-Account"] = pin;
    if (body) headers["Content-Type"] = "application/json";
    const response = await fetch(new URL(path, base), {
      method, headers, credentials: "include", body: JSON.stringify(body),
    });
    return { status: response.status, data: await response.json().catch(() => null),
      account: response.headers.get("X-Surge-Account") };
  }, { base, path, method, body, pin });
}
async function register(page, adding) {
  // Browser navigation also works when inline flow creation is disabled.
  await page.goto(app + "/v1/login?" + new URLSearchParams({
    return_to: hosted, ...(adding ? { intent: "add_account" } : {}),
  }));
  const flowId = new URL(page.url()).searchParams.get("flow");
  assert(flowId);
  const path = "/v1/flows/" + flowId;
  const flow = await request(page, app, path);
  const username = "rollout" + randomBytes(6).toString("hex");
  const result = await request(page, app, path + "/register", "POST", {
    csrf_token: flow.data.csrf_token, username, display_name: username, password,
  });
  assert.equal(result.status, 201);
  return result.data.session.identity.id;
}
try {
  const workIdentity = await register(work, false);
  const workId = (await request(work, app, "/v1/whoami")).account;
  const personalIdentity = await register(personal, true);
  const list = await request(personal, app, "/v1/accounts");
  const personalId = list.data.accounts.find(a => a.identity.id === personalIdentity).account_id;
  assert(workId && workId !== personalId);
  const verifier = randomBytes(32).toString("base64url");
  const uri = new URL("/oauth2/authorize", issuer);
  uri.search = new URLSearchParams({
    account_id: workId, client_id: process.env.OAUTH_CLIENT_ID, resource: process.env.OAUTH_RESOURCE,
    redirect_uri: callback, response_type: "code", code_challenge_method: "S256",
    code_challenge: createHash("sha256").update(verifier).digest("base64url"),
  });
  await work.goto(uri.href);
  const flow = new URL(work.url()).searchParams.get("consent_flow");
  assert(flow);
  const path = "/v1/oauth/consent/" + flow;
  const screen = await request(work, issuer, path);
  assert.equal((await request(personal, app, "/v1/accounts/default", "PUT", { account_id: personalId })).status, 204);
  const change = (page, pin, old, next) => request(page, app, "/v1/account/password", "POST",
    { step_up: old, new_password: next }, pin);
  assert.equal((await change(work, workId, password, password + "work")).status, 204);
  assert.equal((await change(personal, personalId, password, password + "personal")).status, 204);
  const decision = await request(work, issuer, path, "POST", { approve: true, csrf_token: screen.data.csrf_token });
  const code = new URL(decision.data.redirect_to).searchParams.get("code");
  const token = await fetch(new URL("/oauth2/token", issuer), { method: "POST", body: new URLSearchParams({
    grant_type: "authorization_code", client_id: process.env.OAUTH_CLIENT_ID, resource: process.env.OAUTH_RESOURCE,
    code, code_verifier: verifier, redirect_uri: callback,
  }) });
  assert.equal(token.status, 200);
  const { access_token } = await token.json();
  assert.equal(JSON.parse(Buffer.from(access_token.split(".")[1], "base64url")).sub, workIdentity);
  assert.equal((await request(personal, app, "/v1/logout", "POST", undefined, workId)).status, 204);
  assert.equal((await change(work, workId, password + "personal", password + "unavailable")).status, 401);
  assert.equal((await request(personal, app, "/v1/whoami")).data.identity.id, personalIdentity);
  console.log("Two Chromium tabs preserved the selected write and consent identity.");
} finally {
  await browser.close();
}
