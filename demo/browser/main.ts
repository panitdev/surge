import { SurgeClient } from "../../packages/surge-client/src/index";

const { origin: baseUrl, clientId, resource, scope } = await (await fetch("/config")).json();
// Surge fills the opt-in callback fragment with the completed membership.
const returned = new URLSearchParams(location.hash.slice(1)).get("surge_account");
if (returned && location.pathname === "/") {
  history.replaceState(null, "", `/u/${encodeURIComponent(returned)}/`);
}
const accountId = /^\/u\/([^/]+)\/?$/.exec(location.pathname)?.[1];
const client = new SurgeClient({ baseUrl, accountId });
const path = (id: string) => `/u/${encodeURIComponent(id)}/`;
const element = (id: string) => document.getElementById(id)!;
const run = (action: () => Promise<void>) => action().catch((err: Error) => {
  element("error").textContent = err.message;
});

const callback = location.origin + "/oauth/callback";
const transactionKey = "surge-demo-oauth";
const base64url = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes))
  .replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
async function authorize() {
  const verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
  const state = crypto.randomUUID();
  sessionStorage.setItem(transactionKey, JSON.stringify({ state, verifier, accountId }));
  const url = new URL("/oauth2/authorize", baseUrl);
  url.search = new URLSearchParams({ client_id: clientId, resource, redirect_uri: callback,
    response_type: "code", code_challenge_method: "S256", code_challenge: challenge, state }).toString();
  if (scope) url.searchParams.set("scope", scope);
  if (accountId) url.searchParams.set("account_id", accountId);
  location.assign(url);
}

if (location.pathname === "/oauth/callback") {
  element("login").hidden = true;
  element("session").textContent = "Completing authorization…";
  let returnPath: string | undefined;
  try {
    const params = new URLSearchParams(location.search);
    const saved = JSON.parse(sessionStorage.getItem(transactionKey) || "null");
    if (!saved || params.get("state") !== saved.state) throw new Error("Unknown authorization response.");
    returnPath = saved.accountId ? path(saved.accountId) : "/";
    sessionStorage.removeItem(transactionKey);
    history.replaceState(null, "", callback);
    const code = params.get("code");
    if (!code) throw new Error(params.get("error") ?? "Missing authorization code.");
    const response = await fetch(new URL("/oauth2/token", baseUrl), {
      method: "POST", body: new URLSearchParams({ grant_type: "authorization_code", client_id: clientId,
        code, redirect_uri: callback, code_verifier: saved.verifier, resource }),
    });
    if (!response.ok) throw new Error("Could not exchange the authorization code.");
    element("session").textContent = "Authorization complete.";
  } catch (err) {
    element("session").textContent = "Authorization failed.";
    element("error").textContent = err instanceof Error ? err.message : "Unknown error.";
  }
  if (returnPath) {
    const link = document.createElement("a");
    link.href = returnPath;
    link.textContent = "Return to account";
    element("session").append(" ", link);
  }
} else {
  await showAccounts();
}

async function showAccounts() {
  let adding = false;
  await run(async () => {
    const result = await client.whoamiWithAccount();
    if (result?.accountId && !accountId) {
      location.replace(path(result.accountId));
      return;
    }
    if (accountId && result && result.accountId !== accountId) throw new Error("Invalid account response.");
    adding = Boolean(result);
    if (result && clientId && resource) {
      element("authorize").hidden = false;
      element("authorize").onclick = () => void run(authorize);
    }
    element("session").textContent = result ? `Signed in as ${result.session.identity.username}` :
      accountId ? "This account is unavailable." : "No default account.";
    element("logout").hidden = !result;
    element("logout-all").hidden = !result?.accountId;
    const { accounts, default_account_id } = await client.listAccounts();
    adding ||= accounts.length > 0;
    for (const account of accounts) {
      const item = document.createElement("li");
      const link = document.createElement("a");
      link.textContent = account.identity.username;
      link.href = path(account.account_id);
      item.append(link);
      if (account.account_id === default_account_id) item.append(" (default)");
      else {
        const button = document.createElement("button");
        button.textContent = "Make default";
        button.onclick = () => void run(async () => {
          await client.setDefaultAccount(account.account_id);
          location.reload();
        });
        item.append(" ", button);
      }
      element("accounts").append(item);
    }
  });
  const login = element("login") as HTMLButtonElement;
  login.textContent = adding ? "Add account" : "Sign in";
  login.disabled = false;
  login.onclick = () => {
    const callback = new URL("/#surge_account", location.origin);
    location.assign(client.loginUrl(callback.href, adding ? { intent: "add_account" } : undefined));
  };
  element("logout").onclick = () => void run(async () => { await client.logout(); location.assign("/"); });
  element("logout-all").onclick = () => void run(async () => { await client.logoutAll(); location.assign("/"); });
}
