import { SurgeClient } from "../../packages/surge-client/src/index";

const { origin: baseUrl } = await (await fetch("/config")).json();
// Surge fills the opt-in callback fragment with the completed membership.
const returned = new URLSearchParams(location.hash.slice(1)).get("surge_account");
if (returned && location.pathname === "/") {
  history.replaceState(null, "", `/u/${encodeURIComponent(returned)}/`);
}
const accountId = location.pathname.split("/")[2] || undefined;
const client = new SurgeClient({ baseUrl, accountId });
const path = (id: string) => `/u/${encodeURIComponent(id)}/`;
const element = (id: string) => document.getElementById(id)!;
const run = (action: () => Promise<void>) => action().catch((err: Error) => {
  element("error").textContent = err.message;
});

let adding = false;
await run(async () => {
  const result = await client.whoamiWithAccount();
  if (result?.accountId && !accountId) {
    location.replace(path(result.accountId));
    return;
  }
  if (accountId && result && result.accountId !== accountId) throw new Error("Invalid account response.");
  adding = Boolean(result);
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
