// Bun bundles the browser SDK with this app. Surge owns only the API routes.
import page from "./index.html";
const origin = new URL(process.env.SURGE_URL ?? "http://127.0.0.1:3000").origin;
const server = Bun.serve({
  hostname: "127.0.0.1",
  port: Number(process.env.PORT ?? 3300),
  routes: {
    "/": page,
    "/u/:accountId/": page,
    "/oauth/callback": page,
    "/config": () => Response.json({
      origin, clientId: process.env.OAUTH_CLIENT_ID, resource: process.env.OAUTH_RESOURCE,
      scope: process.env.OAUTH_SCOPE,
    }),
  },
});
console.log(`Browser demo listening at ${server.url}`);
