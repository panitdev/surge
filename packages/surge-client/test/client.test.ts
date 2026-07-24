import { describe, expect, test } from "bun:test";

import { SurgeClient, SurgeError } from "../src/index.js";
import type { FlowResult, PolicyBlock, Session } from "../src/index.js";

const session: Session = {
  id: "018f9a1b-c2d3-4b5e-a6f7-d8e9f0a1b2c3",
  identity: {
    id: "018f9a1b-2c3d-4e5f-a6b7-c8d9e0f1a2b3",
    username: "alice",
    display_name: "Alice",
    avatar_url: null,
    state: "active",
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
  },
  issued_at: "2026-07-08T12:00:00Z",
  expires_at: "2026-07-11T12:00:00Z",
  authenticated_via: "password",
};

const policy: PolicyBlock = {
  required: { totp: false, passphrase: false },
  has: { totp: false, passphrase: false },
  compliant: true,
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/** Returns a client whose fetch records every request and replays `responses` in order. */
function mockClient(...responses: Response[]) {
  const requests: { url: string; init: RequestInit | undefined }[] = [];
  const client = new SurgeClient({
    baseUrl: "https://auth.example.com/",
    fetch: (async (url: string | URL | Request, init?: RequestInit) => {
      requests.push({ url: String(url), init });
      const next = responses.shift();
      if (!next) throw new Error("mock fetch: no response queued");
      return next;
    }) as typeof fetch,
  });
  return { client, requests };
}

describe("loginUrl", () => {
  test("builds the redirect-mode URL and strips trailing slash from baseUrl", () => {
    const { client } = mockClient();
    expect(client.loginUrl("https://app.example.com/dashboard")).toBe(
      "https://auth.example.com/v1/login?return_to=https%3A%2F%2Fapp.example.com%2Fdashboard",
    );
  });
});

describe("initLoginFlow", () => {
  test("sends Accept: application/json with credentials and parses the flow", async () => {
    const { client, requests } = mockClient(
      json({ flow_id: "aeg_f_x", csrf_token: "tok", registration_mode: "open" }),
    );
    const flow = await client.initLoginFlow("https://app.example.com/");
    expect(flow.flow_id).toBe("aeg_f_x");
    expect(flow.registration_mode).toBe("open");
    const req = requests[0]!;
    expect(req.url).toContain("/v1/login?return_to=");
    expect(new Headers(req.init?.headers).get("Accept")).toBe("application/json");
    expect(req.init?.credentials).toBe("include");
  });

  test("throws unexpected_response when the server redirects to HTML instead", async () => {
    const { client } = mockClient(
      new Response("<html></html>", { status: 200, headers: { "Content-Type": "text/html" } }),
    );
    const err = await client.initLoginFlow("https://app.example.com/").catch((e) => e);
    expect(err).toBeInstanceOf(SurgeError);
    expect(err.code).toBe("unexpected_response");
  });

  test("surfaces validation_error with message", async () => {
    const { client } = mockClient(
      json({ error: "validation_error", message: "invalid URL" }, 422),
    );
    const err = await client.initLoginFlow("not-a-url").catch((e) => e);
    expect(err).toBeInstanceOf(SurgeError);
    expect(err.code).toBe("validation_error");
    expect(err.status).toBe(422);
    expect(err.message).toBe("invalid URL");
  });

  test("omits return_to from the request URL when called without one", async () => {
    const { client, requests } = mockClient(
      json({ flow_id: "aeg_f_x", csrf_token: "tok", registration_mode: "open" }),
    );
    await client.initLoginFlow();
    const req = requests[0]!;
    expect(req.url).toBe("https://auth.example.com/v1/login");
    expect(req.url).not.toContain("return_to");
  });
});

describe("getFlow", () => {
  test("fetches flow state by id", async () => {
    const { client, requests } = mockClient(
      json({
        id: "aeg_f_x",
        state: "created",
        csrf_token: "tok",
        error: null,
        registration_enabled: true,
      }),
    );
    const flow = await client.getFlow("aeg_f_x");
    expect(flow.state).toBe("created");
    expect(requests[0]!.url).toBe("https://auth.example.com/v1/flows/aeg_f_x");
  });
});

describe("submitPassword", () => {
  const result: FlowResult = {
    return_to: "https://app.example.com/dashboard",
    session,
    policy,
  };

  test("POSTs credentials with csrf_token in the body", async () => {
    const { client, requests } = mockClient(json(result));
    const res = await client.submitPassword("aeg_f_x", {
      username: "alice",
      password: "correct-horse-battery-staple",
      csrf_token: "tok",
    });
    expect(res.return_to).toBe("https://app.example.com/dashboard");
    expect("session" in res && res.session.identity.username).toBe("alice");
    const req = requests[0]!;
    expect(req.url).toBe("https://auth.example.com/v1/flows/aeg_f_x/password");
    expect(req.init?.method).toBe("POST");
    expect(req.init?.credentials).toBe("include");
    expect(JSON.parse(req.init?.body as string)).toEqual({
      username: "alice",
      password: "correct-horse-battery-staple",
      csrf_token: "tok",
    });
  });

  test("maps invalid_credentials to a non-retryable SurgeError", async () => {
    const { client } = mockClient(json({ error: "invalid_credentials" }, 401));
    const err = await client
      .submitPassword("aeg_f_x", { username: "a", password: "b", csrf_token: "t" })
      .catch((e) => e);
    expect(err.code).toBe("invalid_credentials");
    expect(err.isRetryable).toBe(false);
  });

  test("exposes retry_after on rate_limited and marks it retryable", async () => {
    const { client } = mockClient(json({ error: "rate_limited", retry_after: 30 }, 429));
    const err = await client
      .submitPassword("aeg_f_x", { username: "a", password: "b", csrf_token: "t" })
      .catch((e) => e);
    expect(err.code).toBe("rate_limited");
    expect(err.retryAfter).toBe(30);
    expect(err.isRetryable).toBe(true);
  });

  test("return_to is null when the flow was started without one", async () => {
    const { client } = mockClient(json({ return_to: null, session, policy }));
    const res = await client.submitPassword("aeg_f_x", {
      username: "alice",
      password: "correct-horse-battery-staple",
      csrf_token: "tok",
    });
    expect(res.return_to).toBeNull();
  });

  test("returns totp_required (no session) when the user has TOTP enrolled", async () => {
    const { client } = mockClient(
      json({ status: "totp_required", return_to: "https://app.example.com/" }),
    );
    const res = await client.submitPassword("aeg_f_x", {
      username: "alice",
      password: "correct-horse-battery-staple",
      csrf_token: "tok",
    });
    expect("status" in res && res.status).toBe("totp_required");
    expect("session" in res).toBe(false);
  });
});

describe("second-factor and recovery flow steps", () => {
  test("submitTotp POSTs the code to the totp step", async () => {
    const { client, requests } = mockClient(
      json({ return_to: null, session, policy }),
    );
    const res = await client.submitTotp("aeg_f_x", { code: "123456", csrf_token: "tok" });
    expect(res.session.id).toBe(session.id);
    expect(requests[0]!.url).toBe("https://auth.example.com/v1/flows/aeg_f_x/totp");
    expect(JSON.parse(requests[0]!.init?.body as string)).toEqual({
      code: "123456",
      csrf_token: "tok",
    });
  });

  test("submitPassphrase hits the passphrase step with username", async () => {
    const { client, requests } = mockClient(
      json({ return_to: null, session, policy }),
    );
    await client.submitPassphrase("aeg_f_x", {
      username: "alice",
      passphrase: "correct horse battery staple pin oak",
      csrf_token: "tok",
    });
    expect(requests[0]!.url).toBe("https://auth.example.com/v1/flows/aeg_f_x/passphrase");
  });

  test("recoverPassword hits the recover step", async () => {
    const { client, requests } = mockClient(
      json({ return_to: null, session, policy }),
    );
    await client.recoverPassword("aeg_f_x", {
      username: "alice",
      passphrase: "correct horse battery staple pin oak",
      new_password: "a-brand-new-password",
      csrf_token: "tok",
    });
    expect(requests[0]!.url).toBe("https://auth.example.com/v1/flows/aeg_f_x/recover");
  });
});

describe("factor management (authenticated)", () => {
  test("getFactors reads the policy block", async () => {
    const { client, requests } = mockClient(json({ policy }));
    const res = await client.getFactors();
    expect(res.policy.compliant).toBe(true);
    expect(requests[0]!.url).toBe("https://auth.example.com/v1/factors");
    expect(requests[0]!.init?.credentials).toBe("include");
  });

  test("enrollTotp sends step_up and the CSRF header, returns provisioning material", async () => {
    const { client, requests } = mockClient(
      json({ otpauth_uri: "otpauth://totp/Surge:alice?secret=ABC", secret: "ABC" }),
    );
    const res = await client.enrollTotp("current-password");
    expect(res.otpauth_uri).toContain("otpauth://");
    const req = requests[0]!;
    expect(req.url).toBe("https://auth.example.com/v1/factors/totp/enroll");
    expect(req.init?.method).toBe("POST");
    expect(new Headers(req.init?.headers).get("X-Surge-CSRF")).toBe("1");
    expect(JSON.parse(req.init?.body as string)).toEqual({ step_up: "current-password" });
  });

  test("enrollPassphrase returns the generated passphrase once", async () => {
    const { client, requests } = mockClient(
      json({ passphrase: "correct horse battery staple pin oak" }),
    );
    const res = await client.enrollPassphrase("current-password");
    expect(res.passphrase.split(" ")).toHaveLength(6);
    expect(requests[0]!.url).toBe("https://auth.example.com/v1/factors/passphrase");
  });

  test("confirmPassphrase echoes passphrase to confirm endpoint", async () => {
    const { client, requests } = mockClient(json({ policy }));
    await client.confirmPassphrase("correct horse battery staple pin oak");
    const req = requests[0]!;
    expect(req.url).toBe("https://auth.example.com/v1/factors/passphrase/confirm");
    expect(req.init?.method).toBe("POST");
    expect(JSON.parse(req.init?.body as string)).toEqual({
      passphrase: "correct horse battery staple pin oak",
    });
  });

  test("removeTotp uses DELETE with the step-up proof", async () => {
    const { client, requests } = mockClient(json({ policy }));
    await client.removeTotp("my passphrase words here now go");
    const req = requests[0]!;
    expect(req.url).toBe("https://auth.example.com/v1/factors/totp");
    expect(req.init?.method).toBe("DELETE");
    expect(new Headers(req.init?.headers).get("X-Surge-CSRF")).toBe("1");
  });

  test("changePassword posts step_up and new_password, accepts 204", async () => {
    const { client, requests } = mockClient(new Response(null, { status: 204 }));
    await client.changePassword("current-passphrase", "a-brand-new-password");
    const req = requests[0]!;
    expect(req.url).toBe("https://auth.example.com/v1/account/password");
    expect(JSON.parse(req.init?.body as string)).toEqual({
      step_up: "current-passphrase",
      new_password: "a-brand-new-password",
    });
  });
});

describe("register", () => {
  test("POSTs the registration body and parses the 201 result", async () => {
    const { client, requests } = mockClient(
      json({ return_to: "https://app.example.com/", session, policy }, 201),
    );
    const res = await client.register("aeg_f_x", {
      username: "bob",
      password: "correct-horse-battery-staple",
      display_name: "Bob",
      csrf_token: "tok",
    });
    expect(res.session.id).toBe(session.id);
    expect(requests[0]!.url).toBe("https://auth.example.com/v1/flows/aeg_f_x/register");
  });

  test("surfaces username_taken", async () => {
    const { client } = mockClient(json({ error: "username_taken" }, 409));
    const err = await client
      .register("aeg_f_x", {
        username: "alice",
        password: "pw-long-enough",
        display_name: "",
        csrf_token: "t",
      })
      .catch((e) => e);
    expect(err.code).toBe("username_taken");
    expect(err.status).toBe(409);
  });
});

describe("whoami", () => {
  test("returns the session when authenticated", async () => {
    const { client, requests } = mockClient(json(session));
    const res = await client.whoami();
    expect(res?.identity.username).toBe("alice");
    expect(requests[0]!.url).toBe("https://auth.example.com/v1/whoami");
    expect(requests[0]!.init?.credentials).toBe("include");
  });

  test("returns null on 401 instead of throwing", async () => {
    const { client } = mockClient(json({ error: "invalid_token" }, 401));
    expect(await client.whoami()).toBeNull();
  });

  test("throws on non-401 errors", async () => {
    const { client } = mockClient(json({ error: "unavailable" }, 503));
    const err = await client.whoami().catch((e) => e);
    expect(err.code).toBe("unavailable");
    expect(err.isRetryable).toBe(true);
  });
});

describe("logout", () => {
  test("POSTs with the X-Surge-CSRF header and accepts 204", async () => {
    const { client, requests } = mockClient(new Response(null, { status: 204 }));
    await client.logout();
    const req = requests[0]!;
    expect(req.url).toBe("https://auth.example.com/v1/logout");
    expect(req.init?.method).toBe("POST");
    expect(new Headers(req.init?.headers).get("X-Surge-CSRF")).toBe("1");
    expect(req.init?.credentials).toBe("include");
  });

  test("tolerates the plain-text 401 body from a CSRF rejection", async () => {
    const { client } = mockClient(new Response("missing csrf header", { status: 401 }));
    const err = await client.logout().catch((e) => e);
    expect(err).toBeInstanceOf(SurgeError);
    expect(err.code).toBe("unexpected_response");
    expect(err.status).toBe(401);
  });
});
