import { errorFromResponse, SurgeError } from "./errors.js";
import type {
  Flow,
  FlowInit,
  FlowResult,
  PasswordSubmit,
  RegisterSubmit,
  Session,
} from "./types.js";

export interface SurgeClientOptions {
  /**
   * Origin the Surge server is reachable at, e.g. `https://auth.example.com`.
   * A trailing slash is tolerated.
   */
  baseUrl: string;
  /**
   * Custom `fetch` implementation. Defaults to the global `fetch`, bound to
   * `globalThis`. Useful for tests or non-browser runtimes.
   */
  fetch?: typeof fetch;
}

/**
 * Browser client for the Surge authentication API (v1).
 *
 * Every request is sent with `credentials: "include"` so the browser attaches
 * and stores the `surge_session` cookie. For cross-origin use, the frontend's
 * origin must be listed in the server's `SURGE_SESSION_CORS_ORIGINS`
 * (session endpoints) and inline flow init requires `allow_inline` on the
 * server.
 */
export class SurgeClient {
  readonly baseUrl: string;
  private readonly fetch: typeof fetch;

  constructor(options: SurgeClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
  }

  /**
   * URL for redirect-mode login (`GET /v1/login`). Navigate the browser to
   * it (e.g. `window.location.assign(client.loginUrl(returnTo))`) and Surge
   * will redirect to the auth UI with a fresh flow.
   *
   * @param returnTo Absolute URL to redirect to after successful login. Its
   *   origin must be registered on the server (`svc create --origin`).
   */
  loginUrl(returnTo: string): string {
    return `${this.baseUrl}/v1/login?return_to=${encodeURIComponent(returnTo)}`;
  }

  /**
   * Starts a login flow in inline mode (`GET /v1/login` with
   * `Accept: application/json`). Requires `allow_inline` on the server —
   * without it Surge responds with a redirect instead of JSON, which this
   * method surfaces as a `SurgeError` with code `unexpected_response`.
   *
   * @param returnTo Absolute URL to redirect to after successful login.
   */
  async initLoginFlow(returnTo: string): Promise<FlowInit> {
    const response = await this.fetch(this.loginUrl(returnTo), {
      headers: { Accept: "application/json" },
      credentials: "include",
    });
    if (!response.ok) throw await errorFromResponse(response);
    if (!isJson(response)) {
      throw new SurgeError(
        "unexpected_response",
        response.status,
        "expected inline JSON but got a non-JSON response — is `allow_inline` enabled on the server?",
      );
    }
    return (await response.json()) as FlowInit;
  }

  /**
   * Fetches the state of an existing flow (`GET /v1/flows/{id}`). Used by
   * auth UIs that received the flow ID via the `?flow=` redirect param and
   * need its CSRF token and state.
   */
  async getFlow(flowId: string): Promise<Flow> {
    const response = await this.fetch(
      `${this.baseUrl}/v1/flows/${encodeURIComponent(flowId)}`,
      { credentials: "include" },
    );
    if (!response.ok) throw await errorFromResponse(response);
    return (await response.json()) as Flow;
  }

  /**
   * Submits a password credential into an active flow
   * (`POST /v1/flows/{id}/password`). On success the session cookie is set
   * by the response and the returned `return_to` is where the app should
   * navigate next.
   */
  async submitPassword(flowId: string, body: PasswordSubmit): Promise<FlowResult> {
    return this.submitFlow(flowId, "password", body);
  }

  /**
   * Registers a new identity within an active flow
   * (`POST /v1/flows/{id}/register`). The user is logged in immediately —
   * the session cookie is set and no separate password submission is needed.
   */
  async register(flowId: string, body: RegisterSubmit): Promise<FlowResult> {
    return this.submitFlow(flowId, "register", body);
  }

  /**
   * Returns the current session (`GET /v1/whoami`), or `null` when not
   * authenticated (any 401 — no cookie, expired, or revoked session).
   * Other errors are thrown as `SurgeError`.
   */
  async whoami(): Promise<Session | null> {
    const response = await this.fetch(`${this.baseUrl}/v1/whoami`, {
      credentials: "include",
    });
    if (response.status === 401) return null;
    if (!response.ok) throw await errorFromResponse(response);
    return (await response.json()) as Session;
  }

  /**
   * Revokes the current session and clears the session cookie
   * (`POST /v1/logout`). Idempotent — succeeds whether or not a valid
   * session was present.
   */
  async logout(): Promise<void> {
    const response = await this.fetch(`${this.baseUrl}/v1/logout`, {
      method: "POST",
      headers: { "X-Surge-CSRF": "1" },
      credentials: "include",
    });
    if (!response.ok) throw await errorFromResponse(response);
  }

  private async submitFlow(
    flowId: string,
    action: "password" | "register",
    body: PasswordSubmit | RegisterSubmit,
  ): Promise<FlowResult> {
    const response = await this.fetch(
      `${this.baseUrl}/v1/flows/${encodeURIComponent(flowId)}/${action}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify(body),
      },
    );
    if (!response.ok) throw await errorFromResponse(response);
    return (await response.json()) as FlowResult;
  }
}

function isJson(response: Response): boolean {
  return (response.headers.get("Content-Type") ?? "").includes("application/json");
}
