import { errorFromResponse, SurgeError } from "./errors.js";
import type {
  FactorsResult,
  Flow,
  FlowInit,
  FlowResult,
  PassphraseLogin,
  PassphraseResult,
  PasswordSubmit,
  PasswordSubmitResult,
  RecoverSubmit,
  RegisterSubmit,
  Session,
  TotpEnrollment,
  TotpSubmit,
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
   *   Optional in inline mode — omit it if the caller manages its own
   *   post-login navigation; the flow's completion response will then
   *   carry `return_to: null`.
   */
  async initLoginFlow(returnTo?: string): Promise<FlowInit> {
    const url =
      returnTo === undefined
        ? `${this.baseUrl}/v1/login`
        : this.loginUrl(returnTo);
    const response = await this.fetch(url, {
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
   * (`POST /v1/flows/{id}/password`). Two outcomes:
   *
   * - The user has no TOTP → logged in: the session cookie is set and a
   *   {@link FlowResult} is returned.
   * - The user has a confirmed TOTP → a {@link TotpRequired} is returned with
   *   `status: "totp_required"` and no cookie; complete login with
   *   {@link submitTotp}. Narrow on the `status` field to tell them apart.
   */
  async submitPassword(
    flowId: string,
    body: PasswordSubmit,
  ): Promise<PasswordSubmitResult> {
    return this.submitFlow<PasswordSubmitResult>(flowId, "password", body);
  }

  /**
   * Completes the mandatory second step after {@link submitPassword} returned
   * `totp_required` (`POST /v1/flows/{id}/totp`). On success the session
   * cookie is set.
   */
  async submitTotp(flowId: string, body: TotpSubmit): Promise<FlowResult> {
    return this.submitFlow<FlowResult>(flowId, "totp", body);
  }

  /**
   * Logs in with the standalone passphrase, bypassing password and TOTP
   * (`POST /v1/flows/{id}/passphrase`). On success the session cookie is set.
   */
  async submitPassphrase(
    flowId: string,
    body: PassphraseLogin,
  ): Promise<FlowResult> {
    return this.submitFlow<FlowResult>(flowId, "passphrase", body);
  }

  /**
   * Unauthenticated password recovery authorized by the passphrase
   * (`POST /v1/flows/{id}/recover`). Sets a new password and logs the user in.
   */
  async recoverPassword(
    flowId: string,
    body: RecoverSubmit,
  ): Promise<FlowResult> {
    return this.submitFlow<FlowResult>(flowId, "recover", body);
  }

  /**
   * Registers a new identity within an active flow
   * (`POST /v1/flows/{id}/register`). The user is logged in immediately —
   * the session cookie is set and no separate password submission is needed.
   */
  async register(flowId: string, body: RegisterSubmit): Promise<FlowResult> {
    return this.submitFlow<FlowResult>(flowId, "register", body);
  }

  /**
   * Reads the logged-in user's factor status and policy compliance
   * (`GET /v1/factors`).
   */
  async getFactors(): Promise<FactorsResult> {
    const response = await this.fetch(`${this.baseUrl}/v1/factors`, {
      credentials: "include",
    });
    if (!response.ok) throw await errorFromResponse(response);
    return (await response.json()) as FactorsResult;
  }

  /**
   * Begins TOTP enrollment (`POST /v1/factors/totp/enroll`). Returns the
   * provisioning URI and secret; the enrollment is inactive until confirmed
   * with {@link confirmTotp}. `stepUp` is the passphrase if the user has one,
   * otherwise their current password.
   */
  async enrollTotp(stepUp: string): Promise<TotpEnrollment> {
    const response = await this.authed(
      "/v1/factors/totp/enroll",
      "POST",
      { step_up: stepUp },
    );
    return (await response.json()) as TotpEnrollment;
  }

  /**
   * Confirms a pending TOTP enrollment with a code
   * (`POST /v1/factors/totp/confirm`), activating it for login.
   */
  async confirmTotp(code: string): Promise<FactorsResult> {
    const response = await this.authed(
      "/v1/factors/totp/confirm",
      "POST",
      { code },
    );
    return (await response.json()) as FactorsResult;
  }

  /**
   * Removes TOTP (`DELETE /v1/factors/totp`). `stepUp` is the passphrase if
   * the user has one, otherwise their current password.
   */
  async removeTotp(stepUp: string): Promise<FactorsResult> {
    const response = await this.authed("/v1/factors/totp", "DELETE", {
      step_up: stepUp,
    });
    return (await response.json()) as FactorsResult;
  }

  /**
   * Begins passphrase enrollment (`POST /v1/factors/passphrase`). Returns the
   * generated passphrase so the user can record it. The passphrase is **not
   * active** until confirmed with {@link confirmPassphrase}. Calling again
   * before confirming rerolls (generates a new one). `stepUp` is the password
   * (no confirmed passphrase exists yet — remove it first to re-enroll).
   */
  async enrollPassphrase(stepUp: string): Promise<PassphraseResult> {
    const response = await this.authed("/v1/factors/passphrase", "POST", {
      step_up: stepUp,
    });
    return (await response.json()) as PassphraseResult;
  }

  /**
   * Confirms a pending passphrase enrollment
   * (`POST /v1/factors/passphrase/confirm`). The user echoes the passphrase
   * back to prove they recorded it; the server verifies against the pending
   * hash and marks it confirmed.
   */
  async confirmPassphrase(passphrase: string): Promise<FactorsResult> {
    const response = await this.authed(
      "/v1/factors/passphrase/confirm",
      "POST",
      { passphrase },
    );
    return (await response.json()) as FactorsResult;
  }

  /**
   * Removes the passphrase (`DELETE /v1/factors/passphrase`). `stepUp` is the
   * current passphrase.
   */
  async removePassphrase(stepUp: string): Promise<FactorsResult> {
    const response = await this.authed("/v1/factors/passphrase", "DELETE", {
      step_up: stepUp,
    });
    return (await response.json()) as FactorsResult;
  }

  /**
   * Changes the password for the logged-in user (`POST /v1/account/password`).
   * `stepUp` is the passphrase if the user has one, otherwise their current
   * password.
   */
  async changePassword(stepUp: string, newPassword: string): Promise<void> {
    await this.authed("/v1/account/password", "POST", {
      step_up: stepUp,
      new_password: newPassword,
    });
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

  private async submitFlow<T>(
    flowId: string,
    action: "password" | "totp" | "passphrase" | "recover" | "register",
    body:
      | PasswordSubmit
      | TotpSubmit
      | PassphraseLogin
      | RecoverSubmit
      | RegisterSubmit,
  ): Promise<T> {
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
    return (await response.json()) as T;
  }

  /**
   * Cookie-authenticated, CSRF-guarded JSON request for the factor-management
   * and account endpoints. Sends `X-Surge-CSRF: 1` (the header a cross-origin
   * form post can't set) alongside the session cookie.
   */
  private async authed(
    path: string,
    method: "POST" | "DELETE",
    body: unknown,
  ): Promise<Response> {
    const response = await this.fetch(`${this.baseUrl}${path}`, {
      method,
      headers: { "Content-Type": "application/json", "X-Surge-CSRF": "1" },
      credentials: "include",
      body: JSON.stringify(body),
    });
    if (!response.ok) throw await errorFromResponse(response);
    return response;
  }
}

function isJson(response: Response): boolean {
  return (response.headers.get("Content-Type") ?? "").includes("application/json");
}
