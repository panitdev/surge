/**
 * Wire types for the Surge browser API (v1). Field names match the JSON
 * returned by the server exactly (snake_case) — see docs/api/browser.
 */

/** Registration mode configured on the deployment (`SURGE_REGISTRATION`). */
export type RegistrationMode = "open" | "invite" | "closed";

/** How the session was authenticated. Currently always `"password"`. */
export type AuthenticatedVia = "password";

/** Identity lifecycle state. */
export type IdentityState = "active" | "disabled";

export interface Identity {
  /** Identity UUID. */
  id: string;
  /** Always lowercase. */
  username: string;
  display_name: string;
  avatar_url: string | null;
  state: IdentityState;
  /** ISO 8601. */
  created_at: string;
  /** ISO 8601. */
  updated_at: string;
}

export interface Session {
  /** Session UUID. */
  id: string;
  identity: Identity;
  /** ISO 8601. */
  issued_at: string;
  /** ISO 8601. */
  expires_at: string;
  authenticated_via: AuthenticatedVia;
}

/** Response of `GET /v1/login` in inline (JSON) mode. */
export interface FlowInit {
  /** Flow ID, prefixed `aeg_f_`. */
  flow_id: string;
  /** One-time CSRF token scoped to this flow; submit it with every flow submission. */
  csrf_token: string;
  registration_mode: RegistrationMode;
}

/** Response of `GET /v1/flows/{id}`. */
export interface Flow {
  /** Flow ID, prefixed `aeg_f_`. */
  id: string;
  /** `"created"` while the flow is open for submissions. */
  state: string;
  csrf_token: string;
  /** Error code recorded by a previous failed submission, if any. */
  error: string | null;
  /** Whether the deployment allows self-service registration. */
  registration_enabled: boolean;
}

/** Response of a successful flow completion (password login or registration). */
export interface FlowResult {
  /**
   * The URL to navigate to after authentication (the flow's `return_to`).
   * `null` if the flow was started without a `return_to` (only possible in
   * inline mode — see {@link SurgeClient.initLoginFlow}).
   */
  return_to: string | null;
  session: Session;
}

/** Request body for `POST /v1/flows/{id}/password`. */
export interface PasswordSubmit {
  username: string;
  password: string;
  csrf_token: string;
}

/** Request body for `POST /v1/flows/{id}/register`. */
export interface RegisterSubmit {
  /** 3-32 chars, lowercase letters, digits, hyphens. Case-folded to lowercase. */
  username: string;
  /** 8-256 chars, not a common password. */
  password: string;
  /** May be an empty string for no display name. */
  display_name: string;
  csrf_token: string;
}
