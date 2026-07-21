/**
 * Wire types for the Surge browser API (v1). Field names match the JSON
 * returned by the server exactly (snake_case) — see docs/api/browser.
 */

/** Registration mode configured on the deployment (`SURGE_REGISTRATION`). */
export type RegistrationMode = "open" | "invite" | "closed";

/**
 * How the session was authenticated. Always `"password"` on the wire — factor
 * specifics (TOTP, passphrase, recovery) are recorded in the server audit log,
 * not the session, to keep the introspection contract append-only.
 */
export type AuthenticatedVia = "password";

/** Server-wide soft factor-enrollment policy (`SURGE_FACTOR_POLICY`). */
export type FactorPolicyName = "none" | "totp" | "passphrase" | "both";

/**
 * Soft factor-enrollment compliance, surfaced on login/register/whoami. Never
 * blocks — the frontend uses it to prompt the user to enroll missing factors.
 */
export interface PolicyBlock {
  /** Which factors the policy expects the user to have. */
  required: { totp: boolean; passphrase: boolean };
  /** Which factors the user has actually enrolled (TOTP counts once confirmed). */
  has: { totp: boolean; passphrase: boolean };
  /** True when every required factor is enrolled. */
  compliant: boolean;
}

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
  /** Present on `GET /v1/whoami`: soft factor-enrollment compliance. */
  policy?: PolicyBlock;
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
  /** Soft factor-enrollment compliance for the just-authenticated user. */
  policy: PolicyBlock;
}

/**
 * Returned by `POST /v1/flows/{id}/password` when the user has a confirmed
 * TOTP: no session is issued yet: complete the flow with
 * {@link SurgeClient.submitTotp}.
 */
export interface TotpRequired {
  status: "totp_required";
  return_to: string | null;
}

/** Union result of a password submission: either logged in, or TOTP is needed. */
export type PasswordSubmitResult = FlowResult | TotpRequired;

/** One-time TOTP enrollment material from `POST /v1/factors/totp/enroll`. */
export interface TotpEnrollment {
  /** `otpauth://` URI to render as a QR code. */
  otpauth_uri: string;
  /** Base32 secret for manual entry. */
  secret: string;
}

/** Returned once from `POST /v1/factors/passphrase` — never recoverable after. */
export interface PassphraseResult {
  /** The generated 6-word Diceware passphrase. */
  passphrase: string;
}

/** Current factor status for the logged-in user (`GET /v1/factors`). */
export interface FactorsResult {
  policy: PolicyBlock;
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

/** Request body for `POST /v1/flows/{id}/totp` (the mandatory second step). */
export interface TotpSubmit {
  /** 6-digit code from the authenticator app. */
  code: string;
  csrf_token: string;
}

/**
 * Request body for `POST /v1/flows/{id}/passphrase` — standalone passphrase
 * login that bypasses password and TOTP.
 */
export interface PassphraseLogin {
  username: string;
  passphrase: string;
  csrf_token: string;
}

/**
 * Request body for `POST /v1/flows/{id}/recover` — unauthenticated password
 * reset authorized by the passphrase.
 */
export interface RecoverSubmit {
  username: string;
  passphrase: string;
  /** 8-256 chars, not a common password. */
  new_password: string;
  csrf_token: string;
}
