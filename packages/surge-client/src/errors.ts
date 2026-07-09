/**
 * Machine-readable error codes returned by the Surge API (docs/api/errors).
 * Stable across releases — branch on these, not on `message`.
 */
export type SurgeErrorCode =
  | "invalid_service_token"
  | "missing_service_token"
  | "invalid_credentials"
  | "session_expired"
  | "invalid_token"
  | "identity_disabled"
  | "forbidden"
  | "rate_limited"
  | "validation_error"
  | "not_found"
  | "username_taken"
  | "unavailable"
  | "timeout"
  // Client-side codes (never sent by the server):
  | "unexpected_response";

/** An error response from the Surge API, or a malformed/unexpected response. */
export class SurgeError extends Error {
  /** Machine-readable code — use this for branching logic. */
  readonly code: SurgeErrorCode;
  /** HTTP status of the response, or 0 when no response was decodable. */
  readonly status: number;
  /** Present only on `rate_limited` — seconds until the next request is allowed. */
  readonly retryAfter?: number;

  constructor(
    code: SurgeErrorCode,
    status: number,
    message?: string,
    retryAfter?: number,
  ) {
    super(message ?? code);
    this.name = "SurgeError";
    this.code = code;
    this.status = status;
    this.retryAfter = retryAfter;
  }

  /** `rate_limited`, `unavailable`, and `timeout` are safe to retry with backoff. */
  get isRetryable(): boolean {
    return (
      this.code === "rate_limited" ||
      this.code === "unavailable" ||
      this.code === "timeout"
    );
  }
}

/**
 * Builds a SurgeError from a non-2xx response, tolerating non-JSON bodies
 * (e.g. the plain-text 401 from a missing `X-Surge-CSRF` header).
 */
export async function errorFromResponse(response: Response): Promise<SurgeError> {
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    return new SurgeError(
      "unexpected_response",
      response.status,
      `Surge returned ${response.status} with a non-JSON body`,
    );
  }

  if (typeof body === "object" && body !== null && "error" in body) {
    const { error, message, retry_after } = body as {
      error: string;
      message?: string;
      retry_after?: number;
    };
    return new SurgeError(
      error as SurgeErrorCode,
      response.status,
      message,
      retry_after,
    );
  }

  return new SurgeError(
    "unexpected_response",
    response.status,
    `Surge returned ${response.status} with an unrecognized error body`,
  );
}
