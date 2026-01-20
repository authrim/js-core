/**
 * Authrim SDK Error Types
 */

/**
 * User action recommended for error recovery
 */
export type AuthrimErrorUserAction =
  | 'retry'
  | 'reauthenticate'
  | 'contact_support'
  | 'check_network'
  | 'none';

/**
 * Error severity level
 */
export type AuthrimErrorSeverity = 'fatal' | 'error' | 'warning';

/**
 * Error metadata for recovery information
 */
export interface AuthrimErrorMeta {
  /** Whether this is a transient error */
  transient: boolean;
  /** Whether automatic retry is possible */
  retryable: boolean;
  /** Suggested retry wait time in milliseconds */
  retryAfterMs?: number;
  /** Maximum number of retry attempts */
  maxRetries?: number;
  /** Recommended user action */
  userAction: AuthrimErrorUserAction;
  /** Error severity level */
  severity: AuthrimErrorSeverity;
}

/**
 * Error codes used by the SDK
 */
export type AuthrimErrorCode =
  // OAuth 2.0 / OIDC standard errors
  | 'invalid_request'
  | 'unauthorized_client'
  | 'access_denied'
  | 'unsupported_response_type'
  | 'invalid_scope'
  | 'server_error'
  | 'temporarily_unavailable'
  | 'invalid_grant'
  | 'invalid_token'
  // SDK-specific errors
  | 'invalid_state'
  | 'expired_state'
  | 'invalid_nonce'
  | 'nonce_mismatch'
  | 'session_expired'
  | 'session_check_failed'
  | 'network_error'
  | 'timeout_error'
  | 'discovery_error'
  | 'discovery_mismatch'
  | 'configuration_error'
  | 'storage_error'
  | 'flow_engine_error'
  // Token errors
  | 'no_tokens'
  | 'token_expired'
  | 'token_error'
  | 'refresh_error'
  | 'token_exchange_error'
  // Callback errors
  | 'oauth_error'
  | 'missing_code'
  | 'missing_state'
  // Initialization errors
  | 'not_initialized'
  | 'no_discovery'
  // Session errors
  | 'no_userinfo_endpoint'
  | 'userinfo_error'
  // Token introspection/revocation errors
  | 'introspection_error'
  | 'revocation_error'
  | 'no_introspection_endpoint'
  | 'no_revocation_endpoint'
  // Silent auth errors (OIDC prompt=none)
  | 'login_required'
  | 'interaction_required'
  | 'consent_required'
  | 'account_selection_required'
  // Browser/Popup auth errors (@authrim/web)
  | 'dom_not_ready'
  | 'state_mismatch'
  | 'popup_blocked'
  | 'popup_closed'
  | 'invalid_response'
  // Direct Auth errors
  | 'passkey_not_found'
  | 'passkey_verification_failed'
  | 'passkey_not_supported'
  | 'passkey_cancelled'
  | 'passkey_invalid_credential'
  | 'email_code_invalid'
  | 'email_code_expired'
  | 'email_code_too_many_attempts'
  | 'challenge_expired'
  | 'challenge_invalid'
  | 'auth_code_invalid'
  | 'auth_code_expired'
  | 'pkce_mismatch'
  | 'origin_not_allowed'
  | 'mfa_required'
  | 'email_verification_required'
  | 'consent_required_direct'
  | 'rate_limited'
  // Event errors
  | 'event_handler_error';

/**
 * Options for creating an AuthrimError
 */
export interface AuthrimErrorOptions {
  details?: Record<string, unknown>;
  errorUri?: string;
  cause?: Error;
}

/**
 * Authrim SDK Error class
 */
export class AuthrimError extends Error {
  /** Error code for programmatic handling */
  readonly code: AuthrimErrorCode;

  /** Additional error details */
  readonly details?: Record<string, unknown>;

  /** OAuth error_uri if provided */
  readonly errorUri?: string;

  /** Underlying cause */
  readonly cause?: Error;

  constructor(code: AuthrimErrorCode, message: string, options?: AuthrimErrorOptions) {
    super(message);
    this.name = 'AuthrimError';
    this.code = code;
    this.details = options?.details;
    this.errorUri = options?.errorUri;
    this.cause = options?.cause;
  }

  /**
   * Create an AuthrimError from an OAuth error response
   */
  static fromOAuthError(error: {
    error: string;
    error_description?: string;
    error_uri?: string;
  }): AuthrimError {
    const oauthCodes = [
      'invalid_request',
      'unauthorized_client',
      'access_denied',
      'unsupported_response_type',
      'invalid_scope',
      'server_error',
      'temporarily_unavailable',
      'invalid_grant',
      'invalid_token',
    ] as const;

    type OAuthErrorCode = (typeof oauthCodes)[number];

    const code: AuthrimErrorCode = oauthCodes.includes(error.error as OAuthErrorCode)
      ? (error.error as OAuthErrorCode)
      : 'invalid_request';

    return new AuthrimError(code, error.error_description ?? error.error, {
      errorUri: error.error_uri,
      details: { originalError: error.error },
    });
  }

  /**
   * Check if an error is retryable (e.g., network errors)
   */
  isRetryable(): boolean {
    return this.code === 'network_error' || this.code === 'timeout_error';
  }

  /**
   * Get error metadata for recovery guidance
   */
  get meta(): AuthrimErrorMeta {
    return getErrorMeta(this.code);
  }
}

/**
 * Error metadata mapping for each error code
 */
const ERROR_META_MAP: Record<AuthrimErrorCode, AuthrimErrorMeta> = {
  // OAuth 2.0 / OIDC standard errors
  invalid_request: {
    transient: false,
    retryable: false,
    userAction: 'contact_support',
    severity: 'error',
  },
  unauthorized_client: {
    transient: false,
    retryable: false,
    userAction: 'contact_support',
    severity: 'fatal',
  },
  access_denied: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
    severity: 'error',
  },
  unsupported_response_type: {
    transient: false,
    retryable: false,
    userAction: 'contact_support',
    severity: 'fatal',
  },
  invalid_scope: {
    transient: false,
    retryable: false,
    userAction: 'contact_support',
    severity: 'error',
  },
  server_error: {
    transient: true,
    retryable: true,
    retryAfterMs: 5000,
    maxRetries: 3,
    userAction: 'retry',
    severity: 'error',
  },
  temporarily_unavailable: {
    transient: true,
    retryable: true,
    retryAfterMs: 10000,
    maxRetries: 3,
    userAction: 'retry',
    severity: 'warning',
  },
  invalid_grant: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
    severity: 'error',
  },
  invalid_token: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
    severity: 'error',
  },

  // SDK-specific errors
  invalid_state: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
    severity: 'error',
  },
  expired_state: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
    severity: 'warning',
  },
  invalid_nonce: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
    severity: 'error',
  },
  nonce_mismatch: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
    severity: 'error',
  },
  session_expired: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
    severity: 'warning',
  },
  session_check_failed: {
    transient: true,
    retryable: true,
    retryAfterMs: 3000,
    maxRetries: 2,
    userAction: 'retry',
    severity: 'warning',
  },
  network_error: {
    transient: true,
    retryable: true,
    retryAfterMs: 2000,
    maxRetries: 3,
    userAction: 'check_network',
    severity: 'error',
  },
  timeout_error: {
    transient: true,
    retryable: true,
    retryAfterMs: 3000,
    maxRetries: 3,
    userAction: 'retry',
    severity: 'warning',
  },
  discovery_error: {
    transient: true,
    retryable: true,
    retryAfterMs: 5000,
    maxRetries: 2,
    userAction: 'retry',
    severity: 'error',
  },
  discovery_mismatch: {
    transient: false,
    retryable: false,
    userAction: 'contact_support',
    severity: 'fatal',
  },
  configuration_error: {
    transient: false,
    retryable: false,
    userAction: 'contact_support',
    severity: 'fatal',
  },
  storage_error: {
    transient: true,
    retryable: true,
    retryAfterMs: 1000,
    maxRetries: 2,
    userAction: 'retry',
    severity: 'error',
  },
  flow_engine_error: {
    transient: false,
    retryable: false,
    userAction: 'contact_support',
    severity: 'error',
  },

  // Token errors
  no_tokens: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
    severity: 'warning',
  },
  token_expired: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
    severity: 'warning',
  },
  token_error: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
    severity: 'error',
  },
  refresh_error: {
    transient: true,
    retryable: true,
    retryAfterMs: 2000,
    maxRetries: 2,
    userAction: 'retry',
    severity: 'error',
  },
  token_exchange_error: {
    transient: true,
    retryable: true,
    retryAfterMs: 2000,
    maxRetries: 2,
    userAction: 'retry',
    severity: 'error',
  },

  // Callback errors
  oauth_error: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
    severity: 'error',
  },
  missing_code: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
    severity: 'error',
  },
  missing_state: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
    severity: 'error',
  },

  // Initialization errors
  not_initialized: {
    transient: false,
    retryable: false,
    userAction: 'none',
    severity: 'fatal',
  },
  no_discovery: {
    transient: true,
    retryable: true,
    retryAfterMs: 3000,
    maxRetries: 2,
    userAction: 'retry',
    severity: 'error',
  },

  // Session errors
  no_userinfo_endpoint: {
    transient: false,
    retryable: false,
    userAction: 'none',
    severity: 'warning',
  },
  userinfo_error: {
    transient: true,
    retryable: true,
    retryAfterMs: 2000,
    maxRetries: 2,
    userAction: 'retry',
    severity: 'error',
  },

  // Token introspection/revocation errors
  introspection_error: {
    transient: true,
    retryable: true,
    retryAfterMs: 2000,
    maxRetries: 2,
    userAction: 'retry',
    severity: 'error',
  },
  revocation_error: {
    transient: true,
    retryable: true,
    retryAfterMs: 2000,
    maxRetries: 2,
    userAction: 'retry',
    severity: 'error',
  },
  no_introspection_endpoint: {
    transient: false,
    retryable: false,
    userAction: 'none',
    severity: 'warning',
  },
  no_revocation_endpoint: {
    transient: false,
    retryable: false,
    userAction: 'none',
    severity: 'warning',
  },

  // Silent auth errors
  login_required: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
    severity: 'warning',
  },
  interaction_required: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
    severity: 'warning',
  },
  consent_required: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
    severity: 'warning',
  },
  account_selection_required: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
    severity: 'warning',
  },

  // Browser/Popup auth errors (@authrim/web)
  dom_not_ready: {
    transient: true,
    retryable: true,
    retryAfterMs: 100,
    maxRetries: 3,
    userAction: 'retry',
    severity: 'error',
  },
  state_mismatch: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
    severity: 'error',
  },
  popup_blocked: {
    transient: false,
    retryable: false,
    userAction: 'none',
    severity: 'warning',
  },
  popup_closed: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
    severity: 'warning',
  },
  invalid_response: {
    transient: false,
    retryable: false,
    userAction: 'contact_support',
    severity: 'error',
  },

  // Direct Auth errors
  passkey_not_found: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
    severity: 'warning',
  },
  passkey_verification_failed: {
    transient: false,
    retryable: true,
    retryAfterMs: 1000,
    maxRetries: 3,
    userAction: 'retry',
    severity: 'error',
  },
  passkey_not_supported: {
    transient: false,
    retryable: false,
    userAction: 'none',
    severity: 'warning',
  },
  passkey_cancelled: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
    severity: 'warning',
  },
  passkey_invalid_credential: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
    severity: 'error',
  },
  email_code_invalid: {
    transient: false,
    retryable: true,
    retryAfterMs: 0,
    maxRetries: 5,
    userAction: 'retry',
    severity: 'warning',
  },
  email_code_expired: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
    severity: 'warning',
  },
  email_code_too_many_attempts: {
    transient: false,
    retryable: false,
    retryAfterMs: 300000,
    userAction: 'retry',
    severity: 'error',
  },
  challenge_expired: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
    severity: 'warning',
  },
  challenge_invalid: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
    severity: 'error',
  },
  auth_code_invalid: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
    severity: 'error',
  },
  auth_code_expired: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
    severity: 'warning',
  },
  pkce_mismatch: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
    severity: 'error',
  },
  origin_not_allowed: {
    transient: false,
    retryable: false,
    userAction: 'contact_support',
    severity: 'fatal',
  },
  mfa_required: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
    severity: 'warning',
  },
  email_verification_required: {
    transient: false,
    retryable: false,
    userAction: 'none',
    severity: 'warning',
  },
  consent_required_direct: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
    severity: 'warning',
  },
  rate_limited: {
    transient: true,
    retryable: true,
    retryAfterMs: 60000,
    maxRetries: 3,
    userAction: 'retry',
    severity: 'warning',
  },

  // Event errors
  event_handler_error: {
    transient: false,
    retryable: false,
    userAction: 'none',
    severity: 'warning',
  },
};

/**
 * Get error metadata for a given error code
 */
export function getErrorMeta(code: AuthrimErrorCode): AuthrimErrorMeta {
  return ERROR_META_MAP[code];
}
