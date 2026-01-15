/**
 * Authrim SDK Error Types
 */

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
  | 'userinfo_error';

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
}
