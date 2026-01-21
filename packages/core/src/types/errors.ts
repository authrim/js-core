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
 * Error severity level (legacy - 3 levels)
 */
export type AuthrimErrorSeverity = 'fatal' | 'error' | 'warning';

/**
 * Error remediation action
 *
 * Specifies what action should be taken to recover from an error.
 * Separated from severity for clearer decision making.
 */
export type AuthrimErrorRemediation =
  | 'retry'              // Retry the same operation
  | 'reauthenticate'     // Re-authentication required
  | 'switch_flow'        // Switch to different flow (e.g., popup → redirect)
  | 'contact_support'    // Contact support
  | 'none';              // No action needed (informational)

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
  | 'missing_nonce'
  | 'missing_id_token'
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
  | 'invalid_callback'
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
  | 'event_handler_error'
  // PAR errors (RFC 9126)
  | 'par_required'
  | 'no_par_endpoint'
  | 'par_error'
  | 'par_request_uri_expired'
  // Device Flow errors (RFC 8628)
  | 'no_device_authorization_endpoint'
  | 'device_authorization_error'
  | 'device_authorization_pending'
  | 'device_slow_down'
  | 'device_authorization_expired'
  | 'device_access_denied'
  // Client Credentials errors
  | 'client_credentials_error'
  | 'invalid_client_authentication'
  | 'insecure_client_auth'
  // DPoP errors (RFC 9449)
  | 'dpop_key_generation_error'
  | 'dpop_proof_generation_error'
  | 'dpop_nonce_required'
  // JAR errors (RFC 9101)
  | 'jar_signing_error'
  | 'jar_required'
  // JARM errors
  | 'jarm_validation_error'
  | 'jarm_signature_invalid'
  // Operation errors
  | 'operation_cancelled'
  // returnTo errors
  | 'invalid_return_to';

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
  missing_nonce: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
    severity: 'error',
  },
  missing_id_token: {
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
    transient: false,
    retryable: false,
    retryAfterMs: 0,
    maxRetries: 0,
    userAction: 'reauthenticate',
    severity: 'error',
  },
  token_exchange_error: {
    transient: false,
    retryable: false,
    retryAfterMs: 0,
    maxRetries: 0,
    userAction: 'reauthenticate',
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
  invalid_callback: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
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

  // PAR errors (RFC 9126)
  par_required: {
    transient: false,
    retryable: false,
    userAction: 'none',
    severity: 'fatal',
  },
  no_par_endpoint: {
    transient: false,
    retryable: false,
    userAction: 'contact_support',
    severity: 'fatal',
  },
  par_error: {
    transient: true,
    retryable: true,
    retryAfterMs: 2000,
    maxRetries: 2,
    userAction: 'retry',
    severity: 'error',
  },
  par_request_uri_expired: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
    severity: 'warning',
  },

  // Device Flow errors (RFC 8628)
  no_device_authorization_endpoint: {
    transient: false,
    retryable: false,
    userAction: 'contact_support',
    severity: 'fatal',
  },
  device_authorization_error: {
    transient: true,
    retryable: true,
    retryAfterMs: 2000,
    maxRetries: 2,
    userAction: 'retry',
    severity: 'error',
  },
  device_authorization_pending: {
    transient: true,
    retryable: true,
    retryAfterMs: 5000,
    maxRetries: 60,
    userAction: 'none',
    severity: 'warning',
  },
  device_slow_down: {
    transient: true,
    retryable: true,
    retryAfterMs: 10000,
    maxRetries: 60,
    userAction: 'none',
    severity: 'warning',
  },
  device_authorization_expired: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
    severity: 'warning',
  },
  device_access_denied: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
    severity: 'error',
  },

  // Client Credentials errors
  client_credentials_error: {
    transient: true,
    retryable: true,
    retryAfterMs: 2000,
    maxRetries: 2,
    userAction: 'retry',
    severity: 'error',
  },
  invalid_client_authentication: {
    transient: false,
    retryable: false,
    userAction: 'contact_support',
    severity: 'fatal',
  },
  insecure_client_auth: {
    transient: false,
    retryable: false,
    userAction: 'none',
    severity: 'fatal',
  },

  // DPoP errors (RFC 9449)
  dpop_key_generation_error: {
    transient: true,
    retryable: true,
    retryAfterMs: 1000,
    maxRetries: 2,
    userAction: 'retry',
    severity: 'error',
  },
  dpop_proof_generation_error: {
    transient: false,
    retryable: false,
    userAction: 'none',
    severity: 'error',
  },
  dpop_nonce_required: {
    transient: true,
    retryable: true,
    retryAfterMs: 0,
    maxRetries: 1,
    userAction: 'none',
    severity: 'warning',
  },

  // JAR errors (RFC 9101)
  jar_signing_error: {
    transient: false,
    retryable: false,
    userAction: 'contact_support',
    severity: 'error',
  },
  jar_required: {
    transient: false,
    retryable: false,
    userAction: 'none',
    severity: 'fatal',
  },

  // JARM errors
  jarm_validation_error: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
    severity: 'error',
  },
  jarm_signature_invalid: {
    transient: false,
    retryable: false,
    userAction: 'reauthenticate',
    severity: 'error',
  },

  // Operation errors
  operation_cancelled: {
    transient: false,
    retryable: true,
    retryAfterMs: 0,
    maxRetries: 1,
    userAction: 'retry',
    severity: 'warning',
  },

  // returnTo errors
  invalid_return_to: {
    transient: false,
    retryable: false,
    userAction: 'none',
    severity: 'error',
  },
};

/**
 * Get error metadata for a given error code
 */
export function getErrorMeta(code: AuthrimErrorCode): AuthrimErrorMeta {
  return ERROR_META_MAP[code];
}

/**
 * Error classification result
 */
export interface ErrorClassification {
  /** Severity: recoverable or fatal */
  severity: 'recoverable' | 'fatal';
  /** Recommended remediation action */
  remediation: AuthrimErrorRemediation;
}

/**
 * Classify an error by severity and remediation
 *
 * This provides a simplified 2-axis classification for UI decision making:
 * - severity: Is this recoverable or fatal?
 * - remediation: What action should be taken?
 */
export function classifyError(error: AuthrimError): ErrorClassification {
  const meta = error.meta;

  // Fatal: not retryable AND user action is contact_support
  if (!meta.retryable && meta.userAction === 'contact_support') {
    return { severity: 'fatal', remediation: 'contact_support' };
  }

  // Fatal: severity is 'fatal' in meta
  if (meta.severity === 'fatal') {
    return { severity: 'fatal', remediation: mapUserActionToRemediation(meta.userAction) };
  }

  // Recoverable: determine remediation
  let remediation: AuthrimErrorRemediation = 'none';

  if (meta.retryable) {
    remediation = 'retry';
  } else if (meta.userAction === 'reauthenticate') {
    remediation = 'reauthenticate';
  } else if (error.code === 'popup_blocked') {
    remediation = 'switch_flow';
  } else if (meta.userAction === 'contact_support') {
    remediation = 'contact_support';
  }

  return { severity: 'recoverable', remediation };
}

/**
 * Map user action to remediation (internal helper)
 */
function mapUserActionToRemediation(userAction: AuthrimErrorUserAction): AuthrimErrorRemediation {
  switch (userAction) {
    case 'retry':
    case 'check_network':
      return 'retry';
    case 'reauthenticate':
      return 'reauthenticate';
    case 'contact_support':
      return 'contact_support';
    case 'none':
    default:
      return 'none';
  }
}

/**
 * Check if an error is retryable based on classification
 */
export function isRetryableError(error: AuthrimError): boolean {
  const classification = classifyError(error);
  return classification.severity === 'recoverable' && classification.remediation === 'retry';
}

/**
 * Event emitter interface for error emission
 *
 * Minimal interface required by emitClassifiedError
 */
export interface ErrorEventEmitter {
  emit(event: 'error', payload: {
    error: AuthrimError;
    severity: 'recoverable' | 'fatal';
    remediation: AuthrimErrorRemediation;
    context: string;
    timestamp: number;
    source: 'core' | 'web';
    operationId?: string;
  }): void;
  emit(event: 'error:recoverable', payload: {
    error: AuthrimError;
    severity: 'recoverable';
    remediation: AuthrimErrorRemediation;
    context: string;
    timestamp: number;
    source: 'core' | 'web';
    operationId?: string;
  }): void;
  emit(event: 'error:fatal', payload: {
    error: AuthrimError;
    severity: 'fatal';
    remediation: AuthrimErrorRemediation;
    context: string;
    timestamp: number;
    source: 'core' | 'web';
    operationId?: string;
  }): void;
}

/**
 * Options for emitting classified errors
 */
export interface EmitClassifiedErrorOptions {
  /** Operation context where the error occurred */
  context: string;
  /** Operation tracking ID */
  operationId?: string;
  /** Event source (defaults to 'core') */
  source?: 'core' | 'web';
}

/**
 * Emit error events with proper classification
 *
 * Emits three events:
 * 1. 'error' - Legacy event for backward compatibility
 * 2. 'error:recoverable' - If severity is recoverable
 * 3. 'error:fatal' - If severity is fatal
 *
 * @param emitter - Event emitter instance
 * @param error - The error to emit
 * @param options - Emission options (context, operationId, source)
 */
export function emitClassifiedError(
  emitter: ErrorEventEmitter,
  error: AuthrimError,
  options: EmitClassifiedErrorOptions
): void {
  const { severity, remediation } = classifyError(error);
  const timestamp = Date.now();
  const source = options.source ?? 'core';

  // Common payload
  const payload = {
    error,
    severity,
    remediation,
    context: options.context,
    timestamp,
    source,
    operationId: options.operationId,
  };

  // Legacy error event (backward compatibility)
  emitter.emit('error', payload);

  // Severity-specific events
  if (severity === 'recoverable') {
    emitter.emit('error:recoverable', { ...payload, severity: 'recoverable' as const });
  } else {
    emitter.emit('error:fatal', { ...payload, severity: 'fatal' as const });
  }
}
