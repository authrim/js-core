/**
 * Device Authorization Flow
 * RFC 8628: OAuth 2.0 Device Authorization Grant
 *
 * Used for devices with limited input capabilities where the user
 * authenticates on a separate device (phone, computer).
 *
 * Flow:
 * 1. Client requests device code from authorization server
 * 2. User goes to verification URI and enters user code
 * 3. Client polls token endpoint until user completes auth
 *
 * NOTE: This core SDK returns "facts" only - UX events like
 * 'device:started' or 'device:pending' are the responsibility
 * of upper-layer SDKs (web/react/svelte).
 */

import type { HttpClient } from '../providers/http.js';
import type { OIDCDiscoveryDocument } from '../types/oidc.js';
import type { TokenSet, TokenResponse } from '../types/token.js';
import type {
  DeviceAuthorizationResponse,
  DeviceFlowState,
  DeviceFlowPollResult,
  DeviceFlowStartOptions,
} from '../types/device-flow.js';
import { AuthrimError } from '../types/errors.js';

/** Default polling interval in seconds (RFC 8628 §3.2) */
const DEFAULT_INTERVAL = 5;

/**
 * Device Flow Client
 *
 * Handles the OAuth 2.0 Device Authorization Grant (RFC 8628).
 */
export class DeviceFlowClient {
  constructor(
    private readonly http: HttpClient,
    private readonly clientId: string
  ) {}

  /**
   * Start device authorization
   *
   * Requests a device code and user code from the authorization server.
   *
   * @param discovery - OIDC discovery document
   * @param options - Start options (scope, etc.)
   * @returns Device flow state with codes and URIs
   * @throws AuthrimError with code 'no_device_authorization_endpoint' if endpoint not available
   * @throws AuthrimError with code 'device_authorization_error' if request fails
   */
  async startDeviceAuthorization(
    discovery: OIDCDiscoveryDocument,
    options?: DeviceFlowStartOptions
  ): Promise<DeviceFlowState> {
    const endpoint = discovery.device_authorization_endpoint;

    if (!endpoint) {
      throw new AuthrimError(
        'no_device_authorization_endpoint',
        'Device authorization endpoint not available in discovery document'
      );
    }

    // Build request body
    const body = new URLSearchParams({
      client_id: this.clientId,
    });

    if (options?.scope) {
      body.set('scope', options.scope);
    }

    // Add extra parameters
    if (options?.extraParams) {
      const protectedParams = new Set(['client_id', 'scope']);

      for (const [key, value] of Object.entries(options.extraParams)) {
        if (protectedParams.has(key.toLowerCase())) {
          continue;
        }
        body.set(key, value);
      }
    }

    // Make request
    let response;
    try {
      response = await this.http.fetch<DeviceAuthorizationResponse>(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: body.toString(),
      });
    } catch (error) {
      throw new AuthrimError('network_error', 'Device authorization request failed', {
        cause: error instanceof Error ? error : undefined,
      });
    }

    if (!response.ok) {
      const errorData = response.data as unknown as Record<string, unknown>;
      throw new AuthrimError('device_authorization_error', 'Device authorization request failed', {
        details: {
          status: response.status,
          error: errorData?.error,
          error_description: errorData?.error_description,
        },
      });
    }

    const data = response.data;

    // Validate required fields
    if (!data.device_code || !data.user_code || !data.verification_uri) {
      throw new AuthrimError(
        'device_authorization_error',
        'Invalid device authorization response: missing required fields'
      );
    }

    // Calculate expiration
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + data.expires_in;

    return {
      deviceCode: data.device_code,
      userCode: data.user_code,
      verificationUri: data.verification_uri,
      verificationUriComplete: data.verification_uri_complete,
      expiresAt,
      interval: data.interval ?? DEFAULT_INTERVAL,
    };
  }

  /**
   * Poll the token endpoint once
   *
   * Returns the current state of the authorization:
   * - 'pending': User hasn't completed auth yet
   * - 'completed': Auth complete, tokens received
   * - 'slow_down': Polling too fast, increase interval
   * - 'expired': Device code expired
   * - 'access_denied': User denied the request
   *
   * @param discovery - OIDC discovery document
   * @param state - Device flow state from startDeviceAuthorization
   * @returns Poll result
   */
  async pollOnce(
    discovery: OIDCDiscoveryDocument,
    state: DeviceFlowState
  ): Promise<DeviceFlowPollResult> {
    // Check if expired
    const now = Math.floor(Date.now() / 1000);
    if (now >= state.expiresAt) {
      return { status: 'expired' };
    }

    const tokenEndpoint = discovery.token_endpoint;

    // Build request body
    const body = new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
      device_code: state.deviceCode,
      client_id: this.clientId,
    });

    // Make token request
    let response;
    try {
      response = await this.http.fetch<TokenResponse | { error: string; error_description?: string }>(
        tokenEndpoint,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: body.toString(),
        }
      );
    } catch (error) {
      throw new AuthrimError('network_error', 'Device flow token request failed', {
        cause: error instanceof Error ? error : undefined,
      });
    }

    // Handle error responses (RFC 8628 §3.5)
    if (!response.ok) {
      const errorData = response.data as { error: string; error_description?: string };
      const errorCode = errorData?.error;

      switch (errorCode) {
        case 'authorization_pending':
          // User hasn't completed the authorization yet
          return {
            status: 'pending',
            retryAfter: state.interval,
          };

        case 'slow_down':
          // Polling too frequently - increase interval by 5 seconds (RFC 8628 §3.5)
          return {
            status: 'slow_down',
            retryAfter: state.interval + 5,
          };

        case 'expired_token':
          // Device code has expired
          return { status: 'expired' };

        case 'access_denied':
          // User denied the authorization request
          return { status: 'access_denied' };

        default:
          // Unknown error
          throw new AuthrimError('device_authorization_error', 'Device flow token request failed', {
            details: {
              status: response.status,
              error: errorCode,
              error_description: errorData?.error_description,
            },
          });
      }
    }

    // Success - tokens received
    const tokenResponse = response.data as TokenResponse;

    // Calculate expiresAt (epoch seconds)
    const expiresAt = tokenResponse.expires_in ? now + tokenResponse.expires_in : now + 3600;

    const tokens: TokenSet = {
      accessToken: tokenResponse.access_token,
      tokenType: (tokenResponse.token_type as 'Bearer') ?? 'Bearer',
      expiresAt,
      refreshToken: tokenResponse.refresh_token,
      idToken: tokenResponse.id_token,
      scope: tokenResponse.scope,
    };

    return {
      status: 'completed',
      tokens,
    };
  }

  /**
   * Poll until authorization is complete or expires
   *
   * Automatically handles polling interval and retries.
   *
   * @param discovery - OIDC discovery document
   * @param state - Device flow state from startDeviceAuthorization
   * @param options - Polling options
   * @returns Token set on success
   * @throws AuthrimError with code 'device_authorization_expired' if device code expires
   * @throws AuthrimError with code 'device_access_denied' if user denies authorization
   */
  async pollUntilComplete(
    discovery: OIDCDiscoveryDocument,
    state: DeviceFlowState,
    options?: { signal?: AbortSignal }
  ): Promise<TokenSet> {
    let currentInterval = state.interval;

    // eslint-disable-next-line no-constant-condition
    while (true) {
      // Check for abort
      if (options?.signal?.aborted) {
        throw new AuthrimError('device_authorization_error', 'Device flow polling aborted');
      }

      const result = await this.pollOnce(discovery, state);

      switch (result.status) {
        case 'completed':
          return result.tokens;

        case 'pending':
          // Wait and continue polling
          await this.sleep(result.retryAfter * 1000, options?.signal);
          continue;

        case 'slow_down':
          // Increase interval and continue polling
          currentInterval = result.retryAfter;
          // Update state for future polls
          state.interval = currentInterval;
          await this.sleep(currentInterval * 1000, options?.signal);
          continue;

        case 'expired':
          throw new AuthrimError(
            'device_authorization_expired',
            'Device authorization has expired. Please start a new authorization.'
          );

        case 'access_denied':
          throw new AuthrimError(
            'device_access_denied',
            'User denied the device authorization request'
          );
      }
    }
  }

  /**
   * Sleep for a given number of milliseconds
   * @param ms - Milliseconds to sleep
   * @param signal - Optional abort signal
   */
  private sleep(ms: number, signal?: AbortSignal): Promise<void> {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(resolve, ms);

      if (signal) {
        signal.addEventListener(
          'abort',
          () => {
            clearTimeout(timeout);
            reject(new AuthrimError('device_authorization_error', 'Device flow polling aborted'));
          },
          { once: true }
        );
      }
    });
  }
}
