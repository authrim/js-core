/**
 * HTTP Client Provider Interface
 *
 * Platform-agnostic HTTP client abstraction.
 * Implementations must be injected - @authrim/core does not use fetch directly.
 */

/**
 * HTTP request options
 */
export interface HttpOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  headers?: Record<string, string>;
  body?: string | FormData | URLSearchParams;
  /** Request timeout in milliseconds */
  timeout?: number;
  /** Signal for request cancellation */
  signal?: AbortSignal;
}

/**
 * HTTP response wrapper
 */
export interface HttpResponse<T = unknown> {
  /** HTTP status code */
  status: number;
  /** HTTP status text */
  statusText: string;
  /** Response headers */
  headers: Record<string, string>;
  /** Parsed response body */
  data: T;
  /** Whether the response was successful (2xx) */
  ok: boolean;
}

/**
 * HTTP Client interface
 *
 * Implementations should:
 * - Handle JSON parsing automatically when Content-Type is application/json
 * - Handle form data submissions
 * - Implement timeout handling
 * - Propagate network errors appropriately
 */
export interface HttpClient {
  /**
   * Make an HTTP request
   *
   * @param url - Full URL to request
   * @param options - Request options
   * @returns Promise resolving to the response
   * @throws Error on network failure or timeout
   */
  fetch<T = unknown>(url: string, options?: HttpOptions): Promise<HttpResponse<T>>;
}

/**
 * HTTP error response body (OAuth 2.0 / OIDC standard)
 */
export interface OAuthErrorResponse {
  error: string;
  error_description?: string;
  error_uri?: string;
}
