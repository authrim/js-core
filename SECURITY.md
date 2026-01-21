# Security Design

This document describes the security design decisions and measures implemented in the Authrim SDK.

## Overview

The Authrim SDK implements OAuth 2.0 and OpenID Connect protocols with security best practices. This document covers the key security considerations and how they are addressed.

## Security Measures

### 1. PKCE (Proof Key for Code Exchange)

**Implementation:** `src/auth/pkce.ts`

- Uses S256 (SHA-256) method exclusively
- Code verifier: 32 bytes of cryptographically secure random data (256-bit entropy)
- Code challenge: Base64URL-encoded SHA-256 hash of the verifier

**Design Decision:** Code verifier is stored as a string in AuthState. While JavaScript cannot provide true memory protection like Rust or C, the following mitigations are in place:
- Code verifier is never exposed to external APIs
- AuthState is deleted immediately after use via `validateAndConsumeState()`
- TTL-based expiration ensures cleanup of abandoned states

### 2. State Parameter (CSRF Protection)

**Implementation:** `src/auth/state.ts`

- 32 bytes of cryptographically secure random data (256-bit entropy)
- Stored with timestamps (`createdAt`, `expiresAt`)
- Default TTL: 10 minutes
- State is **always** deleted after validation (success or failure)
- Replay attack prevention via one-time use pattern

**Validation:**
```typescript
// State is always consumed in a finally block
async validateAndConsumeState(state: string): Promise<AuthState> {
  try {
    // ... validation logic
  } finally {
    await this.storage.remove(key); // ALWAYS delete
  }
}
```

### 3. Nonce Validation (Replay Attack Prevention)

**Implementation:** `src/auth/authorization-code.ts`

- 32 bytes of cryptographically secure random data (256-bit entropy)
- Required in ID token when `openid` scope is requested
- Constant-time comparison using timing-safe equality check
- Missing nonce in ID token results in authentication failure

**OIDC Compliance:**
- If `openid` scope was requested, ID token MUST be present in response
- If ID token is present, nonce claim MUST match the one sent in authorization request

### 4. JWT Handling

**Implementation:** `src/utils/jwt.ts`

**Important:** This SDK does NOT verify JWT signatures. This is by design:

- The SDK is a **client-side (public client)** implementation
- Token validation MUST be performed by the Identity Provider (IdP)
- Client-side JWT signature verification provides false security (keys can be extracted)
- The SDK only decodes JWTs for reading claims after IdP validation

**Security Boundary:**
- ID tokens are validated by the IdP during token exchange
- Access tokens should be validated by resource servers, not clients
- The SDK validates: nonce, expiration (for local use), and required claims

### 5. Storage Security

**Implementation:** `src/providers/storage.ts`

The SDK supports multiple storage backends with different security characteristics:

| Storage Type | XSS Risk | Persistence | Use Case |
|-------------|----------|-------------|----------|
| Memory | Lowest | Tab only | SPA (recommended for security) |
| sessionStorage | Medium | Tab/reload | Default |
| localStorage | Highest | Permanent | Explicit opt-in only |

**Storage Key Hashing:**
- Issuer and client ID are hashed before use in storage keys
- Prevents information leakage in storage key names
- Uses SHA-256 truncated to 16 characters

### 6. Token Security

- Refresh tokens are stored securely in the selected storage backend
- Token refresh uses request coalescing to prevent race conditions
- Expired tokens are not returned from `getAccessToken()`

## Security Parameters Protection

The SDK protects critical OAuth parameters from being overwritten via `extraParams`:

Protected parameters that cannot be overridden:
- `client_id`
- `response_type`
- `redirect_uri`
- `state`
- `nonce`
- `code_challenge`
- `code_challenge_method`
- `scope`

## Error Handling

Security-sensitive information is not included in error messages:
- Nonce values are not logged or included in error details
- Token values are not included in error messages
- Storage keys use hashes, not raw values

## Recommendations for Implementers

1. **Always use HTTPS** for all endpoints
2. **Validate redirect URIs** on the server side with strict matching
3. **Use short token lifetimes** and refresh tokens for long sessions
4. **Implement proper CORS** on your IdP endpoints
5. **Consider using `memory` storage** for high-security applications
6. **Never store tokens in URLs** or pass them via query parameters

## Reporting Security Issues

If you discover a security vulnerability, please report it via GitHub Security Advisories at:
https://github.com/sgrastar/authrim/security/advisories

Please do not report security vulnerabilities through public GitHub issues.
