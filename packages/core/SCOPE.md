# @authrim/core - Scope and Implementation Status

This document describes what @authrim/core implements, what it intentionally does not implement, and the boundaries between this core package and platform-specific packages.

## Overview

@authrim/core is the **platform-agnostic** core library of the official [Authrim](https://github.com/sgrastar/authrim) JavaScript SDK. It provides the foundational OAuth 2.0 / OpenID Connect building blocks for authentication with Authrim Identity Provider.

This package is designed to be used by platform-specific packages (e.g., @authrim/web, @authrim/node, @authrim/react-native) that handle environment-specific concerns.

---

## What is Implemented

### Core Authentication Flow

| Feature | Status | Description |
|---------|--------|-------------|
| Authorization Code Flow with PKCE | ✅ Implemented | RFC 7636 compliant PKCE implementation |
| State Management | ✅ Implemented | Secure state/nonce generation and validation |
| Token Storage | ✅ Implemented | Abstracted storage with pluggable providers |
| Token Refresh | ✅ Implemented | Automatic refresh with request coalescing |
| Token Exchange (RFC 8693) | ✅ Implemented | Cross-service token acquisition, delegation |

### Token Operations

| Feature | Status | Description |
|---------|--------|-------------|
| Token Introspection (RFC 7662) | ✅ Implemented | Server-side token validation |
| Token Revocation (RFC 7009) | ✅ Implemented | Explicit token invalidation |
| ID Token Decoding | ✅ Implemented | JWT parsing (without cryptographic verification) |
| Token Expiry Tracking | ✅ Implemented | Expiration calculation with configurable skew |

### Session Management

| Feature | Status | Description |
|---------|--------|-------------|
| RP-Initiated Logout | ✅ Implemented | OIDC RP-Initiated Logout 1.0 |
| Local Token Cleanup | ✅ Implemented | Secure token removal from storage |
| Logout with Token Revocation | ✅ Implemented | Optional revocation before logout |
| Session Check (UserInfo) | ✅ Implemented | Session validation via userinfo endpoint |

### Silent Authentication (Foundation)

| Feature | Status | Description |
|---------|--------|-------------|
| Silent Auth URL Building | ✅ Implemented | prompt=none authorization URL |
| Silent Auth Response Parsing | ✅ Implemented | Error handling (login_required, etc.) |
| Iframe Implementation | ❌ Out of Scope | Platform-specific (see @authrim/web) |

### Discovery

| Feature | Status | Description |
|---------|--------|-------------|
| OIDC Discovery | ✅ Implemented | /.well-known/openid-configuration |
| Discovery Caching | ✅ Implemented | Configurable TTL-based caching |
| Issuer Validation | ✅ Implemented | Issuer URL normalization and matching |

### Error Handling

| Feature | Status | Description |
|---------|--------|-------------|
| Typed Error Codes | ✅ Implemented | 38 specific error codes |
| Error Metadata | ✅ Implemented | Recovery guidance (retryable, userAction, severity) |
| OAuth Error Mapping | ✅ Implemented | Standard OAuth error translation |

### Events

| Feature | Status | Description |
|---------|--------|-------------|
| Token Events | ✅ Implemented | token:refreshed, token:expired, token:error, token:exchanged |
| Session Events | ✅ Implemented | session:started, session:ended |
| Auth Events | ✅ Implemented | auth:redirecting, auth:callback |

---

## What is NOT Implemented (Out of Scope)

### Platform-Specific Features

These features require platform-specific implementations and belong in @authrim/web, @authrim/node, or similar packages:

| Feature | Reason | Where to Implement |
|---------|--------|-------------------|
| HTTP Client | Platform-specific fetch/XMLHttpRequest | @authrim/web, @authrim/node |
| Crypto Provider | Platform-specific Web Crypto/Node crypto | @authrim/web, @authrim/node |
| Storage Provider | Platform-specific localStorage/AsyncStorage | @authrim/web, @authrim/react-native |
| Silent Auth Iframe | Browser-only feature | @authrim/web |
| Popup Authentication | Browser-only feature | @authrim/web |
| Redirect Handling | Browser/framework-specific | @authrim/web, @authrim/react |
| Cookie Management | Browser-only feature | @authrim/web |
| Session Storage | Browser-only feature | @authrim/web |

### Security Features (Intentionally Excluded)

| Feature | Reason |
|---------|--------|
| ID Token Signature Verification | Requires JWKS fetching and crypto operations; recommended for server-side validation |
| Access Token Validation | Should be done server-side with introspection or JWT validation |
| Client Secret Handling | Public clients should not have secrets; confidential clients are server-side |
| mTLS / DPoP | Advanced security features for server-side implementations |

### OAuth 2.0 Grant Types (Not Implemented)

| Grant Type | Reason |
|------------|--------|
| Client Credentials | Server-side only grant |
| Resource Owner Password | Deprecated/discouraged grant |
| Device Authorization | Specialized flow for devices without browsers |
| JWT Bearer Assertion | Enterprise server-side flow |

### Advanced OIDC Features

| Feature | Status | Notes |
|---------|--------|-------|
| Backchannel Logout | ❌ Not Implemented | Requires server endpoint |
| Front-channel Logout | ❌ Not Implemented | Would need iframe support |
| Session Management (check_session_iframe) | ❌ Not Implemented | Browser-specific |
| OIDC Dynamic Client Registration | ❌ Not Implemented | Usually done at deployment time |
| Request Objects (JAR) | ❌ Not Implemented | Advanced enterprise feature |
| Userinfo Encryption | ❌ Not Implemented | Rarely used |

---

## Provider Interfaces (Must Be Implemented)

@authrim/core defines these interfaces that platform packages must implement:

### HttpClient

```typescript
interface HttpClient {
  fetch<T>(url: string, options?: HttpOptions): Promise<HttpResponse<T>>;
}
```

### CryptoProvider

```typescript
interface CryptoProvider {
  randomBytes(length: number): Uint8Array;
  sha256(data: string | Uint8Array): Promise<Uint8Array>;
}
```

### AuthrimStorage

```typescript
interface AuthrimStorage {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  remove(key: string): Promise<void>;
  getAll(): Promise<Record<string, string>>;
  clear(): Promise<void>;
}
```

---

## API Surface

### Main Entry Points

```typescript
// Client creation
createAuthrimClient(config: AuthrimClientConfig): Promise<AuthrimClient>

// Client methods
client.buildAuthorizationUrl(options)  // Start auth flow
client.handleCallback(callbackUrl)     // Complete auth flow
client.token.getAccessToken()          // Get/refresh token
client.token.introspect(options)       // Validate token (RFC 7662)
client.token.revoke(options)           // Revoke token (RFC 7009)
client.token.exchange(request)         // Exchange token (RFC 8693)
client.logout(options)                 // Log out
client.session.isAuthenticated()       // Check auth status
client.session.check()                 // Validate session
client.getUser()                       // Get user info
client.on(event, handler)              // Subscribe to events
```

### Standalone Classes (Advanced Usage)

```typescript
// For building custom flows
TokenIntrospector    // RFC 7662 introspection
TokenRevoker         // RFC 7009 revocation
SilentAuthHandler    // prompt=none foundation
TokenManager         // Token storage/refresh
LogoutHandler        // Logout logic
AuthorizationCodeFlow // Auth code flow logic
PKCEHelper           // PKCE generation
StateManager         // State/nonce management
DiscoveryClient      // OIDC discovery
EventEmitter         // Event handling
```

---

## Testing Strategy

| Test Type | Location | Count |
|-----------|----------|-------|
| Unit Tests | `__tests__/unit/` | 69 tests |
| Integration Tests | `__tests__/integration/` | 33 tests |
| **Total** | | **102 tests** |

Integration tests use a mock OIDC server (`helpers/mock-server.ts`) that simulates:
- Token endpoint (authorization_code, refresh_token grants)
- Introspection endpoint
- Revocation endpoint
- UserInfo endpoint

---

## Version Compatibility

- **ECMAScript**: ES2020+
- **Node.js**: 18+ (for platform packages)
- **TypeScript**: 5.0+
- **Output Formats**: ESM (.mjs), CJS (.cjs), TypeScript declarations (.d.ts)

---

## Future Considerations

Features that may be added in future versions:

1. **Pushed Authorization Requests (PAR)** - RFC 9126
2. **Rich Authorization Requests (RAR)** - RFC 9396
3. **JWT Secured Authorization Response Mode (JARM)** - For enhanced security
4. **Proof Key for Code Exchange improvements** - Additional methods beyond S256

---

## Related Packages

| Package | Description | Status |
|---------|-------------|--------|
| @authrim/core | Platform-agnostic core (this package) | ✅ Available |
| @authrim/web | Browser implementation | 🚧 Planned |
| @authrim/node | Node.js implementation | 🚧 Planned |
| @authrim/react | React hooks and components | 🚧 Planned |
| @authrim/react-native | React Native implementation | 🚧 Planned |
