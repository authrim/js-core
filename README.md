# @authrim/core

Platform-agnostic OIDC/OAuth 2.0 SDK for JavaScript and TypeScript.

## Features

- **Platform-agnostic**: Core logic with injectable providers for any JavaScript runtime
- **OIDC Compliant**: Full OpenID Connect 1.0 support with OIDC Discovery
- **PKCE**: Secure Authorization Code Flow with Proof Key for Code Exchange
- **Token Management**: Automatic refresh with in-flight request coalescing
- **Token Exchange**: RFC 8693 Token Exchange for delegation and cross-service scenarios
- **Type-safe**: Full TypeScript support with comprehensive type definitions
- **Event-driven**: Subscribe to authentication lifecycle events
- **Tree-shakeable**: ESM-first with minimal bundle size

## Installation

```bash
npm install @authrim/core
# or
pnpm add @authrim/core
# or
yarn add @authrim/core
```

## Quick Start

```typescript
import { createAuthrimClient } from '@authrim/core';

// Create client with platform-specific providers
const client = await createAuthrimClient({
  issuer: 'https://your-idp.com',
  clientId: 'your-client-id',
  scopes: ['openid', 'profile', 'email'],
  // Inject platform-specific providers
  crypto: yourCryptoProvider,
  storage: yourStorageProvider,
  http: yourHttpProvider,
});

// Build authorization URL
const { url, state } = await client.buildAuthorizationUrl({
  redirectUri: 'https://your-app.com/callback',
});

// Redirect user to IdP
window.location.href = url;
```

### Handle Callback

```typescript
// After redirect back from IdP
const tokens = await client.handleCallback(window.location.href);

console.log('Authenticated!', tokens.accessToken);
```

### Token Management

```typescript
// Get access token (auto-refreshes if needed)
const accessToken = await client.token.getAccessToken();

// Check authentication status
const isAuthenticated = await client.token.isAuthenticated();

// Get ID token
const idToken = await client.token.getIdToken();
```

### Token Exchange (RFC 8693)

Exchange tokens for different audiences or delegation scenarios:

```typescript
const result = await client.token.exchange({
  subjectToken: currentAccessToken,
  audience: 'https://api.other-service.com',
  scope: 'read write',
});

console.log(result.tokens.accessToken);
```

### Session Management

```typescript
// Check session with authorization server
const sessionStatus = await client.session.check();

if (!sessionStatus.active) {
  // Session expired, re-authenticate
}
```

### Logout

```typescript
// Local logout only
await client.logout();

// Logout with IdP redirect (RP-Initiated Logout)
const { logoutUrl } = await client.logout({
  postLogoutRedirectUri: 'https://your-app.com',
});
```

### Events

```typescript
// Subscribe to token refresh
client.on('token:refreshed', ({ tokens }) => {
  console.log('Token refreshed:', tokens.accessToken);
});

// Subscribe to token exchange
client.on('token:exchanged', ({ tokens, issuedTokenType }) => {
  console.log('Token exchanged:', issuedTokenType);
});

// Subscribe to errors
client.on('token:error', ({ error }) => {
  console.error('Token error:', error.code, error.message);
});
```

## Providers

`@authrim/core` requires platform-specific providers to be injected:

### CryptoProvider

```typescript
interface CryptoProvider {
  getRandomBytes(length: number): Uint8Array;
  sha256(data: string): Promise<Uint8Array>;
}
```

### StorageProvider

```typescript
interface AuthrimStorage {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  remove(key: string): Promise<void>;
}
```

### HttpProvider

```typescript
interface HttpClient {
  fetch<T>(url: string, options?: HttpRequestOptions): Promise<HttpResponse<T>>;
}
```

## Utilities

### ds_hash Calculation

For Native SSO device_secret verification:

```typescript
import { calculateDsHash } from '@authrim/core';

const dsHash = await calculateDsHash(deviceSecret, cryptoProvider);

// Compare with id_token.ds_hash claim
if (idToken.ds_hash === dsHash) {
  // device_secret is valid
}
```

### JWT Utilities

```typescript
import { decodeJwt, decodeIdToken, isJwtExpired } from '@authrim/core';

// Decode JWT without verification
const decoded = decodeJwt(token);

// Decode ID token
const idTokenClaims = decodeIdToken(idToken);

// Check if JWT is expired
const expired = isJwtExpired(token);
```

## Configuration

```typescript
interface AuthrimClientConfig {
  /** OIDC Issuer URL */
  issuer: string;

  /** OAuth Client ID */
  clientId: string;

  /** Requested scopes (default: ['openid']) */
  scopes?: string[];

  /** Platform-specific crypto provider */
  crypto: CryptoProvider;

  /** Platform-specific storage provider */
  storage: AuthrimStorage;

  /** Platform-specific HTTP client */
  http: HttpClient;

  /** Discovery cache TTL in ms (default: 3600000 = 1 hour) */
  discoveryCacheTtlMs?: number;

  /** Token refresh skew in seconds (default: 30) */
  refreshSkewSeconds?: number;

  /** State TTL in seconds (default: 600 = 10 minutes) */
  stateTtlSeconds?: number;
}
```

## Platform Packages

| Package | Platform | Status |
|---------|----------|--------|
| `@authrim/react` | React | Coming Soon |
| `@authrim/next` | Next.js | Coming Soon |
| `@authrim/svelte` | Svelte/SvelteKit | Coming Soon |

## Requirements

- Node.js >= 18
- TypeScript >= 5.0 (for type definitions)

## License

Apache-2.0
