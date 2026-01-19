# @authrim/core

Platform-agnostic core library for [Authrim](https://github.com/authrim) - a modern, developer-friendly Identity Provider.

## Overview

This is the core package that provides OAuth 2.0 / OpenID Connect functionality without platform-specific dependencies. For most applications, use a framework-specific package (e.g., `@authrim/react`, `@authrim/web`) which includes this as a dependency.

**Use this package directly if you're:**
- Building a custom integration
- Creating a new platform-specific package
- Need full control over HTTP, crypto, and storage implementations

## Installation

```bash
npm install @authrim/core
```

## Features

- **Authorization Code Flow with PKCE** - RFC 7636 compliant
- **Automatic Token Refresh** - With request coalescing for concurrent calls
- **Token Exchange** - RFC 8693 for delegation and cross-service scenarios
- **Token Introspection** - RFC 7662 server-side validation
- **Token Revocation** - RFC 7009 explicit invalidation
- **Silent Authentication** - prompt=none foundation
- **RP-Initiated Logout** - OIDC logout with optional token revocation
- **OIDC Discovery** - Automatic endpoint discovery with caching
- **Event System** - Subscribe to authentication lifecycle events
- **Error Recovery Metadata** - Guidance for retry logic and user actions

## Usage

When using `@authrim/core` directly, you must provide platform implementations:

```typescript
import { createAuthrimClient } from '@authrim/core';

const client = await createAuthrimClient({
  issuer: 'https://your-idp.com',
  clientId: 'your-client-id',
  crypto: yourCryptoProvider,    // CryptoProvider interface
  storage: yourStorageProvider,  // AuthrimStorage interface
  http: yourHttpProvider,        // HttpClient interface
});

// Start login
const { url } = await client.buildAuthorizationUrl({
  redirectUri: 'https://your-app.com/callback',
});

// Handle callback
const tokens = await client.handleCallback(callbackUrl);

// Use tokens
const accessToken = await client.token.getAccessToken();
```

## API Reference

### Token Operations

```typescript
// Get access token (auto-refreshes if needed)
const accessToken = await client.token.getAccessToken();

// Get all tokens
const tokens = await client.token.getTokens();

// Token Exchange (RFC 8693)
const result = await client.token.exchange({
  subjectToken: currentToken,
  audience: 'https://api.other-service.com',
});

// Token Introspection (RFC 7662)
const info = await client.token.introspect({ token: accessToken });

// Token Revocation (RFC 7009)
await client.token.revoke({ token: accessToken });
```

### Session & Logout

```typescript
// Check authentication status
const isAuth = await client.isAuthenticated();

// Get user info
const user = await client.getUser();

// Logout with token revocation
const { logoutUrl } = await client.logout({
  revokeTokens: true,
  postLogoutRedirectUri: 'https://your-app.com',
});
```

### Events

```typescript
client.on('token:refreshed', ({ tokens }) => {
  console.log('Token refreshed');
});

client.on('token:error', ({ error }) => {
  if (error.meta.retryable) {
    // Retry after error.meta.retryAfterMs
  } else if (error.meta.userAction === 'reauthenticate') {
    // Redirect to login
  }
});

client.on('session:ended', ({ reason }) => {
  console.log('Session ended:', reason);
});
```

### Error Handling

All errors include recovery metadata:

```typescript
try {
  await client.token.getAccessToken();
} catch (error) {
  if (error instanceof AuthrimError) {
    console.log('Error code:', error.code);
    console.log('Retryable:', error.meta.retryable);
    console.log('User action:', error.meta.userAction);
    // 'retry' | 'reauthenticate' | 'contact_support' | 'check_network' | 'none'
  }
}
```

## Provider Interfaces

Implement these interfaces for your platform:

```typescript
interface CryptoProvider {
  randomBytes(length: number): Uint8Array;
  sha256(data: string | Uint8Array): Promise<Uint8Array>;
}

interface AuthrimStorage {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  remove(key: string): Promise<void>;
  getAll(): Promise<Record<string, string>>;
  clear(): Promise<void>;
}

interface HttpClient {
  fetch<T>(url: string, options?: HttpOptions): Promise<HttpResponse<T>>;
}
```

## Standards Compliance

| Standard | Status |
|----------|--------|
| OAuth 2.0 (RFC 6749) | Authorization Code Flow |
| PKCE (RFC 7636) | S256 method |
| Token Introspection (RFC 7662) | Full support |
| Token Revocation (RFC 7009) | Full support |
| Token Exchange (RFC 8693) | Full support |
| OpenID Connect Core 1.0 | Core features |
| OIDC Discovery | Full support |
| OIDC RP-Initiated Logout | Full support |

## Related Packages

| Package | Description |
|---------|-------------|
| `@authrim/web` | Browser implementation (planned) |
| `@authrim/react` | React hooks and components (planned) |
| `@authrim/svelte` | Svelte/SvelteKit integration (planned) |

## Requirements

- Node.js >= 18
- TypeScript >= 5.0

## License

Apache-2.0
