# Authrim JS SDK

Official JavaScript/TypeScript SDK for [Authrim](https://github.com/sgrastar/authrim) - a modern, developer-friendly Identity Provider.

## Overview

This monorepo contains the official client libraries for integrating with Authrim:

| Package | Description | Status |
|---------|-------------|--------|
| `@authrim/core` | Platform-agnostic core library | ✅ Available |
| `@authrim/web` | Browser implementation | ✅ Available |
| `@authrim/sveltekit` | SvelteKit integration | ✅ Available |
| `@authrim/react` | React hooks and components | 🚧 Planned |
| `@authrim/vue` | Vue.js integration | 🚧 Planned |
| `@authrim/server` | Node.js server-side implementation | 🚧 Planned |

**Note**: For most applications, you'll use a framework-specific package (e.g., `@authrim/react`) which includes `@authrim/core` as a dependency and provides platform-specific implementations.

## Features

### Core Features (`@authrim/core`)

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

### What's NOT in Core (Platform-Specific)

These features are implemented in platform packages:

- HTTP client (fetch/XMLHttpRequest)
- Crypto operations (Web Crypto API / Node.js crypto)
- Storage (localStorage, sessionStorage, AsyncStorage)
- Silent auth iframe handling
- Popup authentication
- Framework-specific hooks/components

## Installation

### For Browser Applications

```bash
npm install @authrim/web @authrim/core
# or
pnpm add @authrim/web @authrim/core
```

### For React Applications (Coming Soon)

```bash
# Coming soon
npm install @authrim/react
```

### For Svelte/SvelteKit

```bash
npm install @authrim/sveltekit @authrim/core
# or
pnpm add @authrim/sveltekit @authrim/core
```

### Core Only (Advanced)

If you're building a custom integration or a new platform package:

```bash
npm install @authrim/core
```

## Quick Start

### With @authrim/web (Browser)

```typescript
import { createAuthrim } from '@authrim/web';

const auth = await createAuthrim({
  issuer: 'https://your-idp.com',
  clientId: 'your-client-id',
});

// Passkey login (BetterAuth-style { data, error } pattern)
const { data, error } = await auth.passkey.login();
if (error) {
  console.error(error.message);
  return;
}
console.log('User:', data.user);

// Email code authentication
const { data: sendResult } = await auth.emailCode.send('user@example.com');
const { data: verifyResult } = await auth.emailCode.verify('user@example.com', '123456');

// Social login
const { data } = await auth.social.loginWithPopup('google');

// Sign out
await auth.signOut();
```

### With Framework Package (Coming Soon)

```tsx
// React example (coming soon)
import { AuthrimProvider, useAuth } from '@authrim/react';

function App() {
  return (
    <AuthrimProvider
      issuer="https://your-idp.com"
      clientId="your-client-id"
      redirectUri="https://your-app.com/callback"
    >
      <YourApp />
    </AuthrimProvider>
  );
}

function YourApp() {
  const { isAuthenticated, login, logout, user } = useAuth();

  if (!isAuthenticated) {
    return <button onClick={login}>Login</button>;
  }

  return (
    <div>
      <p>Welcome, {user.name}!</p>
      <button onClick={logout}>Logout</button>
    </div>
  );
}
```

### With Core Only (Advanced)

When using `@authrim/core` directly, you must provide platform implementations:

```typescript
import { createAuthrimClient } from '@authrim/core';

// You must implement these providers for your platform
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

## Core API Reference

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
if (info.active) {
  console.log('Token is valid, expires:', info.exp);
}

// Token Revocation (RFC 7009)
await client.token.revoke({ token: accessToken });
```

### Session & Logout

```typescript
// Check authentication status
const isAuth = await client.isAuthenticated();

// Get user info
const user = await client.getUser();

// Logout (local only)
await client.logout();

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
  console.error('Token error:', error.code);

  // Use error metadata for recovery
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
    console.log('Severity:', error.meta.severity);

    // error.meta.userAction can be:
    // 'retry' | 'reauthenticate' | 'contact_support' | 'check_network' | 'none'
  }
}
```

## Provider Interfaces

When using `@authrim/core` directly, implement these interfaces:

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
| OAuth 2.0 (RFC 6749) | ✅ Authorization Code Flow |
| PKCE (RFC 7636) | ✅ S256 method |
| Token Introspection (RFC 7662) | ✅ Full support |
| Token Revocation (RFC 7009) | ✅ Full support |
| Token Exchange (RFC 8693) | ✅ Full support |
| OpenID Connect Core 1.0 | ✅ Core features |
| OIDC Discovery | ✅ Full support |
| OIDC RP-Initiated Logout | ✅ Full support |

## Project Structure

```
packages/
├── core/           # Platform-agnostic core (@authrim/core)
│   ├── src/
│   │   ├── auth/       # Authorization flow, PKCE, state management
│   │   ├── token/      # Token management, introspection, revocation
│   │   ├── session/    # Session management, logout
│   │   ├── client/     # Main client, discovery
│   │   ├── events/     # Event emitter
│   │   ├── providers/  # Interface definitions
│   │   ├── types/      # TypeScript types, error definitions
│   │   └── utils/      # JWT, base64url utilities
│   └── __tests__/
├── web/            # Browser implementation (@authrim/web) ✅
├── react/          # React integration (planned)
└── sveltekit/      # SvelteKit integration (@authrim/sveltekit) ✅
```

## Requirements

- Node.js >= 18
- TypeScript >= 5.0

## Development

```bash
# Install dependencies
pnpm install

# Run tests
pnpm test

# Type check
pnpm typecheck

# Build
pnpm build
```

## License

Apache-2.0

## Documentation

- [Core Package Scope](./packages/core/SCOPE.md) - Detailed implementation status
