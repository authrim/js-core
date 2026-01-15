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

### Package Manager

```bash
npm install @authrim/core
# or
pnpm add @authrim/core
# or
yarn add @authrim/core
```

### CDN

| Type | URL |
|------|-----|
| ESM | `https://esm.sh/@authrim/core` |
| ESM | `https://cdn.jsdelivr.net/npm/@authrim/core/+esm` |
| UMD | `https://unpkg.com/@authrim/core/dist/index.global.js` |

## Quick Start

### ESM (TypeScript / Modern JavaScript)

```typescript
import { createAuthrimClient } from '@authrim/core';

const client = await createAuthrimClient({
  issuer: 'https://your-idp.com',
  clientId: 'your-client-id',
  scopes: ['openid', 'profile', 'email'],
  crypto: yourCryptoProvider,
  storage: yourStorageProvider,
  http: yourHttpProvider,
});

// Start login
const { url } = await client.buildAuthorizationUrl({
  redirectUri: 'https://your-app.com/callback',
});
window.location.href = url;

// Handle callback (on redirect back)
const tokens = await client.handleCallback(window.location.href);
console.log('Authenticated!', tokens.accessToken);
```

### UMD (Browser Script Tag)

```html
<!DOCTYPE html>
<html>
<head>
  <title>Authrim Example</title>
</head>
<body>
  <button id="login">Login</button>
  <button id="logout" style="display:none">Logout</button>
  <pre id="user"></pre>

  <script src="https://unpkg.com/@authrim/core/dist/index.global.js"></script>
  <script>
    const { createAuthrimClient } = Authrim;

    // Browser providers
    const cryptoProvider = {
      getRandomBytes: (len) => crypto.getRandomValues(new Uint8Array(len)),
      sha256: async (data) => {
        const enc = new TextEncoder().encode(data);
        const buf = await crypto.subtle.digest('SHA-256', enc);
        return new Uint8Array(buf);
      }
    };

    const storageProvider = {
      get: async (key) => localStorage.getItem(key),
      set: async (key, value) => localStorage.setItem(key, value),
      remove: async (key) => localStorage.removeItem(key)
    };

    const httpProvider = {
      fetch: async (url, options = {}) => {
        const res = await fetch(url, {
          method: options.method || 'GET',
          headers: options.headers,
          body: options.body
        });
        return {
          ok: res.ok,
          status: res.status,
          data: await res.json()
        };
      }
    };

    // Initialize client
    (async () => {
      const client = await createAuthrimClient({
        issuer: 'https://your-idp.com',
        clientId: 'your-client-id',
        scopes: ['openid', 'profile', 'email'],
        crypto: cryptoProvider,
        storage: storageProvider,
        http: httpProvider
      });

      // Handle callback
      if (window.location.search.includes('code=')) {
        const tokens = await client.handleCallback(window.location.href);
        history.replaceState({}, '', window.location.pathname);
      }

      // Update UI
      const isAuth = await client.isAuthenticated();
      document.getElementById('login').style.display = isAuth ? 'none' : 'block';
      document.getElementById('logout').style.display = isAuth ? 'block' : 'none';

      if (isAuth) {
        const user = await client.getUser();
        document.getElementById('user').textContent = JSON.stringify(user, null, 2);
      }

      // Login button
      document.getElementById('login').onclick = async () => {
        const { url } = await client.buildAuthorizationUrl({
          redirectUri: window.location.origin + window.location.pathname
        });
        window.location.href = url;
      };

      // Logout button
      document.getElementById('logout').onclick = async () => {
        await client.logout();
        window.location.reload();
      };
    })();
  </script>
</body>
</html>
```

## Usage

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
client.on('token:refreshed', ({ tokens }) => {
  console.log('Token refreshed');
});

client.on('token:exchanged', ({ tokens, issuedTokenType }) => {
  console.log('Token exchanged:', issuedTokenType);
});

client.on('token:error', ({ error }) => {
  console.error('Token error:', error.code);
});
```

## Providers

`@authrim/core` requires platform-specific providers:

```typescript
interface CryptoProvider {
  getRandomBytes(length: number): Uint8Array;
  sha256(data: string): Promise<Uint8Array>;
}

interface AuthrimStorage {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  remove(key: string): Promise<void>;
}

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
if (idToken.ds_hash === dsHash) {
  // device_secret is valid
}
```

### JWT Utilities

```typescript
import { decodeJwt, decodeIdToken, isJwtExpired } from '@authrim/core';

const decoded = decodeJwt(token);
const claims = decodeIdToken(idToken);
const expired = isJwtExpired(token);
```

## Configuration

```typescript
interface AuthrimClientConfig {
  issuer: string;                    // OIDC Issuer URL
  clientId: string;                  // OAuth Client ID
  scopes?: string[];                 // Default: ['openid']
  crypto: CryptoProvider;            // Platform crypto
  storage: AuthrimStorage;           // Platform storage
  http: HttpClient;                  // Platform HTTP client
  discoveryCacheTtlMs?: number;      // Default: 3600000 (1 hour)
  refreshSkewSeconds?: number;       // Default: 30
  stateTtlSeconds?: number;          // Default: 600 (10 min)
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
