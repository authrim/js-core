/**
 * Browser session profile contract shared by core and platform adapters.
 *
 * @authrim/core defines the names and safety checks only. Platform packages
 * decide how cookies, fetch, storage, and DPoP keys are implemented.
 */

export const AUTHRIM_MANAGED_BROWSER_SESSION_PROFILE = 'managed_browser_session' as const;

export type AuthrimSessionProfile =
  | typeof AUTHRIM_MANAGED_BROWSER_SESSION_PROFILE
  | 'cookie_session'
  | 'token_session';

export type AuthrimWebSdkProfile = 'auto' | 'cookie' | 'token';

const BROWSER_TOKEN_MATERIAL_FIELDS = new Set([
  'access_token',
  'refresh_token',
  'id_token',
  'token',
  'tokenSet',
]);

export function hasBrowserTokenMaterial(value: unknown): boolean {
  if (!value || typeof value !== 'object') {
    return false;
  }

  for (const key of Object.keys(value)) {
    if (BROWSER_TOKEN_MATERIAL_FIELDS.has(key)) {
      return true;
    }
  }

  return false;
}

export function assertNoBrowserTokenMaterial(value: unknown, context: string): void {
  if (hasBrowserTokenMaterial(value)) {
    throw new Error(`${context} returned OAuth/OIDC token material to the browser session profile`);
  }
}
