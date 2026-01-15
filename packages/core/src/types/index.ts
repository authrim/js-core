/**
 * Type Definitions
 */

export { AuthrimError, type AuthrimErrorCode } from './errors.js';
export type { OIDCDiscoveryDocument, IdTokenClaims, UserInfo } from './oidc.js';
export {
  toTokenSet,
  type TokenSet,
  type TokenEndpointResponse,
  type RefreshTokenResponse,
  type TokenExchangeRequest,
} from './token.js';
