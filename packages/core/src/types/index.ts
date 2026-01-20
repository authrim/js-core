/**
 * Type Definitions
 */

export { AuthrimError, type AuthrimErrorCode } from './errors.js';
export type { OIDCDiscoveryDocument, IdTokenClaims, UserInfo } from './oidc.js';
export type {
  TokenSet,
  TokenEndpointResponse,
  TokenExchangeRequest,
} from './token.js';
