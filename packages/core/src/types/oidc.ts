/**
 * OIDC / OAuth 2.0 Types
 */

/**
 * OIDC Discovery Document
 * https://openid.net/specs/openid-connect-discovery-1_0.html
 */
export interface OIDCDiscoveryDocument {
  /** Issuer identifier (REQUIRED) */
  issuer: string;
  /** Authorization endpoint URL (REQUIRED) */
  authorization_endpoint: string;
  /** Token endpoint URL (REQUIRED unless only implicit flow is used) */
  token_endpoint: string;
  /** UserInfo endpoint URL (RECOMMENDED) */
  userinfo_endpoint?: string;
  /** JWKS URI (REQUIRED) */
  jwks_uri: string;
  /** Registration endpoint URL (RECOMMENDED) */
  registration_endpoint?: string;
  /** Scopes supported (RECOMMENDED) */
  scopes_supported?: string[];
  /** Response types supported (REQUIRED) */
  response_types_supported: string[];
  /** Response modes supported (OPTIONAL) */
  response_modes_supported?: string[];
  /** Grant types supported (OPTIONAL) */
  grant_types_supported?: string[];
  /** ACR values supported (OPTIONAL) */
  acr_values_supported?: string[];
  /** Subject types supported (REQUIRED) */
  subject_types_supported: string[];
  /** ID Token signing algs supported (REQUIRED) */
  id_token_signing_alg_values_supported: string[];
  /** ID Token encryption algs supported (OPTIONAL) */
  id_token_encryption_alg_values_supported?: string[];
  /** ID Token encryption enc supported (OPTIONAL) */
  id_token_encryption_enc_values_supported?: string[];
  /** UserInfo signing algs supported (OPTIONAL) */
  userinfo_signing_alg_values_supported?: string[];
  /** UserInfo encryption algs supported (OPTIONAL) */
  userinfo_encryption_alg_values_supported?: string[];
  /** UserInfo encryption enc supported (OPTIONAL) */
  userinfo_encryption_enc_values_supported?: string[];
  /** Request object signing algs supported (OPTIONAL) */
  request_object_signing_alg_values_supported?: string[];
  /** Request object encryption algs supported (OPTIONAL) */
  request_object_encryption_alg_values_supported?: string[];
  /** Request object encryption enc supported (OPTIONAL) */
  request_object_encryption_enc_values_supported?: string[];
  /** Token endpoint auth methods supported (OPTIONAL) */
  token_endpoint_auth_methods_supported?: string[];
  /** Token endpoint auth signing algs supported (OPTIONAL) */
  token_endpoint_auth_signing_alg_values_supported?: string[];
  /** Display values supported (OPTIONAL) */
  display_values_supported?: string[];
  /** Claim types supported (OPTIONAL) */
  claim_types_supported?: string[];
  /** Claims supported (RECOMMENDED) */
  claims_supported?: string[];
  /** Service documentation URL (OPTIONAL) */
  service_documentation?: string;
  /** Claims locales supported (OPTIONAL) */
  claims_locales_supported?: string[];
  /** UI locales supported (OPTIONAL) */
  ui_locales_supported?: string[];
  /** Claims parameter supported (OPTIONAL) */
  claims_parameter_supported?: boolean;
  /** Request parameter supported (OPTIONAL) */
  request_parameter_supported?: boolean;
  /** Request URI parameter supported (OPTIONAL) */
  request_uri_parameter_supported?: boolean;
  /** Require request URI registration (OPTIONAL) */
  require_request_uri_registration?: boolean;
  /** OP policy URI (OPTIONAL) */
  op_policy_uri?: string;
  /** OP ToS URI (OPTIONAL) */
  op_tos_uri?: string;

  // RP-Initiated Logout
  /** End session endpoint (OPTIONAL) */
  end_session_endpoint?: string;

  // Revocation
  /** Revocation endpoint (OPTIONAL) */
  revocation_endpoint?: string;
  /** Revocation endpoint auth methods supported (OPTIONAL) */
  revocation_endpoint_auth_methods_supported?: string[];
  /** Revocation endpoint auth signing algs supported (OPTIONAL) */
  revocation_endpoint_auth_signing_alg_values_supported?: string[];

  // Introspection
  /** Introspection endpoint (OPTIONAL) */
  introspection_endpoint?: string;
  /** Introspection endpoint auth methods supported (OPTIONAL) */
  introspection_endpoint_auth_methods_supported?: string[];
  /** Introspection endpoint auth signing algs supported (OPTIONAL) */
  introspection_endpoint_auth_signing_alg_values_supported?: string[];

  // PKCE
  /** Code challenge methods supported (OPTIONAL) */
  code_challenge_methods_supported?: string[];

  // Flow Engine (Authrim extension)
  /** Flow Engine support indicator (OPTIONAL, Authrim-specific) */
  flow_engine_supported?: boolean;

  // Additional properties (vendor-specific)
  [key: string]: unknown;
}

/**
 * Standard OIDC claims in ID Token
 */
export interface IdTokenClaims {
  /** Issuer Identifier */
  iss: string;
  /** Subject Identifier */
  sub: string;
  /** Audience */
  aud: string | string[];
  /** Expiration time */
  exp: number;
  /** Issued at time */
  iat: number;
  /** Authentication time */
  auth_time?: number;
  /** Nonce */
  nonce?: string;
  /** ACR - Authentication Context Class Reference */
  acr?: string;
  /** AMR - Authentication Methods References */
  amr?: string[];
  /** Authorized party */
  azp?: string;
  /** Access token hash */
  at_hash?: string;
  /** Code hash */
  c_hash?: string;
  /** Session ID */
  sid?: string;
  // Standard claims
  name?: string;
  given_name?: string;
  family_name?: string;
  middle_name?: string;
  nickname?: string;
  preferred_username?: string;
  profile?: string;
  picture?: string;
  website?: string;
  email?: string;
  email_verified?: boolean;
  gender?: string;
  birthdate?: string;
  zoneinfo?: string;
  locale?: string;
  phone_number?: string;
  phone_number_verified?: boolean;
  address?: {
    formatted?: string;
    street_address?: string;
    locality?: string;
    region?: string;
    postal_code?: string;
    country?: string;
  };
  updated_at?: number;
  // Additional claims
  [key: string]: unknown;
}

/**
 * Address claim
 */
export interface AddressClaim {
  formatted?: string;
  street_address?: string;
  locality?: string;
  region?: string;
  postal_code?: string;
  country?: string;
}

/**
 * Standard OIDC claims (profile, email, phone, address)
 */
export interface StandardClaims {
  name?: string;
  given_name?: string;
  family_name?: string;
  middle_name?: string;
  nickname?: string;
  preferred_username?: string;
  profile?: string;
  picture?: string;
  website?: string;
  email?: string;
  email_verified?: boolean;
  gender?: string;
  birthdate?: string;
  zoneinfo?: string;
  locale?: string;
  phone_number?: string;
  phone_number_verified?: boolean;
  address?: AddressClaim;
  updated_at?: number;
}

/**
 * UserInfo response
 */
export interface UserInfo extends StandardClaims {
  sub: string;
  [key: string]: unknown;
}
