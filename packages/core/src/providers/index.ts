/**
 * Provider Interfaces
 *
 * These interfaces define the platform-agnostic abstractions that must be
 * injected into the SDK. @authrim/core never directly accesses platform APIs.
 */

export type { HttpClient, HttpOptions, HttpResponse, OAuthErrorResponse } from './http.js';
export type { CryptoProvider } from './crypto.js';
export type { AuthrimStorage } from './storage.js';
