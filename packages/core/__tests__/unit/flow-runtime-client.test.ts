import { beforeEach, describe, expect, it } from 'vitest';
import {
  FlowRuntimeClient,
  readStoredFlowRuntimeState,
  runtimeAllowsAuthenticationHandle,
  runtimeAllowsExternalProvider,
  type FlowRuntimeStep,
} from '../../src/index.js';
import { createMockHttp } from '../mocks/http.js';
import { createMockStorage } from '../mocks/storage.js';

describe('FlowRuntimeClient', () => {
  const issuer = 'https://auth.example.com';
  let http: ReturnType<typeof createMockHttp>;
  let storage: ReturnType<typeof createMockStorage>;
  let client: FlowRuntimeClient;

  beforeEach(() => {
    http = createMockHttp();
    storage = createMockStorage();
    client = new FlowRuntimeClient({ issuer, http, storage });
  });

  it('starts and submits flow runtime interactions', async () => {
    http.setHandler((url, options) => {
      if (url.endsWith('/interactions/start')) {
        expect(readBody(options?.body)).toMatchObject({ flow_kind: 'login' });
        return {
          ok: true,
          status: 200,
          data: createStartResponse(),
        };
      }
      if (url.endsWith('/interactions/interaction-1/submit')) {
        expect(readBody(options?.body)).toMatchObject({
          step_id: 'step-1',
          selected_handle: 'passkey',
        });
        return {
          ok: true,
          status: 200,
          data: {
            schema_version: 'authrim.flow_runtime.v1',
            interaction: createStartResponse().interaction,
            step: null,
            completed: true,
            output: { action: 'continue' },
          },
        };
      }
      throw new Error(`unexpected request ${url}`);
    });

    const flow = await client.start({ flow_kind: 'login' });
    await expect(
      client.submit(flow.interaction.id, {
        step_id: 'step-1',
        selected_handle: 'passkey',
        contract_hash: flow.contract_hash,
        signature: flow.signature,
      })
    ).resolves.toMatchObject({ completed: true });
  });

  it('persists and consumes flow runtime state', async () => {
    const flow = createStartResponse();
    await client.persistState(flow, { postAuthRedirect: '/account' });
    expect(storage.getAllKeys()).toEqual(['authrim:flow-runtime:interaction-1']);

    await expect(client.updatePostAuthRedirect('interaction-1', '/dashboard')).resolves.toBe(true);
    await expect(client.consumeState('interaction-1')).resolves.toEqual({
      interaction_id: 'interaction-1',
      contract_hash: 'hash-1',
      signature: 'signature-1',
      post_auth_redirect: '/dashboard',
    });
    expect(storage.getAllKeys()).toEqual([]);
  });

  it('reads stored flow state defensively', () => {
    expect(readStoredFlowRuntimeState(null)).toBeNull();
    expect(readStoredFlowRuntimeState('{bad json')).toBeNull();
    expect(readStoredFlowRuntimeState(JSON.stringify({ interaction_id: 'only-id' }))).toBeNull();
    expect(
      readStoredFlowRuntimeState(
        JSON.stringify({
          interaction_id: 'interaction-1',
          contract_hash: 'hash-1',
          signature: 'signature-1',
        })
      )
    ).toMatchObject({ interaction_id: 'interaction-1' });
  });
});

describe('flow runtime handles', () => {
  const authStep: FlowRuntimeStep = {
    id: 'step-1',
    source_node_id: 'node-1',
    component: 'authentication_method_selector',
    render: true,
    config: {
      output_handles: ['passkey', { id: 'external:google' }],
    },
  };

  it('matches configured authentication handles after normalization', () => {
    expect(runtimeAllowsAuthenticationHandle(authStep, 'Passkey')).toBe(true);
    expect(runtimeAllowsAuthenticationHandle(authStep, 'mail_otp')).toBe(false);
    expect(runtimeAllowsAuthenticationHandle(null, 'anything')).toBe(true);
  });

  it('builds external provider aliases', () => {
    expect(
      runtimeAllowsExternalProvider(authStep, {
        id: 'provider-1',
        slug: 'google',
        type: 'oidc',
      })
    ).toBe(true);
  });
});

function createStartResponse() {
  return {
    schema_version: 'authrim.flow_runtime.v1',
    interaction: {
      id: 'interaction-1',
      state: 'active',
      flow_id: 'flow-1',
      flow_version_id: 'flow-version-1',
      current_node_id: 'node-1',
      current_step_id: 'step-1',
      expires_at: 123456,
    },
    contract: {
      flow_kind: 'login',
      ui: {
        steps: [],
      },
    },
    contract_hash: 'hash-1',
    signature: 'signature-1',
    expires_in: 300,
    resumed: false,
  };
}

function readBody(body: unknown): Record<string, unknown> {
  expect(typeof body).toBe('string');
  return JSON.parse(body as string) as Record<string, unknown>;
}
