import { beforeEach, describe, expect, it, vi } from 'vitest';
import { securityRisksApi } from './resources';

describe('securityRisksApi', () => {
  beforeEach(() => { document.cookie = 'csrf_token=test-csrf'; });

  it('projects risk responses onto a display-safe field allowlist', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ items: [{
      id: 'r1', node_id: 'n1', kind: 'config_token_permissions', severity: 'high', state: 'open',
      evidence: 'mode=0644', first_seen_at: '2026-07-28T01:00:00Z', last_seen_at: '2026-07-29T01:00:00Z',
      repairable: true, allowed_actions: ['restrict_config_permissions', 42], token: 'must-not-reach-ui', raw_log: 'secret log',
    }] }), { status: 200, headers: { 'content-type': 'application/json' } })));
    const result = await securityRisksApi.list({ state: 'open' });
    expect(result.items[0]).toEqual({
      id: 'r1', node_id: 'n1', kind: 'config_token_permissions', severity: 'high', state: 'open', evidence: 'mode=0644',
      first_seen_at: '2026-07-28T01:00:00Z', last_seen_at: '2026-07-29T01:00:00Z', resolved_at: undefined,
      repairable: true, allowed_actions: ['restrict_config_permissions'],
    });
    expect(result.items[0]).not.toHaveProperty('token');
    expect(result.items[0]).not.toHaveProperty('raw_log');
  });

  it('sends scan and repair idempotency keys in the HTTP header', async () => {
    const fetchMock = vi.fn().mockImplementation(() => Promise.resolve(new Response(JSON.stringify({ id: 'task-1' }), { status: 202, headers: { 'content-type': 'application/json' } })));
    vi.stubGlobal('fetch', fetchMock);

    await securityRisksApi.scan('node/1', 'scan-intent');
    expect(fetchMock).toHaveBeenLastCalledWith('/api/v1/nodes/node%2F1/risk-scans', expect.objectContaining({ method: 'POST', headers: expect.any(Headers) }));
    expect(new Headers(fetchMock.mock.calls.at(-1)?.[1]?.headers).get('Idempotency-Key')).toBe('scan-intent');

    await securityRisksApi.repair('risk/1', 'restrict_config_permissions', 'repair-intent');
    expect(fetchMock).toHaveBeenLastCalledWith('/api/v1/risks/risk%2F1/repairs', expect.objectContaining({
      method: 'POST', body: JSON.stringify({ action: 'restrict_config_permissions', maintenance_confirmed: false }), headers: expect.any(Headers),
    }));
    expect(new Headers(fetchMock.mock.calls.at(-1)?.[1]?.headers).get('Idempotency-Key')).toBe('repair-intent');
  });
});
