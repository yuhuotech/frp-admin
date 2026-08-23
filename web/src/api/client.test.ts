import { afterEach, describe, expect, it, vi } from 'vitest';
import { QueryClient } from '@tanstack/react-query';
import { api, ApiError, normalizePage } from './client';
import { alertsApi, auditApi, authApi, configurationsApi, nodesApi, proxiesApi, secretsApi, tasksApi, upgradesApi, usersApi } from './resources';

afterEach(() => vi.restoreAllMocks());

describe('api client', () => {
  it('uses cookie credentials and parses JSON', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ id: 'n1' }), { status: 200, headers: { 'content-type': 'application/json' } }));
    await expect(api.get('/nodes/n1')).resolves.toEqual({ id: 'n1' });
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/nodes/n1', expect.objectContaining({ credentials: 'include' }));
  });

  it('exposes problem details on error', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ title: 'Not found', detail: '节点不存在' }), { status: 404, headers: { 'content-type': 'application/problem+json' } }));
    await expect(api.get('/nodes/missing')).rejects.toMatchObject({ status: 404, message: '节点不存在' } satisfies Partial<ApiError>);
  });

  it('normalizes list response shapes', () => {
    expect(normalizePage([{ id: 1 }])).toEqual({ items: [{ id: 1 }] });
    expect(normalizePage({ data: [{ id: 2 }], total: 1 })).toEqual({ items: [{ id: 2 }], total: 1 });
  });

  it('sends the server bootstrap field names', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ id: 'u1', username: 'admin', role: 'admin' }), { status: 201, headers: { 'content-type': 'application/json' } }));
    await authApi.bootstrap('start-token', 'admin', 'a-secure-password');
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/auth/bootstrap', expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({ bootstrapToken: 'start-token', username: 'admin', password: 'a-secure-password' }),
    }));
  });

  it('downloads authenticated binary responses', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('-----BEGIN CERTIFICATE-----', { status: 200, headers: { 'content-type': 'application/x-pem-file' } }));
    await expect(api.blob('/system/agent-ca')).resolves.toBeInstanceOf(Blob);
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/system/agent-ca', expect.objectContaining({ credentials: 'include' }));
  });

  it('creates a ten-minute one-time enrollment token', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ id: 'e1', token: 'secret', role: 'server', expiresAt: '2026-01-01T00:10:00Z' }), { status: 201, headers: { 'content-type': 'application/json' } }));
    await nodesApi.createEnrollmentToken('server');
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/nodes/enrollment-tokens', expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({ role: 'server', ttlSeconds: 600 }),
    }));
  });

  it('creates immutable TOML revision with explicit strategy', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ id: 'r1', node_id: 'n1', version: 1, content: 'serverPort = 7000', format: 'toml', strategy: 'restart', sha256: 'abc', created_at: '2026-01-01T00:00:00Z' }), { status: 201, headers: { 'content-type': 'application/json' } }));
    await configurationsApi.create('n1', 'serverPort = 7000', 'restart');
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/nodes/n1/config-revisions', expect.objectContaining({ method: 'POST', body: JSON.stringify({ content: 'serverPort = 7000', format: 'toml', strategy: 'restart' }) }));
  });

  it('uses revision and node rollback endpoints', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response(JSON.stringify({ id: 't1', type: 'apply_config', status: 'pending', created_at: '2026-01-01T00:00:00Z' }), { status: 202, headers: { 'content-type': 'application/json' } }));
    await configurationsApi.deploy('r1');
    await configurationsApi.rollback('n1', 'r0');
    expect(fetchMock).toHaveBeenNthCalledWith(1, '/api/v1/config-revisions/r1/deploy', expect.objectContaining({ method: 'POST' }));
    expect(fetchMock).toHaveBeenNthCalledWith(2, '/api/v1/nodes/n1/config-rollbacks', expect.objectContaining({ method: 'POST', body: JSON.stringify({ revision_id: 'r0' }) }));
  });

  it('uses structured service actions and task cancellation endpoints', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response(JSON.stringify({ id: 't1', type: 'service_restart', status: 'queued', created_at: '2026-01-01T00:00:00Z' }), { status: 202, headers: { 'content-type': 'application/json' } }));
    await nodesApi.serviceAction('node/1', 'restart');
    await nodesApi.updateManagementMode('node/1', 'managed');
    await tasksApi.cancel('task/1');
    expect(fetchMock).toHaveBeenNthCalledWith(1, '/api/v1/nodes/node%2F1/service-actions', expect.objectContaining({ method: 'POST', body: JSON.stringify({ action: 'restart' }) }));
    expect(fetchMock).toHaveBeenNthCalledWith(2, '/api/v1/nodes/node%2F1/management-mode', expect.objectContaining({ method: 'PATCH', body: JSON.stringify({ mode: 'managed' }) }));
    expect(fetchMock).toHaveBeenNthCalledWith(3, '/api/v1/tasks/task%2F1/cancel', expect.objectContaining({ method: 'POST' }));
  });

  it('filters and transitions alerts through explicit endpoints', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response(JSON.stringify({ items: [] }), { status: 200, headers: { 'content-type': 'application/json' } }));
    await alertsApi.list('acknowledged');
    await alertsApi.acknowledge('alert/1');
    await alertsApi.resolve('alert/1');
    await alertsApi.close('alert/1');
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      '/api/v1/alerts?limit=200&state=acknowledged',
      '/api/v1/alerts/alert%2F1/acknowledge',
      '/api/v1/alerts/alert%2F1/resolve',
      '/api/v1/alerts/alert%2F1/close',
    ]);
  });

  it('uses global proxy filters and escaped composite detail keys', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response(JSON.stringify({ items: [] }), { status: 200, headers: { 'content-type': 'application/json' } }));
    await proxiesApi.list({ nodeId: 'node/1', status: 'running', type: 'tcp', limit: 50 });
    await proxiesApi.get('node/1', 'proxy/1');
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      '/api/v1/proxies?nodeId=node%2F1&status=running&type=tcp&limit=50',
      '/api/v1/proxies/node%2F1/proxy%2F1',
    ]);
  });

  it('creates idempotent upgrade plans and uses plan cancellation', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response(JSON.stringify({ plan: { id: 'p1' }, task: { id: 't1' } }), { status: 202, headers: { 'content-type': 'application/json' } }));
    const input = { node_id: 'n1', version: '0.61.0', artifact_url: 'https://cdn.example/frp.tar.gz', sha256: 'a'.repeat(64) };
    await upgradesApi.create(input);
    await upgradesApi.cancel('plan/1');
    const createInit = fetchMock.mock.calls[0][1] as RequestInit;
    expect(fetchMock.mock.calls[0][0]).toBe('/api/v1/upgrade-plans');
    expect(createInit.body).toBe(JSON.stringify(input));
    expect(new Headers(createInit.headers).get('Idempotency-Key')).toBe('test-request-id');
    expect(fetchMock.mock.calls[1][0]).toBe('/api/v1/upgrade-plans/plan%2F1/cancel');
  });

  it('loads revision content only from the dedicated endpoint', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ content: 'serverPort = 7000' }), { status: 200, headers: { 'content-type': 'application/json' } }));
    await configurationsApi.content('r1');
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/config-revisions/r1/content', expect.objectContaining({ credentials: 'include' }));
  });

  it('sends secret value only in create and rotate bodies', async () => {
    const storageSpy = vi.spyOn(Storage.prototype, 'setItem');
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response(JSON.stringify({ id: 's1', name: 'frp.token', configured: true, key_version: 1, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z', value: 'server-echoed-secret' }), { status: 200, headers: { 'content-type': 'application/json' } }));
    const created = await secretsApi.create('frp.token', 'secret-value');
    await secretsApi.update('s1', 'new-value');
    expect(created).not.toHaveProperty('value');
    expect(fetchMock).toHaveBeenNthCalledWith(1, '/api/v1/secrets', expect.objectContaining({ body: JSON.stringify({ name: 'frp.token', value: 'secret-value' }) }));
    expect(fetchMock).toHaveBeenNthCalledWith(2, '/api/v1/secrets/s1', expect.objectContaining({ method: 'PUT', body: JSON.stringify({ value: 'new-value' }) }));
    expect(String(fetchMock.mock.calls[0][0])).not.toContain('secret-value');
    expect(storageSpy).not.toHaveBeenCalled();
  });

  it('strips an accidentally echoed secret before Query cache storage', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ items: [{ id: 's1', name: 'token', configured: true, key_version: 1, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z', value: 'must-not-cache' }] }), { status: 200, headers: { 'content-type': 'application/json' } }));
    const queryClient = new QueryClient();
    await queryClient.fetchQuery({ queryKey: ['secrets'], queryFn: secretsApi.list });
    expect(JSON.stringify(queryClient.getQueryData(['secrets']))).not.toContain('must-not-cache');
  });

  it('uses frozen user and audit filter contracts', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response(JSON.stringify({ items: [] }), { status: 200, headers: { 'content-type': 'application/json' } }));
    await usersApi.update('u1', { role: 'operator' });
    await auditApi.list({ actor: 'admin', action: 'secret.create', from: '2026-01-01T00:00:00Z', limit: 50, cursor: 'next' });
    expect(fetchMock).toHaveBeenNthCalledWith(1, '/api/v1/users/u1', expect.objectContaining({ method: 'PATCH', body: JSON.stringify({ role: 'operator' }) }));
    expect(fetchMock.mock.calls[1][0]).toBe('/api/v1/audit-logs?actor=admin&action=secret.create&from=2026-01-01T00%3A00%3A00Z&limit=50&cursor=next');
  });
});
