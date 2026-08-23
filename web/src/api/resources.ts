import { api, normalizePage } from './client';
import type { AlertSummary, AuditLog, BootstrapStatus, ConfigRevision, ConfigStrategy, DashboardSummary, EnrollmentToken, ManagedUser, NodeRole, NodeSummary, Page, ProxySummary, SecretSummary, SecurityRisk, TaskSummary, UpgradePlan, UpgradePlanResult, User } from './types';

export const authApi = {
  bootstrapStatus: () => api.get<BootstrapStatus>('/auth/bootstrap-status'),
  bootstrap: (bootstrapToken: string, username: string, password: string) => api.post<User>('/auth/bootstrap', { bootstrapToken, username, password }),
  login: (username: string, password: string) => api.post<User>('/auth/login', { username, password }),
  logout: () => api.post<void>('/auth/logout'),
  me: () => api.get<User>('/users/me'),
};

export const nodesApi = {
  list: async (query = '') => normalizePage(await api.get<Page<NodeSummary> | NodeSummary[]>(`/nodes${query ? `?${query}` : ''}`)),
  get: (id: string) => api.get<NodeSummary>(`/nodes/${encodeURIComponent(id)}`),
  inspect: (id: string) => api.post<TaskSummary>(`/nodes/${encodeURIComponent(id)}/inspect`),
  collectRuntime: (id: string) => api.post<TaskSummary>(`/nodes/${encodeURIComponent(id)}/runtime-collections`),
  updateManagementMode: (id: string, mode: 'observe' | 'managed') => api.patch<NodeSummary>(`/nodes/${encodeURIComponent(id)}/management-mode`, { mode }),
  serviceAction: (id: string, action: 'start' | 'stop' | 'restart') => api.post<TaskSummary>(`/nodes/${encodeURIComponent(id)}/service-actions`, { action }),
  createEnrollmentToken: (role: NodeRole, ttlSeconds = 600) => api.post<EnrollmentToken>('/nodes/enrollment-tokens', { role, ttlSeconds }),
};

export const systemApi = {
  downloadAgentCA: () => api.blob('/system/agent-ca'),
};

export const configurationsApi = {
  list: async (nodeId: string) => normalizePage(await api.get<Page<ConfigRevision> | ConfigRevision[]>(`/nodes/${encodeURIComponent(nodeId)}/config-revisions`)),
  create: (nodeId: string, content: string, strategy: ConfigStrategy) => api.post<ConfigRevision>(`/nodes/${encodeURIComponent(nodeId)}/config-revisions`, { content, format: 'toml', strategy }),
  content: (revisionId: string) => api.get<{ content: string }>(`/config-revisions/${encodeURIComponent(revisionId)}/content`),
  deploy: (revisionId: string) => api.post<TaskSummary>(`/config-revisions/${encodeURIComponent(revisionId)}/deploy`),
  rollback: (nodeId: string, revisionId: string) => api.post<TaskSummary>(`/nodes/${encodeURIComponent(nodeId)}/config-rollbacks`, { revision_id: revisionId }),
};

export const secretsApi = {
  list: async () => {
    const page = normalizePage(await api.get<Page<SecretSummary> | SecretSummary[]>('/secrets'));
    return { ...page, items: page.items.map(sanitizeSecret) };
  },
  create: async (name: string, value: string) => sanitizeSecret(await api.post<SecretSummary>('/secrets', { name, value })),
  update: async (id: string, value: string) => sanitizeSecret(await api.put<SecretSummary>(`/secrets/${encodeURIComponent(id)}`, { value })),
};

function sanitizeSecret(secret: SecretSummary): SecretSummary {
  return { id: secret.id, name: secret.name, configured: secret.configured, key_version: secret.key_version, created_at: secret.created_at, updated_at: secret.updated_at };
}

export const usersApi = {
  list: async () => normalizePage(await api.get<Page<ManagedUser> | ManagedUser[]>('/users')),
  create: (username: string, password: string, role: string) => api.post<ManagedUser>('/users', { username, password, role }),
  update: (id: string, patch: { status?: string; role?: string }) => api.patch<ManagedUser>(`/users/${encodeURIComponent(id)}`, patch),
};

export interface AuditFilters { actor?: string; action?: string; resource?: string; from?: string; to?: string; limit?: number; cursor?: string }
export const auditApi = {
  list: async (filters: AuditFilters) => {
    const params = new URLSearchParams();
    Object.entries(filters).forEach(([key, value]) => { if (value !== undefined && value !== '') params.set(key, String(value)); });
    return normalizePage(await api.get<Page<AuditLog> | AuditLog[]>(`/audit-logs?${params.toString()}`));
  },
};

export const tasksApi = {
  list: async (query = '') => normalizePage(await api.get<Page<TaskSummary> | TaskSummary[]>(`/tasks${query ? `?${query}` : ''}`)),
  get: (id: string) => api.get<TaskSummary>(`/tasks/${encodeURIComponent(id)}`),
  cancel: (id: string) => api.post<TaskSummary>(`/tasks/${encodeURIComponent(id)}/cancel`),
};

export const alertsApi = {
  list: async (state = '') => normalizePage(await api.get<Page<AlertSummary> | AlertSummary[]>(`/alerts?limit=200${state ? `&state=${encodeURIComponent(state)}` : ''}`)),
  acknowledge: (id: string) => api.post<AlertSummary>(`/alerts/${encodeURIComponent(id)}/acknowledge`),
  resolve: (id: string) => api.post<AlertSummary>(`/alerts/${encodeURIComponent(id)}/resolve`),
  close: (id: string) => api.post<AlertSummary>(`/alerts/${encodeURIComponent(id)}/close`),
};

export interface RiskFilters { nodeId?: string; kind?: string; state?: string; limit?: number; cursor?: string }
type RawRisk = SecurityRisk & Record<string, unknown>;

function sanitizeRisk(risk: RawRisk): SecurityRisk {
  return {
    id: risk.id,
    kind: risk.kind,
    severity: risk.severity,
    state: risk.state,
    node_id: risk.node_id,
    evidence: typeof risk.evidence === 'string' ? risk.evidence : undefined,
    first_seen_at: risk.first_seen_at,
    last_seen_at: risk.last_seen_at,
    resolved_at: risk.resolved_at,
    repairable: Boolean(risk.repairable),
    allowed_actions: Array.isArray(risk.allowed_actions) ? risk.allowed_actions.filter((value): value is string => typeof value === 'string') : [],
  };
}

export const securityRisksApi = {
  list: async (filters: RiskFilters) => {
    const params = new URLSearchParams();
    Object.entries(filters).forEach(([key, value]) => { if (value !== undefined && value !== '') params.set(key === 'nodeId' ? 'node_id' : key, String(value)); });
    const page = normalizePage(await api.get<Page<RawRisk> | RawRisk[]>(`/risks?${params.toString()}`));
    return { ...page, items: page.items.map(sanitizeRisk) };
  },
  scan: (nodeId: string, idempotencyKey: string) => api.post<TaskSummary>(
    `/nodes/${encodeURIComponent(nodeId)}/risk-scans`,
    undefined,
    { 'Idempotency-Key': idempotencyKey },
  ),
  repair: (id: string, action: string, idempotencyKey: string) => api.post<TaskSummary>(
    `/risks/${encodeURIComponent(id)}/repairs`,
    { action, maintenance_confirmed: action === 'bind_admin_api_loopback' },
    { 'Idempotency-Key': idempotencyKey },
  ),
};

export interface ProxyFilters { nodeId?: string; status?: string; type?: string; limit?: number; cursor?: string }
export const proxiesApi = {
  list: async (filters: ProxyFilters) => {
    const params = new URLSearchParams();
    Object.entries(filters).forEach(([key, value]) => { if (value !== undefined && value !== '') params.set(key, String(value)); });
    return normalizePage(await api.get<Page<ProxySummary> | ProxySummary[]>(`/proxies?${params.toString()}`));
  },
  get: (nodeId: string, name: string) => api.get<ProxySummary>(`/proxies/${encodeURIComponent(nodeId)}/${encodeURIComponent(name)}`),
};

export interface UpgradeFilters { nodeId?: string; state?: string; limit?: number; cursor?: string }
export const upgradesApi = {
  list: async (filters: UpgradeFilters) => {
    const params = new URLSearchParams();
    Object.entries(filters).forEach(([key, value]) => { if (value !== undefined && value !== '') params.set(key, String(value)); });
    return normalizePage(await api.get<Page<UpgradePlan> | UpgradePlan[]>(`/upgrade-plans?${params.toString()}`));
  },
  get: (id: string) => api.get<UpgradePlanResult>(`/upgrade-plans/${encodeURIComponent(id)}`),
  create: (input: { node_id: string; version: string; artifact_url: string; sha256: string }) => api.post<UpgradePlanResult>('/upgrade-plans', input, { 'Idempotency-Key': crypto.randomUUID() }),
  cancel: (id: string) => api.post<UpgradePlanResult>(`/upgrade-plans/${encodeURIComponent(id)}/cancel`),
};

export async function getDashboard(): Promise<DashboardSummary> {
  const [nodes, tasks, alerts] = await Promise.all([nodesApi.list('limit=200'), tasksApi.list('limit=100'), alertsApi.list()]);
  return {
    nodes_total: nodes.total ?? nodes.items.length,
    nodes_online: nodes.items.filter((node) => node.status === 'online').length,
    nodes_healthy: nodes.items.filter((node) => node.status === 'online' && node.service_status === 'active' && !node.drifted).length,
    nodes_drifted: nodes.items.filter((node) => node.drifted || node.desired_revision !== node.observed_revision).length,
    alerts_firing: alerts.items.filter((alert) => ['open', 'acknowledged'].includes(alert.state)).length,
    tasks_running: tasks.items.filter((task) => ['pending', 'queued', 'dispatched', 'running'].includes(task.status)).length,
  };
}
