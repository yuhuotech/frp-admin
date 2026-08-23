export type NodeRole = 'client' | 'server';
export type NodeStatus = 'online' | 'offline' | 'unknown';
export type ServiceStatus = 'active' | 'inactive' | 'failed' | 'unknown';

export interface User {
  id: string;
  username: string;
  display_name?: string;
  role: 'admin' | 'operator' | 'viewer' | 'auditor' | string;
}

export interface BootstrapStatus {
  required: boolean;
}

export interface EnrollmentToken {
  id: string;
  token: string;
  role: NodeRole;
  expiresAt: string;
}

export type ConfigStrategy = 'reload' | 'restart';

export interface ConfigRevision {
  id: string;
  node_id: string;
  version: number;
  content?: string;
  format: 'toml';
  mode?: string;
  sensitive_fields_detected?: string[];
  strategy: ConfigStrategy;
  sha256: string;
  created_by?: string;
  created_at: string;
  deployed_at?: string;
}

export interface SecretSummary {
  id: string;
  name: string;
  configured: boolean;
  key_version: number;
  created_at: string;
  updated_at: string;
}

export interface ManagedUser extends User {
  status: 'active' | 'disabled' | string;
  createdAt?: string;
  created_at?: string;
}

export interface AuditLog {
  id: string;
  actor: string;
  action: string;
  resource: string;
  request_id?: string;
  outcome?: 'success' | 'failure' | string;
  created_at: string;
}

export interface NodeSummary {
  id: string;
  name: string;
  hostname?: string;
  role: NodeRole;
  management_mode: 'observe' | 'managed';
  status: NodeStatus;
  service_status: ServiceStatus;
  frp_version?: string;
  agent_version?: string;
  capabilities?: string[];
  desired_revision?: string;
  observed_revision?: string;
  drifted?: boolean;
  last_heartbeat_at?: string;
  os?: string;
  arch?: string;
  labels?: Record<string, string>;
  created_at?: string;
}

export interface TaskStep {
  id?: string;
  name: string;
  status: string;
  started_at?: string;
  finished_at?: string;
  error_code?: string;
  error_message?: string;
}

export interface TaskSummary {
  id: string;
  type: string;
  status: string;
  node_id?: string;
  node_name?: string;
  actor?: string;
  progress?: number;
  error_code?: string;
  error_message?: string;
  created_at: string;
  started_at?: string;
  finished_at?: string;
  steps?: TaskStep[];
}

export interface AlertSummary {
  id: string;
  kind: string;
  severity: string;
  state: string;
  resource: string;
  fingerprint: string;
  message: string;
  created_at: string;
  updated_at: string;
  acknowledged_by?: string;
  acknowledged_at?: string;
  resolved_by?: string;
  resolved_at?: string;
  closed_by?: string;
  closed_at?: string;
}

export type RiskSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info' | string;
export type RiskState = 'open' | 'accepted' | 'resolved' | string;

export interface SecurityRisk {
  id: string;
  kind: string;
  severity: RiskSeverity;
  state: RiskState;
  node_id: string;
  evidence?: string;
  first_seen_at: string;
  last_seen_at: string;
  resolved_at?: string;
  repairable: boolean;
  allowed_actions: string[];
}

export interface ProxyTraffic {
  bytes_in: number;
  bytes_out: number;
  today_bytes_in: number;
  today_bytes_out: number;
  current_connections: number;
}

export interface ProxySummary {
  node_id: string;
  node_name: string;
  name: string;
  type: string;
  status: 'running' | 'offline' | 'error' | 'unknown' | string;
  local_address: string;
  remote_address: string;
  last_error: string;
  traffic: ProxyTraffic;
  collected_at: string;
}

export interface UpgradePlan {
  id: string;
  node_id: string;
  node_name?: string;
  version: string;
  artifact_url: string;
  sha256: string;
  state: 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled' | string;
  task_id: string;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface UpgradePlanResult {
  plan: UpgradePlan;
  task: TaskSummary;
}

export interface Page<T> {
  items: T[];
  next_cursor?: string;
  total?: number;
}

export interface DashboardSummary {
  nodes_total: number;
  nodes_online: number;
  nodes_healthy: number;
  nodes_drifted: number;
  alerts_firing: number;
  tasks_running: number;
}
