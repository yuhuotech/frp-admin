import type { NodeSummary } from '../api/types';
import { canOperate } from './permissions';

interface NodeOperationRequirements {
  capability: string;
  label: string;
  requireManaged?: boolean;
  role?: string;
}

export function nodeOperationBlockedReason(node: NodeSummary | undefined, requirements: NodeOperationRequirements): string {
  if (!canOperate(requirements.role)) return `当前账号无权执行${requirements.label}`;
  if (!node) return '节点状态尚未加载';
  if (requirements.requireManaged && node.management_mode !== 'managed') return `观察模式不允许执行${requirements.label}`;
  if (node.status !== 'online') return `Agent 离线，无法执行${requirements.label}`;
  if (!node.capabilities?.includes(requirements.capability)) return `当前 Agent 或运行环境不支持${requirements.label}`;
  return '';
}

export function assertNodeOperation(node: NodeSummary | undefined, requirements: NodeOperationRequirements): void {
  const reason = nodeOperationBlockedReason(node, requirements);
  if (reason) throw new Error(reason);
}
