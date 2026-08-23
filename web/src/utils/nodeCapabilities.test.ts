import { describe, expect, it } from 'vitest';
import type { NodeSummary } from '../api/types';
import { assertNodeOperation, nodeOperationBlockedReason } from './nodeCapabilities';

const node: NodeSummary = {
  id: 'node-1', name: 'node-1', role: 'client', management_mode: 'managed', status: 'online', service_status: 'active', capabilities: [],
};

describe('node operation capability gates', () => {
  it('reports the first actionable reason', () => {
    const requirements = { capability: 'config.apply', label: '配置发布', requireManaged: true, role: 'operator' };
    expect(nodeOperationBlockedReason({ ...node, management_mode: 'observe', status: 'offline' }, requirements)).toBe('观察模式不允许执行配置发布');
    expect(nodeOperationBlockedReason({ ...node, status: 'offline' }, requirements)).toBe('Agent 离线，无法执行配置发布');
    expect(nodeOperationBlockedReason(node, requirements)).toBe('当前 Agent 或运行环境不支持配置发布');
    expect(nodeOperationBlockedReason({ ...node, capabilities: ['config.apply'] }, requirements)).toBe('');
  });

  it('throws before a request handler can bypass the gate', () => {
    expect(() => assertNodeOperation(node, { capability: 'frp.upgrade', label: 'frp 升级', requireManaged: true, role: 'operator' })).toThrow('当前 Agent 或运行环境不支持frp 升级');
  });
});
