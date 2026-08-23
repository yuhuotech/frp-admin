import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { NodeSummary } from '../api/types';
import { configurationsApi, nodesApi, upgradesApi } from '../api/resources';
import { NodeConfigurationPage } from './NodeConfigurationPage';
import { NodeDetailPage } from './NodeDetailPage';
import { UpgradesPage } from './UpgradesPage';

vi.mock('../app/AuthContext', () => ({ useAuth: () => ({ user: { id: 'u1', username: 'ops', role: 'operator' } }) }));

const node: NodeSummary = {
  id: 'node-1', name: 'edge-client', role: 'client', management_mode: 'managed', status: 'online', service_status: 'active', capabilities: [], desired_revision: 'revision-current',
};

function renderRoute(element: React.ReactNode, route: string, path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<MemoryRouter initialEntries={[route]}><QueryClientProvider client={client}><Routes><Route path={path} element={element} /></Routes></QueryClientProvider></MemoryRouter>);
}

describe('non-risk capability gates', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('blocks service mutations and runtime collection on the node detail page', async () => {
    vi.spyOn(nodesApi, 'get').mockResolvedValue(node);
    const service = vi.spyOn(nodesApi, 'serviceAction').mockResolvedValue({ id: 'task-1', type: 'service_start', status: 'queued', created_at: '' });
    const runtime = vi.spyOn(nodesApi, 'collectRuntime').mockResolvedValue({ id: 'task-2', type: 'collect_runtime', status: 'queued', created_at: '' });
    const user = userEvent.setup();
    renderRoute(<NodeDetailPage />, '/nodes/node-1', '/nodes/:id');

    const start = (await screen.findByText('启动')).closest('button')!;
    const collect = screen.getByText('采集运行态').closest('button')!;
    expect(start).toBeDisabled();
    expect(collect).toBeDisabled();
    await user.hover(start.parentElement!);
    expect(await screen.findByText('当前 Agent 或运行环境不支持服务启动')).toBeInTheDocument();
    await user.click(start);
    await user.click(collect);
    expect(service).not.toHaveBeenCalled();
    expect(runtime).not.toHaveBeenCalled();
  });

  it('blocks config apply and rollback on the configuration page', async () => {
    vi.spyOn(nodesApi, 'get').mockResolvedValue(node);
    vi.spyOn(configurationsApi, 'list').mockResolvedValue({ items: [{ id: 'revision-old', node_id: node.id, version: 1, format: 'toml', sha256: 'a'.repeat(64), strategy: 'restart', created_at: '2026-07-29T00:00:00Z' }] });
    const deploy = vi.spyOn(configurationsApi, 'deploy').mockResolvedValue({ id: 'task-1', type: 'config_apply', status: 'queued', created_at: '' });
    const rollback = vi.spyOn(configurationsApi, 'rollback').mockResolvedValue({ id: 'task-2', type: 'config_rollback', status: 'queued', created_at: '' });
    const user = userEvent.setup();
    renderRoute(<NodeConfigurationPage />, '/nodes/node-1/configuration', '/nodes/:id/configuration');

    const publish = (await screen.findByText('发布')).closest('button')!;
    const rollbackButton = screen.getByText('回滚').closest('button')!;
    expect(publish).toBeDisabled();
    expect(rollbackButton).toBeDisabled();
    await user.hover(publish.parentElement!);
    expect(await screen.findByText('当前 Agent 或运行环境不支持配置发布')).toBeInTheDocument();
    await user.click(publish);
    await user.click(rollbackButton);
    expect(deploy).not.toHaveBeenCalled();
    expect(rollback).not.toHaveBeenCalled();
  });

  it('blocks upgrade creation when no eligible node advertises frp.upgrade', async () => {
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [node] });
    vi.spyOn(upgradesApi, 'list').mockResolvedValue({ items: [] });
    const create = vi.spyOn(upgradesApi, 'create').mockResolvedValue({ plan: { id: 'plan-1', node_id: node.id, version: 'v1', artifact_url: '', sha256: '', state: 'queued', task_id: 'task-1', created_by: 'u1', created_at: '', updated_at: '' }, task: { id: 'task-1', type: 'frp_upgrade', status: 'queued', created_at: '' } });
    const user = userEvent.setup();
    renderRoute(<UpgradesPage />, '/upgrades', '/upgrades');

    const button = (await screen.findByText('新建升级')).closest('button')!;
    expect(button).toBeDisabled();
    await user.hover(button.parentElement!);
    expect(await screen.findByText('没有在线且支持 frp 升级的托管节点')).toBeInTheDocument();
    await user.click(button);
    expect(create).not.toHaveBeenCalled();
  });
});
