import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { nodesApi, securityRisksApi } from '../api/resources';
import { RisksPage } from './RisksPage';

const auth = vi.hoisted(() => ({ role: 'operator' }));
vi.mock('../app/AuthContext', () => ({ useAuth: () => ({ user: { id: 'u1', username: 'ops', role: auth.role } }) }));

const node = {
  id: 'node-1', name: 'frps-main', role: 'server' as const, management_mode: 'managed' as const,
  status: 'online' as const, service_status: 'active' as const, capabilities: ['risk.scan', 'risk.repair.admin_loopback'],
};

function renderPage() {
  return render(<MemoryRouter><QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><RisksPage /></QueryClientProvider></MemoryRouter>);
}

describe('RisksPage', () => {
  beforeEach(() => {
    vi.spyOn(nodesApi, 'list').mockResolvedValue({ items: [node] });
    vi.spyOn(securityRisksApi, 'list').mockResolvedValue({ items: [{
      id: 'risk-1', node_id: node.id, kind: 'admin_api_non_loopback', severity: 'high', state: 'open',
      evidence: '管理 API 正在监听非 loopback 地址', first_seen_at: '2026-07-28T01:00:00Z', last_seen_at: '2026-07-29T01:00:00Z',
      repairable: true, allowed_actions: ['bind_admin_api_loopback'],
    }] });
  });

  it('allows an operator to scan but not restart frps through repair', async () => {
    auth.role = 'operator';
    const user = userEvent.setup();
    renderPage();
    expect(await screen.findByRole('button', { name: /发起扫描/ })).toBeEnabled();
    await user.click(await screen.findByText('管理 API 对非本机地址监听'));
    expect(await screen.findByText('该修复会重启 frps，仅管理员可执行')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /改绑本机地址/ })).not.toBeInTheDocument();
  });

  it('blocks repair when a node is in observe mode', async () => {
    auth.role = 'admin';
    vi.mocked(nodesApi.list).mockResolvedValue({ items: [{ ...node, management_mode: 'observe' }] });
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByText('管理 API 对非本机地址监听'));
    expect(await screen.findByText('观察模式只允许扫描，请先将节点切换为托管模式')).toBeInTheDocument();
  });
});
