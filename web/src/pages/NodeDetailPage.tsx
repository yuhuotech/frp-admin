import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Button, Descriptions, message, Modal, Space, Tabs, Tag, Tooltip, Typography } from 'antd';
import { ArrowLeftOutlined, CaretRightOutlined, ReloadOutlined, StopOutlined } from '@ant-design/icons';
import { useNavigate, useParams } from 'react-router-dom';
import { nodesApi, upgradesApi } from '../api/resources';
import { PageError, PageLoading } from '../components/AsyncState';
import { StatusTag } from '../components/StatusTag';
import { formatTime } from '../utils/format';
import { useAuth } from '../app/AuthContext';
import { canOperate } from '../utils/permissions';
import type { NodeSummary } from '../api/types';
import { assertNodeOperation, nodeOperationBlockedReason } from '../utils/nodeCapabilities';
import { InlineConfigurationPanel, InlineMonitoringPanel, InlineProxiesPanel, InlineTasksPanel } from './NodeDetailPanels';

const serviceActions = {
  start: { label: '启动', icon: <CaretRightOutlined />, danger: false },
  stop: { label: '停止', icon: <StopOutlined />, danger: true },
  restart: { label: '重启', icon: <ReloadOutlined />, danger: true },
} as const;

function versionParts(value: string) {
  const normalized = value.trim().replace(/^v/i, '').split('-')[0];
  return normalized.split('.').map((part) => Number.parseInt(part, 10) || 0).slice(0, 3).concat([0, 0, 0]).slice(0, 3);
}
function isNewerVersion(current: string | undefined, latest: string | undefined) {
  if (!current || !latest) return false;
  const a = versionParts(current); const b = versionParts(latest);
  for (let i = 0; i < 3; i += 1) { if (b[i] !== a[i]) return b[i] > a[i]; }
  return false;
}

export function NodeDetailPage() {
  const { id = '' } = useParams();
  const navigate = useNavigate();
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const query = useQuery({ queryKey: ['nodes', id], queryFn: () => nodesApi.get(id), enabled: Boolean(id), refetchInterval: 15_000 });
  const latestRelease = useQuery({ queryKey: ['frp-release', id], queryFn: () => upgradesApi.latestForNode(id), enabled: Boolean(id), staleTime: 5 * 60_000, retry: false });
  const upgrade = useMutation({
    mutationFn: (input: { version: string; artifact_url: string; sha256: string }) => upgradesApi.create({ node_id: id, ...input }),
    onSuccess: (result) => { message.success('升级任务已创建'); void queryClient.invalidateQueries({ queryKey: ['tasks'] }); navigate(`/tasks/${result.task.id}`); },
    onError: (error) => message.error(error.message),
  });
  const serviceAction = useMutation({
    mutationFn: (action: keyof typeof serviceActions) => { assertNodeOperation(queryClient.getQueryData<NodeSummary>(['nodes', id]), { capability: `service.${action}`, label: `服务${serviceActions[action].label}`, requireManaged: true, role: user?.role }); return nodesApi.serviceAction(id, action); },
    onSuccess: (task, action) => { message.success(`${serviceActions[action].label}任务已创建`); void queryClient.invalidateQueries({ queryKey: ['tasks'] }); navigate(`/tasks/${task.id}`); },
    onError: (error) => message.error(error.message),
  });
  const updateMode = useMutation({
    mutationFn: (mode: 'observe' | 'managed') => nodesApi.updateManagementMode(id, mode),
    onSuccess: (updated) => { queryClient.setQueryData(['nodes', id], updated); void queryClient.invalidateQueries({ queryKey: ['nodes'] }); message.success(updated.management_mode === 'managed' ? '节点已切换为托管模式' : '节点已切换为观察模式'); },
    onError: (error) => message.error(error.message),
  });
  if (query.isLoading) return <PageLoading />;
  if (query.isError) return <PageError error={query.error} retry={() => void query.refetch()} />;
  const node = query.data!;
  const canMutate = canOperate(user?.role);
  const managed = node.management_mode === 'managed';
  const upgradeReason = nodeOperationBlockedReason(node, { capability: 'frp.upgrade', label: '升级 FRP', requireManaged: true, role: user?.role });
  const recommended = latestRelease.data?.recommended;
  const upgradeAvailable = Boolean(recommended && isNewerVersion(node.frp_version, latestRelease.data?.tag_name));
  const confirmServiceAction = (action: keyof typeof serviceActions) => {
    const reason = nodeOperationBlockedReason(node, { capability: `service.${action}`, label: `服务${serviceActions[action].label}`, requireManaged: true, role: user?.role });
    if (reason) { message.error(reason); return; }
    const item = serviceActions[action];
    Modal.confirm({ title: `${item.label} ${node.name} 的 frp 服务？`, content: '该操作会创建异步任务，执行结果会保留在该节点的操作记录中。', okText: `确认${item.label}`, okButtonProps: { danger: item.danger }, cancelText: '取消', onOk: () => serviceAction.mutateAsync(action) });
  };
  const confirmMode = () => {
    const mode = managed ? 'observe' : 'managed';
    Modal.confirm({ title: mode === 'managed' ? `托管 ${node.name}？` : `将 ${node.name} 切换为观察模式？`, content: mode === 'managed' ? '托管模式允许远程服务操作、配置发布和升级。' : '观察模式只采集状态，服务操作、配置变更和升级将被禁止。', okText: mode === 'managed' ? '确认托管' : '确认观察', okButtonProps: { danger: mode === 'managed' }, cancelText: '取消', onOk: () => updateMode.mutateAsync(mode) });
  };
  const confirmUpgrade = () => {
    if (upgradeReason) { message.error(upgradeReason); return; }
    if (!recommended || !latestRelease.data) { message.warning('尚未找到匹配当前节点系统和架构的升级制品'); return; }
    Modal.confirm({ title: `升级 ${node.role === 'server' ? 'frps' : 'frpc'} 到 ${latestRelease.data.tag_name}？`, content: <Space direction="vertical"><Typography.Text>系统已自动匹配当前节点的 {recommended.os}/{recommended.arch} 制品。</Typography.Text><Typography.Text type="secondary">SHA-256：{recommended.sha256}</Typography.Text><Typography.Text type="secondary">确认后会创建任务，由 Agent 下载、校验并原子替换二进制。</Typography.Text></Space>, okText: '确认升级', okButtonProps: { danger: true }, cancelText: '取消', onOk: () => upgrade.mutateAsync({ version: latestRelease.data!.tag_name, artifact_url: recommended.url, sha256: recommended.sha256 ?? '' }) });
  };
  const quickActions = () => <Space wrap>
    {(node.service_status === 'active' ? (['stop', 'restart'] as Array<keyof typeof serviceActions>) : node.service_status === 'inactive' || node.service_status === 'failed' ? (['start'] as Array<keyof typeof serviceActions>) : []).map((action) => { const reason = nodeOperationBlockedReason(node, { capability: `service.${action}`, label: `服务${serviceActions[action].label}`, requireManaged: true, role: user?.role }); return <Tooltip key={action} title={reason}><span><Button danger={serviceActions[action].danger} icon={serviceActions[action].icon} disabled={Boolean(reason)} loading={serviceAction.isPending && serviceAction.variables === action} onClick={() => confirmServiceAction(action)}>{serviceActions[action].label}</Button></span></Tooltip>; })}
    {upgradeAvailable && <Tooltip title={upgradeReason || `检测到新版本 ${latestRelease.data?.tag_name}`}><span><Button danger icon={<ReloadOutlined />} disabled={Boolean(upgradeReason) || upgrade.isPending} loading={upgrade.isPending} onClick={confirmUpgrade}>升级 FRP</Button></span></Tooltip>}
  </Space>;
  const overview = <Space direction="vertical" size={16} style={{ width: '100%' }}>
    <div className="content-panel"><Descriptions bordered size="small" column={{ xs: 1, sm: 2, xl: 4 }} items={[
      { key: 'hostname', label: '主机名', children: node.name || node.hostname || '-' }, { key: 'role', label: '角色', children: <Tag>{node.role === 'server' ? 'frps' : 'frpc'}</Tag> }, { key: 'system', label: '系统', children: `${node.os || '-'} / ${node.arch || '-'}` }, { key: 'mode', label: '管理模式', children: <Space><Tooltip title="托管模式允许远程服务操作、配置发布和升级；观察模式只读采集，不会修改节点。"><Tag color={managed ? 'blue' : 'default'}>{managed ? '托管' : '观察'}</Tag></Tooltip>{user?.role === 'admin' && <Button type="link" size="small" onClick={confirmMode}>修改</Button>}</Space> },
      { key: 'connect', label: 'Agent 连接', children: <StatusTag value={node.status} /> }, { key: 'service', label: 'frp 服务', children: <StatusTag value={node.service_status} /> }, { key: 'heartbeat', label: '最后心跳', children: formatTime(node.last_heartbeat_at) }, { key: 'frp', label: 'frp 版本', children: node.frp_version || '-' },
      { key: 'agent', label: 'Agent 版本', children: node.agent_version || '-' }, { key: 'config-path', label: '配置文件', children: <Typography.Text code>{node.frp_config_path || '-'}</Typography.Text> }, { key: 'discovery', label: '配置发现', children: node.config_discovery_state || '-' }, { key: 'revision', label: '配置版本', children: <span className={node.drifted ? 'text-warning' : ''}>{node.observed_revision ?? '-'} / {node.desired_revision ?? '-'}</span> },
    ]} /></div>
  </Space>;
  return <div className="page-stack">
    <div className="page-heading"><Space><Button type="text" aria-label="返回" icon={<ArrowLeftOutlined />} onClick={() => navigate('/nodes')} /><div><Typography.Title level={3}>{node.name}</Typography.Title><Space><StatusTag value={node.status} /><Typography.Text type="secondary">{node.id}</Typography.Text></Space></div></Space></div>{canMutate && quickActions()}
    <Tabs items={[{ key: 'overview', label: '概览', children: overview }, { key: 'proxies', label: '代理', children: <InlineProxiesPanel nodeId={id} /> }, { key: 'config', label: '配置', children: <InlineConfigurationPanel node={node} /> }, { key: 'tasks', label: '任务', children: <InlineTasksPanel nodeId={id} /> }, { key: 'monitoring', label: '监控', children: <InlineMonitoringPanel nodeId={id} /> }]} />
  </div>;
}
