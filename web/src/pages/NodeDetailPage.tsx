import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Button, Descriptions, Form, Input, message, Modal, Space, Tabs, Tag, Tooltip, Typography } from 'antd';
import { ArrowLeftOutlined, CaretRightOutlined, DatabaseOutlined, EyeOutlined, ReloadOutlined, SafetyCertificateOutlined, SearchOutlined, StopOutlined } from '@ant-design/icons';
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

export function NodeDetailPage() {
  const { id = '' } = useParams();
  const navigate = useNavigate();
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const [upgradeOpen, setUpgradeOpen] = useState(false);
  const [upgradeForm] = Form.useForm<{ version: string; artifact_url: string; sha256: string }>();
  const query = useQuery({ queryKey: ['nodes', id], queryFn: () => nodesApi.get(id), enabled: Boolean(id) });
  const inspect = useMutation({ mutationFn: () => nodesApi.inspect(id), onSuccess: (task) => { message.success('检查任务已创建'); void queryClient.invalidateQueries({ queryKey: ['tasks'] }); navigate(`/tasks/${task.id}`); }, onError: (error) => message.error(error.message) });
  const collectRuntime = useMutation({
    mutationFn: () => { assertNodeOperation(queryClient.getQueryData<NodeSummary>(['nodes', id]), { capability: 'runtime.collect', label: '运行态采集', role: user?.role }); return nodesApi.collectRuntime(id); },
    onSuccess: (task) => { message.success('运行态采集任务已创建'); void queryClient.invalidateQueries({ queryKey: ['tasks'] }); navigate(`/tasks/${task.id}`); },
    onError: (error) => message.error(error.message),
  });
  const upgrade = useMutation({
    mutationFn: (values: { version: string; artifact_url: string; sha256: string }) => upgradesApi.create({ node_id: id, ...values }),
    onSuccess: (result) => { setUpgradeOpen(false); upgradeForm.resetFields(); message.success('升级任务已创建'); void queryClient.invalidateQueries({ queryKey: ['tasks'] }); navigate(`/tasks/${result.task.id}`); },
    onError: (error) => message.error(error.message),
  });
  const latestRelease = useQuery({ queryKey: ['frp-release', id], queryFn: () => upgradesApi.latestForNode(id), enabled: upgradeOpen, staleTime: 5 * 60_000, retry: false });
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
  const agentOnline = node.status === 'online';
  const managed = node.management_mode === 'managed';
  const runtimeReason = nodeOperationBlockedReason(node, { capability: 'runtime.collect', label: '运行态采集', role: user?.role });
  const upgradeReason = nodeOperationBlockedReason(node, { capability: 'frp.upgrade', label: '升级 FRP', requireManaged: true, role: user?.role });
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
  const quickActions = () => <Space wrap>
    {user?.role === 'admin' && <Button icon={managed ? <EyeOutlined /> : <SafetyCertificateOutlined />} loading={updateMode.isPending} onClick={confirmMode}>{managed ? '切换为观察' : '切换为托管'}</Button>}
    {(Object.keys(serviceActions) as Array<keyof typeof serviceActions>).map((action) => { const reason = nodeOperationBlockedReason(node, { capability: `service.${action}`, label: `服务${serviceActions[action].label}`, requireManaged: true, role: user?.role }); return <Tooltip key={action} title={reason}><span><Button danger={serviceActions[action].danger} icon={serviceActions[action].icon} disabled={Boolean(reason)} loading={serviceAction.isPending && serviceAction.variables === action} onClick={() => confirmServiceAction(action)}>{serviceActions[action].label}</Button></span></Tooltip>; })}
    <Tooltip title={runtimeReason}><span><Button icon={<DatabaseOutlined />} disabled={Boolean(runtimeReason)} loading={collectRuntime.isPending} onClick={() => collectRuntime.mutate()}>采集运行态</Button></span></Tooltip>
    <Tooltip title={upgradeReason}><span><Button icon={<ReloadOutlined />} disabled={Boolean(upgradeReason)} onClick={() => { upgradeForm.resetFields(); setUpgradeOpen(true); }}>升级 FRP</Button></span></Tooltip>
    <Tooltip title={agentOnline ? '' : 'Agent 离线，无法立即检查'}><Button type="primary" icon={<SearchOutlined />} disabled={!agentOnline} loading={inspect.isPending} onClick={() => inspect.mutate()}>立即检查</Button></Tooltip>
  </Space>;
  const overview = <Space direction="vertical" size={16} style={{ width: '100%' }}>
    <div className="content-panel"><Descriptions bordered size="small" column={{ xs: 1, sm: 2, xl: 4 }} items={[
      { key: 'hostname', label: '主机名', children: node.name || node.hostname || '-' }, { key: 'role', label: '角色', children: <Tag>{node.role === 'server' ? 'frps' : 'frpc'}</Tag> }, { key: 'system', label: '系统', children: `${node.os || '-'} / ${node.arch || '-'}` }, { key: 'mode', label: '管理模式', children: <Tag color={managed ? 'blue' : 'default'}>{managed ? '托管' : '观察'}</Tag> },
      { key: 'connect', label: 'Agent 连接', children: <StatusTag value={node.status} /> }, { key: 'service', label: 'frp 服务', children: <StatusTag value={node.service_status} /> }, { key: 'heartbeat', label: '最后心跳', children: formatTime(node.last_heartbeat_at) }, { key: 'frp', label: 'frp 版本', children: node.frp_version || '-' },
      { key: 'agent', label: 'Agent 版本', children: node.agent_version || '-' }, { key: 'config-path', label: '配置文件', children: <Typography.Text code>{node.frp_config_path || '-'}</Typography.Text> }, { key: 'discovery', label: '配置发现', children: node.config_discovery_state || '-' }, { key: 'revision', label: '配置版本', children: <span className={node.drifted ? 'text-warning' : ''}>{node.observed_revision ?? '-'} / {node.desired_revision ?? '-'}</span> },
    ]} /></div>
    <div className="content-panel"><div className="section-title"><div><Typography.Title level={5}>常用操作</Typography.Title><Typography.Text type="secondary">服务控制、运行态采集、版本升级和健康检查</Typography.Text></div></div>{canMutate ? quickActions() : <Typography.Text type="secondary">当前角色没有远程操作权限。</Typography.Text>}</div>
  </Space>;
  return <div className="page-stack">
    <div className="page-heading"><Space><Button type="text" aria-label="返回" icon={<ArrowLeftOutlined />} onClick={() => navigate('/nodes')} /><div><Typography.Title level={3}>{node.name}</Typography.Title><Space><StatusTag value={node.status} /><Typography.Text type="secondary">{node.id}</Typography.Text></Space></div></Space></div>
    <Tabs items={[{ key: 'overview', label: '概览', children: overview }, { key: 'proxies', label: '代理', children: <InlineProxiesPanel nodeId={id} /> }, { key: 'config', label: '配置', children: <InlineConfigurationPanel node={node} /> }, { key: 'tasks', label: '任务', children: <InlineTasksPanel nodeId={id} /> }, { key: 'monitoring', label: '监控', children: <InlineMonitoringPanel nodeId={id} /> }]} />
    <Modal title={`升级 ${node.role === 'server' ? 'frps' : 'frpc'}`} open={upgradeOpen} okText="创建升级任务" cancelText="取消" confirmLoading={upgrade.isPending} onCancel={() => setUpgradeOpen(false)} onOk={() => upgradeForm.submit()} destroyOnHidden>
      <Typography.Paragraph type="secondary">升级会先下载并校验 SHA-256，再由 Agent 原子替换二进制并恢复服务。请使用官方制品地址和校验值，不要在生产节点上跳过校验。</Typography.Paragraph>
      <Space direction="vertical" style={{ width: '100%', marginBottom: 16 }}><Button onClick={() => void latestRelease.refetch()} loading={latestRelease.isFetching}>检查 GitHub 最新版本</Button>{latestRelease.data && <Typography.Text type="secondary">最新版本：{latestRelease.data.tag_name}{latestRelease.data.recommended ? `；已匹配 ${latestRelease.data.recommended.os}/${latestRelease.data.recommended.arch} 制品` : '；未找到带 SHA-256 的匹配制品'}</Typography.Text>}{latestRelease.data?.recommended && <Button type="link" onClick={() => { const asset = latestRelease.data!.recommended!; upgradeForm.setFieldsValue({ version: latestRelease.data!.tag_name, artifact_url: asset.url, sha256: asset.sha256 }); }}>使用匹配制品填充表单</Button>}</Space>
      <Form form={upgradeForm} layout="vertical" onFinish={(values) => upgrade.mutate(values)}><Form.Item name="version" label="目标版本" rules={[{ required: true, message: '请输入目标版本' }]}><Input placeholder="例如 v0.69.1" /></Form.Item><Form.Item name="artifact_url" label="制品 URL" rules={[{ required: true, type: 'url', message: '请输入有效的制品 URL' }]}><Input placeholder="https://.../frp_*.tar.gz" /></Form.Item><Form.Item name="sha256" label="SHA-256" rules={[{ required: true, len: 64, message: '请输入 64 位 SHA-256' }, { pattern: /^[a-fA-F0-9]+$/, message: 'SHA-256 只能包含十六进制字符' }]}><Input /></Form.Item></Form>
    </Modal>
  </div>;
}
