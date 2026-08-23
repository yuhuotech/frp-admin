import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Button, Form, Input, message, Modal, Segmented, Select, Space, Table, Tooltip, Typography } from 'antd';
import { PlusOutlined, ReloadOutlined, StopOutlined } from '@ant-design/icons';
import { Link } from 'react-router-dom';
import { nodesApi, upgradesApi } from '../api/resources';
import { PageError } from '../components/AsyncState';
import { StatusTag } from '../components/StatusTag';
import { sanitizeArtifactURL } from '../utils/display';
import { formatTime } from '../utils/format';
import type { NodeSummary, UpgradePlan } from '../api/types';
import { assertNodeOperation, nodeOperationBlockedReason } from '../utils/nodeCapabilities';
import { useAuth } from '../app/AuthContext';

interface UpgradeForm { node_id: string; version: string; artifact_url: string; sha256: string }

export function UpgradesPage() {
  const [state, setState] = useState('');
  const [nodeId, setNodeId] = useState('');
  const [cursor, setCursor] = useState<string>();
  const [history, setHistory] = useState<string[]>([]);
  const [createOpen, setCreateOpen] = useState(false);
  const [form] = Form.useForm<UpgradeForm>();
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const nodes = useQuery({ queryKey: ['nodes', 'upgrade-filter'], queryFn: () => nodesApi.list('limit=200') });
  const allNodes = nodes.data?.items ?? [];
  const upgradeReason = (node: NodeSummary | undefined) => nodeOperationBlockedReason(node, { capability: 'frp.upgrade', label: 'frp 升级', requireManaged: true, role: user?.role });
  const eligibleNodes = allNodes.filter((node) => !upgradeReason(node));
  const createBlockedReason = nodes.isLoading ? '正在加载节点状态' : nodes.isError ? '节点状态加载失败' : eligibleNodes.length ? '' : '没有在线且支持 frp 升级的托管节点';
  const query = useQuery({ queryKey: ['upgrade-plans', nodeId, state, cursor], queryFn: () => upgradesApi.list({ nodeId, state, cursor, limit: 50 }), refetchInterval: 10_000 });
  const create = useMutation({
    mutationFn: (values: UpgradeForm) => {
      const latest = queryClient.getQueryData<{ items: NodeSummary[] }>(['nodes', 'upgrade-filter'])?.items.find((node) => node.id === values.node_id);
      assertNodeOperation(latest, { capability: 'frp.upgrade', label: 'frp 升级', requireManaged: true, role: user?.role });
      return upgradesApi.create(values);
    },
    onSuccess: ({ task }) => { setCreateOpen(false); form.resetFields(); message.success('升级任务已创建'); void queryClient.invalidateQueries({ queryKey: ['upgrade-plans'] }); void queryClient.invalidateQueries({ queryKey: ['tasks'] }); message.info(<span>任务 <Link to={`/tasks/${task.id}`}>{task.id}</Link> 已进入队列</span>); },
    onError: (error) => message.error(error.message),
  });
  const cancel = useMutation({
    mutationFn: upgradesApi.cancel,
    onSuccess: () => { message.success('升级计划已取消'); void queryClient.invalidateQueries({ queryKey: ['upgrade-plans'] }); void queryClient.invalidateQueries({ queryKey: ['tasks'] }); },
    onError: (error) => message.error(error.message),
  });
  const submit = (values: UpgradeForm) => {
    const selected = allNodes.find((node) => node.id === values.node_id);
    const reason = upgradeReason(selected);
    if (reason) { message.error(reason); return; }
    const nodeName = selected?.name || values.node_id;
    Modal.confirm({
      title: `升级 ${nodeName} 到 ${values.version}？`,
      content: <Space direction="vertical" size={4}><Typography.Text>制品：<span className="mono">{sanitizeArtifactURL(values.artifact_url)}</span></Typography.Text><Typography.Text>SHA256：<span className="mono">{values.sha256}</span></Typography.Text></Space>,
      okText: '确认升级', cancelText: '取消', onOk: () => create.mutateAsync(values),
    });
  };
  const confirmCancel = (plan: UpgradePlan) => Modal.confirm({ title: `取消 ${plan.version} 升级？`, content: '已在 Agent 执行的步骤可能无法中断。', okText: '确认取消', okButtonProps: { danger: true }, cancelText: '返回', onOk: () => cancel.mutateAsync(plan.id) });
  const resetPage = () => { setCursor(undefined); setHistory([]); };
  const next = () => { if (query.data?.next_cursor) { setHistory((value) => [...value, cursor ?? '']); setCursor(query.data.next_cursor); } };
  const previous = () => { const prior = history.at(-1); setHistory((value) => value.slice(0, -1)); setCursor(prior || undefined); };
  return <div className="page-stack">
    <div className="page-heading"><div><Typography.Title level={3}>升级计划</Typography.Title><Typography.Text type="secondary">单节点 frp 制品升级与执行历史</Typography.Text></div><Space><Tooltip title={createBlockedReason}><span><Button type="primary" icon={<PlusOutlined />} disabled={Boolean(createBlockedReason)} onClick={() => setCreateOpen(true)}>新建升级</Button></span></Tooltip><Button icon={<ReloadOutlined />} loading={query.isFetching} onClick={() => void query.refetch()}>刷新</Button></Space></div>
    <div className="toolbar"><Select aria-label="节点" allowClear showSearch optionFilterProp="label" placeholder="全部节点" value={nodeId || undefined} onChange={(value) => { setNodeId(value ?? ''); resetPage(); }} loading={nodes.isLoading} options={nodes.data?.items.map((node) => ({ value: node.id, label: node.name }))} style={{ width: 220 }} /><Segmented aria-label="升级状态" value={state} onChange={(value) => { setState(value); resetPage(); }} options={[{ label: '全部', value: '' }, { label: '排队中', value: 'queued' }, { label: '执行中', value: 'running' }, { label: '成功', value: 'succeeded' }, { label: '失败', value: 'failed' }, { label: '已取消', value: 'cancelled' }]} /></div>
    {query.isError ? <PageError error={query.error} retry={() => void query.refetch()} /> : <div className="content-panel table-panel"><Table<UpgradePlan> rowKey="id" size="middle" loading={query.isLoading} dataSource={query.data?.items} scroll={{ x: 1200 }} locale={{ emptyText: '暂无升级历史' }} columns={[
      { title: '节点', dataIndex: 'node_name', width: 160, render: (value, row) => value || row.node_id },
      { title: '目标版本', dataIndex: 'version', width: 130 },
      { title: '状态', dataIndex: 'state', width: 100, render: (value) => <StatusTag value={value} /> },
      { title: '制品', dataIndex: 'artifact_url', ellipsis: true, width: 260, render: (value) => <span className="mono">{sanitizeArtifactURL(value)}</span> },
      { title: 'SHA256', dataIndex: 'sha256', ellipsis: true, width: 180, render: (value) => <span className="mono">{value}</span> },
      { title: '任务', dataIndex: 'task_id', width: 150, render: (value) => value ? <Link to={`/tasks/${value}`}>{value}</Link> : '-' },
      { title: '创建时间', dataIndex: 'created_at', width: 170, render: formatTime },
      { title: '操作', fixed: 'right', width: 100, render: (_, row) => ['queued', 'running'].includes(row.state) ? <Button type="link" danger icon={<StopOutlined />} loading={cancel.isPending && cancel.variables === row.id} onClick={() => confirmCancel(row)}>取消</Button> : '-' },
    ]} pagination={false} /><div className="cursor-pagination"><Typography.Text type="secondary">每页最多 50 条</Typography.Text><Space><Button disabled={!history.length || query.isFetching} onClick={previous}>上一页</Button><Button disabled={!query.data?.next_cursor || query.isFetching} onClick={next}>下一页</Button></Space></div></div>}
    <Modal title="新建单节点升级" open={createOpen} footer={null} destroyOnHidden onCancel={() => { if (!create.isPending) { setCreateOpen(false); form.resetFields(); } }}>
      <Form form={form} layout="vertical" onFinish={submit}>
        <Form.Item name="node_id" label="节点" rules={[{ required: true, message: '请选择节点' }]}><Select showSearch optionFilterProp="label" placeholder="选择在线且支持升级的托管节点" loading={nodes.isLoading} options={allNodes.map((node) => { const reason = upgradeReason(node); return { value: node.id, label: reason ? `${node.name}（${reason}）` : node.name, disabled: Boolean(reason), title: reason }; })} /></Form.Item>
        <Form.Item name="version" label="目标版本" rules={[{ required: true, whitespace: true, message: '请输入目标版本' }, { max: 64 }]}><Input placeholder="例如 0.61.0" autoComplete="off" /></Form.Item>
        <Form.Item name="artifact_url" label="制品 URL" rules={[{ required: true, message: '请输入 HTTPS 制品 URL' }, { validator: async (_, value) => { try { if (new URL(value).protocol !== 'https:') throw new Error(); } catch { throw new Error('仅允许有效的 HTTPS URL'); } } }]}><Input placeholder="https://cdn.example/frp.tar.gz" autoComplete="off" /></Form.Item>
        <Form.Item name="sha256" label="SHA256" rules={[{ required: true, message: '请输入 SHA256' }, { pattern: /^[a-fA-F0-9]{64}$/, message: 'SHA256 必须为 64 位十六进制' }]}><Input className="mono" autoComplete="off" /></Form.Item>
        <Space><Button type="primary" htmlType="submit" loading={create.isPending}>创建升级任务</Button><Button onClick={() => { setCreateOpen(false); form.resetFields(); }}>取消</Button></Space>
      </Form>
    </Modal>
  </div>;
}
