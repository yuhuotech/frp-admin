import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Alert, Button, Descriptions, Space, Spin, Table, Tag, Typography, message } from 'antd';
import { CloudUploadOutlined, EyeOutlined, ReloadOutlined, RollbackOutlined, SaveOutlined } from '@ant-design/icons';
import { Link } from 'react-router-dom';
import { configurationsApi, nodesApi, proxiesApi, tasksApi } from '../api/resources';
import type { ConfigRevision, ConfigStrategy, NodeSummary, ProxySummary, RuntimeSnapshot, TaskSummary } from '../api/types';
import { ConfigEditor } from '../components/ConfigEditor';
import { PageError } from '../components/AsyncState';
import { StatusTag } from '../components/StatusTag';
import { formatBytes } from '../utils/display';
import { formatTime } from '../utils/format';
import { useAuth } from '../app/AuthContext';
import { canOperate } from '../utils/permissions';
import { assertNodeOperation } from '../utils/nodeCapabilities';

export function InlineProxiesPanel({ nodeId }: { nodeId: string }) {
  const query = useQuery({ queryKey: ['node-proxies', nodeId], queryFn: () => proxiesApi.list({ nodeId, limit: 100 }), refetchInterval: 30_000 });
  if (query.isLoading) return <Spin />;
  if (query.isError) return <PageError error={query.error} retry={() => void query.refetch()} />;
  return <div className="content-panel table-panel"><div className="table-heading"><Typography.Text type="secondary">该节点当前运行中的代理，以及连接和流量状态</Typography.Text></div><Table<ProxySummary> rowKey="name" size="small" loading={query.isFetching} dataSource={query.data?.items} pagination={false} scroll={{ x: 900 }} locale={{ emptyText: '暂无运行态代理，请先执行“采集运行态”' }} columns={[{ title: '代理', dataIndex: 'name', render: (value) => <Typography.Text code>{value}</Typography.Text> }, { title: '类型', dataIndex: 'type', render: (value) => <Tag>{value}</Tag> }, { title: '状态', dataIndex: 'status', render: (value) => <StatusTag value={value} /> }, { title: '本地端点', dataIndex: 'local_address', render: (value) => <span className="mono">{value || '-'}</span> }, { title: '远端端点', dataIndex: 'remote_address', render: (value) => <span className="mono">{value || '-'}</span> }, { title: '连接', render: (_, row) => row.traffic?.current_connections ?? 0 }, { title: '流量', render: (_, row) => `${formatBytes(row.traffic?.bytes_in)} / ${formatBytes(row.traffic?.bytes_out)}` }, { title: '错误', dataIndex: 'last_error', render: (value) => value || '-' }]} /></div>;
}

export function InlineConfigurationPanel({ node }: { node: NodeSummary }) {
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const canWrite = canOperate(user?.role) && node.management_mode === 'managed';
  const [editorRevision, setEditorRevision] = useState<ConfigRevision>();
  const revisions = useQuery({ queryKey: ['config-revisions', node.id], queryFn: () => configurationsApi.list(node.id), gcTime: 0 });
  const rows = useMemo(() => [...(revisions.data?.items ?? [])].sort((a, b) => b.version - a.version), [revisions.data]);
  const latest = rows[0];
  const content = useQuery({ queryKey: ['config-revision-content', editorRevision?.id], queryFn: () => configurationsApi.content(editorRevision!.id), enabled: Boolean(editorRevision), gcTime: 0 });
  const save = useMutation({ mutationFn: ({ value, strategy }: { value: string; strategy: ConfigStrategy }) => configurationsApi.create(node.id, value, strategy), onSuccess: async () => { message.success('配置修订已保存'); await queryClient.invalidateQueries({ queryKey: ['config-revisions', node.id] }); }, onError: (error) => message.error(error.message) });
  const deploy = useMutation({ mutationFn: (revision: ConfigRevision) => { assertNodeOperation(node, { capability: 'config.apply', label: '配置发布', requireManaged: true, role: user?.role }); return configurationsApi.deploy(revision.id); }, onSuccess: async (task) => { message.success(`配置发布任务 ${task.id.slice(0, 8)} 已创建`); await queryClient.invalidateQueries({ queryKey: ['tasks'] }); }, onError: (error) => message.error(error.message) });
  const rollback = useMutation({ mutationFn: (revision: ConfigRevision) => { assertNodeOperation(node, { capability: 'config.rollback', label: '配置回滚', requireManaged: true, role: user?.role }); return configurationsApi.rollback(node.id, revision.id); }, onSuccess: (task) => message.success(`配置回滚任务 ${task.id.slice(0, 8)} 已创建`), onError: (error) => message.error(error.message) });
  if (revisions.isLoading) return <Spin />;
  if (revisions.isError) return <PageError error={revisions.error} retry={() => void revisions.refetch()} />;
  const writeHint = node.management_mode === 'managed' ? '' : '观察模式只能查看，切换到托管模式后才能保存和发布。';
  return <Space direction="vertical" size={16} style={{ width: '100%' }}><Alert type={node.config_discovery_state === 'unavailable' ? 'warning' : 'info'} showIcon message={writeHint || '配置以版本修订形式管理'} description={writeHint || `Agent 已发现配置文件：${node.frp_config_path || '未上报路径'}。保存只生成修订，发布才会改变节点服务。`} />{latest && <div className="content-panel"><div className="section-title"><div><Typography.Title level={5}>当前配置</Typography.Title><Typography.Text type="secondary">选择版本查看完整 TOML 内容</Typography.Text></div><Space>{canWrite && <Button icon={<SaveOutlined />} onClick={() => setEditorRevision(latest)}>载入最新版本编辑</Button>}<Button icon={<ReloadOutlined />} onClick={() => void revisions.refetch()}>刷新</Button></Space></div>{content.isLoading ? <Spin /> : editorRevision ? <ConfigEditor key={editorRevision.id} initialContent={content.data?.content ?? ''} initialStrategy={editorRevision.strategy} canWrite={canWrite} saving={save.isPending} onSave={(value, strategy) => save.mutate({ value, strategy })} /> : <Typography.Text type="secondary">点击“载入最新版本编辑”查看配置内容。</Typography.Text>}</div>}<div className="content-panel table-panel"><div className="table-heading"><Typography.Title level={5}>配置修订历史</Typography.Title></div><Table<ConfigRevision> rowKey="id" size="small" dataSource={rows} pagination={{ pageSize: 5 }} columns={[{ title: '版本', dataIndex: 'version', render: (value, row) => <Space><strong>v{value}</strong>{node.desired_revision === row.id && <Tag color="blue">目标版本</Tag>}</Space> }, { title: '来源', dataIndex: 'mode', render: (value) => <Tag>{value || 'raw'}</Tag> }, { title: '策略', dataIndex: 'strategy' }, { title: 'SHA-256', dataIndex: 'sha256', render: (value) => <Typography.Text code>{value ? `${value.slice(0, 12)}…` : '-'}</Typography.Text> }, { title: '创建时间', dataIndex: 'created_at', render: formatTime }, { title: '操作', render: (_, row) => <Space><Button size="small" icon={<EyeOutlined />} onClick={() => setEditorRevision(row)}>查看</Button><Button size="small" type="primary" icon={<CloudUploadOutlined />} disabled={!canWrite || deploy.isPending} onClick={() => deploy.mutate(row)}>发布</Button>{node.desired_revision && node.desired_revision !== row.id && <Button size="small" danger icon={<RollbackOutlined />} disabled={!canWrite || rollback.isPending} onClick={() => rollback.mutate(row)}>回滚</Button>}</Space> }]} /></div></Space>;
}

export function InlineTasksPanel({ nodeId }: { nodeId: string }) {
  const query = useQuery({ queryKey: ['node-tasks', nodeId], queryFn: () => tasksApi.list(`nodeId=${encodeURIComponent(nodeId)}&limit=50`), refetchInterval: 10_000 });
  if (query.isLoading) return <Spin />;
  if (query.isError) return <PageError error={query.error} retry={() => void query.refetch()} />;
  return <div className="content-panel table-panel"><div className="table-heading"><Typography.Text type="secondary">该节点的服务、配置、升级和采集操作记录</Typography.Text></div><Table<TaskSummary> rowKey="id" size="small" dataSource={query.data?.items} pagination={{ pageSize: 8 }} locale={{ emptyText: '暂无操作记录' }} columns={[{ title: '操作', dataIndex: 'type' }, { title: '状态', dataIndex: 'status', render: (value) => <StatusTag value={value} /> }, { title: '发起人', dataIndex: 'actor', render: (value) => value || '-' }, { title: '创建时间', dataIndex: 'created_at', render: formatTime }, { title: '详情', render: (_, row) => <Link to={`/tasks/${row.id}`}>查看</Link> }]} /></div>;
}

export function InlineMonitoringPanel({ nodeId }: { nodeId: string }) {
  const query = useQuery({ queryKey: ['node-runtime', nodeId], queryFn: () => nodesApi.runtime(nodeId), refetchInterval: 30_000 });
  if (query.isLoading) return <Spin />;
  if (query.isError) return <PageError error={query.error} retry={() => void query.refetch()} />;
  const runtime = query.data as RuntimeSnapshot;
  return <Space direction="vertical" size={16} style={{ width: '100%' }}><div className="content-panel"><Descriptions bordered size="small" column={{ xs: 1, sm: 2, xl: 4 }} items={[{ key: 'version', label: 'frp 版本', children: runtime.frp_version || '-' }, { key: 'bind', label: '绑定地址', children: `${runtime.bind_address || '-'}:${runtime.bind_port || '-'}` }, { key: 'proxy', label: '代理数量', children: runtime.proxy_count }, { key: 'client', label: '客户端连接', children: runtime.client_count }, { key: 'time', label: '采集时间', children: formatTime(runtime.collected_at) }]} /></div><div className="content-panel table-panel"><div className="table-heading"><Typography.Title level={5}>运行态代理</Typography.Title></div><Table<ProxySummary> rowKey="name" size="small" dataSource={runtime.proxies} pagination={false} locale={{ emptyText: '暂无运行态代理' }} columns={[{ title: '代理', dataIndex: 'name' }, { title: '类型', dataIndex: 'type' }, { title: '状态', dataIndex: 'status', render: (value) => <StatusTag value={value} /> }, { title: '本地端点', dataIndex: 'local_address' }, { title: '远端端点', dataIndex: 'remote_address' }]} /></div>{runtime.clients?.length > 0 && <div className="content-panel table-panel"><div className="table-heading"><Typography.Title level={5}>FRP 客户端连接</Typography.Title></div><Table rowKey="id" size="small" dataSource={runtime.clients} pagination={false} columns={[{ title: '客户端 ID', dataIndex: 'id' }, { title: '地址', dataIndex: 'address' }, { title: '连接时间', dataIndex: 'connected_at', render: formatTime }]} /></div>}</Space>;
}
