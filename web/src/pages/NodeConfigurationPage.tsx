import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Alert, Button, Descriptions, message, Modal, Space, Spin, Table, Tag, Tooltip, Typography } from 'antd';
import { ArrowLeftOutlined, CloudDownloadOutlined, CloudUploadOutlined, EyeOutlined, RollbackOutlined } from '@ant-design/icons';
import { useNavigate, useParams } from 'react-router-dom';
import { configurationsApi, nodesApi } from '../api/resources';
import type { ConfigRevision, ConfigStrategy } from '../api/types';
import { useAuth } from '../app/AuthContext';
import { ConfigEditor } from '../components/ConfigEditor';
import { EmptyState, PageError, PageLoading } from '../components/AsyncState';
import { formatTime } from '../utils/format';
import type { NodeSummary } from '../api/types';
import { assertNodeOperation, nodeOperationBlockedReason } from '../utils/nodeCapabilities';

function strategyLabel(strategy: ConfigStrategy) {
  return strategy === 'restart' ? 'Restart（重启进程）' : 'Reload（热加载）';
}

export function NodeConfigurationPage() {
  const { id = '' } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { user } = useAuth();
  const hasWriteRole = user?.role === 'admin' || user?.role === 'operator';
  const [viewing, setViewing] = useState<ConfigRevision>();
  const [editorRevision, setEditorRevision] = useState<ConfigRevision>();
  const node = useQuery({ queryKey: ['nodes', id], queryFn: () => nodesApi.get(id), enabled: Boolean(id) });
  const canWrite = hasWriteRole && node.data?.management_mode === 'managed';
  const revisions = useQuery({ queryKey: ['config-revisions', id], queryFn: () => configurationsApi.list(id), enabled: Boolean(id), gcTime: 0 });
  const editorContent = useQuery({ queryKey: ['config-revision-content', editorRevision?.id], queryFn: () => configurationsApi.content(editorRevision!.id), enabled: Boolean(editorRevision), gcTime: 0 });
  const viewedContent = useQuery({ queryKey: ['config-revision-content', viewing?.id], queryFn: () => configurationsApi.content(viewing!.id), enabled: Boolean(viewing), gcTime: 0 });
  const rows = useMemo(() => [...(revisions.data?.items ?? [])].sort((a, b) => b.version - a.version), [revisions.data]);
  const latest = rows[0];
  const save = useMutation({
    mutationFn: ({ content, strategy }: { content: string; strategy: ConfigStrategy }) => configurationsApi.create(id, content, strategy),
    onSuccess: async (revision) => {
      message.success('配置修订已保存');
      if (revision.sensitive_fields_detected?.length) message.warning(`检测到敏感字段：${revision.sensitive_fields_detected.join('、')}。请改用 Secret 引用。`, 8);
      await queryClient.invalidateQueries({ queryKey: ['config-revisions', id] });
    },
    onError: (error) => message.error(error.message),
  });
  const deploy = useMutation({
    mutationFn: (revision: ConfigRevision) => {
      assertNodeOperation(queryClient.getQueryData<NodeSummary>(['nodes', id]), { capability: 'config.apply', label: '配置发布', requireManaged: true, role: user?.role });
      return configurationsApi.deploy(revision.id);
    },
    onSuccess: (task) => { message.success('发布任务已创建'); navigate(`/tasks/${task.id}`); },
    onError: (error) => message.error(error.message),
  });
  const rollback = useMutation({
    mutationFn: (revision: ConfigRevision) => {
      assertNodeOperation(queryClient.getQueryData<NodeSummary>(['nodes', id]), { capability: 'config.rollback', label: '配置回滚', requireManaged: true, role: user?.role });
      return configurationsApi.rollback(id, revision.id);
    },
    onSuccess: (task) => { message.success('回滚任务已创建'); navigate(`/tasks/${task.id}`); },
    onError: (error) => message.error(error.message),
  });
  if (node.isLoading || revisions.isLoading) return <PageLoading />;
  if (node.isError) return <PageError error={node.error} retry={() => void node.refetch()} />;
  if (revisions.isError) return <PageError error={revisions.error} retry={() => void revisions.refetch()} />;
  const confirmDeploy = (revision: ConfigRevision) => {
    const reason = nodeOperationBlockedReason(node.data, { capability: 'config.apply', label: '配置发布', requireManaged: true, role: user?.role });
    if (reason) { message.error(reason); return; }
    Modal.confirm({
    title: `发布配置修订 v${revision.version}？`,
    content: `节点 ${node.data!.name} 将执行 ${strategyLabel(revision.strategy)}。发布会创建异步任务，失败时由 Agent 自动回滚。`,
    okText: `确认 ${revision.strategy === 'restart' ? 'Restart' : 'Reload'}`,
    cancelText: '取消',
    onOk: () => deploy.mutateAsync(revision),
    });
  };
  const confirmRollback = (revision: ConfigRevision) => {
    const reason = nodeOperationBlockedReason(node.data, { capability: 'config.rollback', label: '配置回滚', requireManaged: true, role: user?.role });
    if (reason) { message.error(reason); return; }
    Modal.confirm({
    title: `回滚到配置修订 v${revision.version}？`,
    content: `节点 ${node.data!.name} 将回滚到 SHA ${revision.sha256.slice(0, 12)}…，并按 ${strategyLabel(revision.strategy)} 生效。`,
    icon: <RollbackOutlined />,
    okText: '确认回滚',
    okButtonProps: { danger: true },
    cancelText: '取消',
    onOk: () => rollback.mutateAsync(revision),
    });
  };
  return <div className="page-stack">
    <div className="page-heading"><Space><Button type="text" aria-label="返回节点详情" icon={<ArrowLeftOutlined />} onClick={() => navigate(`/nodes/${id}`)} /><div><Typography.Title level={3}>{node.data!.name} / 配置</Typography.Title><Typography.Text type="secondary">TOML 修订、发布与回滚</Typography.Text></div></Space></div>
    {node.data!.management_mode !== 'managed' && <Alert type="info" showIcon message="节点处于观察模式" description="可查看配置修订元数据，但不能编辑、发布或回滚。请由管理员在节点详情切换为托管模式。" />}
    {canWrite && latest && <div><Button icon={<CloudDownloadOutlined />} loading={editorContent.isFetching} onClick={() => setEditorRevision(latest)}>载入最新版本到编辑器</Button></div>}
    {editorContent.isError && <Alert type="error" showIcon title="配置内容加载失败" description="无法读取配置正文，请检查权限或服务状态。" action={<Button onClick={() => void editorContent.refetch()}>重试</Button>} />}
    <ConfigEditor key={`${editorRevision?.id ?? 'new'}:${Boolean(editorContent.data)}`} initialContent={editorContent.data?.content ?? ''} initialStrategy={editorRevision?.strategy ?? 'reload'} canWrite={canWrite && !editorContent.isFetching} saving={save.isPending} onSave={(content, strategy) => save.mutate({ content, strategy })} />
    <section className="content-panel table-panel">
      <div className="section-title table-heading"><div><Typography.Title level={5}>修订历史</Typography.Title><Typography.Text type="secondary">已保存的修订不可修改</Typography.Text></div></div>
      {rows.length === 0 ? <EmptyState description="尚未保存配置修订" /> : <Table<ConfigRevision> rowKey="id" size="middle" pagination={{ pageSize: 10 }} dataSource={rows} scroll={{ x: 970 }} columns={[
        { title: '版本', dataIndex: 'version', width: 100, render: (value, revision) => <Space><strong>v{value}</strong>{node.data!.desired_revision === revision.id && <Tag color="blue">目标版本</Tag>}</Space> },
        { title: '模式 / 策略', width: 145, render: (_, revision) => <Space size={4}><Tag>{revision.mode || 'raw'}</Tag><Tag color={revision.strategy === 'restart' ? 'orange' : 'green'}>{revision.strategy}</Tag></Space> },
        { title: 'SHA-256', dataIndex: 'sha256', width: 210, render: (value) => <Typography.Text code copyable>{value ? `${value.slice(0, 16)}…` : '-'}</Typography.Text> },
        { title: '创建人', dataIndex: 'created_by', width: 130, render: (value) => value || '-' },
        { title: '创建时间', dataIndex: 'created_at', width: 170, render: formatTime },
        { title: '操作', fixed: 'right', width: 240, render: (_, revision) => { const deployReason = nodeOperationBlockedReason(node.data, { capability: 'config.apply', label: '配置发布', requireManaged: true, role: user?.role }); const rollbackReason = nodeOperationBlockedReason(node.data, { capability: 'config.rollback', label: '配置回滚', requireManaged: true, role: user?.role }); return <Space><Button size="small" icon={<EyeOutlined />} disabled={!hasWriteRole} onClick={() => setViewing(revision)}>查看内容</Button><Tooltip title={deployReason}><span><Button size="small" type="primary" icon={<CloudUploadOutlined />} disabled={Boolean(deployReason)} loading={deploy.isPending && deploy.variables?.id === revision.id} onClick={() => confirmDeploy(revision)}>发布</Button></span></Tooltip>{node.data!.desired_revision && node.data!.desired_revision !== revision.id && <Tooltip title={rollbackReason}><span><Button size="small" danger icon={<RollbackOutlined />} disabled={Boolean(rollbackReason)} loading={rollback.isPending && rollback.variables?.id === revision.id} onClick={() => confirmRollback(revision)}>回滚</Button></span></Tooltip>}</Space>; } },
      ]} />}
    </section>
    <Modal width={760} open={Boolean(viewing)} title={viewing ? `配置修订 v${viewing.version}` : ''} footer={<Button onClick={() => setViewing(undefined)}>关闭</Button>} onCancel={() => setViewing(undefined)} destroyOnHidden>
      {viewing && <><Descriptions size="small" bordered column={2} items={[{ key: 'sha', label: 'SHA-256', span: 2, children: <Typography.Text code copyable>{viewing.sha256}</Typography.Text> }, { key: 'strategy', label: '发布策略', children: strategyLabel(viewing.strategy) }, { key: 'created', label: '创建时间', children: formatTime(viewing.created_at) }]} />{viewedContent.isLoading ? <div className="modal-loading"><Spin /></div> : viewedContent.isError ? <Alert type="error" showIcon title="配置内容加载失败" description="无法读取配置正文，请检查权限或服务状态。" /> : <InputPreview content={viewedContent.data?.content ?? ''} />}</>}
    </Modal>
  </div>;
}

function InputPreview({ content }: { content: string }) {
  return <pre className="config-preview mono">{content}</pre>;
}
