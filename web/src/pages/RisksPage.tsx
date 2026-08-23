import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Alert, Button, Descriptions, Drawer, Form, message, Modal, Segmented, Select, Space, Table, Tag, Tooltip, Typography } from 'antd';
import { ReloadOutlined, SafetyCertificateOutlined, ScanOutlined, ToolOutlined } from '@ant-design/icons';
import { Link, useNavigate } from 'react-router-dom';
import { nodesApi, securityRisksApi } from '../api/resources';
import type { NodeSummary, SecurityRisk } from '../api/types';
import { PageError } from '../components/AsyncState';
import { StatusTag } from '../components/StatusTag';
import { useAuth } from '../app/AuthContext';
import { canOperate, canRemediateRisk } from '../utils/permissions';
import { formatTime } from '../utils/format';

const riskMeta: Record<string, { title: string; recommendation: string }> = {
  config_token_permissions: { title: '配置文件权限过宽', recommendation: '将包含认证信息的 frp 配置文件权限限制为仅服务账户可读写。' },
  admin_api_non_loopback: { title: '管理 API 对非本机地址监听', recommendation: '将管理 API 绑定到 loopback，并通过控制面统一访问。' },
  proxy_name_conflict: { title: '代理名称冲突', recommendation: '依据业务归属确认权威实例，在维护窗口内停用或改名重复代理。' },
};

const repairActions = {
  restrict_config_permissions: {
    label: '收紧配置权限',
    impact: '平台会将 frp 配置文件权限限制为仅服务账户可读写。操作不修改配置内容，通常不需要重启 frp 服务。',
  },
  bind_admin_api_loopback: {
    label: '改绑本机地址',
    impact: '平台会将 frps 管理 API 改绑到 127.0.0.1 并重启 frps。所有客户端与代理会短暂断开并自动重连，外部系统将无法直接访问管理 API。',
  },
} as const;

type RepairAction = keyof typeof repairActions;

function isRepairAction(value: string): value is RepairAction {
  return Object.hasOwn(repairActions, value);
}

function nodeLabel(node?: NodeSummary) {
  return node?.name || node?.hostname || node?.id || '-';
}

function repairBlockedReason(risk: SecurityRisk, node: NodeSummary | undefined, role?: string) {
  if (risk.state !== 'open') return risk.state === 'pending_confirmation' ? '风险正在等待连续扫描确认，当前不可执行修复' : '该风险当前不是待处理状态';
  if (!risk.repairable) return '该风险不支持自动修复，请按维护手册处理';
  if (!risk.allowed_actions.some(isRepairAction)) return '当前没有平台白名单内的修复动作';
  if (risk.kind === 'admin_api_non_loopback' && role !== 'admin') return '该修复会重启 frps，仅管理员可执行';
  if (!node) return '节点信息不可用，无法校验修复条件';
  if (!canRemediateRisk(role, node.management_mode, node.status === 'online')) {
    if (!canOperate(role)) return '当前角色没有修复权限';
    if (node.management_mode !== 'managed') return '观察模式只允许扫描，请先将节点切换为托管模式';
    return 'Agent 离线，无法执行修复';
  }
  const capability = risk.kind === 'admin_api_non_loopback' ? 'risk.repair.admin_loopback' : 'risk.repair.config_permissions';
  if (!node.capabilities?.includes(capability)) return '当前 Agent 或运行环境不支持该自动修复动作';
  return '';
}

export function RisksPage() {
  const [nodeId, setNodeId] = useState('');
  const [kind, setKind] = useState('');
  const [severity, setSeverity] = useState('');
  const [state, setState] = useState('active');
  const [selected, setSelected] = useState<SecurityRisk>();
  const [scanOpen, setScanOpen] = useState(false);
  const [scanIntentKey, setScanIntentKey] = useState('');
  const [scanForm] = Form.useForm<{ node_id: string }>();
  const { user } = useAuth();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const nodes = useQuery({ queryKey: ['nodes', 'risk-center'], queryFn: () => nodesApi.list('limit=200'), refetchInterval: 30_000 });
  const risks = useQuery({ queryKey: ['risks', nodeId, kind, state], queryFn: () => securityRisksApi.list({ nodeId, kind, state, limit: 200 }), refetchInterval: 30_000 });
  const nodeMap = useMemo(() => new Map(nodes.data?.items.map((node) => [node.id, node]) ?? []), [nodes.data]);
  const visibleRisks = useMemo(() => risks.data?.items.filter((risk) => !severity || risk.severity === severity), [risks.data, severity]);
  const onlineNodes = nodes.data?.items.filter((node) => node.status === 'online' && node.capabilities?.includes('risk.scan')) ?? [];

  const scan = useMutation({
    mutationFn: ({ id, idempotencyKey }: { id: string; idempotencyKey: string }) => securityRisksApi.scan(id, idempotencyKey),
    onSuccess: (task) => {
      setScanOpen(false);
      scanForm.resetFields();
      setScanIntentKey('');
      void queryClient.invalidateQueries({ queryKey: ['tasks'] });
      message.success('风险扫描任务已创建');
      navigate(`/tasks/${task.id}`);
    },
    onError: (error) => message.error(error.message),
  });
  const repair = useMutation({
    mutationFn: ({ riskId, action, idempotencyKey }: { riskId: string; action: RepairAction; idempotencyKey: string }) => securityRisksApi.repair(riskId, action, idempotencyKey),
    onSuccess: (task) => {
      setSelected(undefined);
      void queryClient.invalidateQueries({ queryKey: ['risks'] });
      void queryClient.invalidateQueries({ queryKey: ['tasks'] });
      message.success('修复任务已创建');
      navigate(`/tasks/${task.id}`);
    },
    onError: (error) => message.error(error.message),
  });

  const confirmRepair = (risk: SecurityRisk, action: RepairAction) => {
    const node = nodeMap.get(risk.node_id);
    const idempotencyKey = crypto.randomUUID();
    Modal.confirm({
      title: `${repairActions[action].label}：${riskMeta[risk.kind]?.title || risk.kind}？`,
      content: <Space direction="vertical" size={10}>
        <Typography.Text>节点：<strong>{nodeLabel(node)}</strong></Typography.Text>
        <Alert type="warning" showIcon message="影响确认" description={repairActions[action].impact} />
        <Typography.Text type="secondary">执行结果将在任务详情中持续更新，并写入审计日志。</Typography.Text>
      </Space>,
      okText: '确认影响并执行',
      okButtonProps: { danger: action === 'bind_admin_api_loopback' },
      cancelText: '取消',
      width: 560,
      onOk: () => repair.mutateAsync({ riskId: risk.id, action, idempotencyKey }),
    });
  };

  const detailNode = selected ? nodeMap.get(selected.node_id) : undefined;
  const blockedReason = selected ? repairBlockedReason(selected, detailNode, user?.role) : '';
  const actions = selected?.allowed_actions.filter(isRepairAction) ?? [];

  return <div className="page-stack">
    <div className="page-heading"><div><Typography.Title level={3}>风险中心</Typography.Title><Typography.Text type="secondary">节点部署风险扫描与受控修复</Typography.Text></div><Space wrap>
      {canOperate(user?.role) && <Button type="primary" icon={<ScanOutlined />} onClick={() => { setScanIntentKey(crypto.randomUUID()); setScanOpen(true); }}>发起扫描</Button>}
      <Button icon={<ReloadOutlined />} loading={risks.isFetching} onClick={() => void risks.refetch()}>刷新</Button>
    </Space></div>
    <div className="toolbar risk-toolbar"><Space wrap>
      <Select aria-label="节点" allowClear showSearch optionFilterProp="label" placeholder="全部节点" value={nodeId || undefined} onChange={(value) => setNodeId(value ?? '')} loading={nodes.isLoading} options={nodes.data?.items.map((node) => ({ value: node.id, label: nodeLabel(node) }))} style={{ width: 220 }} />
      <Select aria-label="风险类型" allowClear placeholder="全部风险类型" value={kind || undefined} onChange={(value) => setKind(value ?? '')} options={Object.entries(riskMeta).map(([value, item]) => ({ value, label: item.title }))} style={{ width: 220 }} />
      <Select aria-label="严重度" allowClear placeholder="全部严重度" value={severity || undefined} onChange={(value) => setSeverity(value ?? '')} options={[['critical', '严重'], ['high', '高危'], ['medium', '中危'], ['low', '低危'], ['info', '提示']].map(([value, label]) => ({ value, label }))} style={{ width: 150 }} />
    </Space><Segmented aria-label="风险状态" value={state} onChange={setState} options={[{ label: '处理中', value: 'active' }, { label: '待处理', value: 'open' }, { label: '待确认', value: 'pending_confirmation' }, { label: '已解决', value: 'resolved' }, { label: '全部', value: '' }]} /></div>
    {risks.isError ? <PageError error={risks.error} retry={() => void risks.refetch()} /> : <div className="content-panel table-panel"><Table<SecurityRisk> rowKey="id" size="middle" loading={risks.isLoading} dataSource={visibleRisks} scroll={{ x: 1080 }} locale={{ emptyText: '当前筛选条件下没有风险' }} onRow={(row) => ({ onClick: () => setSelected(row) })} rowClassName="clickable-row" columns={[
      { title: '风险', width: 260, render: (_, row) => <div><strong>{riskMeta[row.kind]?.title || row.kind}</strong><div className="cell-secondary mono">{row.kind}</div></div> },
      { title: '严重度', dataIndex: 'severity', width: 90, render: (value) => <StatusTag value={value} /> },
      { title: '节点', dataIndex: 'node_id', width: 180, render: (value) => { const node = nodeMap.get(value); return <div><Link to={`/nodes/${value}`} onClick={(event) => event.stopPropagation()}>{nodeLabel(node)}</Link><div className="cell-secondary"><Tag color={node?.management_mode === 'managed' ? 'blue' : 'default'}>{node?.management_mode === 'managed' ? '托管' : '观察'}</Tag></div></div>; } },
      { title: '状态', dataIndex: 'state', width: 100, render: (value) => <StatusTag value={value} /> },
      { title: '首次发现', dataIndex: 'first_seen_at', width: 170, render: formatTime },
      { title: '最近证据', dataIndex: 'last_seen_at', width: 170, render: formatTime },
      { title: '处置', fixed: 'right', width: 110, render: (_, row) => { const reason = repairBlockedReason(row, nodeMap.get(row.node_id), user?.role); return <Tooltip title={reason}><Button type="link" icon={<ToolOutlined />} disabled={Boolean(reason)} onClick={(event) => { event.stopPropagation(); setSelected(row); }}>查看修复</Button></Tooltip>; } },
    ]} pagination={{ pageSize: 50, showSizeChanger: false }} /></div>}

    <Drawer title="风险详情" size="large" open={Boolean(selected)} onClose={() => setSelected(undefined)} destroyOnHidden extra={selected && <StatusTag value={selected.severity} />}>
      {selected && <Space direction="vertical" size={20} style={{ width: '100%' }}>
        <Descriptions bordered size="small" column={1} items={[
          { key: 'risk', label: '风险', children: riskMeta[selected.kind]?.title || selected.kind },
          { key: 'kind', label: '类型', children: <span className="mono">{selected.kind}</span> },
          { key: 'node', label: '节点', children: <Space><Link to={`/nodes/${selected.node_id}`}>{nodeLabel(detailNode)}</Link><Tag color={detailNode?.management_mode === 'managed' ? 'blue' : 'default'}>{detailNode?.management_mode === 'managed' ? '托管' : '观察'}</Tag><StatusTag value={detailNode?.status} /></Space> },
          { key: 'state', label: '状态', children: <StatusTag value={selected.state} /> },
          { key: 'first', label: '首次发现', children: formatTime(selected.first_seen_at) },
          { key: 'last', label: '最近证据', children: formatTime(selected.last_seen_at) },
          ...(selected.resolved_at ? [{ key: 'resolved', label: '解决时间', children: formatTime(selected.resolved_at) }] : []),
        ]} />
        <div><Typography.Title level={5}>检测依据</Typography.Title><Typography.Paragraph className="risk-evidence">{selected.evidence || 'Agent 已上报该风险，暂无更多脱敏证据摘要。'}</Typography.Paragraph></div>
        <div><Typography.Title level={5}>处置建议</Typography.Title><Typography.Paragraph>{riskMeta[selected.kind]?.recommendation || '请依据节点运行环境和维护手册评估后处置。'}</Typography.Paragraph></div>
        {selected.kind === 'proxy_name_conflict' && <Alert type="warning" showIcon message="需要人工确认权威实例" description="平台不会自动停止或改名代理。请先确认业务归属和流量，再在维护窗口内处理。" />}
        {blockedReason ? <Alert type="info" showIcon message="当前不可自动修复" description={blockedReason} /> : <div><Typography.Title level={5}>自动修复</Typography.Title><Space wrap>{actions.map((action) => <Button key={action} danger={action === 'bind_admin_api_loopback'} icon={<SafetyCertificateOutlined />} loading={repair.isPending && repair.variables?.action === action} onClick={() => confirmRepair(selected, action)}>{repairActions[action].label}</Button>)}</Space></div>}
      </Space>}
    </Drawer>

    <Modal title="发起风险扫描" open={scanOpen} footer={null} destroyOnHidden onCancel={() => { if (!scan.isPending) { setScanOpen(false); scanForm.resetFields(); } }}>
      <Form form={scanForm} layout="vertical" onFinish={({ node_id }) => scan.mutate({ id: node_id, idempotencyKey: scanIntentKey })}>
        <Form.Item name="node_id" label="节点" rules={[{ required: true, message: '请选择节点' }]}><Select showSearch optionFilterProp="label" placeholder="选择在线节点" loading={nodes.isLoading} options={onlineNodes.map((node) => ({ value: node.id, label: `${nodeLabel(node)} · ${node.management_mode === 'managed' ? '托管' : '观察'}` }))} /></Form.Item>
        <Alert type="info" showIcon message="扫描为只读操作" description="观察模式节点也可扫描。扫描只采集脱敏后的风险证据，不读取或展示认证凭据与配置原文。" />
        <Space className="modal-actions"><Button type="primary" htmlType="submit" icon={<ScanOutlined />} loading={scan.isPending}>创建扫描任务</Button><Button onClick={() => { setScanOpen(false); scanForm.resetFields(); }}>取消</Button></Space>
      </Form>
    </Modal>
  </div>;
}
