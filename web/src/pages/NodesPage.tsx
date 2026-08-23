import { useMemo, useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { Button, Form, Input, message, Modal, Radio, Segmented, Space, Table, Tag, Tooltip, Typography } from 'antd';
import { DownloadOutlined, PlusOutlined, ReloadOutlined, SearchOutlined } from '@ant-design/icons';
import { Link } from 'react-router-dom';
import { nodesApi, systemApi } from '../api/resources';
import { PageError } from '../components/AsyncState';
import { StatusTag } from '../components/StatusTag';
import { formatTime } from '../utils/format';
import type { EnrollmentToken, NodeRole, NodeSummary } from '../api/types';
import { useAuth } from '../app/AuthContext';
import { EnrollmentResultModal } from '../components/EnrollmentResultModal';

export function NodesPage() {
  const [role, setRole] = useState('all');
  const [search, setSearch] = useState('');
  const [createOpen, setCreateOpen] = useState(false);
  const [enrollment, setEnrollment] = useState<EnrollmentToken>();
  const [form] = Form.useForm<{ role: NodeRole }>();
  const { user } = useAuth();
  const canEnroll = user?.role === 'admin';
  const query = useQuery({ queryKey: ['nodes'], queryFn: () => nodesApi.list('limit=200'), refetchInterval: 30_000 });
  const createToken = useMutation({
    mutationFn: ({ role: nodeRole }: { role: NodeRole }) => nodesApi.createEnrollmentToken(nodeRole),
    onSuccess: (result) => { setCreateOpen(false); setEnrollment(result); form.resetFields(); },
    onError: (error) => message.error(error.message),
  });
  const downloadCA = useMutation({
    mutationFn: systemApi.downloadAgentCA,
    onSuccess: (blob) => {
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'frp-admin-agent-ca.pem';
      link.click();
      URL.revokeObjectURL(url);
      message.success('Agent CA 已下载');
    },
    onError: (error) => message.error(error.message),
  });
  const rows = useMemo(() => query.data?.items.filter((node) => (role === 'all' || node.role === role) && (!search || `${node.name} ${node.hostname ?? ''}`.toLowerCase().includes(search.toLowerCase()))) ?? [], [query.data, role, search]);
  return <div className="page-stack">
    <div className="page-heading"><div><Typography.Title level={3}>节点</Typography.Title><Typography.Text type="secondary">Agent 与 frp 运行状态</Typography.Text></div><Space>
      <Tooltip title={canEnroll ? '' : '仅管理员可添加节点'}><Button icon={<DownloadOutlined />} disabled={!canEnroll} loading={downloadCA.isPending} onClick={() => downloadCA.mutate()}>下载 Agent CA</Button></Tooltip>
      <Tooltip title={canEnroll ? '' : '仅管理员可添加节点'}><Button type="primary" icon={<PlusOutlined />} disabled={!canEnroll} onClick={() => setCreateOpen(true)}>添加节点</Button></Tooltip>
      <Button icon={<ReloadOutlined />} loading={query.isFetching} onClick={() => void query.refetch()}>刷新</Button>
    </Space></div>
    <div className="toolbar"><Segmented value={role} onChange={setRole} options={[{ label: '全部', value: 'all' }, { label: '客户端', value: 'client' }, { label: '服务端', value: 'server' }]} /><Input allowClear prefix={<SearchOutlined />} placeholder="搜索节点或主机名" value={search} onChange={(event) => setSearch(event.target.value)} className="search-input" /></div>
    {query.isError ? <PageError error={query.error} retry={() => void query.refetch()} /> : <div className="content-panel table-panel"><Table<NodeSummary> size="middle" rowKey="id" loading={query.isLoading} dataSource={rows} scroll={{ x: 1050 }} pagination={{ pageSize: 20, showSizeChanger: true }} locale={{ emptyText: '暂无纳管节点' }} columns={[
      { title: '节点', dataIndex: 'name', fixed: 'left', width: 180, render: (value, row) => <div><Link to={`/nodes/${row.id}`}>{value}</Link><div className="cell-secondary">{row.hostname || row.id}</div></div> },
      { title: '角色', dataIndex: 'role', width: 90, render: (value) => <Tag>{value === 'server' ? 'frps' : 'frpc'}</Tag> },
      { title: '模式', dataIndex: 'management_mode', width: 90, render: (value) => <Tag color={value === 'managed' ? 'blue' : 'default'}>{value === 'managed' ? '托管' : '观察'}</Tag> },
      { title: '连接', dataIndex: 'status', width: 90, render: (value) => <StatusTag value={value} /> },
      { title: '服务', dataIndex: 'service_status', width: 100, render: (value) => <StatusTag value={value} /> },
      { title: 'frp / Agent', width: 160, render: (_, row) => <Space direction="vertical" size={0}><span>{row.frp_version || '-'}</span><span className="cell-secondary">{row.agent_version || '-'}</span></Space> },
      { title: '配置版本', width: 130, render: (_, row) => <span className={row.drifted || Boolean(row.desired_revision && row.desired_revision !== row.observed_revision) ? 'text-warning' : ''}>{row.observed_revision ?? '-'} / {row.desired_revision ?? '-'}</span> },
      { title: '最后心跳', dataIndex: 'last_heartbeat_at', width: 170, render: formatTime },
      { title: '', fixed: 'right', width: 70, render: (_, row) => <Link to={`/nodes/${row.id}`}>详情</Link> },
    ]} /></div>}
    <Modal title="添加节点" open={createOpen} okText="生成注册令牌" cancelText="取消" confirmLoading={createToken.isPending} onCancel={() => { if (!createToken.isPending) { setCreateOpen(false); form.resetFields(); } }} onOk={() => form.submit()}>
      <Form form={form} layout="vertical" initialValues={{ role: 'client' }} onFinish={(values) => createToken.mutate(values)}>
        <Form.Item name="role" label="节点角色" rules={[{ required: true }]}>
          <Radio.Group optionType="button" buttonStyle="solid" options={[{ label: 'frpc 客户端', value: 'client' }, { label: 'frps 服务端', value: 'server' }]} />
        </Form.Item>
        <Typography.Paragraph type="secondary">注册令牌有效期为 10 分钟且仅可使用一次。Agent 私钥在节点本机生成。</Typography.Paragraph>
      </Form>
    </Modal>
    <EnrollmentResultModal result={enrollment} onClose={() => setEnrollment(undefined)} />
  </div>;
}
