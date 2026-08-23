import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Button, Descriptions, Drawer, Segmented, Select, Space, Table, Typography } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import { useSearchParams } from 'react-router-dom';
import { nodesApi, proxiesApi } from '../api/resources';
import { PageError, PageLoading } from '../components/AsyncState';
import { StatusTag } from '../components/StatusTag';
import { formatBytes } from '../utils/display';
import { formatTime } from '../utils/format';
import type { ProxySummary } from '../api/types';

const proxyTypes = ['tcp', 'udp', 'http', 'https', 'stcp', 'xtcp', 'tcpmux'].map((value) => ({ value, label: value }));

export function ProxiesPage() {
  const [params] = useSearchParams();
  const [nodeId, setNodeId] = useState(() => params.get('nodeId') ?? '');
  const [status, setStatus] = useState('');
  const [type, setType] = useState<string>();
  const [cursor, setCursor] = useState<string>();
  const [history, setHistory] = useState<string[]>([]);
  const [selected, setSelected] = useState<{ nodeId: string; name: string }>();
  const nodes = useQuery({ queryKey: ['nodes', 'proxy-filter'], queryFn: () => nodesApi.list('limit=200') });
  const query = useQuery({ queryKey: ['proxies', nodeId, status, type, cursor], queryFn: () => proxiesApi.list({ nodeId, status, type, cursor, limit: 50 }), refetchInterval: 30_000 });
  const detail = useQuery({ queryKey: ['proxies', selected?.nodeId, selected?.name], queryFn: () => proxiesApi.get(selected!.nodeId, selected!.name), enabled: Boolean(selected) });
  const proxy = detail.data;
  const resetPage = () => { setCursor(undefined); setHistory([]); };
  const next = () => { if (query.data?.next_cursor) { setHistory((value) => [...value, cursor ?? '']); setCursor(query.data.next_cursor); } };
  const previous = () => { const prior = history.at(-1); setHistory((value) => value.slice(0, -1)); setCursor(prior || undefined); };
  return <div className="page-stack">
    <div className="page-heading"><div><Typography.Title level={3}>代理</Typography.Title><Typography.Text type="secondary">跨节点代理运行状态与流量</Typography.Text></div><Button icon={<ReloadOutlined />} loading={query.isFetching} onClick={() => void query.refetch()}>刷新</Button></div>
    <div className="toolbar"><Space wrap>
      <Select aria-label="节点" allowClear showSearch optionFilterProp="label" placeholder="全部节点" value={nodeId || undefined} onChange={(value) => { setNodeId(value ?? ''); resetPage(); }} loading={nodes.isLoading} options={nodes.data?.items.map((node) => ({ value: node.id, label: node.name }))} style={{ width: 220 }} />
      <Select aria-label="代理类型" allowClear placeholder="全部类型" value={type} onChange={(value) => { setType(value); resetPage(); }} options={proxyTypes} style={{ width: 150 }} />
    </Space><Segmented aria-label="代理状态" value={status} onChange={(value) => { setStatus(value); resetPage(); }} options={[{ label: '全部', value: '' }, { label: '运行中', value: 'running' }, { label: '离线', value: 'offline' }, { label: '错误', value: 'error' }]} /></div>
    {query.isError ? <PageError error={query.error} retry={() => void query.refetch()} /> : <div className="content-panel table-panel"><Table<ProxySummary> rowKey={(row) => `${row.node_id}:${row.name}`} size="middle" loading={query.isLoading} dataSource={query.data?.items} scroll={{ x: 1250 }} locale={{ emptyText: '暂无代理运行数据' }} columns={[
      { title: '代理', fixed: 'left', width: 190, render: (_, row) => <Button type="link" className="table-link" onClick={() => setSelected({ nodeId: row.node_id, name: row.name })}>{row.name}</Button> },
      { title: '节点', dataIndex: 'node_name', width: 160, render: (value, row) => value || row.node_id },
      { title: '类型', dataIndex: 'type', width: 90 },
      { title: '状态', dataIndex: 'status', width: 100, render: (value) => <StatusTag value={value} /> },
      { title: '本地端点', dataIndex: 'local_address', width: 190, render: (value) => <span className="mono">{value || '-'}</span> },
      { title: '远端端点', dataIndex: 'remote_address', width: 190, render: (value) => <span className="mono">{value || '-'}</span> },
      { title: '连接', dataIndex: ['traffic', 'current_connections'], width: 90, render: (value) => value ?? '-' },
      { title: '累计流量', width: 150, render: (_, row) => `${formatBytes(row.traffic?.bytes_in)} / ${formatBytes(row.traffic?.bytes_out)}` },
      { title: '错误', dataIndex: 'last_error', ellipsis: true, width: 220, render: (value) => value || '-' },
      { title: '采集时间', dataIndex: 'collected_at', width: 170, render: formatTime },
    ]} pagination={false} /><div className="cursor-pagination"><Typography.Text type="secondary">每页最多 50 条</Typography.Text><Space><Button disabled={!history.length || query.isFetching} onClick={previous}>上一页</Button><Button disabled={!query.data?.next_cursor || query.isFetching} onClick={next}>下一页</Button></Space></div></div>}
    <Drawer title={selected?.name || '代理详情'} open={Boolean(selected)} width={560} onClose={() => setSelected(undefined)} destroyOnHidden>
      {detail.isLoading ? <PageLoading /> : detail.isError ? <PageError error={detail.error} retry={() => void detail.refetch()} /> : proxy && <Descriptions bordered size="small" column={1} items={[
        { key: 'node', label: '节点', children: proxy.node_name || proxy.node_id },
        { key: 'type', label: '类型', children: proxy.type },
        { key: 'status', label: '状态', children: <StatusTag value={proxy.status} /> },
        { key: 'local', label: '本地端点', children: <span className="mono">{proxy.local_address || '-'}</span> },
        { key: 'remote', label: '远端端点', children: <span className="mono">{proxy.remote_address || '-'}</span> },
        { key: 'connections', label: '当前连接', children: proxy.traffic?.current_connections ?? '-' },
        { key: 'total', label: '累计流入 / 流出', children: `${formatBytes(proxy.traffic?.bytes_in)} / ${formatBytes(proxy.traffic?.bytes_out)}` },
        { key: 'today', label: '今日流入 / 流出', children: `${formatBytes(proxy.traffic?.today_bytes_in)} / ${formatBytes(proxy.traffic?.today_bytes_out)}` },
        { key: 'error', label: '最近错误', children: proxy.last_error || '-' },
        { key: 'collected', label: '采集时间', children: formatTime(proxy.collected_at) },
      ]} />}
    </Drawer>
  </div>;
}
