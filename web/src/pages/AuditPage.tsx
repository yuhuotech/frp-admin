import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Button, DatePicker, Form, Input, Space, Table, Tag, Typography } from 'antd';
import { SearchOutlined } from '@ant-design/icons';
import type { Dayjs } from 'dayjs';
import { auditApi, type AuditFilters } from '../api/resources';
import type { AuditLog } from '../api/types';
import { PageError } from '../components/AsyncState';
import { formatTime } from '../utils/format';

type FilterForm = { actor?: string; action?: string; resource?: string; range?: [Dayjs, Dayjs] };

export function AuditPage() {
  const [filters, setFilters] = useState<AuditFilters>({ limit: 50 });
  const [history, setHistory] = useState<string[]>([]);
  const query = useQuery({ queryKey: ['audit', filters], queryFn: () => auditApi.list(filters) });
  const search = (values: FilterForm) => { setHistory([]); setFilters({ actor: values.actor?.trim(), action: values.action?.trim(), resource: values.resource?.trim(), from: values.range?.[0].toISOString(), to: values.range?.[1].toISOString(), limit: 50 }); };
  const next = () => { if (query.data?.next_cursor) { setHistory((value) => [...value, filters.cursor ?? '']); setFilters((value) => ({ ...value, cursor: query.data!.next_cursor })); } };
  const previous = () => { const cursor = history.at(-1); setHistory((value) => value.slice(0, -1)); setFilters((value) => ({ ...value, cursor: cursor || undefined })); };
  return <div className="page-stack">
    <div className="page-heading"><div><Typography.Title level={3}>审计日志</Typography.Title><Typography.Text type="secondary">用户与系统操作的追加写记录</Typography.Text></div></div>
    <div className="content-panel"><Form layout="inline" onFinish={search}><Form.Item name="actor"><Input allowClear placeholder="操作者" /></Form.Item><Form.Item name="action"><Input allowClear placeholder="操作" /></Form.Item><Form.Item name="resource"><Input allowClear placeholder="资源" /></Form.Item><Form.Item name="range"><DatePicker.RangePicker showTime /></Form.Item><Form.Item><Button type="primary" htmlType="submit" icon={<SearchOutlined />}>查询</Button></Form.Item></Form></div>
    {query.isError ? <PageError error={query.error} retry={() => void query.refetch()} /> : <div className="content-panel table-panel"><Table<AuditLog> rowKey="id" loading={query.isLoading} dataSource={query.data?.items} pagination={false} scroll={{ x: 1000 }} locale={{ emptyText: '暂无审计记录' }} columns={[
      { title: '时间', dataIndex: 'created_at', width: 180, render: formatTime }, { title: '操作者', dataIndex: 'actor', width: 150 }, { title: '操作', dataIndex: 'action', width: 190 }, { title: '结果', dataIndex: 'outcome', width: 90, render: (value) => value ? <Tag color={value === 'success' ? 'green' : 'red'}>{value === 'success' ? '成功' : '失败'}</Tag> : '-' }, { title: '资源', dataIndex: 'resource', ellipsis: true }, { title: 'Request ID', dataIndex: 'request_id', width: 220, render: (value) => <Typography.Text code>{value || '-'}</Typography.Text> },
    ]} /><div className="cursor-pagination"><Typography.Text type="secondary">每页最多 50 条</Typography.Text><Space><Button disabled={!history.length || query.isFetching} onClick={previous}>上一页</Button><Button disabled={!query.data?.next_cursor || query.isFetching} onClick={next}>下一页</Button></Space></div></div>}
  </div>;
}
