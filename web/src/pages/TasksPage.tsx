import { useQuery } from '@tanstack/react-query';
import { Button, Table, Typography } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import { Link, useSearchParams } from 'react-router-dom';
import { tasksApi } from '../api/resources';
import { PageError } from '../components/AsyncState';
import { StatusTag } from '../components/StatusTag';
import { formatTime } from '../utils/format';
import type { TaskSummary } from '../api/types';

export function TasksPage() {
  const [params] = useSearchParams();
  const queryString = params.toString();
  const query = useQuery({ queryKey: ['tasks', queryString], queryFn: () => tasksApi.list(queryString ? `${queryString}&limit=200` : 'limit=200'), refetchInterval: 10_000 });
  return <div className="page-stack">
    <div className="page-heading"><div><Typography.Title level={3}>任务</Typography.Title><Typography.Text type="secondary">远程操作与执行结果</Typography.Text></div><Button icon={<ReloadOutlined />} loading={query.isFetching} onClick={() => void query.refetch()}>刷新</Button></div>
    {query.isError ? <PageError error={query.error} retry={() => void query.refetch()} /> : <div className="content-panel table-panel"><Table<TaskSummary> rowKey="id" size="middle" loading={query.isLoading} dataSource={query.data?.items} scroll={{ x: 900 }} locale={{ emptyText: '暂无任务' }} columns={[
      { title: '任务 ID', dataIndex: 'id', width: 210, render: (value) => <Link to={`/tasks/${value}`} className="mono">{value}</Link> }, { title: '类型', dataIndex: 'type', width: 150 }, { title: '节点', dataIndex: 'node_name', width: 160, render: (v, r) => r.node_id ? <Link to={`/nodes/${r.node_id}`}>{v || r.node_id}</Link> : '-' },
      { title: '状态', dataIndex: 'status', width: 100, render: (value) => <StatusTag value={value} /> }, { title: '发起人', dataIndex: 'actor', width: 120, render: (v) => v || '-' }, { title: '创建时间', dataIndex: 'created_at', width: 170, render: formatTime }, { title: '错误', dataIndex: 'error_code', ellipsis: true, render: (v, r) => v ? `${v}: ${r.error_message ?? ''}` : '-' },
    ]} /></div>}
  </div>;
}
