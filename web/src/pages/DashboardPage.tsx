import { useQuery } from '@tanstack/react-query';
import { Alert, Col, Progress, Row, Statistic, Table, Typography } from 'antd';
import { Link } from 'react-router-dom';
import { getDashboard, nodesApi, tasksApi } from '../api/resources';
import { PageError, PageLoading } from '../components/AsyncState';
import { StatusTag } from '../components/StatusTag';
import { formatTime } from '../utils/format';
import type { NodeSummary, TaskSummary } from '../api/types';

export function DashboardPage() {
  const summary = useQuery({ queryKey: ['dashboard'], queryFn: getDashboard, refetchInterval: 30_000 });
  const nodes = useQuery({ queryKey: ['nodes', 'recent'], queryFn: () => nodesApi.list('limit=6') });
  const tasks = useQuery({ queryKey: ['tasks', 'recent'], queryFn: () => tasksApi.list('limit=6') });
  if (summary.isLoading) return <PageLoading />;
  if (summary.isError) return <PageError error={summary.error} retry={() => void summary.refetch()} />;
  const data = summary.data!;
  const healthyRatio = data.nodes_total ? Math.round(data.nodes_healthy / data.nodes_total * 100) : 0;
  return <div className="page-stack">
    <div className="page-heading"><div><Typography.Title level={3}>概览</Typography.Title><Typography.Text type="secondary">集群实时运行状态</Typography.Text></div></div>
    {(data.nodes_drifted > 0 || data.alerts_firing > 0) && <Alert showIcon type="warning" message={`${data.nodes_drifted} 个节点配置不一致，${data.alerts_firing} 条告警待处理`} />}
    <Row gutter={[12, 12]}>
      <Col xs={12} lg={6}><div className="metric"><Statistic title="节点" value={data.nodes_total} suffix={<span className="metric-suffix">在线 {data.nodes_online}</span>} /></div></Col>
      <Col xs={12} lg={6}><div className="metric"><Statistic title="健康节点" value={data.nodes_healthy} /><Progress percent={healthyRatio} size="small" showInfo={false} /></div></Col>
      <Col xs={12} lg={6}><div className="metric"><Statistic title="运行中任务" value={data.tasks_running} /></div></Col>
      <Col xs={12} lg={6}><div className="metric"><Statistic title="活跃告警" value={data.alerts_firing} valueStyle={data.alerts_firing ? { color: '#cf1322' } : undefined} /></div></Col>
    </Row>
    <Row gutter={[12, 12]}>
      <Col xs={24} xl={12}><section className="content-panel"><div className="section-title"><Typography.Title level={5}>最近节点</Typography.Title><Link to="/nodes">查看全部</Link></div><Table<NodeSummary> size="small" rowKey="id" loading={nodes.isLoading} dataSource={nodes.data?.items} pagination={false} columns={[{ title: '节点', dataIndex: 'name', render: (v, r) => <Link to={`/nodes/${r.id}`}>{v}</Link> }, { title: '状态', dataIndex: 'status', render: (v) => <StatusTag value={v} /> }, { title: '最后心跳', dataIndex: 'last_heartbeat_at', render: formatTime }]} /></section></Col>
      <Col xs={24} xl={12}><section className="content-panel"><div className="section-title"><Typography.Title level={5}>最近任务</Typography.Title><Link to="/tasks">查看全部</Link></div><Table<TaskSummary> size="small" rowKey="id" loading={tasks.isLoading} dataSource={tasks.data?.items} pagination={false} columns={[{ title: '任务', dataIndex: 'type', render: (v, r) => <Link to={`/tasks/${r.id}`}>{v}</Link> }, { title: '状态', dataIndex: 'status', render: (v) => <StatusTag value={v} /> }, { title: '创建时间', dataIndex: 'created_at', render: formatTime }]} /></section></Col>
    </Row>
  </div>;
}
