import { useMutation, useQuery } from '@tanstack/react-query';
import { Button, Descriptions, message, Modal, Space, Timeline, Typography } from 'antd';
import { ArrowLeftOutlined, StopOutlined } from '@ant-design/icons';
import { useNavigate, useParams } from 'react-router-dom';
import { tasksApi } from '../api/resources';
import { EmptyState, PageError, PageLoading } from '../components/AsyncState';
import { StatusTag } from '../components/StatusTag';
import { formatTime } from '../utils/format';
import { useAuth } from '../app/AuthContext';
import { canOperate, isCancellableTask } from '../utils/permissions';

export function TaskDetailPage() {
  const { id = '' } = useParams();
  const navigate = useNavigate();
  const { user } = useAuth();
  const query = useQuery({ queryKey: ['tasks', id], queryFn: () => tasksApi.get(id), refetchInterval: (q) => isCancellableTask(q.state.data?.status) ? 3000 : false });
  const cancel = useMutation({ mutationFn: () => tasksApi.cancel(id), onSuccess: () => { message.success('取消请求已提交'); void query.refetch(); }, onError: (error) => message.error(error.message) });
  if (query.isLoading) return <PageLoading />;
  if (query.isError) return <PageError error={query.error} retry={() => void query.refetch()} />;
  const task = query.data!;
  const cancellable = canOperate(user?.role) && isCancellableTask(task.status);
  return <div className="page-stack">
    <div className="page-heading"><Space><Button type="text" aria-label="返回" icon={<ArrowLeftOutlined />} onClick={() => navigate('/tasks')} /><div><Typography.Title level={3}>{task.type}</Typography.Title><Space><StatusTag value={task.status} /><Typography.Text code>{task.id}</Typography.Text></Space></div></Space>{cancellable && <Button danger icon={<StopOutlined />} loading={cancel.isPending} onClick={() => Modal.confirm({ title: '取消任务？', content: '已在 Agent 执行的步骤可能无法中断。', okText: '确认取消', okButtonProps: { danger: true }, cancelText: '返回', onOk: () => cancel.mutateAsync() })}>取消任务</Button>}</div>
    <div className="content-panel"><Descriptions size="small" bordered column={{ xs: 1, sm: 2 }} items={[{ key: 'node', label: '节点', children: task.node_name || task.node_id || '-' }, { key: 'actor', label: '发起人', children: task.actor || '-' }, { key: 'created', label: '创建时间', children: formatTime(task.created_at) }, { key: 'finished', label: '完成时间', children: formatTime(task.finished_at) }, ...(task.error_code ? [{ key: 'error', label: '错误', span: 2, children: <Typography.Text type="danger">{task.error_code}: {task.error_message}</Typography.Text> }] : [])]} /></div>
    <section className="content-panel"><Typography.Title level={5}>执行步骤</Typography.Title>{task.steps?.length ? <Timeline items={task.steps.map((step) => ({ color: ['succeeded', 'completed'].includes(step.status) ? 'green' : step.status === 'failed' ? 'red' : step.status === 'running' ? 'blue' : 'gray', children: <div><Space><strong>{step.name}</strong><StatusTag value={step.status} /></Space><div className="cell-secondary">{formatTime(step.started_at)}{step.finished_at ? ` - ${formatTime(step.finished_at)}` : ''}</div>{step.error_code && <Typography.Text type="danger">{step.error_code}: {step.error_message}</Typography.Text>}</div> }))} /> : <EmptyState description="任务尚无步骤记录" />}</section>
  </div>;
}
