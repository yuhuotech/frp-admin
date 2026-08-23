import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Button, message, Modal, Segmented, Space, Table, Typography } from 'antd';
import { CheckOutlined, CloseOutlined, ReloadOutlined, SafetyCertificateOutlined } from '@ant-design/icons';
import { alertsApi } from '../api/resources';
import { PageError } from '../components/AsyncState';
import { StatusTag } from '../components/StatusTag';
import { formatTime } from '../utils/format';
import type { AlertSummary } from '../api/types';
import { useAuth } from '../app/AuthContext';
import { availableAlertActions, type AlertAction } from '../utils/permissions';

const actionMeta = {
  acknowledge: { label: '确认', icon: <CheckOutlined /> },
  resolve: { label: '恢复', icon: <SafetyCertificateOutlined /> },
  close: { label: '关闭', icon: <CloseOutlined /> },
} as const;

export function AlertsPage() {
  const [state, setState] = useState('');
  const { user } = useAuth();
  const queryClient = useQueryClient();
  const query = useQuery({ queryKey: ['alerts', state], queryFn: () => alertsApi.list(state), refetchInterval: 30_000 });
  const transition = useMutation({
    mutationFn: ({ id, action }: { id: string; action: AlertAction }) => alertsApi[action](id),
    onSuccess: (_, variables) => { message.success(`告警已${actionMeta[variables.action].label}`); void queryClient.invalidateQueries({ queryKey: ['alerts'] }); },
    onError: (error) => message.error(error.message),
  });
  const runAction = (row: AlertSummary, action: AlertAction) => {
    const execute = () => transition.mutateAsync({ id: row.id, action });
    if (action !== 'close') {
      void execute();
      return;
    }
    Modal.confirm({ title: '关闭该告警？', content: '关闭后不能回退到待处理状态。', okText: '确认关闭', okButtonProps: { danger: true }, cancelText: '取消', onOk: execute });
  };
  return <div className="page-stack"><div className="page-heading"><div><Typography.Title level={3}>告警中心</Typography.Title><Typography.Text type="secondary">系统自动生成的故障与恢复状态；告警不能手工新增，处理方式是确认、恢复或关闭</Typography.Text></div><Button icon={<ReloadOutlined />} loading={query.isFetching} onClick={() => void query.refetch()}>刷新</Button></div>
    <div className="toolbar"><Segmented aria-label="告警状态" value={state} onChange={setState} options={[{ label: '全部', value: '' }, { label: '待处理', value: 'open' }, { label: '已确认', value: 'acknowledged' }, { label: '已恢复', value: 'resolved' }, { label: '已关闭', value: 'closed' }]} /></div>
    {query.isError ? <PageError error={query.error} retry={() => void query.refetch()} /> : <div className="content-panel table-panel"><Table<AlertSummary> rowKey="id" size="middle" loading={query.isLoading} dataSource={query.data?.items} scroll={{ x: 980 }} locale={{ emptyText: '当前没有告警' }} columns={[
      { title: '告警', width: 300, render: (_, row) => <div><strong>{row.kind}</strong><div className="cell-secondary">{row.message}</div></div> },
      { title: '资源', dataIndex: 'resource', width: 180, render: (value) => <span className="mono">{value}</span> },
      { title: '级别', dataIndex: 'severity', width: 90, render: (value) => <StatusTag value={value} /> },
      { title: '状态', dataIndex: 'state', width: 100, render: (value) => <StatusTag value={value} /> },
      { title: '更新时间', dataIndex: 'updated_at', width: 170, render: formatTime },
      { title: '操作', fixed: 'right', width: 190, render: (_, row) => <Space size="small">{availableAlertActions(user?.role, row.state).map((action) => <Button key={action} type="link" danger={action === 'close'} icon={actionMeta[action].icon} loading={transition.isPending && transition.variables?.id === row.id && transition.variables.action === action} onClick={() => runAction(row, action)}>{actionMeta[action].label}</Button>)}</Space> },
    ]} /></div>}
  </div>;
}
