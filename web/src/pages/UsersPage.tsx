import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Button, Form, Input, message, Modal, Select, Space, Table, Tag, Typography } from 'antd';
import { PlusOutlined, ReloadOutlined } from '@ant-design/icons';
import { usersApi } from '../api/resources';
import type { ManagedUser } from '../api/types';
import { useAuth } from '../app/AuthContext';
import { PageError } from '../components/AsyncState';
import { formatTime } from '../utils/format';

const roles = ['admin', 'operator', 'viewer', 'auditor'].map((value) => ({ value, label: value }));

export function UsersPage() {
  const [open, setOpen] = useState(false);
  const [form] = Form.useForm<{ username: string; password: string; role: string }>();
  const { user: current } = useAuth();
  const queryClient = useQueryClient();
  const query = useQuery({ queryKey: ['users'], queryFn: usersApi.list });
  const create = useMutation({ mutationFn: (value: { username: string; password: string; role: string }) => usersApi.create(value.username, value.password, value.role), onSuccess: async () => { message.success('用户已创建'); form.resetFields(); setOpen(false); await queryClient.invalidateQueries({ queryKey: ['users'] }); }, onError: (error) => message.error(error.message) });
  const update = useMutation({ mutationFn: ({ id, patch }: { id: string; patch: { status?: string; role?: string } }) => usersApi.update(id, patch), onSuccess: async () => { message.success('用户权限已更新'); await queryClient.invalidateQueries({ queryKey: ['users'] }); }, onError: (error) => message.error(error.message) });
  const confirmUpdate = (target: ManagedUser, patch: { status?: string; role?: string }) => Modal.confirm({ title: '确认修改用户权限？', content: patch.role ? `将 ${target.username} 的角色改为 ${patch.role}` : `${patch.status === 'disabled' ? '禁用' : '启用'}用户 ${target.username}`, okText: '确认修改', okButtonProps: { danger: patch.status === 'disabled' || patch.role === 'admin' }, cancelText: '取消', onOk: () => update.mutateAsync({ id: target.id, patch }) });
  return <div className="page-stack">
    <div className="page-heading"><div><Typography.Title level={3}>系统管理</Typography.Title><Typography.Text type="secondary">管理控制台用户、角色和访问状态</Typography.Text></div><Space><Button icon={<ReloadOutlined />} loading={query.isFetching} onClick={() => void query.refetch()}>刷新</Button><Button type="primary" icon={<PlusOutlined />} onClick={() => setOpen(true)}>新建用户</Button></Space></div>
    {query.isError ? <PageError error={query.error} retry={() => void query.refetch()} /> : <div className="content-panel table-panel"><Table<ManagedUser> rowKey="id" loading={query.isLoading} dataSource={query.data?.items} locale={{ emptyText: '暂无用户' }} columns={[
      { title: '账号', dataIndex: 'username', render: (value, row) => <Space><strong>{value}</strong>{row.id === current?.id && <Tag>当前用户</Tag>}</Space> },
      { title: '角色', dataIndex: 'role', width: 180, render: (value, row) => <Select aria-label={`${row.username} 角色`} value={value} options={roles} disabled={row.id === current?.id || update.isPending} onChange={(role) => confirmUpdate(row, { role })} /> },
      { title: '状态', dataIndex: 'status', width: 110, render: (value) => <Tag color={value === 'active' ? 'green' : 'default'}>{value === 'active' ? '启用' : '禁用'}</Tag> },
      { title: '创建时间', width: 180, render: (_, row) => formatTime(row.created_at ?? row.createdAt) },
      { title: '操作', width: 100, render: (_, row) => <Button size="small" danger={row.status === 'active'} disabled={row.id === current?.id || update.isPending} onClick={() => confirmUpdate(row, { status: row.status === 'active' ? 'disabled' : 'active' })}>{row.status === 'active' ? '禁用' : '启用'}</Button> },
    ]} /></div>}
    <Modal destroyOnHidden open={open} title="新建用户" okText="创建" confirmLoading={create.isPending} onCancel={() => { form.resetFields(); setOpen(false); }} onOk={() => form.submit()}>
      <Form form={form} preserve={false} layout="vertical" initialValues={{ role: 'viewer' }} onFinish={(values) => create.mutate(values)}>
        <Form.Item name="username" label="账号" rules={[{ required: true, message: '请输入账号' }]}><Input autoComplete="off" /></Form.Item>
        <Form.Item name="password" label="初始密码" rules={[{ required: true, message: '请输入密码' }, { min: 12, message: '密码至少 12 位' }]}><Input.Password autoComplete="new-password" /></Form.Item>
        <Form.Item name="role" label="角色" rules={[{ required: true }]}><Select options={roles} /></Form.Item>
      </Form>
    </Modal>
  </div>;
}
