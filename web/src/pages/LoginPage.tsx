import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Alert, Button, Form, Input, Skeleton, Typography, message } from 'antd';
import { LockOutlined, UserOutlined } from '@ant-design/icons';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../app/AuthContext';
import { authApi } from '../api/resources';

export function LoginPage() {
  const { user, login } = useAuth();
  const [error, setError] = useState('');
  const navigate = useNavigate();
  const location = useLocation();
  const queryClient = useQueryClient();
  const bootstrapStatus = useQuery({ queryKey: ['auth', 'bootstrap-status'], queryFn: authApi.bootstrapStatus, retry: 1 });
  const bootstrap = useMutation({
    mutationFn: ({ bootstrapToken, username, password }: { bootstrapToken: string; username: string; password: string }) => authApi.bootstrap(bootstrapToken, username, password),
    onSuccess: async () => {
      message.success('管理员已初始化，请登录');
      await queryClient.invalidateQueries({ queryKey: ['auth', 'bootstrap-status'] });
    },
  });
  if (user) return <Navigate to="/" replace />;
  const submit = async ({ username, password }: { username: string; password: string }) => {
    setError('');
    try {
      await login(username, password);
      navigate((location.state as { from?: string } | null)?.from ?? '/', { replace: true });
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '登录失败');
    }
  };
  const initialize = async (values: { bootstrapToken: string; username: string; password: string }) => {
    setError('');
    try { await bootstrap.mutateAsync(values); } catch (reason) { setError(reason instanceof Error ? reason.message : '初始化失败'); }
  };
  return <main className="login-page">
    <section className="login-panel">
      <div className="login-title"><span className="brand-mark">F</span><div><Typography.Title level={2}>frp Admin</Typography.Title><Typography.Text type="secondary">{bootstrapStatus.data?.required ? '初始化管理员' : '集群运维控制台'}</Typography.Text></div></div>
      {error && <Alert type="error" showIcon message={error} />}
      {bootstrapStatus.isLoading ? <Skeleton active paragraph={{ rows: 4 }} /> : bootstrapStatus.isError ? <Alert type="error" showIcon message="无法读取初始化状态" description={bootstrapStatus.error.message} action={<Button onClick={() => void bootstrapStatus.refetch()}>重试</Button>} /> : bootstrapStatus.data?.required ? <Form layout="vertical" requiredMark={false} onFinish={initialize} size="large">
        <Form.Item name="bootstrapToken" label="启动令牌" rules={[{ required: true, message: '请输入服务启动令牌' }]}><Input.Password autoComplete="off" /></Form.Item>
        <Form.Item name="username" label="管理员账号" rules={[{ required: true, message: '请输入管理员账号' }]}><Input prefix={<UserOutlined />} autoComplete="username" /></Form.Item>
        <Form.Item name="password" label="管理员密码" rules={[{ required: true, message: '请输入管理员密码' }, { min: 12, message: '密码至少 12 位' }]}><Input.Password prefix={<LockOutlined />} autoComplete="new-password" /></Form.Item>
        <Form.Item name="confirmPassword" label="确认密码" dependencies={['password']} rules={[{ required: true, message: '请再次输入密码' }, ({ getFieldValue }) => ({ validator(_, value) { return !value || getFieldValue('password') === value ? Promise.resolve() : Promise.reject(new Error('两次输入的密码不一致')); } })]}><Input.Password prefix={<LockOutlined />} autoComplete="new-password" /></Form.Item>
        <Button type="primary" htmlType="submit" block loading={bootstrap.isPending}>创建管理员</Button>
      </Form> : <Form layout="vertical" requiredMark={false} onFinish={submit} size="large">
        <Form.Item name="username" label="账号" rules={[{ required: true, message: '请输入账号' }]}><Input prefix={<UserOutlined />} autoComplete="username" autoFocus /></Form.Item>
        <Form.Item name="password" label="密码" rules={[{ required: true, message: '请输入密码' }]}><Input.Password prefix={<LockOutlined />} autoComplete="current-password" /></Form.Item>
        <Button type="primary" htmlType="submit" block>登录</Button>
      </Form>}
    </section>
  </main>;
}
