import { useState } from 'react';
import { Avatar, Button, Dropdown, Form, Input, Layout, Menu, Modal, Space, Typography, message } from 'antd';
import {
  AlertOutlined, AuditOutlined, CloudServerOutlined, DashboardOutlined, DeploymentUnitOutlined,
  LogoutOutlined, MenuFoldOutlined, MenuUnfoldOutlined, SafetyCertificateOutlined, SwapOutlined, TeamOutlined, UserOutlined,
} from '@ant-design/icons';
import { Outlet, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../app/AuthContext';
import { useEvents } from '../app/useEvents';
import { authApi } from '../api/resources';

const { Header, Sider, Content } = Layout;
const menuItems = [
  { key: '/', icon: <DashboardOutlined />, label: '概览' },
  { key: '/nodes', icon: <CloudServerOutlined />, label: '节点管理' },
  { key: '/proxies', icon: <DeploymentUnitOutlined />, label: '代理管理' },
  { key: '/tasks', icon: <SwapOutlined />, label: '操作记录' },
  { key: '/alerts', icon: <AlertOutlined />, label: '告警中心' },
  { key: '/security', icon: <SafetyCertificateOutlined />, label: '安全检查' },
  { key: '/audit', icon: <AuditOutlined />, label: '审计日志', roles: ['admin', 'auditor'] },
  { key: '/users', icon: <TeamOutlined />, label: '系统管理', roles: ['admin'] },
];

type ProfileValues = { display_name?: string };
type PasswordValues = { current_password: string; new_password: string; confirm_password: string };

export function AppLayout() {
  const [collapsed, setCollapsed] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const [passwordOpen, setPasswordOpen] = useState(false);
  const [profileForm] = Form.useForm<ProfileValues>();
  const [passwordForm] = Form.useForm<PasswordValues>();
  const navigate = useNavigate();
  const location = useLocation();
  const { user, logout, updateUser } = useAuth();
  useEvents(Boolean(user));
  const visibleMenuItems = menuItems.filter((item) => !item.roles || (user && item.roles.includes(user.role)));
  const selected = visibleMenuItems.find((item) => item.key !== '/' && location.pathname.startsWith(item.key))?.key ?? '/';
  const displayName = user?.display_name || user?.displayName || user?.username;
  const submitProfile = async (values: ProfileValues) => {
    try { const updated = await authApi.updateProfile(values.display_name ?? ''); updateUser(updated); message.success('个人信息已更新'); setProfileOpen(false); }
    catch (error) { message.error((error as Error).message); }
  };
  const submitPassword = async (values: PasswordValues) => {
    try { await authApi.changePassword(values.current_password, values.new_password); message.success('密码已修改，请使用新密码重新登录'); setPasswordOpen(false); passwordForm.resetFields(); await logout(); navigate('/login', { replace: true }); }
    catch (error) { message.error((error as Error).message); }
  };
  const profileItems = [
    { key: 'profile', icon: <UserOutlined />, label: '个人信息', onClick: () => { profileForm.setFieldsValue({ display_name: user?.display_name || user?.displayName || '' }); setProfileOpen(true); } },
    { key: 'password', icon: <UserOutlined />, label: '修改密码', onClick: () => { passwordForm.resetFields(); setPasswordOpen(true); } },
    { type: 'divider' as const },
    { key: 'logout', icon: <LogoutOutlined />, label: '退出登录', onClick: async () => { await logout(); navigate('/login'); } },
  ];
  return <Layout className="app-shell">
    <Sider breakpoint="lg" collapsedWidth="0" width={216} trigger={null} collapsible collapsed={collapsed} className="app-sider">
      <div className="brand"><span className="brand-mark">F</span><span>frp Admin</span></div>
      <Menu theme="dark" mode="inline" selectedKeys={[selected]} items={visibleMenuItems} onClick={({ key }) => navigate(key)} />
    </Sider>
    <Layout>
      <Header className="app-header">
        <Button type="text" aria-label={collapsed ? '展开导航' : '收起导航'} icon={collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />} onClick={() => setCollapsed((value) => !value)} />
        <Dropdown menu={{ items: profileItems }} trigger={['click']}>
          <Space className="user-menu"><Avatar size="small" icon={<UserOutlined />} /><Typography.Text>{displayName}</Typography.Text></Space>
        </Dropdown>
      </Header>
      <Content className="app-content"><Outlet /></Content>
    </Layout>
    <Modal title="个人信息" open={profileOpen} okText="保存" cancelText="取消" onCancel={() => setProfileOpen(false)} onOk={() => profileForm.submit()}>
      <Form form={profileForm} layout="vertical" onFinish={(values) => void submitProfile(values)}>
        <Form.Item label="登录账号"><Input value={user?.username} disabled /></Form.Item>
        <Form.Item name="display_name" label="显示名称" rules={[{ max: 128, message: '显示名称不能超过 128 个字符' }]}><Input placeholder="用于右上角和操作记录展示" maxLength={128} /></Form.Item>
        <Form.Item label="角色"><Input value={user?.role} disabled /></Form.Item>
      </Form>
    </Modal>
    <Modal title="修改密码" open={passwordOpen} okText="确认修改" cancelText="取消" onCancel={() => setPasswordOpen(false)} onOk={() => passwordForm.submit()}>
      <Form form={passwordForm} layout="vertical" onFinish={(values) => void submitPassword(values)}>
        <Form.Item name="current_password" label="当前密码" rules={[{ required: true, message: '请输入当前密码' }]}><Input.Password autoComplete="current-password" /></Form.Item>
        <Form.Item name="new_password" label="新密码" rules={[{ required: true, min: 12, message: '新密码至少 12 位' }]}><Input.Password autoComplete="new-password" /></Form.Item>
        <Form.Item name="confirm_password" label="确认新密码" dependencies={['new_password']} rules={[{ required: true, message: '请再次输入新密码' }, ({ getFieldValue }) => ({ validator(_, value) { return !value || value === getFieldValue('new_password') ? Promise.resolve() : Promise.reject(new Error('两次输入的密码不一致')); } })]}><Input.Password autoComplete="new-password" /></Form.Item>
        <Typography.Text type="secondary">修改成功后，当前登录会话会失效，需要重新登录。</Typography.Text>
      </Form>
    </Modal>
  </Layout>;
}
