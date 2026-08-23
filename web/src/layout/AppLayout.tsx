import { useState } from 'react';
import { Avatar, Button, Dropdown, Layout, Menu, Space, Typography } from 'antd';
import {
  AlertOutlined, AuditOutlined, CloudServerOutlined, DashboardOutlined, DeploymentUnitOutlined,
  KeyOutlined, LogoutOutlined, MenuFoldOutlined, MenuUnfoldOutlined, SafetyCertificateOutlined,
  SwapOutlined, TeamOutlined, ThunderboltOutlined, UserOutlined,
} from '@ant-design/icons';
import { Outlet, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../app/AuthContext';
import { useEvents } from '../app/useEvents';

const { Header, Sider, Content } = Layout;
const menuItems = [
  { key: '/', icon: <DashboardOutlined />, label: '概览' },
  { key: '/nodes', icon: <CloudServerOutlined />, label: '节点' },
  { key: '/proxies', icon: <DeploymentUnitOutlined />, label: '代理' },
  { key: '/secrets', icon: <KeyOutlined />, label: 'Secrets', roles: ['admin', 'operator'] },
  { key: '/upgrades', icon: <ThunderboltOutlined />, label: '升级计划', roles: ['admin', 'operator'] },
  { key: '/tasks', icon: <SwapOutlined />, label: '任务' },
  { key: '/alerts', icon: <AlertOutlined />, label: '告警' },
  { key: '/risks', icon: <SafetyCertificateOutlined />, label: '风险中心' },
  { key: '/audit', icon: <AuditOutlined />, label: '审计日志', roles: ['admin', 'auditor'] },
  { key: '/users', icon: <TeamOutlined />, label: '用户与 RBAC', roles: ['admin'] },
];

export function AppLayout() {
  const [collapsed, setCollapsed] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();
  const { user, logout } = useAuth();
  useEvents(Boolean(user));
  const visibleMenuItems = menuItems.filter((item) => !item.roles || (user && item.roles.includes(user.role)));
  const selected = visibleMenuItems.find((item) => item.key !== '/' && location.pathname.startsWith(item.key))?.key ?? '/';
  return (
    <Layout className="app-shell">
      <Sider breakpoint="lg" collapsedWidth="0" width={216} trigger={null} collapsible collapsed={collapsed} className="app-sider">
        <div className="brand"><span className="brand-mark">F</span><span>frp Admin</span></div>
        <Menu theme="dark" mode="inline" selectedKeys={[selected]} items={visibleMenuItems} onClick={({ key }) => navigate(key)} />
      </Sider>
      <Layout>
        <Header className="app-header">
          <Button type="text" aria-label={collapsed ? '展开导航' : '收起导航'} icon={collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />} onClick={() => setCollapsed((value) => !value)} />
          <Dropdown menu={{ items: [{ key: 'logout', icon: <LogoutOutlined />, label: '退出登录', onClick: async () => { await logout(); navigate('/login'); } }] }}>
            <Space className="user-menu"><Avatar size="small" icon={<UserOutlined />} /><Typography.Text>{user?.display_name || user?.username}</Typography.Text></Space>
          </Dropdown>
        </Header>
        <Content className="app-content"><Outlet /></Content>
      </Layout>
    </Layout>
  );
}
