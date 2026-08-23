import { lazy, Suspense } from 'react';
import { Navigate, Outlet, Route, Routes, useLocation } from 'react-router-dom';
import { Spin } from 'antd';
import { useAuth } from './app/AuthContext';
import { AppLayout } from './layout/AppLayout';
import { RoleRoute } from './app/RoleRoute';

const AlertsPage = lazy(() => import('./pages/AlertsPage').then((module) => ({ default: module.AlertsPage })));
const DashboardPage = lazy(() => import('./pages/DashboardPage').then((module) => ({ default: module.DashboardPage })));
const LoginPage = lazy(() => import('./pages/LoginPage').then((module) => ({ default: module.LoginPage })));
const NodeDetailPage = lazy(() => import('./pages/NodeDetailPage').then((module) => ({ default: module.NodeDetailPage })));
const NodeConfigurationPage = lazy(() => import('./pages/NodeConfigurationPage').then((module) => ({ default: module.NodeConfigurationPage })));
const NodesPage = lazy(() => import('./pages/NodesPage').then((module) => ({ default: module.NodesPage })));
const ProxiesPage = lazy(() => import('./pages/ProxiesPage').then((module) => ({ default: module.ProxiesPage })));
const TaskDetailPage = lazy(() => import('./pages/TaskDetailPage').then((module) => ({ default: module.TaskDetailPage })));
const TasksPage = lazy(() => import('./pages/TasksPage').then((module) => ({ default: module.TasksPage })));
const SecretsPage = lazy(() => import('./pages/SecretsPage').then((module) => ({ default: module.SecretsPage })));
const UsersPage = lazy(() => import('./pages/UsersPage').then((module) => ({ default: module.UsersPage })));
const UpgradesPage = lazy(() => import('./pages/UpgradesPage').then((module) => ({ default: module.UpgradesPage })));
const AuditPage = lazy(() => import('./pages/AuditPage').then((module) => ({ default: module.AuditPage })));
const RisksPage = lazy(() => import('./pages/RisksPage').then((module) => ({ default: module.RisksPage })));

function ProtectedRoute() {
  const { user, loading } = useAuth();
  const location = useLocation();
  if (loading) return <div className="screen-loading"><Spin size="large" /></div>;
  return user ? <Outlet /> : <Navigate to="/login" state={{ from: location.pathname + location.search }} replace />;
}

export default function App() {
  return <Suspense fallback={<div className="screen-loading"><Spin size="large" /></div>}><Routes>
    <Route path="/login" element={<LoginPage />} />
    <Route element={<ProtectedRoute />}>
      <Route element={<AppLayout />}>
        <Route index element={<DashboardPage />} />
        <Route path="nodes" element={<NodesPage />} />
        <Route path="nodes/:id" element={<NodeDetailPage />} />
        <Route path="nodes/:id/configuration" element={<NodeConfigurationPage />} />
        <Route path="tasks" element={<TasksPage />} />
        <Route path="tasks/:id" element={<TaskDetailPage />} />
        <Route path="alerts" element={<AlertsPage />} />
        <Route path="risks" element={<RisksPage />} />
        <Route path="proxies" element={<ProxiesPage />} />
        <Route element={<RoleRoute roles={['admin', 'operator']} />}><Route path="secrets" element={<SecretsPage />} /><Route path="upgrades" element={<UpgradesPage />} /></Route>
        <Route element={<RoleRoute roles={['admin', 'auditor']} />}><Route path="audit" element={<AuditPage />} /></Route>
        <Route element={<RoleRoute roles={['admin']} />}><Route path="users" element={<UsersPage />} /></Route>
      </Route>
    </Route>
    <Route path="*" element={<Navigate to="/" replace />} />
  </Routes></Suspense>;
}
