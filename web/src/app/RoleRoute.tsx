import { Navigate, Outlet } from 'react-router-dom';
import { useAuth } from './AuthContext';

export function RoleRoute({ roles }: { roles: string[] }) {
  const { user } = useAuth();
  return user && roles.includes(user.role) ? <Outlet /> : <Navigate to="/" replace />;
}
