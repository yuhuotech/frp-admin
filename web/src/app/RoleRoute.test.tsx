import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { RoleRoute } from './RoleRoute';

const state = vi.hoisted(() => ({ role: 'viewer' }));
vi.mock('./AuthContext', () => ({ useAuth: () => ({ user: { id: 'u1', username: 'test', role: state.role } }) }));

function renderRoute() {
  return render(<MemoryRouter initialEntries={['/admin']}><Routes><Route path="/" element={<span>home</span>} /><Route element={<RoleRoute roles={['admin']} />}><Route path="/admin" element={<span>admin page</span>} /></Route></Routes></MemoryRouter>);
}

describe('RoleRoute', () => {
  it('rejects roles outside the allowlist', () => {
    state.role = 'viewer';
    renderRoute();
    expect(screen.getByText('home')).toBeInTheDocument();
  });

  it('allows an authorized role', () => {
    state.role = 'admin';
    renderRoute();
    expect(screen.getByText('admin page')).toBeInTheDocument();
  });
});
