import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { secretsApi } from '../api/resources';
import { SecretsPage } from './SecretsPage';

describe('SecretsPage', () => {
  it('clears value and does not expose a server error containing it', async () => {
    const user = userEvent.setup();
    vi.spyOn(secretsApi, 'list').mockResolvedValue({ items: [] });
    vi.spyOn(secretsApi, 'create').mockRejectedValue(new Error('backend echoed top-secret-value'));
    render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><SecretsPage /></QueryClientProvider>);
    await screen.findByText('暂无 Secret');
    await user.click(screen.getByRole('button', { name: /新建 Secret/ }));
    fireEvent.change(screen.getByLabelText('名称'), { target: { value: 'frp.token' } });
    fireEvent.change(screen.getByLabelText('值'), { target: { value: 'top-secret-value' } });
    await user.click(screen.getByRole('button', { name: /创\s*建/ }));
    await screen.findByText('Secret 写入失败，请重新输入后重试');
    await waitFor(() => expect(screen.queryByDisplayValue('top-secret-value')).not.toBeInTheDocument());
    expect(screen.queryByText(/backend echoed|top-secret-value/)).not.toBeInTheDocument();
  });
});
