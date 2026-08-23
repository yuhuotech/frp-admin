import { fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { ConfigEditor, MAX_CONFIG_BYTES, configByteLength } from './ConfigEditor';

describe('ConfigEditor', () => {
  it('saves edited TOML and selected strategy', async () => {
    const user = userEvent.setup();
    const onSave = vi.fn();
    render(<ConfigEditor initialContent="" canWrite saving={false} onSave={onSave} />);
    fireEvent.change(screen.getByLabelText('TOML 配置'), { target: { value: '[common]\nserverAddr = "127.0.0.1"' } });
    await user.click(screen.getByText('Restart'));
    await user.click(screen.getByRole('button', { name: /保存修订/ }));
    expect(onSave).toHaveBeenCalledWith('[common]\nserverAddr = "127.0.0.1"', 'restart');
  });

  it('keeps viewer editor read-only', () => {
    render(<ConfigEditor initialContent="serverPort = 7000" canWrite={false} saving={false} onSave={vi.fn()} />);
    expect(screen.getByLabelText('TOML 配置')).toHaveAttribute('readonly');
    expect(screen.getByRole('button', { name: /保存修订/ })).toBeDisabled();
  });

  it('counts UTF-8 bytes for the 1 MiB limit', () => {
    expect(configByteLength('中')).toBe(3);
    expect(MAX_CONFIG_BYTES).toBe(1_048_576);
  });
});
