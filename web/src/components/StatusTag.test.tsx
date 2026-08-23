import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { StatusTag } from './StatusTag';

describe('StatusTag', () => {
  it('renders localized known state', () => {
    render(<StatusTag value="online" />);
    expect(screen.getByText('在线')).toBeInTheDocument();
  });

  it('preserves unknown state', () => {
    render(<StatusTag value="rolling_back" />);
    expect(screen.getByText('rolling_back')).toBeInTheDocument();
  });
});
