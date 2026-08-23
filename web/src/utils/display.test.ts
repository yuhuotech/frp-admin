import { describe, expect, it } from 'vitest';
import { formatBytes, sanitizeArtifactURL } from './display';

describe('production-safe display helpers', () => {
  it('formats traffic counters without changing source values', () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(1536)).toBe('1.50 KiB');
    expect(formatBytes(-1)).toBe('-');
  });

  it('removes credentials carried by artifact query strings and fragments', () => {
    expect(sanitizeArtifactURL('https://cdn.example/frp/v1.tar.gz?X-Signature=secret#download')).toBe('https://cdn.example/frp/v1.tar.gz');
  });
});
