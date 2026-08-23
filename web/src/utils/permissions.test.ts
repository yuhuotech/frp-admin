import { describe, expect, it } from 'vitest';
import { availableAlertActions, canOperate, isCancellableTask } from './permissions';

describe('production action permissions', () => {
  it('limits node and task mutations to admin and operator', () => {
    expect(canOperate('admin')).toBe(true);
    expect(canOperate('operator')).toBe(true);
    expect(canOperate('viewer')).toBe(false);
    expect(canOperate('auditor')).toBe(false);
  });

  it('keeps every non-terminal server task state cancellable', () => {
    for (const state of ['pending', 'queued', 'dispatched', 'running']) expect(isCancellableTask(state)).toBe(true);
    for (const state of ['succeeded', 'failed', 'cancelled']) expect(isCancellableTask(state)).toBe(false);
  });

  it('matches the server alert state machine and RBAC matrix', () => {
    expect(availableAlertActions('operator', 'open')).toEqual(['acknowledge', 'resolve']);
    expect(availableAlertActions('operator', 'acknowledged')).toEqual(['resolve']);
    expect(availableAlertActions('admin', 'acknowledged')).toEqual(['resolve', 'close']);
    expect(availableAlertActions('admin', 'resolved')).toEqual(['close']);
    expect(availableAlertActions('viewer', 'open')).toEqual([]);
    expect(availableAlertActions('auditor', 'resolved')).toEqual([]);
    expect(availableAlertActions('admin', 'closed')).toEqual([]);
  });
});
