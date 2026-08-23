export type AlertAction = 'acknowledge' | 'resolve' | 'close';

export function canOperate(role?: string): boolean {
  return role === 'admin' || role === 'operator';
}

export function canRemediateRisk(role: string | undefined, mode?: string, online?: boolean): boolean {
  return canOperate(role) && mode === 'managed' && online === true;
}

export function isCancellableTask(state?: string): boolean {
  return state !== undefined && ['pending', 'queued', 'dispatched', 'running'].includes(state);
}

export function availableAlertActions(role: string | undefined, state: string): AlertAction[] {
  const actions: AlertAction[] = [];
  if (canOperate(role) && state === 'open') actions.push('acknowledge');
  if (canOperate(role) && (state === 'open' || state === 'acknowledged')) actions.push('resolve');
  if (role === 'admin' && (state === 'acknowledged' || state === 'resolved')) actions.push('close');
  return actions;
}
