import { useEffect } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { API_BASE } from '../api/client';

const RESOURCE_KEYS: Record<string, string> = {
  node: 'nodes',
  task: 'tasks',
  alert: 'alerts',
  proxy: 'proxies',
  audit: 'audit',
};

export function useEvents(enabled: boolean) {
  const queryClient = useQueryClient();
  useEffect(() => {
    if (!enabled) return;
    const source = new EventSource(`${API_BASE}/events`, { withCredentials: true });
    const invalidate = (event: MessageEvent) => {
      try {
        const payload = JSON.parse(event.data) as { resource?: string; type?: string };
        const hint = payload.resource ?? payload.type?.split('.')[0];
        const key = hint ? RESOURCE_KEYS[hint] : undefined;
        if (key) void queryClient.invalidateQueries({ queryKey: [key] });
        else void queryClient.invalidateQueries();
      } catch {
        void queryClient.invalidateQueries();
      }
    };
    source.onmessage = invalidate;
    ['node.changed', 'task.changed', 'alert.changed'].forEach((name) => source.addEventListener(name, invalidate as EventListener));
    return () => source.close();
  }, [enabled, queryClient]);
}
