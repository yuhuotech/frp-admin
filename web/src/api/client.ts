import type { Page } from './types';

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? '/api/v1';

export interface ProblemDetails {
  type?: string;
  title?: string;
  status?: number;
  detail?: string;
  instance?: string;
  request_id?: string;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    public problem: ProblemDetails,
  ) {
    super(problem.detail || problem.title || `请求失败 (${status})`);
    this.name = 'ApiError';
  }
}

function getCookie(name: string): string | undefined {
  return document.cookie
    .split('; ')
    .find((entry) => entry.startsWith(`${name}=`))
    ?.slice(name.length + 1);
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = init.method?.toUpperCase() ?? 'GET';
  const headers = new Headers(init.headers);
  headers.set('Accept', 'application/json');
  if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    const csrf = getCookie('csrf_token');
    if (csrf) headers.set('X-CSRF-Token', decodeURIComponent(csrf));
    headers.set('X-Request-ID', crypto.randomUUID());
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers,
    credentials: 'include',
  });
  if (response.status === 204) return undefined as T;
  const contentType = response.headers.get('content-type') ?? '';
  const body = contentType.includes('json') ? await response.json() : undefined;
  if (!response.ok) throw new ApiError(response.status, body ?? { title: response.statusText });
  return body as T;
}

async function requestBlob(path: string): Promise<Blob> {
  const response = await fetch(`${API_BASE}${path}`, { headers: { Accept: 'application/x-pem-file, text/plain' }, credentials: 'include' });
  if (!response.ok) {
    const contentType = response.headers.get('content-type') ?? '';
    const problem = contentType.includes('json') ? await response.json() as ProblemDetails : { title: response.statusText };
    throw new ApiError(response.status, problem);
  }
  return response.blob();
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown, headers?: HeadersInit) => request<T>(path, { method: 'POST', headers, body: body === undefined ? undefined : JSON.stringify(body) }),
  patch: <T>(path: string, body: unknown) => request<T>(path, { method: 'PATCH', body: JSON.stringify(body) }),
  put: <T>(path: string, body: unknown) => request<T>(path, { method: 'PUT', body: JSON.stringify(body) }),
  delete: <T>(path: string) => request<T>(path, { method: 'DELETE' }),
  blob: requestBlob,
};

export function normalizePage<T>(value: T[] | { data?: T[]; items?: T[]; next_cursor?: string; total?: number }): Page<T> {
  if (Array.isArray(value)) return { items: value };
  return { items: value.items ?? value.data ?? [], next_cursor: value.next_cursor, total: value.total };
}

export { API_BASE };
