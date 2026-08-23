import { expect, test, type Page } from '@playwright/test';
import { randomBytes } from 'node:crypto';

const tracedTest = test.extend<{ traceRecorder: void }>({
  traceRecorder: [async ({ context }, use, testInfo) => {
    await context.tracing.start({ screenshots: true, snapshots: true, sources: true });
    await use();
    if (testInfo.status !== testInfo.expectedStatus) {
      const path = testInfo.outputPath('trace.zip');
      await context.tracing.stop({ path });
      await testInfo.attach('trace', { path, contentType: 'application/zip' });
    } else {
      await context.tracing.stop();
    }
  }, { auto: true }],
});

const admin = { username: 'e2e-admin', password: 'e2e-admin-password-123' };
const accounts = {
  viewer: { username: 'e2e-viewer', password: 'e2e-viewer-password-123' },
  auditor: { username: 'e2e-auditor', password: 'e2e-auditor-password-123' },
  operator: { username: 'e2e-operator', password: 'e2e-operator-password-123' },
};

async function login(page: Page, username: string, password: string) {
  await page.goto('/login');
  await page.getByLabel('账号').fill(username);
  await page.getByLabel('密码').fill(password);
  await page.getByRole('button', { name: /登\s*录/ }).click();
  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByRole('heading', { name: '概览' })).toBeVisible();
}

async function logout(page: Page) {
  await page.locator('.user-menu').click();
  await page.getByText('退出登录').click();
  await expect(page).toHaveURL(/\/login$/);
}

test.describe.configure({ mode: 'serial' });

test('bootstraps a fresh SQLite database and supports logout/login', async ({ page }) => {
    const token = process.env.E2E_BOOTSTRAP_TOKEN;
    if (!token) throw new Error('E2E_BOOTSTRAP_TOKEN is required');
    await page.goto('/login');
    await expect(page.getByText('初始化管理员')).toBeVisible();
    await page.getByLabel('启动令牌').fill(token);
    await page.getByLabel('管理员账号').fill(admin.username);
    await page.getByLabel('管理员密码').fill(admin.password);
    await page.getByLabel('确认密码').fill(admin.password);
    await page.getByRole('button', { name: '创建管理员' }).click();
    await expect(page.getByText('集群运维控制台')).toBeVisible();
    await login(page, admin.username, admin.password);
    await logout(page);
    await login(page, admin.username, admin.password);
});

// Network traces can contain POST bodies, so this test intentionally emits screenshots only.
test('submits a random Secret without persistence or value echo', async ({ page }) => {
    const secretValue = randomBytes(32).toString('base64url');
    await login(page, admin.username, admin.password);
    await page.goto('/secrets');
    await page.getByRole('button', { name: /新建 Secret/ }).click();
    await page.getByLabel('名称').fill('e2e.frp.token');
    await page.getByLabel('值').fill(secretValue);
    await page.getByRole('button', { name: /创\s*建/ }).click();
    await expect(page.getByText('Secret 已创建')).toBeVisible();
    await expect(page.getByText('e2e.frp.token')).toBeVisible();
    await expect(page.getByText(secretValue)).toHaveCount(0);
    const browserState = await page.evaluate(() => ({ url: location.href, local: JSON.stringify(localStorage), session: JSON.stringify(sessionStorage) }));
    expect(browserState.url).not.toContain(secretValue);
    expect(browserState.local).not.toContain(secretValue);
    expect(browserState.session).not.toContain(secretValue);
});

tracedTest('creates users and enforces role navigation and direct URLs', async ({ page }) => {
  await login(page, admin.username, admin.password);
  await page.goto('/users');
  for (const [role, account] of Object.entries(accounts)) {
    await page.getByRole('button', { name: /新建用户/ }).click();
    await page.getByLabel('账号').fill(account.username);
    await page.getByLabel('初始密码').fill(account.password);
    if (role !== 'viewer') {
      const roleSelect = page.getByRole('dialog').getByRole('combobox', { name: /角色/ });
      await roleSelect.click();
      await page
        .locator('.ant-select-dropdown:visible .ant-select-item-option')
        .filter({ hasText: new RegExp(`^${role}$`) })
        .click();
    }
    await page.getByRole('button', { name: /创\s*建/ }).click();
    await expect(page.getByText(account.username)).toBeVisible();
  }
  await logout(page);

  await login(page, accounts.viewer.username, accounts.viewer.password);
  await expect(page.getByText('配置发布', { exact: true })).toHaveCount(0);
  await expect(page.getByText('Secrets', { exact: true })).toHaveCount(0);
  await expect(page.getByText('审计日志', { exact: true })).toHaveCount(0);
  await page.goto('/users');
  await expect(page).toHaveURL(/\/$/);
  await logout(page);

  await login(page, accounts.auditor.username, accounts.auditor.password);
  await expect(page.getByText('审计日志', { exact: true })).toBeVisible();
  await expect(page.getByText('配置发布', { exact: true })).toHaveCount(0);
  await page.goto('/secrets');
  await expect(page).toHaveURL(/\/$/);
  await logout(page);

  await login(page, accounts.operator.username, accounts.operator.password);
  await expect(page.getByText('Secrets', { exact: true })).toBeVisible();
  await expect(page.getByText('审计日志', { exact: true })).toHaveCount(0);
  await page.goto('/audit');
  await expect(page).toHaveURL(/\/$/);
});

tracedTest('runs production operations and preserves server-side RBAC', async ({ page }) => {
  const now = new Date().toISOString();
  const node = {
    id: 'e2e-node',
    name: 'e2e-node',
    hostname: 'e2e-host',
    role: 'client',
    management_mode: 'managed',
    status: 'online',
    service_status: 'active',
    capabilities: ['service.start', 'service.stop', 'service.restart', 'runtime.collect'],
    created_at: now,
  };
  const queuedTask = { id: 'e2e-task', type: 'service_restart', status: 'queued', node_id: node.id, node_name: node.name, actor: admin.username, created_at: now, steps: [] };
  const openAlert = { id: 'e2e-alert', kind: 'node_offline', severity: 'critical', state: 'open', resource: `node/${node.id}`, fingerprint: `node_offline:node/${node.id}`, message: 'Agent heartbeat expired', created_at: now, updated_at: now };
  let serviceActionBody: unknown;
  let managementMode = '';
  let taskCancelled = false;
  let alertAction = '';

  await login(page, admin.username, admin.password);
  await page.route('**/api/v1/nodes/e2e-node', (route) => route.fulfill({ json: { ...node, management_mode: managementMode || node.management_mode } }));
  await page.route('**/api/v1/nodes/e2e-node/management-mode', async (route) => {
    managementMode = route.request().postDataJSON().mode;
    await route.fulfill({ json: { ...node, management_mode: managementMode } });
  });
  await page.route('**/api/v1/nodes/e2e-node/service-actions', async (route) => {
    serviceActionBody = route.request().postDataJSON();
    await route.fulfill({ status: 202, json: queuedTask });
  });
  await page.route('**/api/v1/tasks/e2e-task', (route) => route.fulfill({ json: queuedTask }));
  await page.route('**/api/v1/tasks/e2e-task/cancel', async (route) => {
    taskCancelled = true;
    await route.fulfill({ json: { ...queuedTask, status: 'cancelled' } });
  });
  await page.goto(`/nodes/${node.id}`);
  await page.getByRole('button', { name: /切换为观察/ }).click();
  await page.getByRole('button', { name: '确认观察' }).click();
  await expect.poll(() => managementMode).toBe('observe');
  await expect(page.getByRole('button', { name: /重启/ })).toBeDisabled();
  await page.getByRole('button', { name: /切换为托管/ }).click();
  await page.getByRole('button', { name: '确认托管' }).click();
  await expect.poll(() => managementMode).toBe('managed');
  await page.getByRole('button', { name: /重启/ }).click();
  await page.getByRole('button', { name: '确认重启' }).click();
  await expect(page).toHaveURL(/\/tasks\/e2e-task$/);
  expect(serviceActionBody).toEqual({ action: 'restart' });
  await page.getByRole('button', { name: /取消任务/ }).click();
  await page.getByRole('button', { name: '确认取消' }).click();
  await expect.poll(() => taskCancelled).toBe(true);

  await page.route('**/api/v1/alerts?*', async (route) => {
    const state = new URL(route.request().url()).searchParams.get('state');
    await route.fulfill({ json: { items: [{ ...openAlert, state: state || 'open' }] } });
  });
  await page.route('**/api/v1/alerts/e2e-alert/*', async (route) => {
    alertAction = route.request().url().split('/').at(-1) ?? '';
    await route.fulfill({ json: { ...openAlert, state: alertAction === 'acknowledge' ? 'acknowledged' : alertAction === 'resolve' ? 'resolved' : 'closed' } });
  });
  await page.goto('/alerts');
  await expect(page.getByText('Agent heartbeat expired')).toBeVisible();
  await page.getByRole('button', { name: /确认/ }).click();
  await expect.poll(() => alertAction).toBe('acknowledge');
  await page.getByText('已确认', { exact: true }).click();
  await expect(page).toHaveURL(/\/alerts$/);
  await expect(page.getByRole('button', { name: /关闭/ })).toBeVisible();
  await page.getByRole('button', { name: /关闭/ }).click();
  await page.getByRole('button', { name: '确认关闭' }).click();
  await expect.poll(() => alertAction).toBe('close');

  await page.unrouteAll({ behavior: 'wait' });
  await logout(page);
  await login(page, accounts.viewer.username, accounts.viewer.password);
  const forbiddenStatus = await page.evaluate(async () => {
    const csrf = document.cookie.split('; ').find((entry) => entry.startsWith('csrf_token='))?.split('=').slice(1).join('=') ?? '';
    const response = await fetch('/api/v1/alerts/missing/close', { method: 'POST', credentials: 'include', headers: { 'X-CSRF-Token': decodeURIComponent(csrf), 'X-Request-ID': crypto.randomUUID() } });
    return response.status;
  });
  expect(forbiddenStatus).toBe(403);
});

tracedTest('filters proxy runtime and manages an idempotent upgrade plan', async ({ page }) => {
  const now = new Date().toISOString();
  const node = { id: 'sprint4-node', name: 'edge-shanghai', hostname: 'edge-01', role: 'client', management_mode: 'managed', status: 'online', service_status: 'active', created_at: now };
  const proxy = { node_id: node.id, node_name: node.name, name: 'web-tcp', type: 'tcp', status: 'running', local_address: '127.0.0.1:8080', remote_address: 'frps.example:18080', last_error: '', traffic: { bytes_in: 2048, bytes_out: 4096, today_bytes_in: 1024, today_bytes_out: 1536, current_connections: 3 }, collected_at: now };
  const plan = { id: 'upgrade-plan-1', node_id: node.id, node_name: node.name, version: '0.61.0', artifact_url: 'https://cdn.example/frp.tar.gz', sha256: 'a'.repeat(64), state: 'queued', task_id: 'upgrade-task-1', created_by: admin.username, created_at: now, updated_at: now };
  let proxyQuery = '';
  let upgradeBody: unknown;
  let idempotencyKey = '';
  let upgradeCancelled = false;

  await login(page, admin.username, admin.password);
  await page.route('**/api/v1/nodes?*', (route) => route.fulfill({ json: { items: [node] } }));
  await page.route(/\/api\/v1\/proxies\?.*/, async (route) => {
    proxyQuery = new URL(route.request().url()).search;
    await route.fulfill({ json: { items: [proxy] } });
  });
  await page.route('**/api/v1/proxies/sprint4-node/web-tcp', (route) => route.fulfill({ json: proxy }));
  await page.goto('/proxies');
  await expect(page.getByText('frps.example:18080')).toBeVisible();
  await page.locator('.toolbar').getByText('错误', { exact: true }).click();
  await expect.poll(() => proxyQuery).toContain('status=error');
  await page.getByRole('button', { name: 'web-tcp' }).click();
  await expect(page.getByText('1.50 KiB')).toBeVisible();
  await page.getByRole('button', { name: '关闭', exact: true }).click();

  await page.route(/\/api\/v1\/upgrade-plans\?.*/, (route) => route.fulfill({ json: { items: [plan] } }));
  await page.route(/\/api\/v1\/upgrade-plans$/, async (route) => {
    upgradeBody = route.request().postDataJSON();
    idempotencyKey = route.request().headers()['idempotency-key'] ?? '';
    await route.fulfill({ status: 202, json: { plan, task: { id: plan.task_id, type: 'upgrade_frp', status: 'queued', node_id: node.id, created_at: now } } });
  });
  await page.route('**/api/v1/upgrade-plans/upgrade-plan-1/cancel', async (route) => {
    upgradeCancelled = true;
    await route.fulfill({ json: { plan: { ...plan, state: 'cancelled' }, task: { id: plan.task_id, type: 'upgrade_frp', status: 'cancelled', created_at: now } } });
  });
  await page.goto('/upgrades');
  await page.getByRole('button', { name: /新建升级/ }).click();
  const dialog = page.getByRole('dialog', { name: '新建单节点升级' });
  await dialog.getByRole('combobox', { name: /节点/ }).click();
  await page.locator('.ant-select-dropdown:visible .ant-select-item-option').filter({ hasText: /^edge-shanghai$/ }).click();
  await dialog.getByRole('textbox', { name: /目标版本/ }).fill('0.62.0');
  await dialog.getByRole('textbox', { name: /制品 URL/ }).fill('https://cdn.example/frp-0.62.0.tar.gz');
  await dialog.getByRole('textbox', { name: /SHA256/ }).fill('b'.repeat(64));
  await dialog.getByRole('button', { name: /创建升级任务/ }).click();
  await page.getByRole('button', { name: '确认升级' }).click();
  await expect.poll(() => upgradeBody).toEqual({ node_id: node.id, version: '0.62.0', artifact_url: 'https://cdn.example/frp-0.62.0.tar.gz', sha256: 'b'.repeat(64) });
  expect(idempotencyKey).not.toBe('');
  await page.getByRole('button', { name: /取消/ }).first().click();
  await page.getByRole('button', { name: '确认取消' }).click();
  await expect.poll(() => upgradeCancelled).toBe(true);

  await page.unrouteAll({ behavior: 'wait' });
  await logout(page);
  await login(page, accounts.viewer.username, accounts.viewer.password);
  await page.goto('/upgrades');
  await expect(page).toHaveURL(/\/$/);
  const access = await page.evaluate(async () => {
    const csrf = document.cookie.split('; ').find((entry) => entry.startsWith('csrf_token='))?.split('=').slice(1).join('=') ?? '';
    const proxies = await fetch('/api/v1/proxies?limit=1', { credentials: 'include' });
    const response = await fetch('/api/v1/upgrade-plans', { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': decodeURIComponent(csrf), 'X-Request-ID': crypto.randomUUID(), 'Idempotency-Key': crypto.randomUUID() }, body: JSON.stringify({ node_id: 'missing', version: '0.62.0', artifact_url: 'https://cdn.example/frp.tar.gz', sha256: 'b'.repeat(64) }) });
    return { proxies: proxies.status, upgrade: response.status };
  });
  expect(access).toEqual({ proxies: 200, upgrade: 403 });
});

tracedTest('filters real audit records', async ({ page }) => {
  await login(page, admin.username, admin.password);
  await page.goto('/audit');
  await page.getByRole('textbox', { name: '操作', exact: true }).fill('secret.create');
  await page.getByRole('button', { name: '查询' }).click();
  await expect(page.getByText('secret.create', { exact: true }).first()).toBeVisible();
  await expect(page.getByText('成功', { exact: true }).first()).toBeVisible();
});

tracedTest('shows HTTP 429 after five failed logins', async ({ page }) => {
  await page.goto('/login');
  await page.getByLabel('账号').fill(`blocked-${Date.now()}`);
  await page.getByLabel('密码').fill('wrong-password-123');
  for (let attempt = 1; attempt <= 5; attempt += 1) {
    const responsePromise = page.waitForResponse((response) => response.url().endsWith('/api/v1/auth/login'));
    await page.getByRole('button', { name: /登\s*录/ }).click();
    const response = await responsePromise;
    expect(response.status()).toBe(attempt === 5 ? 429 : 401);
  }
  await expect(page.getByText('too many authentication attempts')).toBeVisible();
});
