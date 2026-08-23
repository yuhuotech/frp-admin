import { useState } from 'react';
import { Alert, Button, Form, Input, Segmented, Space, Typography } from 'antd';
import { SaveOutlined } from '@ant-design/icons';
import type { ConfigStrategy } from '../api/types';

export const MAX_CONFIG_BYTES = 1024 * 1024;

export function configByteLength(value: string) {
  return new TextEncoder().encode(value).byteLength;
}

export function ConfigEditor({ initialContent, initialStrategy = 'reload', canWrite, saving, onSave }: {
  initialContent: string;
  initialStrategy?: ConfigStrategy;
  canWrite: boolean;
  saving: boolean;
  onSave: (content: string, strategy: ConfigStrategy) => void;
}) {
  const [content, setContent] = useState(initialContent);
  const [strategy, setStrategy] = useState<ConfigStrategy>(initialStrategy);
  const bytes = configByteLength(content);
  const invalid = bytes > MAX_CONFIG_BYTES || !content.trim();
  return <div className="content-panel config-editor">
    <div className="section-title"><div><Typography.Title level={5}>新建配置修订</Typography.Title><Typography.Text type="secondary">保存后生成不可变修订，不会自动发布</Typography.Text></div><Space><Typography.Text type={bytes > MAX_CONFIG_BYTES ? 'danger' : 'secondary'}>{bytes.toLocaleString()} / {MAX_CONFIG_BYTES.toLocaleString()} bytes</Typography.Text><Button type="primary" icon={<SaveOutlined />} disabled={!canWrite || invalid} loading={saving} onClick={() => onSave(content, strategy)}>保存修订</Button></Space></div>
    {!canWrite && <Alert showIcon type="info" title="当前角色为只读权限" />}
    <Form layout="vertical">
      <Form.Item label="发布策略"><Segmented disabled={!canWrite} value={strategy} onChange={(value) => setStrategy(value as ConfigStrategy)} options={[{ label: 'Reload', value: 'reload' }, { label: 'Restart', value: 'restart' }]} /></Form.Item>
      <Form.Item label="TOML 配置" validateStatus={bytes > MAX_CONFIG_BYTES ? 'error' : undefined} help={bytes > MAX_CONFIG_BYTES ? '配置不能超过 1 MiB' : undefined}>
        <Input.TextArea aria-label="TOML 配置" className="config-textarea mono" value={content} readOnly={!canWrite} onChange={(event) => setContent(event.target.value)} autoSize={{ minRows: 16, maxRows: 28 }} spellCheck={false} />
      </Form.Item>
    </Form>
  </div>;
}
