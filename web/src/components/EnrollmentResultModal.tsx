import { Button, Descriptions, Input, message, Modal, Space, Tag, Typography } from 'antd';
import { CopyOutlined, WarningOutlined } from '@ant-design/icons';
import type { EnrollmentToken } from '../api/types';
import { formatTime } from '../utils/format';

function shellQuote(value: string) {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

export function buildEnrollmentCommand(token: string) {
  return `sudo frp-agent -config /etc/frp-agent/agent.yaml -enroll-token ${shellQuote(token)} -enroll-ca /etc/frp-agent/agent-ca.pem`;
}

async function copy(value: string) {
  await navigator.clipboard.writeText(value);
  message.success('已复制');
}

export function EnrollmentResultModal({ result, onClose }: { result?: EnrollmentToken; onClose: () => void }) {
  if (!result) return null;
  const command = buildEnrollmentCommand(result.token);
  return <Modal open title="节点注册令牌" footer={<Button type="primary" onClick={onClose}>我已保存，关闭</Button>} closable={false} maskClosable={false} onCancel={onClose}>
    <Typography.Paragraph type="warning"><WarningOutlined /> 令牌只展示一次并在 10 分钟后过期。关闭后无法再次查看。</Typography.Paragraph>
    <Descriptions size="small" column={1} items={[
      { key: 'role', label: '节点角色', children: <Tag>{result.role === 'server' ? 'frps 服务端' : 'frpc 客户端'}</Tag> },
      { key: 'expires', label: '过期时间', children: formatTime(result.expiresAt) },
    ]} />
    <Typography.Text strong>注册令牌</Typography.Text>
    <Space.Compact block className="secret-field"><Input readOnly value={result.token} /><Button aria-label="复制注册令牌" icon={<CopyOutlined />} onClick={() => void copy(result.token)} /></Space.Compact>
    <Typography.Text strong>Agent 注册命令</Typography.Text>
    <Input.TextArea className="command-field mono" readOnly autoSize={{ minRows: 3, maxRows: 5 }} value={command} />
    <Button icon={<CopyOutlined />} onClick={() => void copy(command)}>复制命令</Button>
    <Typography.Paragraph type="secondary" className="result-note">执行前请将下载的 CA 保存到 <Typography.Text code>/etc/frp-agent/agent-ca.pem</Typography.Text>，并确认 <Typography.Text code>agent.yaml</Typography.Text> 中的 role 为 <Typography.Text code>{result.role}</Typography.Text>。</Typography.Paragraph>
  </Modal>;
}
