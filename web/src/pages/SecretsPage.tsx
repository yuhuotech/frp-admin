import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Button, Form, Input, message, Modal, Table, Tag, Typography } from 'antd';
import { KeyOutlined, PlusOutlined, ReloadOutlined } from '@ant-design/icons';
import { secretsApi } from '../api/resources';
import type { SecretSummary } from '../api/types';
import { PageError } from '../components/AsyncState';
import { formatTime } from '../utils/format';

export function SecretsPage() {
  const [open, setOpen] = useState(false);
  const [editing, setEditing] = useState<SecretSummary>();
  const [saving, setSaving] = useState(false);
  const [form] = Form.useForm<{ name: string; value: string }>();
  const queryClient = useQueryClient();
  const query = useQuery({ queryKey: ['secrets'], queryFn: secretsApi.list });
  const save = async ({ name, value }: { name: string; value: string }) => {
    setSaving(true);
    try {
      if (editing) await secretsApi.update(editing.id, value); else await secretsApi.create(name, value);
      message.success(editing ? 'Secret 已轮换' : 'Secret 已创建');
      close();
      await queryClient.invalidateQueries({ queryKey: ['secrets'] });
    } catch {
      form.resetFields();
      message.error('Secret 写入失败，请重新输入后重试');
    } finally {
      setSaving(false);
    }
  };
  const close = () => { form.resetFields(); setOpen(false); setEditing(undefined); };
  const edit = (secret: SecretSummary) => { setEditing(secret); setOpen(true); };
  return <div className="page-stack">
    <div className="page-heading"><div><Typography.Title level={3}>Secrets</Typography.Title><Typography.Text type="secondary">集中管理配置引用的敏感值</Typography.Text></div><div><Button icon={<ReloadOutlined />} loading={query.isFetching} onClick={() => void query.refetch()}>刷新</Button> <Button type="primary" icon={<PlusOutlined />} onClick={() => setOpen(true)}>新建 Secret</Button></div></div>
    {query.isError ? <PageError error={query.error} retry={() => void query.refetch()} /> : <div className="content-panel table-panel"><Table<SecretSummary> rowKey="id" loading={query.isLoading} dataSource={query.data?.items} locale={{ emptyText: '暂无 Secret' }} columns={[
      { title: '名称', dataIndex: 'name', render: (value) => <><KeyOutlined /> <strong>{value}</strong></> },
      { title: '状态', dataIndex: 'configured', width: 110, render: (value) => <Tag color={value ? 'green' : 'red'}>{value ? '已配置' : '未配置'}</Tag> },
      { title: '密钥版本', dataIndex: 'key_version', width: 110, render: (value) => `v${value}` },
      { title: '更新时间', dataIndex: 'updated_at', width: 180, render: formatTime },
      { title: '操作', width: 100, render: (_, secret) => <Button size="small" onClick={() => edit(secret)}>轮换</Button> },
    ]} /></div>}
    <Modal destroyOnHidden open={open} title={editing ? `轮换 Secret：${editing.name}` : '新建 Secret'} okText={editing ? '确认轮换' : '创建'} okButtonProps={{ danger: Boolean(editing) }} confirmLoading={saving} onCancel={close} onOk={() => form.submit()}>
      <Form form={form} preserve={false} layout="vertical" onFinish={(values) => void save(values)}>
        {!editing && <Form.Item name="name" label="名称" rules={[{ required: true, message: '请输入名称' }, { pattern: /^[a-zA-Z][a-zA-Z0-9_.-]{1,63}$/, message: '使用 2-64 位字母、数字、点、下划线或连字符' }]}><Input autoComplete="off" /></Form.Item>}
        <Form.Item name="value" label={editing ? '新值' : '值'} rules={[{ required: true, message: '请输入 Secret 值' }]} extra="提交后不会再次显示该值。"><Input.Password autoComplete="new-password" /></Form.Item>
      </Form>
    </Modal>
  </div>;
}
