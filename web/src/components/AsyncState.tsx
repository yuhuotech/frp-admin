import { Alert, Button, Empty, Skeleton } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';

export function PageLoading() {
  return <div className="content-panel" aria-label="加载中"><Skeleton active paragraph={{ rows: 8 }} /></div>;
}

export function PageError({ error, retry }: { error: unknown; retry?: () => void }) {
  return <Alert type="error" showIcon message="数据加载失败" description={error instanceof Error ? error.message : '服务暂时不可用'} action={retry && <Button icon={<ReloadOutlined />} onClick={retry}>重试</Button>} />;
}

export function EmptyState({ description = '暂无数据' }: { description?: string }) {
  return <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={description} />;
}
