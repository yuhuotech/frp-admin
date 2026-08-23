import { Badge, Tag } from 'antd';

const colors: Record<string, string> = {
  online: 'success', active: 'success', succeeded: 'success', completed: 'success', resolved: 'success', closed: 'default',
  running: 'processing', pending: 'default', queued: 'default', acknowledged: 'warning', open: 'error',
  offline: 'error', failed: 'error', firing: 'error', cancelled: 'default', inactive: 'default', unknown: 'default',
  critical: 'magenta', high: 'red', medium: 'orange', low: 'gold', info: 'blue', accepted: 'default', pending_confirmation: 'warning',
};

const labels: Record<string, string> = {
  online: '在线', offline: '离线', unknown: '未知', active: '运行中', inactive: '未运行', failed: '失败',
  succeeded: '成功', completed: '完成', running: '执行中', pending: '等待中', queued: '排队中',
  cancelled: '已取消', firing: '告警中', open: '待处理', resolved: '已恢复', acknowledged: '已确认', closed: '已关闭',
  critical: '严重', high: '高危', medium: '中危', low: '低危', info: '提示', accepted: '已接受', pending_confirmation: '待确认',
};

export function StatusTag({ value }: { value?: string }) {
  const status = value?.toLowerCase() || 'unknown';
  return <Tag color={colors[status]}>{labels[status] ?? value ?? '未知'}</Tag>;
}

export function OnlineBadge({ online }: { online: boolean }) {
  return <Badge status={online ? 'success' : 'default'} text={online ? '在线' : '离线'} />;
}
