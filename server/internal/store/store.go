package store

import (
	"context"
	"errors"
	"time"

	"github.com/frp-admin/frp-admin/server/internal/domain"
)

type MutationAudit struct{ Actor, Action, Resource, RequestID string }
type auditContextKey struct{}
type webhookContextKey struct{}

func WithMutationAudit(ctx context.Context, a MutationAudit) context.Context {
	return context.WithValue(ctx, auditContextKey{}, a)
}
func MutationAuditFrom(ctx context.Context) (MutationAudit, bool) {
	v, ok := ctx.Value(auditContextKey{}).(MutationAudit)
	return v, ok
}
func WithMutationAction(ctx context.Context, action, resource string) context.Context {
	v, _ := MutationAuditFrom(ctx)
	v.Action = action
	v.Resource = resource
	return WithMutationAudit(ctx, v)
}
func WithWebhookDelivery(ctx context.Context, enabled bool) context.Context {
	return context.WithValue(ctx, webhookContextKey{}, enabled)
}
func WebhookDeliveryEnabled(ctx context.Context) bool {
	v, _ := ctx.Value(webhookContextKey{}).(bool)
	return v
}

var (
	ErrNotFound              = errors.New("not found")
	ErrConflict              = errors.New("conflict")
	ErrObserveOnly           = errors.New("node is in observe mode")
	ErrCapabilityUnavailable = errors.New("agent capability is unavailable")
)

type Store interface {
	Close() error
	Ping(context.Context) error
	CountUsers(context.Context) (int, error)
	CreateUser(context.Context, domain.User) error
	UserByUsername(context.Context, string) (domain.User, error)
	UserByID(context.Context, string) (domain.User, error)
	CreateSession(context.Context, domain.Session) error
	SessionByTokenHash(context.Context, string, time.Time) (domain.Session, error)
	RevokeSession(context.Context, string, time.Time) error
	CreateEnrollmentToken(context.Context, domain.EnrollmentToken) error
	ConsumeEnrollmentTokenAndCreateNode(context.Context, string, string, domain.Node, time.Time) error
	UpsertObservation(context.Context, domain.NodeObservation) error
	SetNodeOnline(context.Context, string, bool, time.Time) error
	NextConfigVersion(context.Context, string) (int64, error)
	CreateConfigRevision(context.Context, domain.ConfigRevision) error
	ListConfigRevisions(context.Context, string, int, string) (domain.Page[domain.ConfigRevision], error)
	ConfigRevisionByID(context.Context, string) (domain.ConfigRevision, error)
	CreateSecret(context.Context, domain.Secret) error
	UpdateSecret(context.Context, domain.Secret) error
	ListSecrets(context.Context, int, string) (domain.Page[domain.Secret], error)
	SecretByName(context.Context, string) (domain.Secret, error)
	SecretByID(context.Context, string) (domain.Secret, error)
	ListUsers(context.Context, int, string) (domain.Page[domain.User], error)
	UpdateUserAccess(context.Context, string, string, string, time.Time) error
	ListNodes(context.Context, int, string) (domain.Page[domain.Node], error)
	NodeByID(context.Context, string) (domain.Node, error)
	SetNodeManagementMode(context.Context, string, string, time.Time) (domain.Node, error)
	ListTasks(context.Context, int, string, string, string) (domain.Page[domain.Task], error)
	TaskByID(context.Context, string) (domain.Task, error)
	TaskByIdempotency(context.Context, string, string) (domain.Task, error)
	CreateTask(context.Context, domain.Task, domain.TaskStep) error
	UpdateTask(context.Context, string, string, string, string, string, string, time.Time) error
	CompleteTaskResult(context.Context, domain.Task, string, string, string, string, time.Time) (domain.TaskCompletionOutcome, error)
	CompleteConfigTask(context.Context, domain.Task, string, string, string, string, string, time.Time) (domain.TaskCompletionOutcome, error)
	CancelTask(context.Context, string, time.Time) (domain.Task, error)
	ExpireTasks(context.Context, time.Time, int) ([]domain.Task, error)
	CreateAlert(context.Context, domain.Alert) error
	ListAlerts(context.Context, int, string, string) (domain.Page[domain.Alert], error)
	UpdateAlertState(context.Context, string, string, string, time.Time) (domain.Alert, error)
	LeaseWebhookDeliveries(context.Context, time.Time, time.Duration, int) ([]domain.WebhookDelivery, error)
	CompleteWebhookDelivery(context.Context, string, bool, time.Time, string, int) error
	CreateUpgradePlanTask(context.Context, domain.UpgradePlan, domain.Task, domain.TaskStep) error
	UpgradePlanByID(context.Context, string) (domain.UpgradePlan, error)
	ListUpgradePlans(context.Context, int, string, string, string) (domain.Page[domain.UpgradePlan], error)
	ReplaceRuntimeSnapshot(context.Context, domain.RuntimeSnapshot) error
	RuntimeSnapshotByNode(context.Context, string) (domain.RuntimeSnapshot, error)
	ListRuntimeProxies(context.Context, int, string, string, string, string) (domain.Page[domain.RuntimeProxy], error)
	RuntimeProxyByKey(context.Context, string, string) (domain.RuntimeProxy, error)
	ReconcileDeploymentRisks(context.Context, string, string, string, string, []domain.DeploymentRiskObservation, []string, time.Time) error
	ReconcileDeploymentRisksOnce(context.Context, string, string, string, string, []domain.DeploymentRiskObservation, []string, time.Time) (bool, error)
	CompleteRiskScanTask(context.Context, domain.Task, string, string, string, string, string, string, []domain.DeploymentRiskObservation, []string, time.Time) (domain.TaskCompletionOutcome, error)
	ListDeploymentRisks(context.Context, domain.DeploymentRiskFilter, int, string) (domain.Page[domain.DeploymentRisk], error)
	DeploymentRiskByID(context.Context, string) (domain.DeploymentRisk, error)
	CreateDeploymentRiskRepairTask(context.Context, string, domain.Task, domain.TaskStep) error
	CreateDerivedDeploymentRiskRepairTask(context.Context, string, domain.ConfigRevision, domain.Task, domain.TaskStep) error
	AppendAudit(context.Context, string, string, string, string) error
	AppendAuditResult(context.Context, string, string, string, string, string) error
	ListAuditLogs(context.Context, domain.AuditFilter, int, string) (domain.Page[domain.AuditLog], error)
}
