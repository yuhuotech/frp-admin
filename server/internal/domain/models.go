package domain

import "time"

type User struct {
	ID, Username, PasswordHash, Status, Role string
	CreatedAt                                time.Time
}

type Session struct {
	ID, UserID, TokenHash, CSRFHash string
	ExpiresAt                       time.Time
	RevokedAt                       *time.Time
}

type EnrollmentToken struct {
	ID, Role, TokenHash, CreatedBy string
	ExpiresAt                      time.Time
	UsedAt                         *time.Time
	CreatedAt                      time.Time
}

type Node struct {
	ID, Name, Role, Labels, ManagementMode string
	DesiredRevisionID                      *string
	CreatedAt, UpdatedAt                   time.Time
	Observation                            *NodeObservation
}

type NodeObservation struct {
	NodeID                                                             string
	Online                                                             bool
	AgentVersion, FRPVersion, ServiceState, ObservedHash, Capabilities string
	ObservedRevisionID                                                 *string
	LastHeartbeat                                                      time.Time
}

type Task struct {
	ID, Type, State, NodeID, IdempotencyKey, RequestedBy, ErrorCode, ErrorMessage string
	Payload                                                                       string
	ConfigRevisionID, ExpectedRevisionID, UpgradePlanID                           *string
	ExpiresAt                                                                     *time.Time
	CancelRequestedAt                                                             *time.Time
	CreatedAt, UpdatedAt                                                          time.Time
	Steps                                                                         []TaskStep
}

type TaskCompletionOutcome struct {
	FinalState   string
	Transitioned bool
	AppliedDrift bool
}

type UpgradePlan struct {
	ID, NodeID, Version, ArtifactURL, ArtifactKeyVersion, SHA256, State, TaskID, CreatedBy string
	ArtifactCiphertext, ArtifactNonce                                                      []byte
	CreatedAt, UpdatedAt                                                                   time.Time
}
type RuntimeTraffic struct{ BytesIn, BytesOut, TodayBytesIn, TodayBytesOut, CurrentConnections int64 }
type RuntimeProxy struct {
	NodeID, NodeName, Name, Type, Status, LocalAddress, RemoteAddress, LastError string
	Traffic                                                                      RuntimeTraffic
	CollectedAt                                                                  time.Time
}
type RuntimeClient struct {
	ID, Address string
	ConnectedAt time.Time
}
type RuntimeSnapshot struct {
	NodeID, Role, FRPVersion, BindAddress string
	BindPort, ProxyCount, ClientCount     int
	CollectedAt                           time.Time
	Proxies                               []RuntimeProxy
	Clients                               []RuntimeClient
}

type Alert struct {
	ID             string     `json:"id"`
	Kind           string     `json:"kind"`
	Severity       string     `json:"severity"`
	State          string     `json:"state"`
	Resource       string     `json:"resource"`
	Fingerprint    string     `json:"fingerprint"`
	Message        string     `json:"message"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	AcknowledgedBy string     `json:"acknowledged_by,omitempty"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
	ResolvedBy     string     `json:"resolved_by,omitempty"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
	ClosedBy       string     `json:"closed_by,omitempty"`
	ClosedAt       *time.Time `json:"closed_at,omitempty"`
}

type DeploymentRisk struct {
	ID, NodeID, Kind, Severity, State, Evidence, Confidence, RuleVersion, ResourceFingerprint string
	RepairTaskID                                                                              *string
	MissedScans                                                                               int
	FirstSeenAt, LastSeenAt, UpdatedAt                                                        time.Time
	PendingConfirmationAt, ResolvedAt                                                         *time.Time
}

type DeploymentRiskScan struct {
	ID, NodeID, TaskID, Status, ErrorCode string
	FindingCount                          int
	ScannedAt                             time.Time
}

type DeploymentRiskFilter struct {
	NodeID, Kind, State string
}

type DeploymentRiskObservation struct {
	Kind, Severity, Evidence, Confidence, RuleVersion, ResourceFingerprint string
}

type WebhookDelivery struct {
	ID, AlertID, EventType, Payload, State, LastError string
	Attempts                                          int
	NextAttemptAt                                     time.Time
	LeaseUntil, DeliveredAt                           *time.Time
	CreatedAt, UpdatedAt                              time.Time
}

type ConfigRevision struct {
	ID, NodeID, SHA256, Strategy, CreatedBy string
	Content                                 string
	Mode, SensitiveFields                   string
	Version                                 int64
	EncryptedContent, Nonce                 []byte
	CreatedAt                               time.Time
}

type Secret struct {
	ID, Name, KeyVersion, CreatedBy, UpdatedBy string
	Ciphertext, Nonce                          []byte
	CreatedAt, UpdatedAt                       time.Time
}
type AuditLog struct {
	ID, Actor, Action, Resource, RequestID, Outcome string
	CreatedAt                                       time.Time
}
type AuditFilter struct {
	Actor, Action, Resource string
	From, To                *time.Time
}

type TaskStep struct {
	ID, TaskID, Name, State, ErrorCode, Output string
	Attempt                                    int
	CreatedAt, UpdatedAt                       time.Time
}

type Page[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"nextCursor,omitempty"`
}
