package agentgateway

import (
	"context"
	"errors"
	"time"
)

var (
	ErrOffline               = errors.New("agent is offline")
	ErrCapabilityUnavailable = errors.New("agent capability is unavailable")
)

// Gateway is the domain-facing boundary for the generated contracts adapter.
// The contracts module implements this interface; server domains never import protobuf types.
type Gateway interface {
	Connected(nodeID string) bool
	Dispatch(context.Context, Command) error
	Cancel(context.Context, string, string, string) error
}

type Command struct {
	ID                                                           string
	NodeID                                                       string
	Type                                                         string
	Payload                                                      []byte
	Revision, SHA256, Strategy                                   string
	Version, ArtifactURL                                         string
	RiskFindingID, RiskKind, RiskAction, RiskResourceFingerprint string
	MaintenanceConfirmed                                         bool
	ExpiresAt                                                    time.Time
}

type ConfigMaterial struct {
	NodeID, Revision, SHA256, Strategy string
	Content                            []byte
}
type ConfigMaterializer interface {
	Materialize(context.Context, string) (ConfigMaterial, error)
}

type UpgradeMaterial struct {
	Version, ArtifactURL, SHA256 string
}

type UpgradeMaterializer interface {
	MaterializeUpgrade(context.Context, string) (UpgradeMaterial, error)
}
