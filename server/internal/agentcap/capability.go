package agentcap

import (
	"encoding/json"

	"github.com/frp-admin/frp-admin/server/internal/domain"
)

func Has(node domain.Node, expected string) bool {
	if node.Observation == nil {
		return false
	}
	var values []string
	if json.Unmarshal([]byte(node.Observation.Capabilities), &values) != nil {
		return false
	}
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
