package discovery

import "testing"

func TestParseCommand(t *testing.T) {
	binary, config := parseCommand("/opt/frp/bin/frpc -c /etc/frp/frpc.toml", "frpc")
	if binary != "/opt/frp/bin/frpc" || config != "/etc/frp/frpc.toml" {
		t.Fatalf("got %q %q", binary, config)
	}
}
func TestResolveExplicitValues(t *testing.T) {
	got := Resolve("client", "frpc.service", "/opt/frp/bin/frpc", "/etc/frp/frpc.toml")
	if got.BinaryPath != "/opt/frp/bin/frpc" || got.ConfigPath != "/etc/frp/frpc.toml" || got.State != "configured" {
		t.Fatalf("got %+v", got)
	}
}
