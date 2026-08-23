package upgrade

import (
	"testing"

	"github.com/frp-admin/frp-admin/server/internal/domain"
)

func TestParseAssetPlatform(t *testing.T) {
	for _, tc := range []struct{ name, os, arch string }{
		{"frp_0.1.0_linux_amd64.tar.gz", "linux", "amd64"},
		{"frp_0.1.0_darwin_arm64.tar.gz", "darwin", "arm64"},
	} {
		osName, arch := parseAssetPlatform(tc.name)
		if osName != tc.os || arch != tc.arch {
			t.Fatalf("%s -> %s/%s", tc.name, osName, arch)
		}
	}
}

func TestRecommendedReleaseAsset(t *testing.T) {
	r := Release{Assets: []ReleaseAsset{{Name: "linux", URL: "https://example.invalid/frp.tar.gz", SHA256: "abc", OS: "linux", Arch: "amd64"}}}
	n := domain.Node{Observation: &domain.NodeObservation{OperatingSystem: "linux", Architecture: "amd64"}}
	if got := recommendedReleaseAsset(r, n); got == nil || got.Name != "linux" {
		t.Fatalf("recommended=%+v", got)
	}
}
