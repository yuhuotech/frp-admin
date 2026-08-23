package upgrade

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/frp-admin/frp-admin/server/internal/domain"
)

const frpRepository = "fatedier/frp"

var assetPlatformPattern = regexp.MustCompile(`(?i)(linux|darwin|windows|freebsd|openbsd|netbsd)[_-](amd64|arm64|386|arm|riscv64|mips64le)`)

type ReleaseAsset struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	SHA256 string `json:"sha256,omitempty"`
	Size   int64  `json:"size"`
	OS     string `json:"os,omitempty"`
	Arch   string `json:"arch,omitempty"`
}
type Release struct {
	TagName     string         `json:"tag_name"`
	Name        string         `json:"name"`
	PublishedAt time.Time      `json:"published_at"`
	HTMLURL     string         `json:"html_url"`
	Assets      []ReleaseAsset `json:"assets"`
	Recommended *ReleaseAsset  `json:"recommended,omitempty"`
}
type githubRelease struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	PublishedAt time.Time `json:"published_at"`
	HTMLURL     string    `json:"html_url"`
	Assets      []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
		Digest             string `json:"digest"`
		Size               int64  `json:"size"`
	} `json:"assets"`
}
type releaseCache struct {
	value   Release
	expires time.Time
}
type GitHubClient struct {
	client *http.Client
	mu     sync.Mutex
	cache  releaseCache
}

func NewGitHubClient() *GitHubClient {
	return &GitHubClient{client: &http.Client{Timeout: 10 * time.Second}}
}
func (c *GitHubClient) Latest(ctx context.Context) (Release, error) {
	c.mu.Lock()
	if time.Now().Before(c.cache.expires) {
		v := c.cache.value
		c.mu.Unlock()
		return v, nil
	}
	c.mu.Unlock()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/"+frpRepository+"/releases/latest", nil)
	if err != nil {
		return Release{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "frp-admin-control-plane")
	resp, err := c.client.Do(req)
	if err != nil {
		return Release{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Release{}, fmt.Errorf("github latest release returned HTTP %d", resp.StatusCode)
	}
	var raw githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return Release{}, err
	}
	if raw.TagName == "" {
		return Release{}, errors.New("github latest release has no tag")
	}
	out := Release{TagName: raw.TagName, Name: raw.Name, PublishedAt: raw.PublishedAt, HTMLURL: raw.HTMLURL, Assets: make([]ReleaseAsset, 0, len(raw.Assets))}
	for _, a := range raw.Assets {
		osName, arch := parseAssetPlatform(a.Name)
		if osName == "" || arch == "" {
			continue
		}
		out.Assets = append(out.Assets, ReleaseAsset{Name: a.Name, URL: a.BrowserDownloadURL, SHA256: normalizeDigest(a.Digest), Size: a.Size, OS: osName, Arch: arch})
	}
	c.mu.Lock()
	c.cache = releaseCache{value: out, expires: time.Now().Add(5 * time.Minute)}
	c.mu.Unlock()
	return out, nil
}
func normalizeDigest(v string) string {
	v = strings.TrimSpace(v)
	if strings.HasPrefix(strings.ToLower(v), "sha256:") {
		return strings.ToLower(strings.TrimPrefix(strings.ToLower(v), "sha256:"))
	}
	if len(v) == 64 {
		return strings.ToLower(v)
	}
	return ""
}
func parseAssetPlatform(name string) (string, string) {
	m := assetPlatformPattern.FindStringSubmatch(name)
	if len(m) != 3 {
		return "", ""
	}
	return strings.ToLower(m[1]), strings.ToLower(m[2])
}
func recommendedReleaseAsset(r Release, n domain.Node) *ReleaseAsset {
	if n.Observation == nil {
		return nil
	}
	osName, arch := strings.ToLower(n.Observation.OperatingSystem), strings.ToLower(n.Observation.Architecture)
	if osName == "macos" {
		osName = "darwin"
	}
	for i := range r.Assets {
		if r.Assets[i].OS == osName && r.Assets[i].Arch == arch && r.Assets[i].SHA256 != "" {
			return &r.Assets[i]
		}
	}
	return nil
}
func (s *Service) LatestRelease(ctx context.Context, nodeID string) (Release, error) {
	n, err := s.store.NodeByID(ctx, nodeID)
	if err != nil {
		return Release{}, err
	}
	r, err := s.github.Latest(ctx)
	if err != nil {
		return Release{}, err
	}
	r.Recommended = recommendedReleaseAsset(r, n)
	return r, nil
}
