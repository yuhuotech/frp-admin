package discovery

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type Candidate struct {
	BinaryPath  string
	ConfigPath  string
	ServiceName string
	Source      string
	Error       string
}

type Result struct {
	BinaryPath  string
	ConfigPath  string
	ServiceName string
	State       string
	Candidates  []Candidate
}

// Resolve fills only missing FRP identity fields. Explicit operator settings
// always win. Discovery is deliberately conservative: it only selects regular
// files and known service/process command-line arguments.
func Resolve(role, serviceName, binaryPath, configPath string) Result {
	r := Result{BinaryPath: binaryPath, ConfigPath: configPath, ServiceName: serviceName, State: "configured"}
	if r.ServiceName == "" {
		r.ServiceName = defaultService(role)
	}
	if r.BinaryPath == "" || r.ConfigPath == "" {
		candidates := collectCandidates(role, r.ServiceName)
		r.Candidates = candidates
		for _, c := range candidates {
			if r.BinaryPath == "" && c.BinaryPath != "" {
				r.BinaryPath = c.BinaryPath
			}
			if r.ConfigPath == "" && c.ConfigPath != "" {
				r.ConfigPath = c.ConfigPath
			}
			if r.BinaryPath != "" && r.ConfigPath != "" {
				break
			}
		}
		if len(candidates) > 0 {
			r.State = "resolved"
		} else {
			r.State = "not_found"
		}
	}
	return r
}

func defaultService(role string) string {
	if runtime.GOOS == "linux" {
		if role == "server" {
			return "frps.service"
		}
		return "frpc.service"
	}
	if role == "server" {
		return "homebrew.mxcl.frps"
	}
	return "homebrew.mxcl.frpc"
}

func collectCandidates(role, serviceName string) []Candidate {
	name := "frpc"
	if role == "server" {
		name = "frps"
	}
	seen := map[string]bool{}
	out := make([]Candidate, 0, 8)
	add := func(c Candidate) {
		key := c.BinaryPath + "|" + c.ConfigPath + "|" + c.ServiceName
		if key == "||" || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, c)
	}
	if runtime.GOOS == "linux" {
		if c := systemdCandidate(serviceName, name); c.ConfigPath != "" || c.BinaryPath != "" {
			add(c)
		}
	}
	if c := processCandidate(name, serviceName); c.ConfigPath != "" || c.BinaryPath != "" {
		add(c)
	}
	for _, binary := range []string{filepath.Join("/opt/frp/bin", name), filepath.Join("/usr/local/bin", name), filepath.Join("/usr/bin", name)} {
		if fileExists(binary) {
			add(Candidate{BinaryPath: binary, ServiceName: serviceName, Source: "known_binary"})
		}
	}
	for _, config := range []string{filepath.Join("/etc/frp", name+".toml"), filepath.Join("/usr/local/etc/frp", name+".toml"), filepath.Join("/opt/frp", name+".toml")} {
		if fileExists(config) {
			add(Candidate{ConfigPath: config, ServiceName: serviceName, Source: "known_config"})
		}
	}
	return out
}

func systemdCandidate(serviceName, binaryName string) Candidate {
	c := Candidate{ServiceName: serviceName, Source: "systemd"}
	out, err := exec.Command("systemctl", "show", serviceName, "-p", "ExecStart", "--value").Output()
	if err != nil {
		c.Error = "systemd service not available"
		return c
	}
	line := strings.TrimSpace(string(out))
	c.BinaryPath, c.ConfigPath = parseCommand(line, binaryName)
	return c
}

func processCandidate(binaryName, serviceName string) Candidate {
	c := Candidate{ServiceName: serviceName, Source: "process"}
	out, err := exec.Command("pgrep", "-x", binaryName).Output()
	if err != nil {
		return c
	}
	for _, pid := range strings.Fields(string(out)) {
		data, err := os.ReadFile(filepath.Join("/proc", pid, "cmdline"))
		if err != nil {
			continue
		}
		args := strings.Split(string(data), "\x00")
		if len(args) == 0 {
			continue
		}
		c.BinaryPath = args[0]
		for i := 1; i < len(args); i++ {
			if (args[i] == "-c" || args[i] == "--config") && i+1 < len(args) {
				c.ConfigPath = args[i+1]
			}
		}
		return c
	}
	return c
}

func parseCommand(command, binaryName string) (string, string) {
	fields := shellFields(command)
	binary := ""
	config := ""
	for i, f := range fields {
		if strings.HasSuffix(f, "/"+binaryName) || f == binaryName {
			binary = f
		}
		if (f == "-c" || f == "--config") && i+1 < len(fields) {
			config = fields[i+1]
		}
	}
	return binary, config
}

func shellFields(line string) []string {
	var fields []string
	scanner := bufio.NewScanner(strings.NewReader(line))
	scanner.Split(bufio.ScanWords)
	for scanner.Scan() {
		fields = append(fields, strings.Trim(scanner.Text(), "\\\"'"))
	}
	return fields
}
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}
