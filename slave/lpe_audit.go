package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type AuditResult struct {
	Timestamp string        `json:"timestamp"`
	System    SystemInfo    `json:"system"`
	Container ContainerInfo `json:"container"`
	Vulns     VulnFindings  `json:"vulns"`
	LPE       LPEFindings   `json:"lpe"`
}

type SystemInfo struct {
	Kernel     string `json:"kernel"`
	KernelBase string `json:"kernel_base"`
	Arch       string `json:"arch"`
	Hostname   string `json:"hostname"`
	Distro     string `json:"distro"`
	DistroID   string `json:"distro_id"`
	DistroVer  string `json:"distro_ver"`
}

type ContainerInfo struct {
	Inside bool   `json:"inside"`
	Type   string `json:"type"`
}

type VulnFindings struct {
	CopyFail       string `json:"copy_fail"`
	DirtyFragESP   string `json:"dirtyfrag_esp"`
	DirtyFragRxrpc string `json:"dirtyfrag_rxrpc"`
	CrackArmor     string `json:"crackarmor"`
}

type LPEFindings struct {
	SudoVersion      string   `json:"sudo_version"`
	SudoCommands     string   `json:"sudo_commands"`
	SUIDBinaries     []string `json:"suid_binaries"`
	CronJobs         string   `json:"cron_jobs"`
	Capabilities     string   `json:"capabilities"`
	DockerSocket     bool     `json:"docker_socket"`
	PATHWritable     []string `json:"path_writable"`
	PasswdWritable   bool     `json:"passwd_writable"`
	ShadowReadable   bool     `json:"shadow_readable"`
	WorldWritable    []string `json:"world_writable"`
	InterestingFiles []string `json:"interesting_files"`
	SSHKeys          []string `json:"ssh_keys"`
}

func runCmd(cmd string) string {
	c := exec.Command("/bin/sh", "-c", cmd)
	var out bytes.Buffer
	c.Stdout = &out
	c.Stderr = &out
	c.Run()
	return strings.TrimSpace(out.String())
}

func verGe(a, b string) bool {
	aa := strings.Split(a, ".")
	bb := strings.Split(b, ".")
	n := len(aa)
	if len(bb) > n {
		n = len(bb)
	}
	for i := 0; i < n; i++ {
		var av, bv int
		fmt.Sscanf(aa[i], "%d", &av)
		if i < len(bb) {
			fmt.Sscanf(bb[i], "%d", &bv)
		}
		if av > bv {
			return true
		}
		if av < bv {
			return false
		}
	}
	return true
}

func checkModule(mod string) (loaded, available, blacklisted bool) {
	// Check if loaded
	if _, err := os.Stat("/sys/module/" + mod); err == nil {
		loaded = true
	}
	if strings.Contains(runCmd("cat /proc/modules 2>/dev/null"), mod+" ") {
		loaded = true
	}

	// Check if available
	if _, err := exec.LookPath("modinfo"); err == nil {
		if runCmd("modinfo "+mod+" 2>/dev/null") != "" {
			available = true
		}
	} else {
		kernel := runCmd("uname -r")
		if _, err := os.Stat("/lib/modules/" + kernel); err == nil {
			out := runCmd("find /lib/modules/" + kernel + " -name '" + mod + ".ko*' 2>/dev/null")
			if out != "" {
				available = true
			}
		}
	}

	// Check if blacklisted
	for _, dir := range []string{"/etc/modprobe.d", "/usr/lib/modprobe.d", "/run/modprobe.d", "/lib/modprobe.d"} {
		if _, err := os.Stat(dir); err == nil {
			out := runCmd("grep -rqsE '^[[:space:]]*(install|blacklist)[[:space:]]+" + mod + "([[:space:]]|$)' " + dir + " 2>/dev/null && echo yes")
			if out == "yes" {
				blacklisted = true
				break
			}
		}
	}
	return
}

func auditSystem() SystemInfo {
	kernel := runCmd("uname -r")
	kernelBase := strings.Split(kernel, "-")[0]
	kernelBase = strings.Split(kernelBase, "+")[0]
	arch := runCmd("uname -m")
	hostname, _ := os.Hostname()

	distroID := "unknown"
	distroVer := "unknown"
	distroName := "unknown"

	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "ID=") {
				distroID = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
			}
			if strings.HasPrefix(line, "VERSION_ID=") {
				distroVer = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"")
			}
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				distroName = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
			}
		}
	}

	return SystemInfo{
		Kernel:     kernel,
		KernelBase: kernelBase,
		Arch:       arch,
		Hostname:   hostname,
		Distro:     distroName,
		DistroID:   distroID,
		DistroVer:  distroVer,
	}
}

func auditContainer() ContainerInfo {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return ContainerInfo{Inside: true, Type: "docker"}
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return ContainerInfo{Inside: true, Type: "podman"}
	}
	cgroup, _ := os.ReadFile("/proc/1/cgroup")
	if strings.Contains(string(cgroup), "docker") || strings.Contains(string(cgroup), "kubepods") ||
		strings.Contains(string(cgroup), "containerd") || strings.Contains(string(cgroup), "lxc") {
		return ContainerInfo{Inside: true, Type: "container"}
	}
	return ContainerInfo{Inside: false, Type: "none"}
}

func auditVulns(kernelBase string) VulnFindings {
	v := VulnFindings{}

	// Copy Fail (CVE-2026-31431)
	if verGe(kernelBase, "4.14") {
		loaded, _, blacklisted := checkModule("algif_aead")
		if blacklisted && !loaded {
			v.CopyFail = "MITIGATED"
		} else if loaded {
			v.CopyFail = "EXPOSED"
		} else {
			v.CopyFail = "NOT_PRESENT"
		}
	} else {
		v.CopyFail = "NOT_AFFECTED"
	}

	// Dirty Frag #1 (xfrm-ESP)
	if verGe(kernelBase, "4.10") {
		esp4Loaded, _, esp4Black := checkModule("esp4")
		esp6Loaded, _, esp6Black := checkModule("esp6")
		espLoaded := esp4Loaded || esp6Loaded
		espBlack := esp4Black && esp6Black

		if espBlack && !espLoaded {
			v.DirtyFragESP = "MITIGATED"
		} else if espLoaded {
			v.DirtyFragESP = "EXPOSED"
		} else {
			v.DirtyFragESP = "NOT_PRESENT"
		}
	} else {
		v.DirtyFragESP = "NOT_AFFECTED"
	}

	// Dirty Frag #2 (RxRPC)
	if verGe(kernelBase, "6.5") {
		loaded, _, blacklisted := checkModule("rxrpc")
		if blacklisted && !loaded {
			v.DirtyFragRxrpc = "MITIGATED"
		} else if loaded {
			v.DirtyFragRxrpc = "EXPOSED"
		} else {
			v.DirtyFragRxrpc = "NOT_PRESENT"
		}
	} else {
		v.DirtyFragRxrpc = "NOT_AFFECTED"
	}

	// CrackArmor (CVE-2026-23268+)
	if verGe(kernelBase, "4.11") {
		aaEnabled := false
		if data, err := os.ReadFile("/sys/module/apparmor/parameters/enabled"); err == nil {
			if strings.TrimSpace(string(data)) == "Y" {
				aaEnabled = true
			}
		}

		if !aaEnabled {
			v.CrackArmor = "NOT_AFFECTED"
		} else {
			sudoVer := runCmd("sudo -V 2>/dev/null | head -1 | awk '{print $NF}'")
			if strings.Contains(strings.ToLower(sudoVer), "sudo-rs") || strings.Contains(strings.ToLower(sudoVer), "rust") {
				v.CrackArmor = "MITIGATED"
			} else {
				v.CrackArmor = "EXPOSED"
			}
		}
	} else {
		v.CrackArmor = "NOT_AFFECTED"
	}

	return v
}

func auditLPE() LPEFindings {
	l := LPEFindings{}

	// Sudo
	l.SudoVersion = runCmd("sudo -V 2>/dev/null | head -1")
	l.SudoCommands = runCmd("sudo -nl 2>/dev/null")

	// SUID binaries
	suidOut := runCmd("find / -perm -4000 -type f 2>/dev/null | head -30")
	if suidOut != "" {
		l.SUIDBinaries = strings.Split(suidOut, "\n")
	}

	// Cron
	l.CronJobs = runCmd("ls -la /etc/cron* 2>/dev/null; cat /etc/crontab 2>/dev/null; crontab -l 2>/dev/null")

	// Capabilities
	l.Capabilities = runCmd("getcap -r / 2>/dev/null | head -20")

	// Docker socket
	l.DockerSocket = false
	if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		l.DockerSocket = true
	}
	if strings.Contains(runCmd("id"), "docker") {
		l.DockerSocket = true
	}

	// PATH writable dirs
	pathDirs := strings.Split(runCmd("echo $PATH"), ":")
	for _, dir := range pathDirs {
		if dir != "" {
			info, err := os.Stat(dir)
			if err == nil && info.IsDir() {
				// Check write permission
				if info.Mode().Perm()&0200 != 0 {
					l.PATHWritable = append(l.PATHWritable, dir)
				}
			}
		}
	}

	// /etc/passwd writable
	l.PasswdWritable = false
	if info, err := os.Stat("/etc/passwd"); err == nil {
		if info.Mode().Perm()&0200 != 0 {
			l.PasswdWritable = true
		}
	}

	// /etc/shadow readable
	l.ShadowReadable = false
	if _, err := os.Open("/etc/shadow"); err == nil {
		l.ShadowReadable = true
	}

	// World-writable files
	wwOut := runCmd("find /etc /usr/local /opt /var -writable -type f 2>/dev/null | head -20")
	if wwOut != "" {
		l.WorldWritable = strings.Split(wwOut, "\n")
	}

	// Interesting files
	var interesting []string

	// SSH keys
	homeDir, _ := os.UserHomeDir()
	if homeDir != "" {
		sshDir := filepath.Join(homeDir, ".ssh")
		if _, err := os.Stat(sshDir); err == nil {
			entries, _ := os.ReadDir(sshDir)
			for _, e := range entries {
				l.SSHKeys = append(l.SSHKeys, filepath.Join(sshDir, e.Name()))
			}
		}
	}

	// Find tokens, keys, env files
	findOut := runCmd("find / -maxdepth 4 -name '*.key' -o -name 'id_rsa' -o -name 'token' -o -name '.env' 2>/dev/null | head -20")
	if findOut != "" {
		interesting = append(interesting, strings.Split(findOut, "\n")...)
	}

	// Users with shells
	usersOut := runCmd("cat /etc/passwd | grep -v nologin | grep -v false | head -10")
	if usersOut != "" {
		interesting = append(interesting, strings.Split(usersOut, "\n")...)
	}

	l.InterestingFiles = interesting

	return l
}

func runLPEAudit() (string, error) {
	result := AuditResult{}

	// Timestamp
	result.Timestamp = time.Now().UTC().Format(time.RFC3339)

	// System info
	result.System = auditSystem()

	// Container detection
	result.Container = auditContainer()

	// Kernel vulnerability checks
	result.Vulns = auditVulns(result.System.KernelBase)

	// LPE checks
	result.LPE = auditLPE()

	// Marshal to JSON
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal json: %v", err)
	}

	return string(data), nil
}
