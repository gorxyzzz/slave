package main

import (
	"bytes"
	"os/exec"
	"strings"
)

type Recon struct {
	Hostname string `json:"hostname"`
	Username string `json:"username"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Kernel   string `json:"kernel"`
	IP       string `json:"ip"`
	PublicIP string `json:"public_ip"`
}

type LPECheck struct {
	Name    string
	Command string
}

var lpeChecks = []LPECheck{
	{"os_info", "uname -a; cat /etc/os-release 2>/dev/null || cat /etc/issue 2>/dev/null"},
	{"sudo", "sudo -nl 2>/dev/null"},
	{"suid", "find / -perm -4000 -type f 2>/dev/null | head -30"},
	{"cron", "ls -la /etc/cron* 2>/dev/null; cat /etc/crontab 2>/dev/null; crontab -l 2>/dev/null; find /etc/cron* -writable -type f 2>/dev/null"},
	{"capabilities", "getcap -r / 2>/dev/null | head -20"},
	{"docker", "id | grep -i docker; ls -la /var/run/docker.sock 2>/dev/null"},
	{"path_writable", "echo $PATH | tr ':' '\\n' | while read d; do [ -w \"$d\" ] && echo \"WRITABLE: $d\"; done"},
	{"passwd_writable", "[ -w /etc/passwd ] && echo 'WRITABLE' || echo 'not writable'"},
	{"shadow_readable", "[ -r /etc/shadow ] && echo 'READABLE' || echo 'not readable'"},
	{"world_writable", "find /etc /usr/local /opt /var -writable -type f 2>/dev/null | head -20"},
	{"interesting_files", "ls -la ~/.ssh/ 2>/dev/null; find / -name '*.key' -o -name 'id_rsa' -o -name 'token' -o -name '.env' 2>/dev/null | head -20; cat /etc/passwd | grep -v nologin | grep -v false | head -10"},
}

func runShell(script string) string {
	cmd := exec.Command("/bin/sh", "-c", script)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return ""
	}
	return strings.TrimSpace(out.String())
}
