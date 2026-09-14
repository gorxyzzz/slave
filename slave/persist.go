package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type InitSystem string

const (
	InitSystemd InitSystem = "systemd"
	InitRunit   InitSystem = "runit"
	InitOpenRC  InitSystem = "openrc"
	InitSysV    InitSystem = "sysv"
	InitUnknown InitSystem = "unknown"
)

func isRoot() bool {
	return os.Getuid() == 0
}

func detectInitSystem() InitSystem {
	// Check systemd
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		return InitSystemd
	}
	if _, err := exec.LookPath("systemctl"); err == nil {
		out, err := exec.Command("systemctl", "is-system-running").CombinedOutput()
		if err == nil || strings.Contains(string(out), "running") || strings.Contains(string(out), "degraded") {
			return InitSystemd
		}
	}

	// Check runit
	if _, err := os.Stat("/run/runit"); err == nil {
		return InitRunit
	}
	if _, err := os.Stat("/etc/runit"); err == nil {
		return InitRunit
	}

	// Check openrc
	if _, err := os.Stat("/sbin/openrc"); err == nil {
		return InitOpenRC
	}

	// Check sysvinit
	if _, err := os.Stat("/etc/init.d"); err == nil {
		return InitSysV
	}

	return InitUnknown
}

func getExePath() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(exePath)
}

func persistSystemd(exePath string) (string, error) {
	serviceName := "zheng.service"
	servicePath := "/etc/systemd/system/" + serviceName
	connectAddr := os.Getenv("ZHENG_CONNECT")
	if connectAddr == "" {
		connectAddr = "127.0.0.1:4443"
	}

	content := fmt.Sprintf(`[Unit]
Description=Zheng Daemon
After=network.target

[Service]
Type=simple
ExecStart=%s -connect %s
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
`, exePath, connectAddr)

	if err := os.WriteFile(servicePath, []byte(content), 0644); err != nil {
		return "", fmt.Errorf("write service file: %v", err)
	}

	// Reload, enable, start
	cmds := [][]string{
		{"systemctl", "daemon-reload"},
		{"systemctl", "enable", serviceName},
		{"systemctl", "start", serviceName},
	}
	for _, cmd := range cmds {
		if out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput(); err != nil {
			return "", fmt.Errorf("%s: %v (%s)", strings.Join(cmd, " "), err, strings.TrimSpace(string(out)))
		}
	}

	return fmt.Sprintf("systemd service installed at %s", servicePath), nil
}

func persistRunit(exePath string) (string, error) {
	serviceDir := "/etc/sv/zheng"
	connectAddr := os.Getenv("ZHENG_CONNECT")
	if connectAddr == "" {
		connectAddr = "127.0.0.1:4443"
	}

	if err := os.MkdirAll(serviceDir, 0755); err != nil {
		return "", fmt.Errorf("create service dir: %v", err)
	}

	// run script
	runScript := fmt.Sprintf("#!/bin/sh\nexec %s -connect %s\n", exePath, connectAddr)
	if err := os.WriteFile(serviceDir+"/run", []byte(runScript), 0755); err != nil {
		return "", fmt.Errorf("write run script: %v", err)
	}

	// Log script
	logScript := `#!/bin/sh
exec svlogd -tt /var/log/zheng/
`
	logDir := serviceDir + "/log"
	os.MkdirAll(logDir, 0755)
	os.WriteFile(logDir+"/run", []byte(logScript), 0755)

	// Symlink to /var/service to enable
	os.Symlink(serviceDir, "/var/run/service/zheng")

	return fmt.Sprintf("runit service installed at %s", serviceDir), nil
}

func persistOpenRC(exePath string) (string, error) {
	servicePath := "/etc/init.d/zheng"
	connectAddr := os.Getenv("ZHENG_CONNECT")
	if connectAddr == "" {
		connectAddr = "127.0.0.1:4443"
	}

	content := fmt.Sprintf(`#!/sbin/openrc-run

name="zheng"
description="Zheng Daemon"

command="%s"
command_args="-connect %s"
command_background=true
pidfile="/run/zheng.pid"
output_log="/var/log/zheng.log"
error_log="/var/log/zheng.log"

depend() {
    need net
    after firewall
}
`, exePath, connectAddr)

	if err := os.WriteFile(servicePath, []byte(content), 0755); err != nil {
		return "", fmt.Errorf("write init script: %v", err)
	}

	// Enable and start
	cmds := [][]string{
		{"rc-update", "add", "zheng", "default"},
		{"rc-service", "zheng", "start"},
	}
	for _, cmd := range cmds {
		if out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput(); err != nil {
			return "", fmt.Errorf("%s: %v (%s)", strings.Join(cmd, " "), err, strings.TrimSpace(string(out)))
		}
	}

	return fmt.Sprintf("openrc service installed at %s", servicePath), nil
}

func persistSysV(exePath string) (string, error) {
	servicePath := "/etc/init.d/zheng"
	connectAddr := os.Getenv("ZHENG_CONNECT")
	if connectAddr == "" {
		connectAddr = "127.0.0.1:4443"
	}

	content := fmt.Sprintf(`#!/bin/sh
### BEGIN INIT INFO
# Provides:          zheng
# Required-Start:    $network $remote_fs
# Required-Stop:     $network $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Zheng Daemon
### END INIT INFO

NAME="zheng"
DAEMON="%s"
PIDFILE="/var/run/zheng.pid"

case "$1" in
    start)
        echo "Starting $NAME"
        $DAEMON -connect %s &
        echo $! > $PIDFILE
        ;;
    stop)
        echo "Stopping $NAME"
        kill $(cat $PIDFILE) 2>/dev/null
        rm -f $PIDFILE
        ;;
    restart)
        $0 stop
        sleep 1
        $0 start
        ;;
    *)
        echo "Usage: $0 {start|stop|restart}"
        exit 1
        ;;
esac
exit 0
`, exePath, connectAddr)

	if err := os.WriteFile(servicePath, []byte(content), 0755); err != nil {
		return "", fmt.Errorf("write init script: %v", err)
	}

	// Enable
	exec.Command("update-rc.d", "zheng", "defaults").Run()

	return fmt.Sprintf("sysv init script installed at %s", servicePath), nil
}

func persist() (string, error) {
	if !isRoot() {
		return "", fmt.Errorf("not running as root")
	}

	exePath, err := getExePath()
	if err != nil {
		return "", fmt.Errorf("failed to get executable path: %v", err)
	}

	init := detectInitSystem()
	switch init {
	case InitSystemd:
		return persistSystemd(exePath)
	case InitRunit:
		return persistRunit(exePath)
	case InitOpenRC:
		return persistOpenRC(exePath)
	case InitSysV:
		return persistSysV(exePath)
	default:
		return "", fmt.Errorf("unsupported init system")
	}
}
