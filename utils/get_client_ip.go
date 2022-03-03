package utils

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

func GetIP(r *http.Request) (string, error) {

	IP := r.Header.Get("x-real-ip")
	netIP := net.ParseIP(IP)
	if netIP != nil {
		return netIP.String(), nil
	}

	IPs := r.Header.Get("x-forwarded-for")
	splitIPs := strings.Split(IPs, ",")
	for _, ip := range splitIPs {
		netIP := net.ParseIP(ip)
		if netIP != nil {
			return netIP.String(), nil
		}
	}

	IP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", err
	}
	netIP = net.ParseIP(IP)
	if netIP != nil {
		return netIP.String(), nil
	}

	return "", fmt.Errorf("no valid ip found")
}
