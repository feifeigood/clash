// +build darwin

package gw

import (
	"errors"
	"net"
	"os/exec"
	"strings"
)

func discoverGatewayOSSpecific() (net.IP, error) {
	routeCmd := exec.Command("/sbin/route", "-n", "get", "0.0.0.0")
	output, err := routeCmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	return parseDarwinRouteGet(output)
}

func discoverGatewayInterfaceOSSpecific() (ip net.IP, err error) {
	return nil, errNotImplemented
}

func autoInterfaceName() (string, error) {
	routeCmd := exec.Command("/sbin/route", "-n", "get", "0.0.0.0")
	output, err := routeCmd.CombinedOutput()
	if err != nil {
		return "", err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "interface:" {
			return fields[1], nil
		}
	}

	return "", errors.New("can't auto detect macos default interface name")
}
