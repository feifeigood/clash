// +build !darwin,!linux,!windows,!solaris,!freebsd

package gw

import (
	"net"
)

func discoverGatewayOSSpecific() (ip net.IP, err error) {
	return ip, errNotImplemented
}

func discoverGatewayInterfaceOSSpecific() (ip net.IP, err error) {
	return nil, errNotImplemented
}

func autoInterfaceName() (string, error) {
	return "", errNotImplemented
}
