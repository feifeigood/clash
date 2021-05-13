package tun

import (
	"encoding/binary"
	"fmt"
	"net"

	adapters "github.com/Dreamacro/clash/adapters/inbound"
	"github.com/Dreamacro/clash/component/socks5"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/proxy/tun/netstack"
	"github.com/Dreamacro/clash/proxy/tun/tuntap"
	"github.com/Dreamacro/clash/tunnel"
	"gvisor.dev/gvisor/pkg/tcpip"
)

type tunAdapter struct {
	ifce    *tuntap.Tun
	ipstack *netstack.Stack
}

func NewTUNAdapter(name string) (TUNAdapter, error) {
	ifce, err := tuntap.NewTun(name)
	if err != nil {
		return nil, fmt.Errorf("can't open tun interface: %w", err)
	}

	if err := ifce.SetInterfaceAddress("198.18.0.1/24"); err != nil {
		return nil, err
	}

	ipstack := netstack.NewStack(&fakeHandler{})
	if err := ipstack.Start(ifce); err != nil {
		return nil, err
	}

	return &tunAdapter{ifce: ifce, ipstack: ipstack}, nil
}

func (a *tunAdapter) Close() {
	if a.ipstack != nil {
		a.ipstack.Close()
	}
}

type fakeHandler struct{}

func (h *fakeHandler) Handle(conn netstack.Conn, target *net.TCPAddr) {
	tunnel.Add(adapters.NewSocket(socksAddr(target.IP, target.Port), conn, C.TUN))
}

func (h *fakeHandler) HandlePacket(packet netstack.Packet, target *net.UDPAddr) {
	tunnel.AddPacket(adapters.NewPacket(socksAddr(target.IP, target.Port), packet, C.TUN))
}

func socksAddr(ip net.IP, localport int) socks5.Addr {
	ipv4 := ip.To4()

	// get the big-endian binary represent of port
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(localport))

	if ipv4 != nil {
		addr := make([]byte, 1+net.IPv4len+2)
		addr[0] = socks5.AtypIPv4
		copy(addr[1:1+net.IPv4len], []byte(ipv4))
		addr[1+net.IPv4len], addr[1+net.IPv4len+1] = port[0], port[1]
		return addr
	} else {
		addr := make([]byte, 1+net.IPv6len+2)
		addr[0] = socks5.AtypIPv6
		copy(addr[1:1+net.IPv6len], []byte(tcpip.Address(ip.To16())))
		addr[1+net.IPv6len], addr[1+net.IPv6len+1] = port[0], port[1]
		return addr
	}
}
