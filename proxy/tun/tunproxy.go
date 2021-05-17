package tun

import (
	"encoding/binary"
	"fmt"
	"net"

	adapters "github.com/Dreamacro/clash/adapters/inbound"
	"github.com/Dreamacro/clash/component/socks5"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/dns"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/proxy/tun/netstack"
	"github.com/Dreamacro/clash/proxy/tun/tuntap"
	"github.com/Dreamacro/clash/tunnel"
	"gvisor.dev/gvisor/pkg/tcpip"
)

type tunAdapter struct {
	ifce      *tuntap.Tun
	ipstack   *netstack.Stack
	dnsserver *netstack.DNSServer
}

func NewTUNAdapter(name string, macOSAutoRoute bool) (TUNAdapter, error) {
	ifce, err := tuntap.NewTun(name)
	if err != nil {
		return nil, fmt.Errorf("can't open tun interface: %w", err)
	}

	if err := ifce.SetInterfaceAddress("198.18.0.1/24"); err != nil {
		return nil, err
	}

	if macOSAutoRoute {
		if err := ifce.AddRouteEntry([]string{"1.0.0.0/8", "2.0.0.0/7", "4.0.0.0/6", "8.0.0.0/5", "16.0.0.0/4", "32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/1"}); err != nil {
			return nil, err
		}
	}

	ipstack := netstack.NewStack(&fakeHandler{})
	if err := ipstack.Start(ifce); err != nil {
		return nil, err
	}

	log.Infoln("Enabled tun mode setup interface name: %s", ifce.Name)

	return &tunAdapter{ifce: ifce, ipstack: ipstack}, nil
}

func (t *tunAdapter) DNSListen() string {
	if t.dnsserver != nil {
		id := t.dnsserver.UDPEndpointID()
		return fmt.Sprintf("%s:%d", id.LocalAddress.String(), id.LocalPort)
	}
	return ""
}

// Stop stop the DNS Server on tun
func (a *tunAdapter) ReCreateDNSServer(resolver *dns.Resolver, mapper *dns.ResolverEnhancer, enable bool) error {
	if !enable && a.dnsserver == nil {
		return nil
	}

	if enable && a.dnsserver != nil && a.dnsserver.Resolver() == resolver {
		return nil
	}

	if a.dnsserver != nil {
		a.dnsserver.Stop()
		a.dnsserver = nil
		log.Debugln("tun DNS server stoped")
	}

	var err error
	if resolver == nil {
		return fmt.Errorf("failed to create DNS server on tun: resolver not provided")
	}

	server, err := netstack.CreateDNSServer(a.ipstack.Stack.Stack, resolver, mapper, a.ipstack.Stack.NICID)
	if err != nil {
		return err
	}
	a.dnsserver = server

	log.Infoln("Tun DNS server listening at: %s", a.DNSListen())

	return nil
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
