package netstack

import (
	"errors"
	"fmt"
	"net"
	"unsafe"

	"github.com/Dreamacro/clash/dns"
	"github.com/Dreamacro/clash/log"
	D "github.com/miekg/dns"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/ports"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type DNSServer struct {
	*dns.Server
	resolver *dns.Resolver

	tcpip.NICID
	stack         *stack.Stack
	tcpListener   net.Listener
	udpEdpoint    *DNSEndpoint
	udpEndpointID *stack.TransportEndpointID
}

type DNSResponseWriter struct {
	s   *stack.Stack
	pkt *stack.PacketBuffer
	id  stack.TransportEndpointID
}

func (w *DNSResponseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IP(w.id.LocalAddress), Port: int(w.id.LocalPort)}
}

func (w *DNSResponseWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IP(w.id.RemoteAddress), Port: int(w.id.RemotePort)}
}

func (w *DNSResponseWriter) WriteMsg(msg *D.Msg) error {
	b, err := msg.Pack()
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}
func (w *DNSResponseWriter) TsigStatus() error {
	// Unsupported
	return nil
}
func (w *DNSResponseWriter) TsigTimersOnly(bool) {
	// Unsupported
}
func (w *DNSResponseWriter) Hijack() {
	// Unsupported
}

func (w *DNSResponseWriter) Write(b []byte) (int, error) {
	v := buffer.View(b)
	if len(v) > header.UDPMaximumPacketSize {
		return 0, errors.New((&tcpip.ErrMessageTooLong{}).String())
	}

	// w.id.LocalAddress is the source ip of DNS response
	route, tcperr := w.s.FindRoute(w.pkt.NICID, w.id.LocalAddress, w.id.RemoteAddress, w.pkt.NetworkProtocolNumber, false)
	if tcperr != nil {
		return 0, errors.New(tcperr.String())
	}
	defer route.Release()

	if tcperr := sendUDP(
		route,
		v.ToVectorisedView(),
		w.id.LocalPort,
		w.id.RemotePort,
		0,    /* ttl */
		true, /* useDefaultTTL */
		0,    /* tos */
		nil,  /* owner */
		true,
	); tcperr != nil {
		return 0, errors.New((*tcperr).String())
	}

	return len(b), nil
}

func (w *DNSResponseWriter) Close() error {
	return nil
}

// use unsafe package
var _ unsafe.Pointer = unsafe.Pointer(nil)

// sendUDP sends a UDP segment via the provided network endpoint and under the
// provided identity.
//
//go:linkname sendUDP gvisor.dev/gvisor/pkg/tcpip/transport/udp.sendUDP
func sendUDP(r *stack.Route, data buffer.VectorisedView, localPort, remotePort uint16, ttl uint8, useDefaultTTL bool, tos uint8, owner tcpip.PacketOwner, noChecksum bool) *tcpip.Error

type DNSEndpoint struct {
	stack.TransportEndpoint
	stack  *stack.Stack
	server *dns.Server
}

func (ep *DNSEndpoint) Close() {}
func (ep *DNSEndpoint) Wait()  {}
func (ep *DNSEndpoint) Abort() { ep.Close() }
func (ep *DNSEndpoint) UniqueID() uint64 {
	return ep.stack.UniqueID()
}
func (ep *DNSEndpoint) HandleError(terr stack.TransportError, pkt *stack.PacketBuffer) {
	log.Warnln("DNSEndpoint(gvisor) received a transport error - %v", terr)
	log.Debugln("DNSEndpoint(gvisor) transport error packet - %v", pkt)
}
func (ep *DNSEndpoint) HandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) {
	hdr := header.UDP(pkt.TransportHeader().View())
	if int(hdr.Length()) > pkt.Data().Size()+header.UDPMinimumSize {
		// Malformed packet.
		ep.stack.Stats().UDP.MalformedPacketsReceived.Increment()
		return
	}

	var msg D.Msg
	msg.Unpack(pkt.Data().AsRange().ToOwnedView())
	writer := DNSResponseWriter{s: ep.stack, pkt: pkt, id: id}
	go ep.server.ServeDNS(&writer, &msg)
}

func CreateDNSServer(s *stack.Stack, resolver *dns.Resolver, mapper *dns.ResolverEnhancer, nicID tcpip.NICID) (*DNSServer, error) {
	var err error

	// listen 0.0.0.0:53 for hijack all dns query
	address := tcpip.FullAddress{NIC: nicID, Addr: tcpip.Address(""), Port: uint16(53)}

	handler := dns.NewHandler(resolver, mapper)
	embededsrv := &dns.Server{}
	embededsrv.SetHandler(handler)

	id := &stack.TransportEndpointID{
		LocalAddress:  address.Addr,
		LocalPort:     uint16(53),
		RemotePort:    0,
		RemoteAddress: "",
	}

	endpoint := &DNSEndpoint{stack: s, server: embededsrv}

	// UDP
	if tcpiperr := s.RegisterTransportEndpoint(
		[]tcpip.NetworkProtocolNumber{ipv4.ProtocolNumber, ipv6.ProtocolNumber},
		udp.ProtocolNumber,
		*id,
		endpoint,
		ports.Flags{LoadBalanced: true}, // it's actually the SO_REUSEPORT. Not sure it take effect.
		nicID); err != nil {
		log.Errorln("unable to start UDP DNS on tun - %v", tcpiperr.String())
	}

	// TCP
	var tcpListener net.Listener
	if tcpListener, err = gonet.ListenTCP(s, address, ipv4.ProtocolNumber); err != nil {
		return nil, fmt.Errorf("DNS server can't listen on tun - %v", err)
	}

	srv := &DNSServer{
		Server:        embededsrv,
		resolver:      resolver,
		stack:         s,
		tcpListener:   tcpListener,
		udpEdpoint:    endpoint,
		udpEndpointID: id,
		NICID:         nicID,
	}
	srv.SetHandler(handler)
	srv.Server.Server = &D.Server{Listener: tcpListener, Handler: srv}

	go func() {
		srv.ActivateAndServe()
	}()

	return srv, err
}

func (s *DNSServer) Stop() {
	s.Server.Shutdown()
	if s.Listener != nil {
		s.Listener.Close()
	}
	s.stack.UnregisterTransportEndpoint(
		[]tcpip.NetworkProtocolNumber{ipv4.ProtocolNumber, ipv6.ProtocolNumber},
		udp.ProtocolNumber, *s.udpEndpointID, s.udpEdpoint,
		ports.Flags{LoadBalanced: true}, // it's actually the SO_REUSEPORT. Not sure it take effect.
		s.NICID)
}

func (s *DNSServer) UDPEndpointID() *stack.TransportEndpointID {
	return s.udpEndpointID
}

func (s *DNSServer) Resolver() *dns.Resolver {
	return s.resolver
}
