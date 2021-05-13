package netstack

import (
	"io"
	"net"

	"github.com/Dreamacro/clash/proxy/tun/netstack/core"
)

type Device interface {
	io.Closer
	core.Device
}

type Stack struct {
	core.Stack
	Handler Handler
	Hijack  bool
}

func NewStack(handler Handler) *Stack {
	return &Stack{Handler: handler}
}

func (s *Stack) Start(device Device) error {
	return s.Stack.Start(device, s)
}

func (s *Stack) Handle(conn *core.TCPConn, target *net.TCPAddr) {
	s.Handler.Handle(conn, target)
}

func (s *Stack) HandlePacket(pkt *core.UDPPacket, target *net.UDPAddr) {
	s.Handler.HandlePacket(pkt, target)
}
