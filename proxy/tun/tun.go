package tun

import (
	"fmt"

	adapters "github.com/Dreamacro/clash/adapters/inbound"
	"github.com/Dreamacro/clash/common/netdevice"
	"github.com/Dreamacro/clash/common/netdevice/stack"
	"github.com/Dreamacro/clash/common/netdevice/tun"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/tunnel"
)

type TunAdapter interface {
	Close()
}

type tunAdapter struct {
	stack  *stack.Stack
	device netdevice.Device
}

func NewTunAdapter() (TunAdapter, error) {
	tundev, err := tun.Open(tun.WithName("utun"))
	if err != nil {
		return nil, fmt.Errorf("can't open tun: %v", err)
	}

	h := &handler{}
	stack, err := stack.New(tundev, h, stack.WithDefault())
	if err != nil {
		return nil, fmt.Errorf("can't create ipstack: %v", err)
	}

	adapter := &tunAdapter{
		stack:  stack,
		device: tundev,
	}

	return adapter, nil
}

// Close close the TunAdapter
func (t *tunAdapter) Close() {
	if t.device != nil {
		t.device.Close()
	}
}

type handler struct{}

func (*handler) Add(conn stack.TCPConn) {
	target := stack.GetSocks5Addr(conn.ID())
	tunnel.Add(adapters.NewSocket(target, conn, C.TUN))

}

func (*handler) AddPacket(packet stack.UDPPacket) {
	target := stack.GetSocks5Addr(packet.ID())
	tunnel.AddPacket(adapters.NewPacket(target, packet, C.TUN))
}
