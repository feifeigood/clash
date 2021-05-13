package tun

import "github.com/Dreamacro/clash/dns"

type TUNAdapter interface {
	Close()
	ReCreateDNSServer(resolver *dns.Resolver, mapper *dns.ResolverEnhancer, enable bool) error
}
