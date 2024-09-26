package resolve

import (
	"context"
	"net"
	//"github.com/lkyzhu/socks5/internal/context"
)

type Resolver interface {
	Resolve(ctx context.Context, name string) (net.IP, error)
}

func NewResolver() Resolver {
	return &resolver{}
}

type resolver struct {
}

func (self *resolver) Resolve(ctx context.Context, name string) (net.IP, error) {
	addr, err := net.ResolveIPAddr("ip", name)
	if err != nil {
		return nil, err
	}

	return addr.IP, nil
}
