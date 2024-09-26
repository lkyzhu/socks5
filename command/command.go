package command

import (
	"errors"
	"net"

	sc "context"

	"github.com/lkyzhu/socks5/internal/context"
	"github.com/lkyzhu/socks5/internal/proto"
	"github.com/lkyzhu/socks5/resolve"
)

type Handler interface {
	resolve.Resolver
	Process(ctx *context.Context, conn net.Conn) error
}

type handler struct {
	resolver resolve.Resolver
}

func NewHandler(resolver resolve.Resolver) Handler {
	return &handler{resolver: resolver}
}

func (self *handler) Process(ctx *context.Context, conn net.Conn) error {
	request, err := proto.ReadCommandRequest(conn)
	if err != nil {
		ctx.Logger.WithError(err).Errorf("read command fail")
		return err
	}

	if request.Dest.Domain != "" {
		ip, err := self.resolver.Resolve(sc.Background(), request.Dest.Domain)
		if err != nil {
			ctx.Logger.WithError(err).Errorf("resolve domain[%v] fail", request.Dest.Domain)
			return err
		}
		request.Dest.IP = ip

		ctx.Logger.Debugf("resolve domain[%v] to ip[%v] success", request.Dest.Domain, ip)
	}

	return self.HandleCommand(ctx, conn, request)
}

func (self *handler) HandleCommand(ctx *context.Context, conn net.Conn, request *proto.CommandRequest) error {
	ctx.Logger.Debugf("handle request command:%v,%v:%v begin\n", request.Cmd, request.Dest.IP.String(), request.Dest.Port)
	switch request.Cmd {
	case proto.Connect:
		return self.Connect(ctx, conn, request)
	case proto.Bind:
		return self.Bind(ctx, conn, request)
	case proto.Associate:
		return self.Associate(ctx, conn, request)
	default:
		self.SendReply(conn, proto.CommandNotSupport, proto.Addr{})
	}

	repCode := proto.CommandNotSupport
	return errors.New(repCode.String())
}

func (self *handler) SendReply(conn net.Conn, code proto.ReplyCode, addr proto.Addr) error {
	reply := &proto.CommandReply{
		Ver: proto.VERSION,
		Rep: byte(code),
		Rsv: 0x00,
		Bnd: addr,
	}

	return proto.WriteCommandReply(conn, reply)
}

func (self *handler) Resolve(ctx sc.Context, name string) (net.IP, error) {
	return self.resolver.Resolve(ctx, name)
}
