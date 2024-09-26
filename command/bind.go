package command

import (
	"net"
	"strconv"

	"github.com/lkyzhu/socks5/internal/context"
	"github.com/lkyzhu/socks5/internal/proto"
)

func (self *handler) Bind(ctx *context.Context, conn net.Conn, request *proto.CommandRequest) error {
	addr := net.JoinHostPort(request.Dest.IP.String(), strconv.Itoa(int(request.Dest.Port)))
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		self.SendReply(conn, proto.ServerFailure, proto.Addr{})
		return err
	}

	defer listener.Close()

	local := listener.Addr()

	bnd := proto.Addr{
		Type: proto.ATYP_IPV4,
	}
	if tcpAddr, ok := local.(*net.TCPAddr); ok {
		bnd.IP = tcpAddr.IP
		bnd.Port = uint16(tcpAddr.Port)
	}

	if bnd.IP.To16() != nil {
		bnd.Type = proto.ATYP_IPV6
	}

	self.SendReply(conn, proto.Success, bnd)

	dest, err := listener.Accept()
	if err != nil {
		self.SendReply(conn, proto.ServerFailure, proto.Addr{})
		return err
	}

	defer dest.Close()

	rbnd := proto.Addr{
		Type: proto.ATYP_IPV4,
	}
	rAddr := dest.RemoteAddr()
	if tcpAddr, ok := rAddr.(*net.TCPAddr); ok {
		rbnd.IP = tcpAddr.IP
		rbnd.Port = uint16(tcpAddr.Port)
	} else {
		self.SendReply(conn, proto.AddressTypeNotSupport, proto.Addr{})
		return err
	}

	if rbnd.IP.To16() != nil {
		rbnd.Type = proto.ATYP_IPV6
	}

	self.SendReply(conn, proto.Success, rbnd)

	self.proxy(ctx, conn, dest)

	return nil
}
