package command

import (
	"net"

	"github.com/lkyzhu/socks5/internal/context"
	"github.com/lkyzhu/socks5/internal/proto"
)

func (self *handler) Associate(ctx *context.Context, conn net.Conn, request *proto.CommandRequest) error {
	return nil
}
