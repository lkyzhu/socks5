package socks5

import (
	"net"

	"github.com/lkyzhu/socks5/auth"
	"github.com/lkyzhu/socks5/command"
	"github.com/lkyzhu/socks5/internal/context"
	"github.com/lkyzhu/socks5/internal/proto"
)

type Server struct {
	auth    *auth.AuthenticatorMgr
	handler command.Handler
}

func NewServer(auth *auth.AuthenticatorMgr, handler command.Handler) *Server {
	return &Server{
		auth:    auth,
		handler: handler,
	}
}

func (self *Server) ServeConn(conn net.Conn) error {
	defer conn.Close()

	ctx := context.NewContext()

	// method read
	method, err := proto.ReadMethodRequest(conn)
	if err != nil {
		ctx.Logger.WithError(err).Errorf("read method fail")
		return err
	}

	// authenticate
	err = self.auth.Authenticate(ctx, conn, method)
	if err != nil {
		ctx.Logger.WithError(err).Errorf("authenticate fail")
		return err
	}

	ctx.Logger.Debugf("authenticate success")
	// command
	err = self.handler.Process(ctx, conn)

	return err
}
