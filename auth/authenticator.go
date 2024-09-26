package auth

import (
	"net"
	"sync"

	"github.com/lkyzhu/socks5/internal/context"
	"github.com/lkyzhu/socks5/internal/proto"
)

const (
	MethodNoAcceptable byte = 0xFF
)

type Authenticator interface {
	//Authenticate(conn net.Conn, method *proto.MethodRequest) error
	Authenticate(conn net.Conn) error
	Method() byte
}

type Config struct {
}

type AuthenticatorMgr struct {
	authenticators sync.Map
}

func (self *AuthenticatorMgr) Regist(auth Authenticator) {
	self.authenticators.Store(auth.Method(), auth)
}

func (self *AuthenticatorMgr) Authenticate(ctx *context.Context, conn net.Conn, req *proto.MethodRequest) error {
	ctx.Logger.Debugf("request with method:%v", req.Methods)
	for _, m := range req.Methods {
		if val, exist := self.authenticators.Load(m); exist {
			if authenticator, ok := val.(Authenticator); !ok {
				continue
			} else {
				proto.WriteMethodReply(conn, &proto.MethodReply{Ver: proto.VERSION, Method: authenticator.Method()})
				return authenticator.Authenticate(conn)
			}
		}
	}

	return self.invalidMethod(conn)
}

func (self *AuthenticatorMgr) invalidMethod(conn net.Conn) error {
	rep := &proto.MethodReply{Ver: proto.VERSION, Method: MethodNoAcceptable}
	return proto.WriteMethodReply(conn, rep)
}
