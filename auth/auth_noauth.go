package auth

import (
	"net"
)

const (
	MethodNoAuth byte = 0x00
)

func NewNoAuthAuthenticator() Authenticator {
	return &noAuthAuthenticatorImpl{}
}

type noAuthAuthenticatorImpl struct {
}

func (self *noAuthAuthenticatorImpl) Method() byte {
	return MethodNoAuth
}

func (self *noAuthAuthenticatorImpl) Authenticate(conn net.Conn) error {
	return nil
}
