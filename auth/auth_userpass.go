package auth

import (
	"errors"
	"net"

	"github.com/lkyzhu/socks5/internal/proto"
)

const (
	MethodUserPassword byte = 0x02
)

var (
	ERR_INVALID_USER_PASSWORD = errors.New("user or password is invalid")
)

type UserPassAuthenticator interface {
	Authenticator
	Create(user, passwd string) error
	Update(user, passwd string) error
	Delete(user string) error
	Validate(user, passwd string) (bool, error)
}

type UserPassStore interface {
	Create(user, passwd string) error
	Update(user, passwd string) error
	Delete(user string) error
	Validate(user, passwd string) (bool, error)
}

func NewUserPassAuthenticator(store UserPassStore) UserPassAuthenticator {
	return &userPassAuthenticatorImpl{
		store: store,
	}
}

type userPassAuthenticatorImpl struct {
	store UserPassStore
}

func (self *userPassAuthenticatorImpl) Method() byte {
	return MethodUserPassword
}

func (self *userPassAuthenticatorImpl) Authenticate(conn net.Conn) error {
	req, err := proto.ReadUserPasswordRequest(conn)
	if err != nil {
		proto.WriteAuthReply(conn, &proto.AuthReply{Ver: proto.VERSION, Status: proto.AuthFailure})
		return err
	}

	ok, err := self.store.Validate(string(req.Uname), string(req.Passwd))
	if err != nil {
		proto.WriteAuthReply(conn, &proto.AuthReply{Ver: proto.VERSION, Status: proto.AuthFailure})
		return err
	}

	if !ok {
		proto.WriteAuthReply(conn, &proto.AuthReply{Ver: proto.VERSION, Status: proto.AuthFailure})
		return ERR_INVALID_USER_PASSWORD
	}

	proto.WriteAuthReply(conn, &proto.AuthReply{Ver: proto.VERSION, Status: proto.AuthSuccess})
	return nil
}

func (self *userPassAuthenticatorImpl) Create(user, passwd string) error {
	return self.store.Create(user, passwd)
}

func (self *userPassAuthenticatorImpl) Update(user, passwd string) error {
	return self.store.Update(user, passwd)
}

func (self *userPassAuthenticatorImpl) Delete(user string) error {
	return self.store.Delete(user)
}

func (self *userPassAuthenticatorImpl) Validate(user, passwd string) (bool, error) {
	return self.store.Validate(user, passwd)
}
