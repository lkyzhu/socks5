package context

import (
	sc "context"
	"crypto/rand"
	"encoding/hex"
	"net"

	"github.com/sirupsen/logrus"
)

type Context struct {
	Id       string
	Src      net.Conn
	Dst      net.Conn
	Identity string
	Logger   *logrus.Entry
	sc.Context
}

func NewContext() *Context {
	bytes := make([]byte, 4)
	rand.Read(bytes)
	id := hex.EncodeToString(bytes)

	ctx := &Context{
		Id: id,
	}

	ctx.Logger = logrus.WithField("id", id)
	return ctx
}
