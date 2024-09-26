package main

import (
	"net"
	"os"

	"github.com/lkyzhu/socks5"
	"github.com/lkyzhu/socks5/auth"
	"github.com/lkyzhu/socks5/command"
	"github.com/lkyzhu/socks5/resolve"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func main() {
	cmd := cobra.Command{
		Use: "socks5",
		Run: run,
	}

	cmd.Flags().String("addr", "", "addr to listen")
	cmd.Execute()
}

func run(cmd *cobra.Command, args []string) {
	logrus.SetOutput(os.Stderr)
	logrus.SetLevel(logrus.DebugLevel)
	store := &userPass{users: make(map[string]*Password)}
	store.Create("test", "SecAbc@123")

	userPassAuth := auth.NewUserPassAuthenticator(store)
	authMgr := &auth.AuthenticatorMgr{}
	authMgr.Regist(userPassAuth)
	noAuth := auth.NewNoAuthAuthenticator()
	authMgr.Regist(noAuth)

	handler := command.NewHandler(resolve.NewResolver())
	server := socks5.NewServer(authMgr, handler)

	addr, err := cmd.Flags().GetString("addr")
	if err != nil {
		return
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		logrus.WithError(err).Errorf("listen addr[%v] fail", addr)
		return
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			logrus.WithError(err).Errorf("accept for [%v] fail", addr)
			return
		}

		logrus.Debugf("receive conn:%v\n", conn.RemoteAddr().String())

		go server.ServeConn(conn)

	}
}
