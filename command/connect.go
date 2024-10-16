package command

import (
	"io"
	"net"
	"strconv"
	"sync"

	"github.com/lkyzhu/socks5/internal/context"
	"github.com/lkyzhu/socks5/internal/proto"
)

func (self *handler) Connect(ctx *context.Context, conn net.Conn, request *proto.CommandRequest) error {
	addr := net.JoinHostPort(request.Dest.IP.String(), strconv.Itoa(int(request.Dest.Port)))
	dest, err := net.Dial("tcp", addr)
	if err != nil {
		ctx.Logger.WithError(err).Errorf("dial target[%v] fail", addr)

		//send fail reply
		rep := proto.PasreReplyCode(err.Error())
		self.SendReply(conn, rep, proto.Addr{})
		return err
	}
	defer dest.Close()

	// send success reply
	bnd := proto.Addr{
		Type: proto.ATYP_IPV4,
	}
	local := dest.LocalAddr()
	if tcpAddr, ok := local.(*net.TCPAddr); ok {
		bnd.IP = tcpAddr.IP
		bnd.Port = uint16(tcpAddr.Port)
	} else if udpAddr, ok := local.(*net.UDPAddr); ok {
		bnd.IP = udpAddr.IP
		bnd.Port = uint16(udpAddr.Port)
	}
	self.SendReply(conn, proto.Success, bnd)

	// start proxy
	self.proxy(ctx, conn, dest)
	return nil
}

func (self *handler) proxy(ctx *context.Context, src, dest net.Conn) {
	wg := sync.WaitGroup{}

	ctx.Logger.Debugf("start proxy[%v<-->%v]\n", src.RemoteAddr().String(), dest.RemoteAddr().String())
	wg.Add(1)
	go func() {
		defer wg.Done()
		size, err := io.Copy(dest, src)
		if err != nil {
			ctx.Logger.WithError(err).Errorf("proxy[%v<-->%v] receive failed\n", src.RemoteAddr().String(), dest.RemoteAddr().String())
			return
		}
		ctx.Logger.Debugf("proxy[%v<-->%v] receive data:%v\n", src.RemoteAddr().String(), dest.RemoteAddr().String(), size)

	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		size, err := io.Copy(src, dest)
		if err != nil {
			ctx.Logger.WithError(err).Errorf("proxy[%v<-->%v] receive failed\n", src.RemoteAddr().String(), dest.RemoteAddr().String())
			return
		}
		ctx.Logger.Debugf("proxy[%v<-->%v] receive data:%v\n", src.RemoteAddr().String(), dest.RemoteAddr().String(), size)
	}()

	wg.Wait()

	ctx.Logger.Debugf("start proxy[%v<-->%v] end\n", src.RemoteAddr().String(), dest.RemoteAddr().String())
}
