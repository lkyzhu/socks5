package proto

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
)

const (
	VERSION byte = 0x5
)

var (
	ERR_INVALID_VERSION = errors.New("unsupported version")
	ERR_INVALID_ADDR    = errors.New("invalid addr")
)

const (
	ATYP_IPV4   = 0x01
	ATYP_DOMAIN = 0x03
	ATYP_IPV6   = 0x04
)

// https://datatracker.ietf.org/doc/html/rfc1928

// version identifier/method selection message:
// +----+----------+----------+
// |VER | NMETHODS | METHODS  |
// +----+----------+----------+
// | 1  |    1     | 1 to 255 |
// +----+----------+----------+
type MethodRequest struct {
	Ver      byte
	NMethods byte
	Methods  []byte
}

func (self *MethodRequest) Read(conn net.Conn) error {
	buf := bufio.NewReader(conn)

	tmp := make([]byte, 2)
	_, err := buf.Read(tmp)
	if err != nil {
		return err
	}
	self.Ver = tmp[0]
	self.NMethods = tmp[1]

	self.Methods = make([]byte, self.NMethods)

	if _, err := io.ReadAtLeast(buf, self.Methods, int(self.NMethods)); err != nil {
		return err
	}

	return nil
}

func (self *MethodRequest) Write(conn net.Conn) error {
	buf := bufio.NewWriter(conn)

	tmp := make([]byte, 2)
	tmp[0] = self.Ver
	tmp[1] = self.NMethods
	if _, err := buf.Write(tmp); err != nil {
		return err
	}

	if _, err := buf.Write(self.Methods); err != nil {
		return err
	}

	if err := buf.Flush(); err != nil {
		return err
	}
	return nil
}

func ReadMethodRequest(conn net.Conn) (*MethodRequest, error) {
	req := &MethodRequest{}
	if err := req.Read(conn); err != nil {
		return nil, err
	}

	return req, nil
}

func WriteMethodRequest(conn net.Conn, req *MethodRequest) error {
	if req == nil {
		return errors.New("req is invalid")
	}
	return req.Write(conn)
}

// METHOD selection message:
// +----+--------+
// |VER | METHOD |
// +----+--------+
// | 1  |   1    |
// +----+--------+
type MethodReply struct {
	Ver    byte
	Method byte
}

func (self *MethodReply) Read(conn net.Conn) error {
	buf := bufio.NewReader(conn)

	tmp := make([]byte, 2)
	if _, err := buf.Read(tmp); err != nil {
		return err
	}
	self.Ver = tmp[0]
	if self.Ver != VERSION {
		return ERR_INVALID_VERSION
	}
	self.Method = tmp[1]

	return nil
}

func (self *MethodReply) Write(conn net.Conn) error {
	buf := bufio.NewWriter(conn)
	tmp := make([]byte, 2)
	tmp[0] = self.Ver
	tmp[1] = self.Method

	if _, err := buf.Write(tmp); err != nil {
		return err
	}

	if err := buf.Flush(); err != nil {
		return err
	}

	return nil
}

func ReadMethodReply(conn net.Conn) (*MethodReply, error) {
	rep := &MethodReply{}
	if err := rep.Read(conn); err != nil {
		return nil, err
	}

	return rep, nil
}

func WriteMethodReply(conn net.Conn, rep *MethodReply) error {
	if rep == nil {
		return errors.New("rep is invalid")
	}

	return rep.Write(conn)
}

// The SOCKS request is formed as follows:
// +----+-----+-------+------+----------+----------+
// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  | X'00' |  1   | Variable |    2     |
// +----+-----+-------+------+----------+----------+
type CommandRequest struct {
	Ver  byte
	Cmd  byte
	Rsv  byte
	Dest Addr
}

func (self *CommandRequest) Read(conn net.Conn) error {
	buf := bufio.NewReader(conn)
	tmp := make([]byte, 3)
	if _, err := buf.Read(tmp); err != nil {
		return err
	} else {
		self.Ver = tmp[0]
		self.Cmd = tmp[1]
		self.Rsv = tmp[2]
	}

	if self.Ver != VERSION {
		return ERR_INVALID_VERSION
	}

	return self.Dest.Read(buf)
}

func (self *CommandRequest) Write(conn net.Conn) error {
	buf := bufio.NewWriter(conn)
	tmp := make([]byte, 3)
	tmp[0] = self.Ver
	tmp[1] = self.Cmd
	tmp[2] = self.Rsv
	if _, err := buf.Write(tmp); err != nil {
		return err
	}

	if err := self.Dest.Write(buf); err != nil {
		return err
	}

	if err := buf.Flush(); err != nil {
		return err
	}

	return nil
}

func (self *Addr) Read(buf *bufio.Reader) error {
	if t, err := buf.ReadByte(); err != nil {
		return err
	} else {
		self.Type = t
	}

	switch self.Type {
	case ATYP_IPV4:
		tmp := make([]byte, net.IPv4len+2)
		if _, err := buf.Read(tmp); err != nil {
			return err
		}
		self.IP = net.IPv4(tmp[0], tmp[1], tmp[2], tmp[3])
		self.Port = binary.BigEndian.Uint16(tmp[net.IPv4len:])

	case ATYP_IPV6:
		tmp := make([]byte, net.IPv6len+2)
		if _, err := buf.Read(tmp); err != nil {
			return err
		}
		self.IP = tmp[:net.IPv6len]
		self.Port = binary.BigEndian.Uint16(tmp[net.IPv6len:])

	case ATYP_DOMAIN:
		dlen, err := buf.ReadByte()
		if err != nil {
			return err
		}
		tmp := make([]byte, dlen+2)
		if _, err := buf.Read(tmp); err != nil {
			return err
		}
		self.Domain = string(tmp[:dlen])
		self.Port = binary.BigEndian.Uint16(tmp[dlen:])

	default:
		return ERR_INVALID_ADDR
	}

	return nil
}

func (self *Addr) Write(buf *bufio.Writer) error {
	if err := buf.WriteByte(self.Type); err != nil {
		return err
	}

	switch self.Type {
	case ATYP_IPV4:
		tmp := make([]byte, net.IPv4len+2)
		copy(tmp, self.IP[net.IPv6len-net.IPv4len:])
		binary.BigEndian.PutUint16(tmp[net.IPv4len:], self.Port)
		_, err := buf.Write(tmp)
		return err

	case ATYP_IPV6:
		tmp := make([]byte, net.IPv6len+2)
		copy(tmp, self.IP)
		binary.BigEndian.PutUint16(tmp[net.IPv6len:], self.Port)
		_, err := buf.Write(tmp)
		return err

	case ATYP_DOMAIN:
		dlen := len(self.Domain)
		tmp := make([]byte, dlen+2+1)
		tmp[0] = byte(dlen)
		copy(tmp[1:], []byte(self.Domain))
		binary.BigEndian.PutUint16(tmp[1+dlen:], self.Port)
		_, err := buf.Write(tmp)
		return err

	default:
		return ERR_INVALID_ADDR
	}
}

func ReadCommandRequest(conn net.Conn) (*CommandRequest, error) {
	req := &CommandRequest{}
	if err := req.Read(conn); err != nil {
		return nil, err
	}

	return req, nil
}

func WriteCommandRequest(conn net.Conn, req *CommandRequest) error {
	if req == nil {
		return errors.New("req is invalid")
	}

	return req.Write(conn)
}

type Addr struct {
	Type   byte
	Port   uint16
	IP     net.IP
	Domain string
}

// The SOCKS reply formed as follows:
// +----+-----+-------+------+----------+----------+
// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  | X'00' |  1   | Variable |    2     |
// +----+-----+-------+------+----------+----------+
type CommandReply struct {
	Ver byte
	Rep byte
	Rsv byte
	Bnd Addr
}

func (self *CommandReply) Read(conn net.Conn) error {
	buf := bufio.NewReader(conn)
	tmp := make([]byte, 3)
	if _, err := buf.Read(tmp); err != nil {
		return err
	} else {
		self.Ver = tmp[0]
		self.Rep = tmp[1]
		self.Rsv = tmp[2]
	}

	return self.Bnd.Read(buf)
}

func (self *CommandReply) Write(conn net.Conn) error {
	buf := bufio.NewWriter(conn)
	tmp := make([]byte, 3)
	tmp[0] = self.Ver
	tmp[1] = self.Rep
	tmp[2] = self.Rsv
	if _, err := buf.Write(tmp); err != nil {
		return err
	}

	if err := self.Bnd.Write(buf); err != nil {
		return err
	}

	if err := buf.Flush(); err != nil {
		return err
	}

	return nil
}

func ReadCommandReply(conn net.Conn) (*CommandReply, error) {
	rep := &CommandReply{}
	if err := rep.Read(conn); err != nil {
		return nil, err
	}

	return rep, nil
}

func WriteCommandReply(conn net.Conn, rep *CommandReply) error {
	if rep == nil {
		return errors.New("rep is invalid")
	}

	return rep.Write(conn)
}

type ReplyCode byte

const (
	Success ReplyCode = iota
	ServerFailure
	RuleFailure
	NetworkUnreachable
	HostUnreachable
	ConnectionRefused
	TTLExpired
	CommandNotSupport
	AddressTypeNotSupport

	//  X'09' to X'FF' unassigned
)

func (self *ReplyCode) String() string {
	switch *self {
	case Success:
		return "success"
	case ServerFailure:
		return "general SOCKS server failure"
	case RuleFailure:
		return "connection not allowed by ruleset"
	case NetworkUnreachable:
		return "Network unreachable"
	case HostUnreachable:
		return "Host unreachable"
	case ConnectionRefused:
		return "Connection refused"
	case TTLExpired:
		return "TTL expired"
	case CommandNotSupport:
		return "Command not supported"
	case AddressTypeNotSupport:
		return "Address type not supported"
	}

	return "unassigned code"
}

func PasreReplyCode(msg string) ReplyCode {
	switch {
	case msg == "success":
		return Success
	case strings.Contains(msg, "network is unreachable"):
		return NetworkUnreachable
	case strings.Contains(msg, "host is unreachable"):
		return HostUnreachable
	case strings.Contains(msg, "refused"):
		return ConnectionRefused
	case strings.Contains(msg, "expired"):
		return TTLExpired
	case strings.Contains(msg, "command not support"):
		return CommandNotSupport
	case strings.Contains(msg, "address type not support"):
		return AddressTypeNotSupport
	}

	return 0xFF
}

const (
	CmdType byte = iota
	Connect
	Bind
	Associate
)
