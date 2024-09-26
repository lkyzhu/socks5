package proto

import (
	"bufio"
	"errors"
	"fmt"
	"net"
)

// https://www.rfc-editor.org/rfc/rfc1929

// Username/Password request:
// +----+------+----------+------+----------+
// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
// +----+------+----------+------+----------+
// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
// +----+------+----------+------+----------+

type UserPasswordRequest struct {
	Ver    byte
	Ulen   byte
	Uname  []byte
	Plen   byte
	Passwd []byte
}

func (self *UserPasswordRequest) Read(conn net.Conn) error {
	buf := bufio.NewReader(conn)

	tmp := make([]byte, 2)
	if _, err := buf.Read(tmp); err != nil {
		return err
	}
	self.Ver = tmp[0]
	self.Ulen = tmp[1]

	if self.Ver != VERSION {
		return ERR_INVALID_VERSION
	}

	self.Uname = make([]byte, self.Ulen)
	if _, err := buf.Read(self.Uname); err != nil {
		return err
	}

	if plen, err := buf.ReadByte(); err != nil {
		return err
	} else {
		self.Plen = plen
	}

	self.Passwd = make([]byte, self.Plen)
	if _, err := buf.Read(self.Passwd); err != nil {
		return err
	}

	return nil
}

func (self *UserPasswordRequest) Write(conn net.Conn) error {
	buf := bufio.NewWriter(conn)

	if err := buf.WriteByte(self.Ver); err != nil {
		return err
	}

	if err := buf.WriteByte(self.Ulen); err != nil {
		return err
	}

	if _, err := buf.Write(self.Uname); err != nil {
		return err
	}

	if err := buf.WriteByte(self.Plen); err != nil {
		return err
	}

	if _, err := buf.Write(self.Passwd); err != nil {
		return err
	}

	return nil
}

func ReadUserPasswordRequest(conn net.Conn) (*UserPasswordRequest, error) {
	req := &UserPasswordRequest{}
	if err := req.Read(conn); err != nil {
		return nil, err
	}

	return req, nil
}

func WriteUserPasswordRequest(conn net.Conn, req *UserPasswordRequest) error {
	if req == nil {
		return errors.New("invalid request")
	}

	return req.Write(conn)
}

// Username/Password reply:
// +----+--------+
// |VER | STATUS |
// +----+--------+
// | 1  |   1    |
// +----+--------+
type AuthReply struct {
	Ver    byte
	Status byte
}

const (
	AuthSuccess = byte(0x00)
	AuthFailure = byte(0x01)
)

func (self *AuthReply) Read(conn net.Conn) error {
	buf := bufio.NewReader(conn)
	tmp := make([]byte, 2)
	if _, err := buf.Read(tmp); err != nil {
		return err
	}

	self.Ver = tmp[0]
	self.Status = tmp[1]

	return nil
}

func (self *AuthReply) Write(conn net.Conn) error {
	buf := bufio.NewWriter(conn)
	tmp := make([]byte, 2)
	tmp[0] = self.Ver
	tmp[1] = self.Status

	fmt.Printf("write reply:%v\n", tmp)
	n, err := buf.Write(tmp)
	fmt.Printf("write:%v, err:%v\n", n, err)

	return err
}

func ReadAuthReply(conn net.Conn) (*AuthReply, error) {
	rep := &AuthReply{}
	if err := rep.Read(conn); err != nil {
		return nil, err
	}

	return rep, nil
}

func WriteAuthReply(conn net.Conn, rep *AuthReply) error {
	if rep == nil {
		return errors.New("invalid reply")
	}

	return rep.Write(conn)
}
