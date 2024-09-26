package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"

	"golang.org/x/crypto/argon2"
)

type Password struct {
	hash []byte
	salt []byte
}

type userPass struct {
	lock  sync.RWMutex
	users map[string]*Password
}

func (self *userPass) Create(user, password string) error {
	self.lock.Lock()
	defer self.lock.Unlock()

	pwd := self.hashPassword(password)
	if pwd == nil {
		return errors.New("hash password failed")
	}
	self.users[user] = pwd

	return nil
}

func (self *userPass) Update(user, password string) error {
	self.lock.Lock()
	defer self.lock.Unlock()

	pwd := self.hashPassword(password)
	self.users[user] = pwd

	return nil
}

func (self *userPass) Delete(user string) error {
	self.lock.Lock()
	defer self.lock.Unlock()

	delete(self.users, user)

	return nil
}

func (self *userPass) Validate(user, password string) (bool, error) {
	self.lock.RLock()
	defer self.lock.RUnlock()

	pwd, exist := self.users[user]
	if exist {
		sHash := self.hash(password, pwd.salt)
		return string(pwd.hash) == string(sHash.hash), nil
	} else {
		return false, nil
	}
}

func (self *userPass) hashPassword(password string) *Password {
	salt, err := self.salt()
	if err != nil {
		return nil
	}

	hash := self.hash(password, salt)
	return hash
}

func (self *userPass) salt() ([]byte, error) {
	salt := make([]byte, binary.MaxVarintLen64)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}

	return salt, nil
}
func (self *userPass) hash(password string, salt []byte) *Password {
	hash := argon2.IDKey([]byte(password), salt, 1, 3*1024, 4, 32)

	return &Password{salt: salt, hash: hash}
}
