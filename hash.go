package encrypt

import (
	"unsafe"

	"github.com/alexedwards/argon2id"
	"golang.org/x/crypto/bcrypt"
)

type Hasher interface {
	Mode() Mode
	Prefix() string
	_hash(data []byte) ([]byte, error)
	_compare(text []byte, hash []byte) error
}

type Bcrypt struct {
	Cost int
}

func (Bcrypt) Mode() Mode {
	return HashModeBcrypt
}

func (b Bcrypt) Prefix() string {
	return getPrefix(b.Mode())
}

func (b Bcrypt) _hash(data []byte) ([]byte, error) {
	var ret = make([]byte, 0)

	bret, err := bcrypt.GenerateFromPassword(data, b.Cost)
	if err != nil {
		return nil, err
	}
	ret = append(ret, []byte(b.Prefix())...)
	ret = append(ret, bret...)
	return ret, nil

}

func (b Bcrypt) _compare(text []byte, hash []byte) error {
	// if b.Mode() != getPrefixMode(string(hash[:prefixLen])) {
	// 	return errors.New("invaild mode")
	// }
	return bcrypt.CompareHashAndPassword(hash[prefixLen:], text)
}

func (Argon2) Mode() Mode {
	return HashModeArgon2
}

func (ag Argon2) Prefix() string {
	return getPrefix(ag.Mode())
}

func (ag Argon2) _hash(data []byte) (ret []byte, err error) {
	if (ag == Argon2{}) {
		ag = DefaultArgon2Params
	}
	h, err := argon2id.CreateHash(BytesToString(data), (*argon2id.Params)(unsafe.Pointer(&ag)))
	if err != nil {
		return nil, err
	}
	ret = append(ret, []byte(ag.Prefix())...)
	ret = append(ret, []byte(h)...)
	return ret, nil
}

func (ag Argon2) _compare(text []byte, hash []byte) error {
	match, err := argon2id.ComparePasswordAndHash(BytesToString(text), BytesToString(hash[prefixLen:]))
	if err != nil {
		return err
	}
	if !match {
		return ErrInvalidCredentials
	}
	return nil

}
