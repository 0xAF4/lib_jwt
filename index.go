package libjwt

import (
	"errors"
	"time"
)

type InitMap map[int]interface{}

type TJWT struct {
	algorithm       int
	secretKey       []byte
	accessDuration  time.Duration
	refreshDuration time.Duration
}

const (
	Algorithm = iota
	SecretKey
	AccessDuration
	RefreshDuration
)

const (
	HS256 = iota
	HS384
	HS512
	RS256
	RS384
	RS512
	ES256
	ES384
	ES512
)

func New(m *InitMap) (*TJWT, error) {
	jwt := TJWT{}
	var ok bool

	if jwt.algorithm, ok = (*m)[Algorithm].(int); !ok {
		return nil, errors.New("Укажите Algorithm")
	}

	if jwt.secretKey, ok = (*m)[SecretKey].([]byte); !ok {
		return nil, errors.New("Укажите SecretKey")
	}

	if jwt.accessDuration, ok = (*m)[AccessDuration].(time.Duration); !ok {
		return nil, errors.New("Укажите AccessDuration")
	}

	if jwt.refreshDuration, ok = (*m)[RefreshDuration].(time.Duration); !ok {
		return nil, errors.New("Укажите RefreshDuration")
	}

	return &jwt, nil
}
