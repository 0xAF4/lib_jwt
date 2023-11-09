package libjwt

import (
	"errors"
	"time"
)

type InitMap map[string]interface{}

type TJWT struct {
	algorithm       int
	secretKey       []byte
	accessDuration  time.Duration
	refreshDuration time.Duration
}

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

	if jwt.algorithm, ok = (*m)["algorithm"].(int); !ok {
		return nil, errors.New("Укажите algorithm")
	}

	if jwt.secretKey, ok = (*m)["secretKey"].([]byte); !ok {
		return nil, errors.New("Укажите accessToken")
	}

	if jwt.accessDuration, ok = (*m)["accessDuration"].(time.Duration); !ok {
		return nil, errors.New("Укажите accessDuration")
	}

	if jwt.refreshDuration, ok = (*m)["refreshDuration"].(time.Duration); !ok {
		return nil, errors.New("Укажите refreshDuration")
	}

	return &jwt, nil
}
