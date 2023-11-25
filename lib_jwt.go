package lib_jwt

import (
	"fmt"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type JWTConfig map[int]interface{}
type JWTClaim map[string]interface{}
type JWTBlackList map[string]time.Time

type TokenPair struct {
	AccessToken  *string
	RefreshToken *string
}

type TJWT struct {
	method          jwt.SigningMethod
	secretKey       []byte
	accessDuration  time.Duration
	refreshDuration time.Duration
}

const (
	Method = iota
	SecretKey
	AccessDuration
	RefreshDuration
)

const (
	HS256 = iota
	HS384
	HS512
	ES256
	ES384
	ES512
	EDDSA
	NONE
	RS256
	RS384
	RS512
	PS256
	PS384
	PS512
)

var (
	BlackList JWTBlackList
)

func (b JWTBlackList) AddToBlackList(UUID string, expire time.Time) {
	for token, duration := range b {
		if duration.Before(time.Now()) {
			delete(b, token)
		} 

		if token == UUID {
			return
		}
	}

	b[UUID] = expire
}

func MapStrToMethod(str string) int {
	switch strings.ToUpper(str) {
	case "HS256":
		return HS256
	case "HS384":
		return HS384
	case "HS512":
		return HS512
	case "ES256":
		return ES256
	case "ES384":
		return ES384
	case "ES512":
		return ES512
	case "EDDSA":
		return EDDSA
	case "NONE":
		return NONE
	case "RS256":
		return RS256
	case "RS384":
		return RS384
	case "RS512":
		return RS512
	case "PS256":
		return PS256
	case "PS384":
		return PS384
	case "PS512":
		return PS512
	default:
		return -1
	}
}

func New(m *JWTConfig) (*TJWT, error) {
	var (
		j      TJWT
		ok     bool
		method int
	)

	if method, ok = (*m)[Method].(int); !ok {
		return nil, fmt.Errorf("Укажите Method")
	}

	if method == -1 {
		return nil, fmt.Errorf("Укажите Method")
	}

	if j.secretKey, ok = (*m)[SecretKey].([]byte); !ok {
		return nil, fmt.Errorf("Укажите SecretKey")
	}

	if j.accessDuration, ok = (*m)[AccessDuration].(time.Duration); !ok {
		return nil, fmt.Errorf("Укажите AccessDuration")
	}

	if j.refreshDuration, ok = (*m)[RefreshDuration].(time.Duration); !ok {
		return nil, fmt.Errorf("Укажите RefreshDuration")
	}

	switch method {
	case HS256:
		j.method = jwt.SigningMethodHS256
	case HS384:
		j.method = jwt.SigningMethodHS384
	case HS512:
		j.method = jwt.SigningMethodHS512
	case ES256:
		j.method = jwt.SigningMethodES256
	case ES384:
		j.method = jwt.SigningMethodES384
	case ES512:
		j.method = jwt.SigningMethodES512
	case EDDSA:
		j.method = jwt.SigningMethodEdDSA
	case NONE:
		j.method = jwt.SigningMethodNone
	case RS256:
		j.method = jwt.SigningMethodRS256
	case RS384:
		j.method = jwt.SigningMethodRS384
	case RS512:
		j.method = jwt.SigningMethodRS512
	case PS256:
		j.method = jwt.SigningMethodPS256
	case PS384:
		j.method = jwt.SigningMethodPS384
	case PS512:
		j.method = jwt.SigningMethodPS512
	}

	return &j, nil
}

func (j *TJWT) GenerateTokenPair(claims *JWTClaim) (*TokenPair, error) {
	UID := uuid.New()

	(*claims)["uid"] = UID
	(*claims)["sub"] = "access"
	(*claims)["iat"] = time.Now().Unix()
	(*claims)["exp"] = time.Now().Add(j.accessDuration).Unix()

	accessToken, err := jwt.NewWithClaims(j.method, jwt.MapClaims(*claims)).SignedString(j.secretKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка генерации AccessToken: %v", err)
	}

	rClaim := &JWTClaim{
		"uid": UID,
		"sub": "refresh",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(j.refreshDuration).Unix(),
	}

	refreshToken, err := jwt.NewWithClaims(j.method, jwt.MapClaims(*rClaim)).SignedString(j.secretKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка генерации RefreshToken: %v", err)
	}

	return &TokenPair{
		AccessToken:  &accessToken,
		RefreshToken: &refreshToken,
	}, nil
}

func (j *TJWT) ParseToken(tokenString *string) (*JWTClaim, error) {
	token, err := jwt.Parse(*tokenString, func(token *jwt.Token) (interface{}, error) {
		return j.secretKey, nil
	})

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	cl := JWTClaim(claims)
	return &cl, err
}
