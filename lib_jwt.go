package lib_jwt

import (
	"fmt"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

type InitMap map[int]interface{}

type TokenPair struct {
	AccessToken  *string
	RefreshToken *string
}

type TJWT struct {
	algorithm       int
	secretKey       []byte
	accessDuration  time.Duration
	refreshDuration time.Duration
	token           *jwt.Token
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

func New(m *InitMap) (*TJWT, error) {
	j := TJWT{}
	var ok bool

	if j.algorithm, ok = (*m)[Algorithm].(int); !ok {
		return nil, fmt.Errorf("Укажите Algorithm")
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

	var method jwt.SigningMethod
	switch j.algorithm {
	case HS256:
		method = jwt.SigningMethodHS256
	case HS384:
		method = jwt.SigningMethodHS384
	case HS512:
		method = jwt.SigningMethodHS512
	case ES256:
		method = jwt.SigningMethodES256
	case ES384:
		method = jwt.SigningMethodES384
	case ES512:
		method = jwt.SigningMethodES512
	case EDDSA:
		method = jwt.SigningMethodEdDSA
	case NONE:
		method = jwt.SigningMethodNone
	case RS256:
		method = jwt.SigningMethodRS256
	case RS384:
		method = jwt.SigningMethodRS384
	case RS512:
		method = jwt.SigningMethodRS512
	case PS256:
		method = jwt.SigningMethodPS256
	case PS384:
		method = jwt.SigningMethodPS384
	case PS512:
		method = jwt.SigningMethodPS512
	}

	j.token = jwt.New(method)

	return &j, nil
}

func (j *TJWT) GenerateTokenPair(claims map[string]interface{}) (*TokenPair, error) {
	accessToken, err := j.generateAccessToken(claims)
	if err != nil {
		return nil, fmt.Errorf("ошибка генерации AccessToken: %v", err)
	}

	refreshToken, err := j.generateRefreshToken(claims)
	if err != nil {
		return nil, fmt.Errorf("ошибка генерации RefreshToken: %v", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (j *TJWT) generateAccessToken(claims map[string]interface{}) (*string, error) {
	claims["exp"] = time.Now().Add(j.accessDuration).Unix()
	//accesstoken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
	//accessToken, err := accesstoken.SignedString(j.secretKey)
	if err != nil {
		return nil, err
	}
	return &accessToken, nil
}

/*
func (j *TJWT) generateRefreshToken(claims map[string]interface{}) (*string, error) {
	claims["exp"] = time.Now().Add(j.refreshDuration).Unix()
	//refreshtoken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
	//refreshToken, err := refreshtoken.SignedString(j.secretKey)
	if err != nil {
		return nil, err
	}
	return &refreshToken, nil
}
*/
/*
func (j *TJWT) ParseToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return j.secretKey, nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}
*/
