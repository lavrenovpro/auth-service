package jwt

import (
	"github.com/dgrijalva/jwt-go"
	"log"
	"os"
	"strconv"
	"time"
)

var issuer string
var secretKey string
var experationHours int64

type JwtWrapper struct {
	SecretKey       string
	Issuer          string
	ExpirationHours int64
}

type JwtClaim struct {
	guid string
	jwt.StandardClaims
}

func GenerateAccessToken(guid string) (signedToken string, err error) {
	claims := &JwtClaim{
		guid: guid,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Hour * time.Duration(experationHours)).Unix(),
			Issuer:    issuer,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	signedToken, err = token.SignedString([]byte(secretKey))
	if err != nil {
		return
	}
	return
}

func init() {
	log.Println("Init jwtWrapper.")
	issuer = os.Getenv("ISSUER")
	secretKey = os.Getenv("SECRET_KEY")

	var err error
	experationHours, err = strconv.ParseInt(os.Getenv("ACCESS_TOKEN_VALID_HOURS"), 10, 64)
	if err != nil {
		defaultValue := int64(24)
		log.Println("ACCESS_TOKEN_VALID_HOURS is not specified. Use default value " + strconv.FormatInt(defaultValue, 10))
		experationHours = defaultValue
	}
}
