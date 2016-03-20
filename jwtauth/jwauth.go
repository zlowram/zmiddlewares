package jwtauth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/context"
)

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
)

type AuthHandler struct {
	next http.Handler
}

func NewAuthHandler(privkey string, pubkey string) func(http.Handler) http.Handler {
	priv, _ := ioutil.ReadFile(privkey)
	parsedPriv, err := jwt.ParseRSAPrivateKeyFromPEM(priv)
	if err != nil {
		log.Fatal(err)
	}
	pub, _ := ioutil.ReadFile(pubkey)
	parsedPub, err := jwt.ParseRSAPublicKeyFromPEM(pub)
	if err != nil {
		log.Fatal(err)
	}
	privateKey = parsedPriv
	publicKey = parsedPub
	return func(handler http.Handler) http.Handler {
		return &AuthHandler{
			next: handler,
		}
	}
}

func (a *AuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	headerToken := r.Header.Get("Authorization")
	if headerToken == "" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "{\"code\":\"401\",\"title\":\"Unauthorized\",\"detail\":\"Access not authorized.\"}]}")
		return
	}

	token := strings.TrimPrefix(headerToken, "Bearer ")
	claims, err := verifyToken(token)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "{\"code\":\"401\",\"title\":\"Unauthorized\",\"detail\":\"Access not authorized.\"}]}")
		return
	}

	context.Set(r, "user", claims)

	a.next.ServeHTTP(w, r)
}

func NewToken(claims map[string]string) (string, error) {
	var err error
	token := jwt.New(jwt.SigningMethodRS512)
	for k, v := range claims {
		if token.Claims[k], err = encryptClaim(v); err != nil {
			return "", err
		}
	}
	if token.Claims["iat"], err = encryptClaim(strconv.FormatInt(time.Now().Unix(), 10)); err != nil {
		return "", err
	}
	if token.Claims["exp"], err = encryptClaim(strconv.FormatInt(time.Now().Add(time.Hour*72).Unix(), 10)); err != nil {
		return "", err
	}
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func verifyToken(token string) (map[string]string, error) {
	recvToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	if recvToken.Method != jwt.SigningMethodRS512 {
		return nil, errors.New("Illegal Signing Method")
	}
	if recvToken.Claims["iat"] == nil || recvToken.Claims["exp"] == nil {
		return nil, errors.New("Illegal token")
	}

	claims := make(map[string]string)
	for k, v := range recvToken.Claims {
		if v != "iat" && v != "exp" {
			if claims[k], err = decryptClaim(v.(string)); err != nil {
				return nil, err
			}
		}
	}

	c, err := decryptClaim(recvToken.Claims["iat"].(string))
	if err != nil {
		return nil, err
	}
	iat, err := strconv.ParseInt(c, 10, 64)
	if err != nil {
		return nil, err
	}
	issuedAt := time.Unix(iat, 0)
	c, err = decryptClaim(recvToken.Claims["exp"].(string))
	if err != nil {
		return nil, err
	}
	exp, err := strconv.ParseInt(c, 10, 64)
	if err != nil {
		return nil, err
	}
	expiration := time.Unix(exp, 0)
	currentTime := time.Now()

	if !recvToken.Valid || (issuedAt.After(currentTime) && expiration.Before(currentTime)) {
		return nil, errors.New("Invalid token")
	}
	return claims, nil
}

func encryptClaim(claim string) (string, error) {
	label := []byte("authenticator")
	rng := rand.Reader
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, publicKey, []byte(claim), label)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decryptClaim(claim string) (string, error) {
	label := []byte("authenticator")
	rng := rand.Reader
	decoded, err := base64.StdEncoding.DecodeString(claim)
	if err != nil {
		return "", err
	}
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rng, privateKey, decoded, label)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}
