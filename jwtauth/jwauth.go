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
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/context"
)

type AuthHandler struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

type AllClaims struct {
	jwt.StandardClaims
	CustomClaims map[string]string
}

func NewAuthHandler(privkey string, pubkey string) *AuthHandler {
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
	return &AuthHandler{
		privateKey: parsedPriv,
		publicKey:  parsedPub,
	}
}

func (a *AuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	headerToken := r.Header.Get("Authorization")
	if headerToken == "" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "{\"code\":\"401\",\"title\":\"Unauthorized\",\"detail\":\"Access not authorized.\"}")
		return
	}

	token := strings.TrimPrefix(headerToken, "Bearer ")
	claims, err := a.verifyToken(token)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, "{\"code\":\"401\",\"title\":\"Unauthorized\",\"detail\":\"Access not authorized.\"}")
		return
	}

	context.Set(r, "user", claims)
}

func (a *AuthHandler) NewToken(claims map[string]string, duration time.Duration) (string, error) {
	var err error

	tokenClaims := &AllClaims{CustomClaims: claims}
	for k, v := range claims {
		if tokenClaims.CustomClaims[k], err = encryptClaim(v, a.publicKey); err != nil {
			return "", err
		}
	}

	tokenClaims.StandardClaims.IssuedAt = time.Now().Unix()
	tokenClaims.StandardClaims.ExpiresAt = time.Now().Add(duration).Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodRS512, tokenClaims)
	tokenString, err := token.SignedString(a.privateKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func (a *AuthHandler) verifyToken(token string) (map[string]string, error) {
	recvToken, err := jwt.ParseWithClaims(token, &AllClaims{}, func(token *jwt.Token) (interface{}, error) {
		return a.publicKey, nil
	})
	if err != nil {
		return nil, err
	}
	if recvToken.Method != jwt.SigningMethodRS512 {
		return nil, errors.New("Illegal Signing Method")
	}

	tokenClaims, ok := recvToken.Claims.(*AllClaims)
	if !ok || !recvToken.Valid {
		return nil, errors.New("Invalid token")

	}

	issuedAt := time.Unix(tokenClaims.StandardClaims.IssuedAt, 0)
	expiration := time.Unix(tokenClaims.StandardClaims.ExpiresAt, 0)
	currentTime := time.Now()

	if issuedAt.After(currentTime) && expiration.Before(currentTime) {
		return nil, errors.New("Token expired or not yet valid")
	}

	claims := make(map[string]string)
	for k, v := range tokenClaims.CustomClaims {
		if claims[k], err = decryptClaim(v, a.privateKey); err != nil {
			return nil, err
		}
	}

	return claims, nil
}

func encryptClaim(claim string, publicKey *rsa.PublicKey) (string, error) {
	label := []byte("authenticator")
	rng := rand.Reader
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, publicKey, []byte(claim), label)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decryptClaim(claim string, privateKey *rsa.PrivateKey) (string, error) {
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
